// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// A collection for sent packets.

use std::{
    collections::VecDeque,
    ops::RangeInclusive,
    rc::Rc,
    time::{Duration, Instant},
};

use crate::{packet, recovery};

#[derive(Debug, Clone)]
pub struct Packet {
    pt: packet::Type,
    pn: packet::Number,
    ack_eliciting: bool,
    time_sent: Instant,
    primary_path: bool,
    tokens: Rc<recovery::Tokens>,

    time_declared_lost: Option<Instant>,
    /// After a PTO, this is true when the packet has been released.
    pto: bool,

    len: usize,
}

impl Packet {
    #[must_use]
    pub fn new(
        pt: packet::Type,
        pn: packet::Number,
        time_sent: Instant,
        ack_eliciting: bool,
        tokens: recovery::Tokens,
        len: usize,
    ) -> Self {
        Self {
            pt,
            pn,
            time_sent,
            ack_eliciting,
            primary_path: true,
            tokens: Rc::new(tokens),
            time_declared_lost: None,
            pto: false,
            len,
        }
    }

    /// The type of this packet.
    #[must_use]
    pub const fn packet_type(&self) -> packet::Type {
        self.pt
    }

    /// The number of the packet.
    #[must_use]
    pub const fn pn(&self) -> packet::Number {
        self.pn
    }

    /// The ECN mark of the packet.
    #[must_use]
    pub fn ecn_marked_ect0(&self) -> bool {
        self.tokens
            .iter()
            .any(|t| matches!(t, recovery::Token::EcnEct0))
    }

    /// The time that this packet was sent.
    #[must_use]
    pub const fn time_sent(&self) -> Instant {
        self.time_sent
    }

    /// Returns `true` if the packet will elicit an ACK.
    #[must_use]
    pub const fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    /// Returns `true` if the packet was sent on the primary path.
    #[must_use]
    pub const fn on_primary_path(&self) -> bool {
        self.primary_path
    }

    /// The length of the packet that was sent.
    #[allow(
        clippy::allow_attributes,
        clippy::len_without_is_empty,
        reason = "OK here."
    )]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Access the recovery tokens that this holds.
    #[must_use]
    pub fn tokens(&self) -> &recovery::Tokens {
        self.tokens.as_ref()
    }

    /// Clears the flag that had this packet on the primary path.
    /// Used when migrating to clear out state.
    pub fn clear_primary_path(&mut self) {
        self.primary_path = false;
    }

    /// For Initial packets, it is possible that the packet builder needs to amend the length.
    pub fn track_padding(&mut self, padding: usize) {
        debug_assert_eq!(self.pt, packet::Type::Initial);
        self.len += padding;
    }

    /// Whether the packet has been declared lost.
    #[must_use]
    pub const fn lost(&self) -> bool {
        self.time_declared_lost.is_some()
    }

    /// Whether accounting for the loss or acknowledgement in the
    /// congestion controller is pending.
    /// Returns `true` if the packet counts as being "in flight",
    /// and has not previously been declared lost.
    /// Note that this should count packets that contain only ACK and PADDING,
    /// but we don't send PADDING, so we don't track that.
    #[must_use]
    pub const fn cc_outstanding(&self) -> bool {
        self.ack_eliciting() && self.on_primary_path() && !self.lost()
    }

    /// Whether the packet should be tracked as in-flight.
    #[must_use]
    pub const fn cc_in_flight(&self) -> bool {
        self.ack_eliciting() && self.on_primary_path()
    }

    /// Declare the packet as lost.  Returns `true` if this is the first time.
    pub fn declare_lost(&mut self, now: Instant) -> bool {
        if self.lost() {
            false
        } else {
            self.time_declared_lost = Some(now);
            true
        }
    }

    /// Ask whether this tracked packet has been declared lost for long enough
    /// that it can be expired and no longer tracked.
    #[must_use]
    pub fn expired(&self, now: Instant, expiration_period: Duration) -> bool {
        self.time_declared_lost
            .is_some_and(|loss_time| (loss_time + expiration_period) <= now)
    }

    /// Whether the packet contents were cleared out after a PTO.
    #[must_use]
    pub const fn pto_fired(&self) -> bool {
        self.pto
    }

    /// On PTO, we need to get the recovery tokens so that we can ensure that
    /// the frames we sent can be sent again in the PTO packet(s).  Do that just once.
    #[must_use]
    pub fn pto(&mut self) -> bool {
        if self.pto || self.lost() {
            false
        } else {
            self.pto = true;
            true
        }
    }
}

/// A collection for packets that we have sent that haven't been acknowledged.
/// Optimized for sequential packet numbers using `VecDeque` for O(1) insertion.
#[derive(Debug, Default)]
pub struct Packets {
    /// Packets stored sequentially, indexed by (pn - `base_pn`).
    packets: VecDeque<Option<Packet>>,
    /// The packet number corresponding to `packets[0]`.
    base_pn: u64,
}

impl Packets {
    #[allow(
        clippy::allow_attributes,
        clippy::len_without_is_empty,
        reason = "OK here."
    )]
    #[must_use]
    pub fn len(&self) -> usize {
        self.packets.iter().filter(|p| p.is_some()).count()
    }

    pub fn track(&mut self, packet: Packet) {
        let pn = packet.pn;
        let index =
            usize::try_from(pn.saturating_sub(self.base_pn)).expect("packet number within range");

        match index.cmp(&self.packets.len()) {
            std::cmp::Ordering::Equal => {
                // Common case: sequential packet (pn = pn + 1)
                self.packets.push_back(Some(packet));
            }
            std::cmp::Ordering::Less => {
                // Slot exists - overwrite (retransmission or gap fill)
                self.packets[index] = Some(packet);
            }
            std::cmp::Ordering::Greater => {
                // Gap in packet numbers (rare)
                self.packets.resize(index + 1, None);
                self.packets[index] = Some(packet);
            }
        }
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Packet> {
        self.packets.iter_mut().filter_map(|p| p.as_mut())
    }

    /// Take values from specified ranges of packet numbers.
    /// The values returned will be reversed, so that the most recent packet appears first.
    /// This is because ACK frames arrive with ranges starting from the largest acknowledged
    /// and we want to match that.
    pub fn take_ranges<R>(&mut self, acked_ranges: R) -> Vec<Packet>
    where
        R: IntoIterator<Item = RangeInclusive<packet::Number>>,
        R::IntoIter: ExactSizeIterator,
    {
        let mut result = Vec::new();

        for range in acked_ranges {
            // Iterate in reverse order to match expected output order
            for pn in (*range.start()..=*range.end()).rev() {
                if let Some(index) = pn.checked_sub(self.base_pn) {
                    if let Ok(index) = usize::try_from(index) {
                        if index < self.packets.len() {
                            if let Some(packet) = self.packets[index].take() {
                                result.push(packet);
                            }
                        }
                    }
                }
            }
        }

        // Shrink from front to reclaim memory from acked packets
        while matches!(self.packets.front(), Some(None)) {
            self.packets.pop_front();
            self.base_pn += 1;
        }

        result
    }

    /// Empty out the packets, but keep the offset.
    pub fn drain_all(&mut self) -> impl Iterator<Item = Packet> {
        std::mem::take(&mut self.packets).into_iter().flatten()
    }

    /// See `LossRecoverySpace::remove_old_lost` for details on `now` and `cd`.
    /// Returns the number of ack-eliciting packets removed.
    pub fn remove_expired(&mut self, now: Instant, cd: Duration) -> usize {
        // Check if the first packet is expired (most common case: it's not)
        if let Some(Some(first)) = self.packets.front() {
            if !first.expired(now, cd) {
                return 0;
            }
        } else {
            return 0;
        }

        // Find the first non-expired packet
        let first_keep_index = self
            .packets
            .iter()
            .position(|p| p.as_ref().is_some_and(|pkt| !pkt.expired(now, cd)));

        let ack_eliciting_count = if let Some(keep_at) = first_keep_index {
            // Remove expired packets from front
            let mut removed_count = 0;
            for _ in 0..keep_at {
                match self.packets.pop_front() {
                    Some(Some(packet)) => {
                        if packet.ack_eliciting() {
                            removed_count += 1;
                        }
                    }
                    Some(None) => {
                        // Empty slot
                    }
                    None => {
                        break;
                    }
                }
                self.base_pn += 1;
            }
            removed_count
        } else {
            // All packets are expired
            let removed_count = self
                .packets
                .iter()
                .filter_map(|p| p.as_ref())
                .filter(|p| p.ack_eliciting())
                .count();
            self.packets.clear();
            removed_count
        };

        ack_eliciting_count
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        cell::OnceCell,
        time::{Duration, Instant},
    };

    use super::{Packet, Packets};
    use crate::{packet, recovery};

    const PACKET_GAP: Duration = Duration::from_secs(1);
    fn start_time() -> Instant {
        thread_local!(static STARTING_TIME: OnceCell<Instant> = const { OnceCell::new() });
        STARTING_TIME.with(|t| *t.get_or_init(Instant::now))
    }

    fn pkt(n: u32) -> Packet {
        Packet::new(
            packet::Type::Short,
            packet::Number::from(n),
            start_time() + (PACKET_GAP * n),
            true,
            recovery::Tokens::new(),
            100,
        )
    }

    fn pkts() -> Packets {
        let mut pkts = Packets::default();
        pkts.track(pkt(0));
        pkts.track(pkt(1));
        pkts.track(pkt(2));
        assert_eq!(pkts.len(), 3);
        pkts
    }

    trait HasPacketNumber {
        fn pn(&self) -> packet::Number;
    }
    impl HasPacketNumber for Packet {
        fn pn(&self) -> packet::Number {
            self.pn
        }
    }
    impl HasPacketNumber for &'_ mut Packet {
        fn pn(&self) -> packet::Number {
            self.pn
        }
    }

    fn remove_one(pkts: &mut Packets, idx: packet::Number) {
        assert_eq!(pkts.len(), 3);
        let store = pkts.take_ranges([idx..=idx]);
        let mut it = store.into_iter();
        assert_eq!(idx, it.next().unwrap().pn());
        assert!(it.next().is_none());
        drop(it);
        assert_eq!(pkts.len(), 2);
    }

    fn assert_zero_and_two<'a, 'b: 'a>(
        mut it: impl Iterator<Item = impl HasPacketNumber + 'b> + 'a,
    ) {
        assert_eq!(it.next().unwrap().pn(), 0);
        assert_eq!(it.next().unwrap().pn(), 2);
        assert!(it.next().is_none());
    }

    #[test]
    fn iterate_skipped() {
        let mut pkts = pkts();
        for (i, p) in pkts.iter_mut().enumerate() {
            assert_eq!(i, usize::try_from(p.pn()).unwrap());
        }
        remove_one(&mut pkts, 1);

        // Validate the merged result multiple ways.
        assert_zero_and_two(pkts.iter_mut());

        {
            // Reverse the expectations here as this iterator reverses its output.
            let store = pkts.take_ranges([0..=2]);
            let mut it = store.into_iter();
            assert_eq!(it.next().unwrap().pn(), 2);
            assert_eq!(it.next().unwrap().pn(), 0);
            assert!(it.next().is_none());
        };

        // The None values are still there in this case, so offset is 0.
        assert_eq!(pkts.packets.len(), 0);
        assert_eq!(pkts.len(), 0);
    }

    #[test]
    fn drain() {
        let mut pkts = pkts();
        remove_one(&mut pkts, 1);

        assert_zero_and_two(pkts.drain_all());
        assert_eq!(pkts.len(), 0);
    }

    #[test]
    fn remove_expired() {
        let mut pkts = pkts();
        remove_one(&mut pkts, 0);

        for p in pkts.iter_mut() {
            p.declare_lost(p.time_sent); // just to keep things simple.
        }

        // Expire up to pkt(1).
        let count = pkts.remove_expired(start_time() + PACKET_GAP, Duration::new(0, 0));
        assert_eq!(count, 1);
        assert_eq!(pkts.len(), 1);
    }

    #[test]
    fn first_skipped_ok() {
        let mut pkts = Packets::default();
        pkts.track(pkt(4)); // This is fine.
        assert_eq!(pkts.len(), 1);
    }

    #[test]
    fn ignore_unknown() {
        let mut pkts = Packets::default();
        pkts.track(pkt(0));
        assert!(pkts.take_ranges([1..=1]).is_empty());
    }
}
