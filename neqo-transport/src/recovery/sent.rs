// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// A collection for sent packets.

use std::{
    cmp::min,
    convert::TryFrom,
    ops::RangeInclusive,
    time::{Duration, Instant},
};

use crate::{
    packet::{PacketNumber, PacketType},
    recovery::RecoveryToken,
};

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub pt: PacketType,
    pub pn: PacketNumber,
    ack_eliciting: bool,
    pub time_sent: Instant,
    primary_path: bool,
    pub tokens: Vec<RecoveryToken>,

    time_declared_lost: Option<Instant>,
    /// After a PTO, this is true when the packet has been released.
    pto: bool,

    pub size: usize,
}

impl SentPacket {
    pub fn new(
        pt: PacketType,
        pn: PacketNumber,
        time_sent: Instant,
        ack_eliciting: bool,
        tokens: Vec<RecoveryToken>,
        size: usize,
    ) -> Self {
        Self {
            pt,
            pn,
            time_sent,
            ack_eliciting,
            primary_path: true,
            tokens,
            time_declared_lost: None,
            pto: false,
            size,
        }
    }

    /// The number of the packet.
    pub fn pn(&self) -> PacketNumber {
        self.pn
    }

    /// Returns `true` if the packet will elicit an ACK.
    pub fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    /// Returns `true` if the packet was sent on the primary path.
    pub fn on_primary_path(&self) -> bool {
        self.primary_path
    }

    /// Clears the flag that had this packet on the primary path.
    /// Used when migrating to clear out state.
    pub fn clear_primary_path(&mut self) {
        self.primary_path = false;
    }

    /// Whether the packet has been declared lost.
    pub fn lost(&self) -> bool {
        self.time_declared_lost.is_some()
    }

    /// Whether accounting for the loss or acknowledgement in the
    /// congestion controller is pending.
    /// Returns `true` if the packet counts as being "in flight",
    /// and has not previously been declared lost.
    /// Note that this should count packets that contain only ACK and PADDING,
    /// but we don't send PADDING, so we don't track that.
    pub fn cc_outstanding(&self) -> bool {
        self.ack_eliciting() && self.on_primary_path() && !self.lost()
    }

    /// Whether the packet should be tracked as in-flight.
    pub fn cc_in_flight(&self) -> bool {
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
    pub fn expired(&self, now: Instant, expiration_period: Duration) -> bool {
        self.time_declared_lost
            .map_or(false, |loss_time| (loss_time + expiration_period) <= now)
    }

    /// Whether the packet contents were cleared out after a PTO.
    pub fn pto_fired(&self) -> bool {
        self.pto
    }

    /// On PTO, we need to get the recovery tokens so that we can ensure that
    /// the frames we sent can be sent again in the PTO packet(s).  Do that just once.
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
#[derive(Debug, Default)]
pub struct SentPackets {
    /// The collection.
    packets: Vec<Option<SentPacket>>,
    /// The packet number of the first item in the collection.
    offset: PacketNumber,
    /// The number of `Some` values in the packet.  This is cached to keep things squeaky-fast.
    len: usize,
}

impl SentPackets {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn track(&mut self, packet: SentPacket) {
        if self.offset + PacketNumber::try_from(self.packets.len()).unwrap() != packet.pn {
            assert_eq!(
                self.len, 0,
                "packet number skipping only supported for the first packet in a space"
            );
            self.offset = packet.pn;
        }
        self.len += 1;
        self.packets.push(Some(packet));
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut SentPacket> {
        self.packets.iter_mut().flatten()
    }

    /// Take values from a specified range of packet numbers.
    /// Note that this will not remove values unless the iterator is consumed.
    /// The values returned will be reversed, so that the most recent packet appears first.
    /// This is because ACK frames arrive with ranges starting from the largest acknowledged
    /// and we want to match that.
    pub fn take_range(&mut self, r: RangeInclusive<PacketNumber>, store: &mut Vec<SentPacket>) {
        let start = usize::try_from((*r.start()).saturating_sub(self.offset)).unwrap();
        let end = min(
            usize::try_from((*r.end() + 1).saturating_sub(self.offset)).unwrap(),
            self.packets.len(),
        );

        let before = store.len();
        if self.packets[..start].iter().all(Option::is_none) {
            // If there are extra empty slots, split those off too.
            let extra = self.packets[end..]
                .iter()
                .take_while(|&p| p.is_none())
                .count();
            self.offset += u64::try_from(end + extra).unwrap();
            let mut other = self.packets.split_off(end + extra);
            std::mem::swap(&mut self.packets, &mut other);
            store.extend(
                other
                    .into_iter()
                    .rev()
                    .skip(extra)
                    .take(end - start)
                    .flatten(),
            );
        } else {
            store.extend(
                self.packets[start..end]
                    .iter_mut()
                    .rev()
                    .filter_map(Option::take),
            );
        }
        self.len -= store.len() - before;
    }

    /// Empty out the packets, but keep the offset.
    pub fn drain_all(&mut self) -> impl Iterator<Item = SentPacket> {
        self.len = 0;
        self.offset += u64::try_from(self.packets.len()).unwrap();
        std::mem::take(&mut self.packets).into_iter().flatten()
    }

    /// See `LossRecoverySpace::remove_old_lost` for details on `now` and `cd`.
    pub fn remove_expired(
        &mut self,
        now: Instant,
        cd: Duration,
    ) -> impl Iterator<Item = SentPacket> {
        let mut count = 0;
        // Find the first unexpired packet and only keep from that one onwards.
        for (i, p) in self.packets.iter().enumerate() {
            if p.as_ref().map_or(false, |p| !p.expired(now, cd)) {
                let mut other = self.packets.split_off(i);
                self.len -= count;
                self.offset += u64::try_from(i).unwrap();
                std::mem::swap(&mut self.packets, &mut other);
                return other.into_iter().flatten();
            }
            // Count `Some` values that we are removing.
            count += usize::from(p.is_some());
        }

        self.len = 0;
        self.offset += u64::try_from(self.packets.len()).unwrap();
        std::mem::take(&mut self.packets).into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::OnceCell,
        convert::TryFrom,
        time::{Duration, Instant},
    };

    use super::{SentPacket, SentPackets};
    use crate::packet::{PacketNumber, PacketType};

    const PACKET_GAP: Duration = Duration::from_secs(1);
    fn start_time() -> Instant {
        thread_local!(static STARTING_TIME: OnceCell<Instant> = OnceCell::new());
        STARTING_TIME.with(|t| *t.get_or_init(Instant::now))
    }

    fn pkt(n: u32) -> SentPacket {
        SentPacket::new(
            PacketType::Short,
            PacketNumber::from(n),
            start_time() + (PACKET_GAP * n),
            true,
            Vec::new(),
            100,
        )
    }

    fn pkts() -> SentPackets {
        let mut pkts = SentPackets::default();
        pkts.track(pkt(0));
        pkts.track(pkt(1));
        pkts.track(pkt(2));
        assert_eq!(pkts.len(), 3);
        pkts
    }

    trait HasPacketNumber {
        fn pn(&self) -> PacketNumber;
    }
    impl HasPacketNumber for SentPacket {
        fn pn(&self) -> PacketNumber {
            self.pn
        }
    }
    impl HasPacketNumber for &'_ SentPacket {
        fn pn(&self) -> PacketNumber {
            self.pn
        }
    }
    impl HasPacketNumber for &'_ mut SentPacket {
        fn pn(&self) -> PacketNumber {
            self.pn
        }
    }

    fn remove_one(pkts: &mut SentPackets, idx: PacketNumber) {
        assert_eq!(pkts.len(), 3);
        let mut store = Vec::new();
        pkts.take_range(idx..=idx, &mut store);
        let mut it = store.into_iter();
        assert_eq!(idx, it.next().unwrap().pn());
        assert!(it.next().is_none());
        std::mem::drop(it);
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
        for (i, p) in pkts.packets.iter().enumerate() {
            assert_eq!(i, usize::try_from(p.as_ref().unwrap().pn).unwrap());
        }
        remove_one(&mut pkts, 1);

        // Validate the merged result multiple ways.
        assert_zero_and_two(pkts.iter_mut());

        {
            // Reverse the expectations here as this iterator reverses its output.
            let mut store = Vec::new();
            pkts.take_range(0..=2, &mut store);
            let mut it = store.into_iter();
            assert_eq!(it.next().unwrap().pn(), 2);
            assert_eq!(it.next().unwrap().pn(), 0);
            assert!(it.next().is_none());
        };

        // The None values are still there in this case, so offset is 0.
        assert_eq!(pkts.offset, 3);
        assert_eq!(pkts.packets.len(), 0);
        assert_eq!(pkts.len(), 0);
    }

    #[test]
    fn drain() {
        let mut pkts = pkts();
        remove_one(&mut pkts, 1);

        assert_zero_and_two(pkts.drain_all());
        assert_eq!(pkts.offset, 3);
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
        let mut it = pkts.remove_expired(start_time() + PACKET_GAP, Duration::new(0, 0));
        assert_eq!(it.next().unwrap().pn(), 1);
        assert!(it.next().is_none());
        std::mem::drop(it);

        assert_eq!(pkts.offset, 2);
        assert_eq!(pkts.len(), 1);
    }

    #[test]
    #[should_panic(expected = "packet number skipping only supported for the first packet")]
    fn skipped_not_ok() {
        let mut pkts = pkts();
        pkts.track(pkt(4));
    }

    #[test]
    fn first_skipped_ok() {
        let mut pkts = SentPackets::default();
        pkts.track(pkt(4)); // This is fine.
        assert_eq!(pkts.offset, 4);
        assert_eq!(pkts.len(), 1);
    }
}
