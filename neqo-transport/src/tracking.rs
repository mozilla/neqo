// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracking of received packets and generating acks thereof.

#![deny(clippy::pedantic)]

use std::cmp::min;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::ops::{Index, IndexMut};
use std::rc::Rc;
use std::time::{Duration, Instant};

use neqo_common::{qdebug, qinfo, qtrace, qwarn};
use neqo_crypto::{Epoch, TLS_EPOCH_HANDSHAKE, TLS_EPOCH_INITIAL};

use crate::frame::{AckRange, Frame};
use crate::packet::{PacketNumber, PacketType};
use crate::recovery::RecoveryToken;

use smallvec::{smallvec, SmallVec};

// TODO(mt) look at enabling EnumMap for this: https://stackoverflow.com/a/44905797/1375574
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum PNSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[allow(clippy::use_self)] // https://github.com/rust-lang/rust-clippy/issues/3410
impl PNSpace {
    pub fn iter() -> impl Iterator<Item = &'static PNSpace> {
        const SPACES: &[PNSpace] = &[
            PNSpace::Initial,
            PNSpace::Handshake,
            PNSpace::ApplicationData,
        ];
        SPACES.iter()
    }
}

impl From<Epoch> for PNSpace {
    fn from(epoch: Epoch) -> Self {
        match epoch {
            TLS_EPOCH_INITIAL => Self::Initial,
            TLS_EPOCH_HANDSHAKE => Self::Handshake,
            _ => Self::ApplicationData,
        }
    }
}

impl From<PacketType> for PNSpace {
    fn from(pt: PacketType) -> Self {
        match pt {
            PacketType::Initial => Self::Initial,
            PacketType::Handshake => Self::Handshake,
            PacketType::ZeroRtt | PacketType::Short => Self::ApplicationData,
            _ => panic!("Attempted to get space from wrong packet type"),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct PNSpaceSet {
    initial: bool,
    handshake: bool,
    application_data: bool,
}

impl Index<PNSpace> for PNSpaceSet {
    type Output = bool;

    fn index(&self, space: PNSpace) -> &Self::Output {
        match space {
            PNSpace::Initial => &self.initial,
            PNSpace::Handshake => &self.handshake,
            PNSpace::ApplicationData => &self.application_data,
        }
    }
}

impl IndexMut<PNSpace> for PNSpaceSet {
    fn index_mut(&mut self, space: PNSpace) -> &mut Self::Output {
        match space {
            PNSpace::Initial => &mut self.initial,
            PNSpace::Handshake => &mut self.handshake,
            PNSpace::ApplicationData => &mut self.application_data,
        }
    }
}

impl<T: AsRef<[PNSpace]>> From<T> for PNSpaceSet {
    fn from(spaces: T) -> Self {
        let mut v = Self::default();
        for sp in spaces.as_ref() {
            v[*sp] = true;
        }
        v
    }
}

impl std::fmt::Debug for PNSpaceSet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut first = true;
        f.write_str("(")?;
        for sp in PNSpace::iter() {
            if self[*sp] {
                if !first {
                    f.write_str("+")?;
                    first = false;
                }
                std::fmt::Display::fmt(sp, f)?;
            }
        }
        f.write_str(")")
    }
}

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub pt: PacketType,
    pub pn: u64,
    ack_eliciting: bool,
    pub time_sent: Instant,
    pub tokens: Rc<Vec<RecoveryToken>>,

    time_declared_lost: Option<Instant>,
    /// After a PTO, this is true when the packet has been released.
    pto: bool,

    pub size: usize,
}

impl SentPacket {
    pub fn new(
        pt: PacketType,
        pn: u64,
        time_sent: Instant,
        ack_eliciting: bool,
        tokens: Rc<Vec<RecoveryToken>>,
        size: usize,
    ) -> Self {
        Self {
            pt,
            pn,
            time_sent,
            ack_eliciting,
            tokens,
            time_declared_lost: None,
            pto: false,
            size,
        }
    }

    /// Returns `true` if the packet will elicit an ACK.
    pub fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
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
        self.ack_eliciting() && !self.lost()
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
        if let Some(loss_time) = self.time_declared_lost {
            (loss_time + expiration_period) <= now
        } else {
            false
        }
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

impl std::fmt::Display for PNSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Self::Initial => "in",
            Self::Handshake => "hs",
            Self::ApplicationData => "ap",
        })
    }
}

/// `InsertionResult` tracks whether something was inserted for `PacketRange::add()`.
pub enum InsertionResult {
    Largest,
    Smallest,
    NotInserted,
}

#[derive(Clone, Debug, Default)]
pub struct PacketRange {
    largest: PacketNumber,
    smallest: PacketNumber,
    ack_needed: bool,
}

impl PacketRange {
    /// Make a single packet range.
    pub fn new(pn: PacketNumber) -> Self {
        Self {
            largest: pn,
            smallest: pn,
            ack_needed: true,
        }
    }

    /// Get the number of acknowleged packets in the range.
    pub fn len(&self) -> u64 {
        self.largest - self.smallest + 1
    }

    /// Returns whether this needs to be sent.
    pub fn ack_needed(&self) -> bool {
        self.ack_needed
    }

    /// Return whether the given number is in the range.
    pub fn contains(&self, pn: PacketNumber) -> bool {
        (pn >= self.smallest) && (pn <= self.largest)
    }

    /// Maybe add a packet number to the range.  Returns true if it was added
    /// at the small end (which indicates that this might need merging with a
    /// preceding range).
    pub fn add(&mut self, pn: PacketNumber) -> InsertionResult {
        assert!(!self.contains(pn));
        // Only insert if this is adjacent the current range.
        if (self.largest + 1) == pn {
            qtrace!([self], "Adding largest {}", pn);
            self.largest += 1;
            self.ack_needed = true;
            InsertionResult::Largest
        } else if self.smallest == (pn + 1) {
            qtrace!([self], "Adding smallest {}", pn);
            self.smallest -= 1;
            self.ack_needed = true;
            InsertionResult::Smallest
        } else {
            InsertionResult::NotInserted
        }
    }

    /// Maybe merge a higher-numbered range into this.
    fn merge_larger(&mut self, other: &Self) {
        qinfo!([self], "Merging {}", other);
        // This only works if they are immediately adjacent.
        assert_eq!(self.largest + 1, other.smallest);

        self.largest = other.largest;
        self.ack_needed = self.ack_needed || other.ack_needed;
    }

    /// When a packet containing the range `other` is acknowledged,
    /// clear the `ack_needed` attribute on this.
    /// Requires that other is equal to this, or a larger range.
    pub fn acknowledged(&mut self, other: &Self) {
        if (other.smallest <= self.smallest) && (other.largest >= self.largest) {
            self.ack_needed = false;
        }
    }
}

impl ::std::fmt::Display for PacketRange {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}->{}", self.largest, self.smallest)
    }
}

/// The ACK delay we use.
pub const DEFAULT_ACK_DELAY: Duration = Duration::from_millis(20); // 20ms
/// The default number of in-order packets we will receive after
/// largest acknowledged without sending an immediate acknowledgment.
pub const DEFAULT_ACK_PACKET_THRESHOLD: PacketNumber = 1;
/// The default number of packets we will receive after largest
/// acknowledged sending an immediate acknowledgment, in case of a gap.
pub const DEFAULT_ACK_LOSS_THRESHOLD: PacketNumber = 1;
const MAX_TRACKED_RANGES: usize = 32;
const MAX_ACKS_PER_FRAME: usize = 32;

/// A structure that tracks what was included in an ACK.
#[derive(Debug, Clone)]
pub struct AckToken {
    space: PNSpace,
    ranges: Vec<PacketRange>,
}

/// A structure that tracks what packets have been received,
/// and what needs acknowledgement for a packet number space.
#[derive(Debug)]
pub struct RecvdPackets {
    space: PNSpace,
    ranges: VecDeque<PacketRange>,
    /// The packet number of the lowest number packet that we are tracking.
    min_tracked: PacketNumber,
    /// The time we got the largest acknowledged.
    largest_pn_time: Option<Instant>,
    /// The time at which the next acknowledgment should be sent.
    ack_time: Option<Instant>,

    /// The current ACK frequency sequence number.
    ack_frequency_seqno: u64,
    /// The time to delay after receiving the first packet that is
    /// not immediately acknowledged.
    ack_delay: Duration,
    /// The first unacknowledged packet number.  Rather than tracking the largest
    /// acknowledged, which would require `Option<PacketNumber>`, this tracks the
    /// next packet.  That way it starts at 0 when no packets have been acknowledged.
    next_unacknowledged: PacketNumber,
    /// The number of contiguous packets that can be received without
    /// acknowledging immediately.
    packet_threshold: PacketNumber,
    /// The number of non-contiguous packets that can be received without
    /// acknowledging immediately.
    loss_threshold: PacketNumber,
}

impl RecvdPackets {
    /// Make a new `RecvdPackets` for the indicated packet number space.
    pub fn new(space: PNSpace) -> Self {
        Self {
            space,
            ranges: VecDeque::new(),
            min_tracked: 0,
            largest_pn_time: None,
            ack_time: None,

            ack_frequency_seqno: 0,
            ack_delay: DEFAULT_ACK_DELAY,
            next_unacknowledged: 0,
            packet_threshold: DEFAULT_ACK_PACKET_THRESHOLD,
            loss_threshold: DEFAULT_ACK_LOSS_THRESHOLD,
        }
    }

    /// Get the time at which the next ACK should be sent.
    pub fn ack_time(&self) -> Option<Instant> {
        self.ack_time
    }

    /// Update acknowledgment delay parameters.
    pub fn update_ack_freq(
        &mut self,
        seqno: u64,
        delay: Duration,
        packet_threshold: u64,
        loss_threshold: u64,
    ) {
        // Yes, this means that we will overwrite values if a sequence number is
        // reused, but that is better than using an `Option<PacketNumber>`
        // when it will always be `Some`.
        if seqno >= self.ack_frequency_seqno {
            self.ack_frequency_seqno = seqno;
            self.ack_delay = delay;
            self.packet_threshold = packet_threshold;
            self.loss_threshold = min(loss_threshold, packet_threshold);
        }
    }

    /// Returns true if an ACK frame should be sent now.
    fn ack_now(&self, now: Instant) -> bool {
        match self.ack_time {
            Some(t) => t <= now,
            None => false,
        }
    }

    // A simple addition of a packet number to the tracked set.
    // This doesn't do a binary search on the assumption that
    // new packets will generally be added to the start of the list.
    fn add(&mut self, pn: PacketNumber) {
        for i in 0..self.ranges.len() {
            match self.ranges[i].add(pn) {
                InsertionResult::Largest => return,
                InsertionResult::Smallest => {
                    // If this was the smallest, it might have filled a gap.
                    let nxt = i + 1;
                    if (nxt < self.ranges.len()) && (pn - 1 == self.ranges[nxt].largest) {
                        let larger = self.ranges.remove(i).unwrap();
                        self.ranges[i].merge_larger(&larger);
                    }
                    return;
                }
                InsertionResult::NotInserted => {
                    if self.ranges[i].largest < pn {
                        self.ranges.insert(i, PacketRange::new(pn));
                        return;
                    }
                }
            }
        }
        self.ranges.push_back(PacketRange::new(pn));
    }

    fn trim_ranges(&mut self) {
        // Limit the number of ranges that are tracked to MAX_TRACKED_RANGES.
        if self.ranges.len() > MAX_TRACKED_RANGES {
            let oldest = self.ranges.pop_back().unwrap();
            if oldest.ack_needed {
                qwarn!([self], "Dropping unacknowledged ACK range: {}", oldest);
            // TODO(mt) Record some statistics about this so we can tune MAX_TRACKED_RANGES.
            } else {
                qdebug!([self], "Drop ACK range: {}", oldest);
            }
            self.min_tracked = oldest.largest + 1;
        }
    }

    /// Add the packet to the tracked set.
    pub fn set_received(&mut self, now: Instant, pn: PacketNumber, ack_eliciting: bool) {
        let next_largest = self.ranges.front().map_or(0, |r| r.largest + 1);
        qdebug!([self], "received {}, next largest: {}", pn, next_largest);

        self.add(pn);
        self.trim_ranges();

        if pn >= next_largest {
            self.largest_pn_time = Some(now);
        }

        if ack_eliciting {
            let immediate_ack = if self.space != PNSpace::ApplicationData {
                // Acknowledge Initial and Handshake packets immediately.
                true
            } else if pn >= next_largest {
                // IF the first range doesn't include the next unacknowledged, then
                // there is a gap, so use loss_threshold.
                // Otherwise, there are no gaps, so use packet_threshold.
                let threshold = if self.next_unacknowledged < self.ranges[0].smallest {
                    self.loss_threshold
                } else {
                    self.packet_threshold
                };
                qtrace!(
                    [self],
                    "Determine immediate ACK for {} >= {}+{}",
                    pn,
                    self.next_unacknowledged,
                    threshold
                );
                pn >= self.next_unacknowledged + threshold
            } else {
                // If this packet fills a gap before the last sent acknowledgment,
                // acknowledge it immediately (if it is ack-eliciting).
                pn < self.next_unacknowledged
            };

            // Set the time for sending an acknowledgement.
            self.ack_time = Some(if immediate_ack {
                now
            } else {
                self.ack_time.unwrap_or(now + self.ack_delay)
            });
            qdebug!([self], "Set ACK timer to {:?}", self.ack_time);
        } else if pn == self.next_unacknowledged {
            // If the packet was not ack-eliciting, then it won't be acknowledged,
            // but - assuming that it arrives in order - disregard it for the purpose
            // of determining whether to acknowledge subsequent packets immediately.
            // Ideally, all packets that are not ack-eliciting are ignored when doing
            // that calculation, but whether packets are ack-eliciting is not tracked.
            // Instead, this increments `next_unacknowledged`.  This isn't perfect,
            // because even if no received packet is ack-eliciting, the immediate
            // acknowledgment calculation will start at the first reordered packet
            // non-ack-eliciting packet rather than the first ack-eliciting packet.
            self.next_unacknowledged += 1;
        }
    }

    /// If we just received a PING frame, we should immediately acknowledge.
    pub fn immediate_ack(&mut self, now: Instant) {
        self.ack_time = Some(now);
        qdebug!([self], "immediate_ack at {:?}", now);
    }

    /// Check if the packet is a duplicate.
    pub fn is_duplicate(&self, pn: PacketNumber) -> bool {
        if pn < self.min_tracked {
            return true;
        }
        self.ranges
            .iter()
            .take_while(|r| pn <= r.largest)
            .any(|r| r.contains(pn))
    }

    /// Mark the given range as having been acknowledged.
    pub fn acknowledged(&mut self, acked: &[PacketRange]) {
        let mut range_iter = self.ranges.iter_mut();
        let mut cur = range_iter.next().expect("should have at least one range");
        for ack in acked {
            while cur.smallest > ack.largest {
                cur = match range_iter.next() {
                    Some(c) => c,
                    None => return,
                };
            }
            cur.acknowledged(&ack);
        }
    }

    /// Generate an ACK frame for this packet number space.
    ///
    /// Unlike other frame generators this doesn't modify the underlying instance
    /// to track what has been sent. This only clears the delayed ACK timer.
    ///
    /// When sending ACKs, we want to always send the most recent ranges,
    /// even if they have been sent in other packets.
    ///
    /// We don't send ranges that have been acknowledged, but they still need
    /// to be tracked so that duplicates can be detected.
    fn get_frame(&mut self, now: Instant) -> Option<(Frame, Option<RecoveryToken>)> {
        // Check that we aren't delaying ACKs.
        if !self.ack_now(now) {
            return None;
        }

        // Limit the number of ACK ranges we send so that we'll always
        // have space for data in packets.
        let ranges: Vec<PacketRange> = self
            .ranges
            .iter()
            .filter(|r| r.ack_needed())
            .take(MAX_ACKS_PER_FRAME)
            .cloned()
            .collect();
        let mut iter = ranges.iter();

        let first = match iter.next() {
            Some(v) => v,
            None => return None, // Nothing to send.
        };
        let mut ack_ranges = Vec::new();
        let mut last = first.smallest;

        for range in iter {
            ack_ranges.push(AckRange {
                // the difference must be at least 2 because 0-length gaps,
                // (difference 1) are illegal.
                gap: last - range.largest - 2,
                range: range.len() - 1,
            });
            last = range.smallest;
        }

        // We've sent an ACK, reset the timer.
        self.ack_time = None;
        self.next_unacknowledged = first.largest + 1;

        let ack_delay = now.duration_since(self.largest_pn_time.unwrap());
        // We use the default exponent so
        // ack_delay is in multiples of 8 microseconds.
        if let Ok(delay) = u64::try_from(ack_delay.as_micros() / 8) {
            let ack = Frame::Ack {
                largest_acknowledged: first.largest,
                ack_delay: delay,
                first_ack_range: first.len() - 1,
                ack_ranges,
            };
            let token = RecoveryToken::Ack(AckToken {
                space: self.space,
                ranges,
            });
            Some((ack, Some(token)))
        } else {
            qwarn!(
                "ack_delay.as_micros() did not fit a u64 {:?}",
                ack_delay.as_micros()
            );
            None
        }
    }
}

impl ::std::fmt::Display for RecvdPackets {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Recvd-{}", self.space)
    }
}

#[derive(Debug)]
pub struct AckTracker {
    /// This stores information about received packets in *reverse* order
    /// by spaces.  Why reverse?  Because we ultimately only want to keep
    /// `ApplicationData` and this allows us to drop other spaces easily.
    spaces: SmallVec<[RecvdPackets; 1]>,
}

impl AckTracker {
    /// Update acknowledgment delay parameters.
    pub fn update_ack_freq(
        &mut self,
        seqno: u64,
        delay: Duration,
        packet_threshold: u64,
        loss_threshold: u64,
    ) {
        // Only ApplicationData ever delays ACK.
        self.get_mut(PNSpace::ApplicationData)
            .unwrap()
            .update_ack_freq(seqno, delay, packet_threshold, loss_threshold);
    }

    // Force an ACK to be generated immediately (a PING was received).
    pub fn immediate_ack(&mut self, now: Instant) {
        self.get_mut(PNSpace::ApplicationData)
            .unwrap()
            .immediate_ack(now);
    }

    pub fn drop_space(&mut self, space: PNSpace) {
        let sp = match space {
            PNSpace::Initial => self.spaces.pop(),
            PNSpace::Handshake => {
                let sp = self.spaces.pop();
                self.spaces.shrink_to_fit();
                sp
            }
            PNSpace::ApplicationData => panic!("discarding application space"),
        };
        assert_eq!(sp.unwrap().space, space, "dropping spaces out of order");
    }

    pub fn get_mut(&mut self, space: PNSpace) -> Option<&mut RecvdPackets> {
        self.spaces.get_mut(match space {
            PNSpace::ApplicationData => 0,
            PNSpace::Handshake => 1,
            PNSpace::Initial => 2,
        })
    }

    /// Determine the earliest time that an ACK might be needed.
    pub fn ack_time(&self, now: Instant) -> Option<Instant> {
        for recvd in &self.spaces {
            qtrace!("ack_time for {} = {:?}", recvd.space, recvd.ack_time());
        }

        if self.spaces.len() == 1 {
            self.spaces[0].ack_time()
        } else {
            // Ignore any time that is in the past relative to `now`.
            // That is something of a hack, but there are cases where we can't send ACK
            // frames for all spaces, which can mean that one space is stuck in the past.
            // That isn't a problem because we guarantee that earlier spaces will always
            // be able to send ACK frames.
            self.spaces
                .iter()
                .filter_map(|recvd| recvd.ack_time().filter(|t| *t > now))
                .min()
        }
    }

    pub fn acked(&mut self, token: &AckToken) {
        if let Some(space) = self.get_mut(token.space) {
            space.acknowledged(&token.ranges);
        }
    }

    pub(crate) fn get_frame(
        &mut self,
        now: Instant,
        pn_space: PNSpace,
    ) -> Option<(Frame, Option<RecoveryToken>)> {
        self.get_mut(pn_space)
            .and_then(|space| space.get_frame(now))
    }
}

impl Default for AckTracker {
    fn default() -> Self {
        Self {
            spaces: smallvec![
                RecvdPackets::new(PNSpace::ApplicationData),
                RecvdPackets::new(PNSpace::Handshake),
                RecvdPackets::new(PNSpace::Initial),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AckTracker, Duration, Instant, PNSpace, PNSpaceSet, RecoveryToken, RecvdPackets,
        MAX_TRACKED_RANGES,
    };
    use crate::packet::PacketNumber;
    use lazy_static::lazy_static;
    use std::collections::HashSet;

    lazy_static! {
        static ref NOW: Instant = Instant::now();
    }

    fn test_ack_range(pns: &[u64], nranges: usize) {
        let mut rp = RecvdPackets::new(PNSpace::Initial); // Any space will do.
        let mut packets = HashSet::new();

        for pn in pns {
            rp.set_received(*NOW, *pn, true);
            packets.insert(*pn);
        }

        assert_eq!(rp.ranges.len(), nranges);

        // Check that all these packets will be detected as duplicates.
        for pn in pns {
            assert!(rp.is_duplicate(*pn));
        }

        // Check that the ranges decrease monotonically and don't overlap.
        let mut iter = rp.ranges.iter();
        let mut last = iter.next().expect("should have at least one");
        for n in iter {
            assert!(n.largest + 1 < last.smallest);
            last = n;
        }

        // Check that the ranges include the right values.
        let mut in_ranges = HashSet::new();
        for range in &rp.ranges {
            for included in range.smallest..=range.largest {
                in_ranges.insert(included);
            }
        }
        assert_eq!(packets, in_ranges);
    }

    #[test]
    fn pn0() {
        test_ack_range(&[0], 1);
    }

    #[test]
    fn pn1() {
        test_ack_range(&[1], 1);
    }

    #[test]
    fn two_ranges() {
        test_ack_range(&[0, 1, 2, 5, 6, 7], 2);
    }

    #[test]
    fn fill_in_range() {
        test_ack_range(&[0, 1, 2, 5, 6, 7, 3, 4], 1);
    }

    #[test]
    fn too_many_ranges() {
        let mut rp = RecvdPackets::new(PNSpace::Initial); // Any space will do.

        // This will add one too many disjoint ranges.
        for i in 0..=MAX_TRACKED_RANGES {
            rp.set_received(*NOW, (i * 2) as u64, true);
        }

        assert_eq!(rp.ranges.len(), MAX_TRACKED_RANGES);
        assert_eq!(rp.ranges.back().unwrap().largest, 2);

        // Even though the range was dropped, we still consider it a duplicate.
        assert!(rp.is_duplicate(0));
        assert!(!rp.is_duplicate(1));
        assert!(rp.is_duplicate(2));
    }

    #[test]
    fn ack_delay() {
        const COUNT: PacketNumber = 9;
        const DELAY: Duration = Duration::from_millis(7);
        // Only application data packets are delayed.
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);
        assert!(rp.ack_time().is_none());
        assert!(!rp.ack_now(*NOW));

        rp.update_ack_freq(0, DELAY, COUNT, 1);

        // Some packets won't cause an ACK to be needed.
        for i in 0..COUNT {
            rp.set_received(*NOW, i, true);
            assert_eq!(Some(*NOW + DELAY), rp.ack_time());
            assert!(!rp.ack_now(*NOW));
            assert!(rp.ack_now(*NOW + DELAY));
        }

        // Exceeding COUNT will move the ACK time to now.
        rp.set_received(*NOW, COUNT, true);
        assert_eq!(Some(*NOW), rp.ack_time());
        assert!(rp.ack_now(*NOW));
    }

    #[test]
    fn no_ack_delay() {
        for space in &[PNSpace::Initial, PNSpace::Handshake] {
            let mut rp = RecvdPackets::new(*space);
            assert!(rp.ack_time().is_none());
            assert!(!rp.ack_now(*NOW));

            // Any packet in these spaces is acknowledged straight away.
            rp.set_received(*NOW, 0, true);
            assert_eq!(Some(*NOW), rp.ack_time());
            assert!(rp.ack_now(*NOW));
        }
    }

    #[test]
    fn ooo_no_ack_delay_new() {
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);
        assert!(rp.ack_time().is_none());
        assert!(!rp.ack_now(*NOW));

        // Anything other than packet 0 is acknowledged immediately.
        rp.set_received(*NOW, 1, true);
        assert_eq!(Some(*NOW), rp.ack_time());
        assert!(rp.ack_now(*NOW));
    }

    #[test]
    fn ooo_no_ack_delay_gap() {
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);
        assert!(rp.ack_time().is_none());
        assert!(!rp.ack_now(*NOW));

        // Packet number 0 causes delayed acknowledgment.
        rp.set_received(*NOW, 0, true);
        assert_ne!(Some(*NOW), rp.ack_time());

        // A gap causes immediate acknowledgment.
        rp.set_received(*NOW, 2, true);
        assert_eq!(Some(*NOW), rp.ack_time());
        assert!(rp.ack_now(*NOW));
    }

    #[test]
    fn ooo_no_ack_delay_fill() {
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);
        rp.set_received(*NOW, 1, true);
        assert!(rp.get_frame(*NOW).is_some());

        // Filling in behind the largest acknowledged causes immediate ACK.
        rp.set_received(*NOW, 0, true);
        assert_eq!(Some(*NOW), rp.ack_time());
        assert!(rp.ack_now(*NOW));
    }

    #[test]
    fn ooo_no_ack_delay_threshold_new() {
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);

        // Set loss threshold to 3 and then it takes three packets.
        rp.update_ack_freq(0, Duration::from_millis(10), 10, 3);

        rp.set_received(*NOW, 1, true);
        assert_ne!(Some(*NOW), rp.ack_time());
        rp.set_received(*NOW, 2, true);
        assert_ne!(Some(*NOW), rp.ack_time());
        rp.set_received(*NOW, 3, true);
        assert_eq!(Some(*NOW), rp.ack_time());
    }

    #[test]
    fn ooo_no_ack_delay_threshold_gap() {
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);
        rp.set_received(*NOW, 1, true);
        assert!(rp.get_frame(*NOW).is_some());

        // Set loss threshold to 3 and then it takes three packets.
        rp.update_ack_freq(0, Duration::from_millis(10), 10, 3);

        rp.set_received(*NOW, 3, true);
        assert_ne!(Some(*NOW), rp.ack_time());
        rp.set_received(*NOW, 4, true);
        assert_ne!(Some(*NOW), rp.ack_time());
        rp.set_received(*NOW, 5, true);
        assert_eq!(Some(*NOW), rp.ack_time());
    }

    /// Test that an in-order packet that is not ack-eliciting doesn't
    /// increase the number of packets needed to cause an ACK.
    #[test]
    fn non_ack_eliciting_skip() {
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);
        rp.update_ack_freq(0, Duration::from_millis(10), 2, 2);

        // This should be ignored.
        rp.set_received(*NOW, 0, false);
        assert_ne!(Some(*NOW), rp.ack_time());
        // Skip 1 (it has no effect).
        rp.set_received(*NOW, 2, true);
        assert_ne!(Some(*NOW), rp.ack_time());
        rp.set_received(*NOW, 3, true);
        assert_eq!(Some(*NOW), rp.ack_time());
    }

    /// If a packet that is not ack-eliciting is reordered, we lose track
    /// and start counting it toward the limit.
    #[test]
    fn non_ack_eliciting_reorder() {
        let mut rp = RecvdPackets::new(PNSpace::ApplicationData);
        rp.update_ack_freq(0, Duration::from_millis(10), 2, 2);

        // This won't be counted as it arrives out of order.
        rp.set_received(*NOW, 1, false);
        assert_ne!(Some(*NOW), rp.ack_time());
        // This should be ignored, but packet 1 has no such chance.
        rp.set_received(*NOW, 0, false);
        assert_ne!(Some(*NOW), rp.ack_time());
        // This counts 0, but not 1.
        rp.set_received(*NOW, 2, true);
        assert_ne!(Some(*NOW), rp.ack_time());
        rp.set_received(*NOW, 3, true);
        assert_eq!(Some(*NOW), rp.ack_time());
    }

    #[test]
    fn aggregate_ack_time() {
        const DELAY: Duration = Duration::from_millis(17);
        let mut tracker = AckTracker::default();
        tracker.update_ack_freq(0, DELAY, 1, 1);
        // This packet won't trigger an ACK.
        tracker
            .get_mut(PNSpace::Handshake)
            .unwrap()
            .set_received(*NOW, 0, false);
        assert_eq!(None, tracker.ack_time(*NOW));

        // This should be delayed.
        tracker
            .get_mut(PNSpace::ApplicationData)
            .unwrap()
            .set_received(*NOW, 0, true);
        assert_eq!(Some(*NOW + DELAY), tracker.ack_time(*NOW));

        // This should move the time forward.
        let later = *NOW + DELAY / 2;
        tracker
            .get_mut(PNSpace::Initial)
            .unwrap()
            .set_received(later, 0, true);
        assert_eq!(Some(later), tracker.ack_time(*NOW));
    }

    #[test]
    #[should_panic(expected = "discarding application space")]
    fn drop_app() {
        let mut tracker = AckTracker::default();
        tracker.drop_space(PNSpace::ApplicationData);
    }

    #[test]
    #[should_panic(expected = "dropping spaces out of order")]
    fn drop_out_of_order() {
        let mut tracker = AckTracker::default();
        tracker.drop_space(PNSpace::Handshake);
    }

    #[test]
    fn drop_spaces() {
        let mut tracker = AckTracker::default();
        tracker
            .get_mut(PNSpace::Initial)
            .unwrap()
            .set_received(*NOW, 0, true);
        // The reference time for `ack_time` has to be in the past or we filter out the timer.
        assert!(tracker.ack_time(*NOW - Duration::from_millis(1)).is_some());
        let (_ack, token) = tracker.get_frame(*NOW, PNSpace::Initial).unwrap();
        assert!(token.is_some());

        // Mark another packet as received so we have cause to send another ACK in that space.
        tracker
            .get_mut(PNSpace::Initial)
            .unwrap()
            .set_received(*NOW, 1, true);
        assert!(tracker.ack_time(*NOW - Duration::from_millis(1)).is_some());

        // Now drop that space.
        tracker.drop_space(PNSpace::Initial);

        assert!(tracker.get_mut(PNSpace::Initial).is_none());
        assert!(tracker.ack_time(*NOW - Duration::from_millis(1)).is_none());
        assert!(tracker.get_frame(*NOW, PNSpace::Initial).is_none());
        if let RecoveryToken::Ack(tok) = token.as_ref().unwrap() {
            tracker.acked(tok); // Should be a noop.
        } else {
            panic!("not an ACK token");
        }
    }

    #[test]
    fn ack_time_elapsed() {
        let mut tracker = AckTracker::default();

        // While we have multiple PN spaces, we ignore ACK timers from the past.
        // Send out of order to cause the delayed ack timer to be set to `*NOW`.
        tracker
            .get_mut(PNSpace::ApplicationData)
            .unwrap()
            .set_received(*NOW, 3, true);
        assert!(tracker.ack_time(*NOW + Duration::from_millis(1)).is_none());

        // When we are reduced to one space, that filter is off.
        tracker.drop_space(PNSpace::Initial);
        tracker.drop_space(PNSpace::Handshake);
        assert_eq!(
            tracker.ack_time(*NOW + Duration::from_millis(1)),
            Some(*NOW)
        );
    }

    #[test]
    fn pnspaceset_default() {
        let set = PNSpaceSet::default();
        assert!(!set[PNSpace::Initial]);
        assert!(!set[PNSpace::Handshake]);
        assert!(!set[PNSpace::ApplicationData]);
    }

    #[test]
    fn pnspaceset_from() {
        let set = PNSpaceSet::from(&[PNSpace::Initial]);
        assert!(set[PNSpace::Initial]);
        assert!(!set[PNSpace::Handshake]);
        assert!(!set[PNSpace::ApplicationData]);

        let set = PNSpaceSet::from(&[PNSpace::Handshake, PNSpace::Initial]);
        assert!(set[PNSpace::Initial]);
        assert!(set[PNSpace::Handshake]);
        assert!(!set[PNSpace::ApplicationData]);

        let set = PNSpaceSet::from(&[PNSpace::ApplicationData, PNSpace::ApplicationData]);
        assert!(!set[PNSpace::Initial]);
        assert!(!set[PNSpace::Handshake]);
        assert!(set[PNSpace::ApplicationData]);
    }

    #[test]
    fn pnspaceset_copy() {
        let set = PNSpaceSet::from(&[PNSpace::Handshake, PNSpace::ApplicationData]);
        let copy = set;
        assert!(!copy[PNSpace::Initial]);
        assert!(copy[PNSpace::Handshake]);
        assert!(copy[PNSpace::ApplicationData]);
    }
}
