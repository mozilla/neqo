// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracking of sent packets and detecting their loss.

use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::ops::{Index, IndexMut};
use std::time::{Duration, Instant};

use smallvec::SmallVec;

use neqo_common::{qdebug, qtrace};

use crate::cc::CongestionControl;
use crate::crypto::CryptoRecoveryToken;
use crate::flow_mgr::FlowControlRecoveryToken;
use crate::send_stream::StreamRecoveryToken;
use crate::tracking::{AckToken, PNSpace, SentPacket};
use crate::LOCAL_IDLE_TIMEOUT;

pub const GRANULARITY: Duration = Duration::from_millis(20);
// Defined in -recovery 6.2 as 500ms but using lower value until we have RTT
// caching. See https://github.com/mozilla/neqo/issues/79
const INITIAL_RTT: Duration = Duration::from_millis(100);
const PACKET_THRESHOLD: u64 = 3;
/// The number of packets we send on a PTO.
/// And the number to declare lost when the PTO timer is hit.
const PTO_PACKET_COUNT: usize = 2;

#[derive(Debug, Clone)]
pub enum RecoveryToken {
    Ack(AckToken),
    Stream(StreamRecoveryToken),
    Crypto(CryptoRecoveryToken),
    Flow(FlowControlRecoveryToken),
    HandshakeDone,
}

#[derive(Debug, Default)]
struct RttVals {
    latest_rtt: Duration,
    smoothed_rtt: Option<Duration>,
    rttvar: Duration,
    min_rtt: Duration,
    max_ack_delay: Duration,
}

impl RttVals {
    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = latest_rtt;
        // min_rtt ignores ack delay.
        self.min_rtt = min(self.min_rtt, self.latest_rtt);
        // Limit ack_delay by max_ack_delay
        let ack_delay = min(ack_delay, self.max_ack_delay);
        // Adjust for ack delay if it's plausible.
        if self.latest_rtt - self.min_rtt >= ack_delay {
            self.latest_rtt -= ack_delay;
        }
        // Based on {{?RFC6298}}.
        match self.smoothed_rtt {
            None => {
                self.smoothed_rtt = Some(self.latest_rtt);
                self.rttvar = self.latest_rtt / 2;
            }
            Some(smoothed_rtt) => {
                let rttvar_sample = if smoothed_rtt > self.latest_rtt {
                    smoothed_rtt - self.latest_rtt
                } else {
                    self.latest_rtt - smoothed_rtt
                };

                self.rttvar = (self.rttvar * 3 + rttvar_sample) / 4;
                self.smoothed_rtt = Some((smoothed_rtt * 7 + self.latest_rtt) / 8);
            }
        }
    }

    pub fn rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(self.latest_rtt)
    }

    fn pto(&self, pn_space: PNSpace) -> Duration {
        self.rtt()
            + max(4 * self.rttvar, GRANULARITY)
            + if pn_space != PNSpace::ApplicationData {
                Duration::from_millis(0)
            } else {
                self.max_ack_delay
            }
    }
}

#[derive(Debug, Default)]
pub(crate) struct LossRecoverySpace {
    largest_acked: Option<u64>,
    largest_acked_sent_time: Option<Instant>,
    time_of_last_sent_ack_eliciting_packet: Option<Instant>,
    ack_eliciting_outstanding: u64,
    sent_packets: BTreeMap<u64, SentPacket>,
    out_of_order_found: bool,
}

impl LossRecoverySpace {
    pub fn earliest_sent_time(&self) -> Option<Instant> {
        // Lowest PN must have been sent earliest
        let earliest = self.sent_packets.values().next().map(|sp| sp.time_sent);
        debug_assert_eq!(
            earliest,
            self.sent_packets
                .values()
                .min_by_key(|sp| sp.time_sent)
                .map(|sp| sp.time_sent)
        );
        earliest
    }

    pub fn ack_eliciting_outstanding(&self) -> bool {
        self.ack_eliciting_outstanding > 0
    }

    pub fn pto_packets(&mut self, count: usize) -> impl Iterator<Item = &SentPacket> {
        self.sent_packets
            .iter_mut()
            .filter_map(|(pn, sent)| {
                if sent.pto() {
                    qtrace!("PTO: marking packet {} lost ", pn);
                    Some(&*sent)
                } else {
                    None
                }
            })
            .take(count)
    }

    pub fn time_of_last_sent_ack_eliciting_packet(&self) -> Option<Instant> {
        if self.ack_eliciting_outstanding() {
            debug_assert!(self.time_of_last_sent_ack_eliciting_packet.is_some());
            self.time_of_last_sent_ack_eliciting_packet
        } else {
            None
        }
    }

    pub fn on_packet_sent(&mut self, packet_number: u64, sent_packet: SentPacket) {
        if sent_packet.ack_eliciting {
            self.time_of_last_sent_ack_eliciting_packet = Some(sent_packet.time_sent);
            self.ack_eliciting_outstanding += 1;
        }
        self.sent_packets.insert(packet_number, sent_packet);
    }

    pub fn remove_packet(&mut self, pn: u64) -> Option<SentPacket> {
        if let Some(sent) = self.sent_packets.remove(&pn) {
            if sent.ack_eliciting {
                debug_assert!(self.ack_eliciting_outstanding > 0);
                self.ack_eliciting_outstanding -= 1;
            }
            Some(sent)
        } else {
            None
        }
    }

    // Remove all the acked packets. Returns them in ascending order -- largest
    // (i.e. highest PN) acked packet is last.
    fn remove_acked(&mut self, acked_ranges: Vec<(u64, u64)>) -> (Vec<SentPacket>, bool) {
        let mut acked_packets = BTreeMap::new();
        let mut eliciting = false;
        for (end, start) in acked_ranges {
            // ^^ Notabug: see Frame::decode_ack_frame()
            for pn in start..=end {
                if let Some(sent) = self.remove_packet(pn) {
                    qdebug!("acked={}", pn);
                    eliciting |= sent.ack_eliciting;
                    acked_packets.insert(pn, sent);
                }
            }
        }
        (
            acked_packets.into_iter().map(|(_k, v)| v).collect(),
            eliciting,
        )
    }

    /// Remove all tracked packets from the space.
    /// This is called by a client when 0-RTT packets are dropped, when a Retry is received
    /// and when keys are dropped.
    fn remove_ignored(&mut self) -> impl Iterator<Item = SentPacket> {
        self.ack_eliciting_outstanding = 0;
        std::mem::take(&mut self.sent_packets)
            .into_iter()
            .map(|(_, v)| v)
    }

    /// This returns a boolean indicating whether out-of-order packets were found.
    pub fn has_out_of_order(&self) -> bool {
        self.out_of_order_found
    }

    pub fn detect_lost_packets(
        &mut self,
        now: Instant,
        loss_delay: Duration,
        lost_packets: &mut Vec<SentPacket>,
    ) {
        // Packets sent before this time are deemed lost.
        let lost_deadline = now - loss_delay;
        qtrace!(
            "detect lost packets = now {:?} loss delay {:?} lost_deadline {:?}",
            now,
            loss_delay,
            lost_deadline
        );
        self.out_of_order_found = false;

        let largest_acked = self.largest_acked;

        // Lost for retrans/CC purposes
        let mut lost_pns = SmallVec::<[_; 8]>::new();

        // Lost for we-can-actually-forget-about-it purposes
        let mut really_lost_pns = SmallVec::<[_; 8]>::new();

        for (pn, packet) in self
            .sent_packets
            .iter_mut()
            // BTreeMap iterates in order of ascending PN
            .take_while(|(&k, _)| Some(k) < largest_acked)
        {
            if packet.time_sent <= lost_deadline {
                qdebug!(
                    "lost={}, time sent {:?} is before lost_deadline {:?}",
                    pn,
                    packet.time_sent,
                    lost_deadline
                );
            } else if largest_acked >= Some(*pn + PACKET_THRESHOLD) {
                qdebug!(
                    "lost={}, is >= {} from largest acked {:?}",
                    pn,
                    PACKET_THRESHOLD,
                    largest_acked
                );
            } else {
                self.out_of_order_found = true;
                // No more packets can be declared lost after this one.
                break;
            };

            if packet.time_declared_lost.is_none() {
                // Track declared-lost packets for a little while, maybe they
                // will still show up?
                packet.time_declared_lost = Some(now);

                lost_pns.push(*pn);
            } else if packet
                .time_declared_lost
                .map(|tdl| tdl + (loss_delay * 2) < now)
                .unwrap_or(false)
            {
                really_lost_pns.push(*pn);
            }
        }

        for pn in really_lost_pns {
            self.remove_packet(pn).expect("lost packet missing");
        }

        lost_packets.extend(lost_pns.iter().map(|pn| self.sent_packets[pn].clone()));
    }
}

#[derive(Debug, Default)]
pub(crate) struct LossRecoverySpaces([LossRecoverySpace; 3]);

impl Index<PNSpace> for LossRecoverySpaces {
    type Output = LossRecoverySpace;

    fn index(&self, index: PNSpace) -> &Self::Output {
        &self.0[index as usize]
    }
}

impl IndexMut<PNSpace> for LossRecoverySpaces {
    fn index_mut(&mut self, index: PNSpace) -> &mut Self::Output {
        &mut self.0[index as usize]
    }
}

impl LossRecoverySpaces {
    fn iter(&self) -> impl Iterator<Item = &LossRecoverySpace> {
        self.0.iter()
    }
    fn iter_mut(&mut self) -> impl Iterator<Item = &mut LossRecoverySpace> {
        self.0.iter_mut()
    }
}

#[derive(Debug)]
struct PtoState {
    space: PNSpace,
    count: usize,
    packets: usize,
}

impl PtoState {
    pub fn new(space: PNSpace) -> Self {
        Self {
            space,
            count: 1,
            packets: PTO_PACKET_COUNT,
        }
    }

    pub fn pto(&mut self, space: PNSpace) {
        self.space = space;
        self.count += 1;
        self.packets = PTO_PACKET_COUNT;
    }

    /// Take a packet, indicating what space it should be from.
    /// Returns `None` if there are no packets left.
    pub fn take_packet(&mut self) -> Option<PNSpace> {
        if self.packets > 0 {
            self.packets -= 1;
            Some(self.space)
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct LossRecovery {
    pto_state: Option<PtoState>,
    rtt_vals: RttVals,
    cc: CongestionControl,

    enable_timed_loss_detection: bool,
    spaces: LossRecoverySpaces,
}

impl LossRecovery {
    pub fn new() -> Self {
        Self {
            rtt_vals: RttVals {
                min_rtt: Duration::from_secs(u64::max_value()),
                max_ack_delay: Duration::from_millis(25),
                latest_rtt: INITIAL_RTT,
                ..RttVals::default()
            },

            ..Self::default()
        }
    }

    #[cfg(test)]
    pub fn cwnd(&self) -> usize {
        self.cc.cwnd()
    }

    #[cfg(test)]
    pub fn ssthresh(&self) -> usize {
        self.cc.ssthresh()
    }

    pub fn rtt(&self) -> Duration {
        self.rtt_vals.rtt()
    }

    pub fn set_initial_rtt(&mut self, value: Duration) {
        debug_assert!(self.rtt_vals.smoothed_rtt.is_none());
        self.rtt_vals.latest_rtt = value
    }

    pub fn cwnd_avail(&self) -> usize {
        self.cc.cwnd_avail()
    }

    pub fn largest_acknowledged_pn(&self, pn_space: PNSpace) -> Option<u64> {
        self.spaces[pn_space].largest_acked
    }

    pub fn pto(&self) -> Duration {
        self.rtt_vals.pto(PNSpace::ApplicationData)
    }

    pub fn drop_0rtt(&mut self) -> Vec<SentPacket> {
        // The largest acknowledged or loss_time should still be unset.
        // The client should not have received any ACK frames when it drops 0-RTT.
        assert!(self.spaces[PNSpace::ApplicationData]
            .largest_acked
            .is_none());
        self.spaces[PNSpace::ApplicationData]
            .remove_ignored()
            .inspect(|p| self.cc.discard(&p))
            .collect()
    }

    pub fn on_packet_sent(
        &mut self,
        pn_space: PNSpace,
        packet_number: u64,
        sent_packet: SentPacket,
    ) {
        qdebug!([self], "packet {:?}-{} sent.", pn_space, packet_number);
        self.cc.on_packet_sent(&sent_packet);
        self.spaces[pn_space].on_packet_sent(packet_number, sent_packet);
    }

    /// Returns (acked packets, lost packets)
    pub fn on_ack_received(
        &mut self,
        pn_space: PNSpace,
        largest_acked: u64,
        acked_ranges: Vec<(u64, u64)>,
        ack_delay: Duration,
        now: Instant,
    ) -> (Vec<SentPacket>, Vec<SentPacket>) {
        qdebug!(
            [self],
            "ACK for {} - largest_acked={}.",
            pn_space,
            largest_acked
        );

        let (acked_packets, any_ack_eliciting) = self.spaces[pn_space].remove_acked(acked_ranges);
        if acked_packets.is_empty() {
            // No new information.
            return (Vec::new(), Vec::new());
        }

        // Track largest PN acked per space
        let space = &mut self.spaces[pn_space];
        let prev_largest_acked_sent_time = space.largest_acked_sent_time;
        if Some(largest_acked) > space.largest_acked {
            space.largest_acked = Some(largest_acked);

            // If the largest acknowledged is newly acked and any newly acked
            // packet was ack-eliciting, update the RTT. (-recovery 5.1)
            let largest_acked_pkt = acked_packets.last().expect("must be there");
            space.largest_acked_sent_time = Some(largest_acked_pkt.time_sent);
            if any_ack_eliciting {
                let latest_rtt = now - largest_acked_pkt.time_sent;
                self.rtt_vals.update_rtt(latest_rtt, ack_delay);
            }
        }

        // TODO Process ECN information if present.

        let loss_delay = self.loss_delay();
        let mut lost_packets = Vec::new();
        self.spaces[pn_space].detect_lost_packets(now, loss_delay, &mut lost_packets);

        self.pto_state = None;

        self.cc.on_packets_acked(&acked_packets);

        self.cc.on_packets_lost(
            now,
            prev_largest_acked_sent_time,
            self.rtt_vals.pto(pn_space),
            &lost_packets,
        );

        (acked_packets, lost_packets)
    }

    fn loss_delay(&self) -> Duration {
        // kTimeThreshold = 9/8
        // loss_delay = kTimeThreshold * max(latest_rtt, smoothed_rtt)
        // loss_delay = max(loss_delay, kGranularity)
        let rtt = match self.rtt_vals.smoothed_rtt {
            None => self.rtt_vals.latest_rtt,
            Some(smoothed_rtt) => max(self.rtt_vals.latest_rtt, smoothed_rtt),
        };
        max(rtt * 9 / 8, GRANULARITY)
    }

    /// When receiving a retry, get all the sent packets so that they can be flushed.
    /// We also need to pretend that they never happened for the purposes of congestion control.
    pub fn retry(&mut self) -> Vec<SentPacket> {
        let cc = &mut self.cc;
        self.spaces
            .iter_mut()
            .flat_map(|spc| spc.remove_ignored())
            .inspect(|p| cc.discard(&p))
            .collect()
    }

    /// Discard state for a given packet number space.
    pub fn discard(&mut self, space: PNSpace) {
        qdebug!([self], "Reset loss recovery state for {}", space);
        // We just made progress, so discard PTO count.
        self.pto_state = None;
        for p in self.spaces[space].remove_ignored() {
            self.cc.discard(&p);
        }
    }

    /// Calculate when the next timeout is likely to be.  This is the earlier of the loss timer
    /// and the PTO timer; either or both might be disabled, so this can return `None`.
    pub fn next_timeout(&mut self) -> Option<Instant> {
        let loss_time = self.earliest_loss_time();
        let pto_time = self.earliest_pto();
        qtrace!(
            [self],
            "next_timeout loss={:?} pto={:?}",
            loss_time,
            pto_time
        );
        match (loss_time, pto_time) {
            (Some((_, loss_time)), Some((_, pto_time))) => Some(min(loss_time, pto_time)),
            (Some((_, loss_time)), None) => Some(loss_time),
            (None, Some((_, pto_time))) => Some(pto_time),
            _ => None,
        }
    }

    /// Find when the earliest sent packet should be considered lost.
    fn earliest_loss_time(&self) -> Option<(PNSpace, Instant)> {
        if self.enable_timed_loss_detection {
            PNSpace::iter()
                .filter_map(|&spc| {
                    self.spaces[spc]
                        .earliest_sent_time()
                        .map(|time| (spc, time))
                })
                .min_by_key(|&(_, time)| time)
                .map(|(spc, val)| (spc, val + self.loss_delay()))
        } else {
            None
        }
    }

    /// Get the Base PTO value, which is derived only from the RTT and RTTvar values.
    /// This is for those cases where you need a value for the time you might sensibly
    /// wait for a packet to propagate.  Using `3*raw_pto()` is common.
    pub fn raw_pto(&self) -> Duration {
        self.rtt_vals.pto(PNSpace::ApplicationData)
    }

    // Calculate PTO time for the given space.
    fn pto_time(&self, space: PNSpace) -> Option<Instant> {
        self.spaces[space]
            .time_of_last_sent_ack_eliciting_packet()
            .map(|t| {
                t + self
                    .rtt_vals
                    .pto(space)
                    .checked_mul(1 << self.pto_state.as_ref().map_or(0, |p| p.count))
                    .unwrap_or(LOCAL_IDLE_TIMEOUT * 2)
            })
    }

    /// Find when the last ack eliciting packet was sent.
    fn earliest_pto(&self) -> Option<(PNSpace, Instant)> {
        match (
            self.pto_time(PNSpace::Initial),
            self.pto_time(PNSpace::Handshake),
        ) {
            (Some(initial_pto), Some(handshake_pto)) => {
                if initial_pto <= handshake_pto {
                    Some((PNSpace::Initial, initial_pto))
                } else {
                    Some((PNSpace::Handshake, handshake_pto))
                }
            }
            (Some(initial_pto), None) => Some((PNSpace::Initial, initial_pto)),
            (None, Some(handshake_pto)) => Some((PNSpace::Handshake, handshake_pto)),
            _ => self
                .pto_time(PNSpace::ApplicationData)
                .map(|t| (PNSpace::ApplicationData, t)),
        }
    }

    /// This checks whether the PTO timer has fired.
    /// When it has, mark a few packets as "lost" for the purposes of having frames
    /// regenerated in subsequent packets.  The packets aren't truly lost, so
    /// we have to clone the `SentPacket` instance.
    fn maybe_pto(&mut self, now: Instant, lost: &mut Vec<SentPacket>) {
        let mut pto_space = None;
        for space in PNSpace::iter() {
            // Skip early packet number spaces where the PTO timer hasn't fired.
            // Once the timer for one space has fired, include higher spaces. Declaring more
            // data as "lost" makes it more likely that PTO packets will include useful data.
            if pto_space.is_none() && self.pto_time(*space).map(|t| t > now).unwrap_or(true) {
                continue;
            }
            qdebug!([self], "PTO timer fired for {}", space);
            pto_space = pto_space.or(Some(*space));
            lost.extend(self.spaces[*space].pto_packets(PTO_PACKET_COUNT).cloned());
        }

        // This has to happen outside the loop. Increasing the PTO count here causes the
        // pto_time to increase which might cause PTO for later packet number spaces to not fire.
        if let Some(space) = pto_space {
            if let Some(st) = &mut self.pto_state {
                st.pto(space);
            } else {
                self.pto_state = Some(PtoState::new(space));
            }
        }
    }

    pub fn timeout(&mut self, now: Instant) -> Vec<SentPacket> {
        qtrace!([self], "timeout {:?}", now);

        let loss_delay = self.loss_delay();
        let mut lost_packets = Vec::new();
        for space in self.spaces.iter_mut() {
            space.detect_lost_packets(now, loss_delay, &mut lost_packets);
        }
        self.enable_timed_loss_detection = self.spaces.iter().any(|space| space.has_out_of_order());
        self.maybe_pto(now, &mut lost_packets);
        lost_packets
    }

    pub fn pto_active(&self) -> bool {
        self.pto_state.is_some()
    }

    pub fn take_pto_packet(&mut self) -> Option<PNSpace> {
        self.pto_state.as_mut().unwrap().take_packet()
    }
}

impl ::std::fmt::Display for LossRecovery {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "LossRecovery")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use std::time::{Duration, Instant};

    const ON_SENT_SIZE: usize = 100;

    fn assert_rtts(
        lr: &LossRecovery,
        latest_rtt: Duration,
        smoothed_rtt: Duration,
        rttvar: Duration,
        min_rtt: Duration,
    ) {
        println!(
            "rtts: {:?} {:?} {:?} {:?}",
            lr.rtt_vals.latest_rtt,
            lr.rtt_vals.smoothed_rtt,
            lr.rtt_vals.rttvar,
            lr.rtt_vals.min_rtt,
        );
        assert_eq!(lr.rtt_vals.latest_rtt, latest_rtt, "latest RTT");
        assert_eq!(lr.rtt_vals.smoothed_rtt, Some(smoothed_rtt), "smoothed RTT");
        assert_eq!(lr.rtt_vals.rttvar, rttvar, "RTT variance");
        assert_eq!(lr.rtt_vals.min_rtt, min_rtt, "min RTT");
    }

    fn assert_sent_times(
        lr: &LossRecovery,
        initial: Option<Instant>,
        handshake: Option<Instant>,
        app_data: Option<Instant>,
    ) {
        if !lr.enable_timed_loss_detection {
            return;
        }
        println!(
            "loss times: {:?} {:?} {:?}",
            lr.spaces[PNSpace::Initial].earliest_sent_time(),
            lr.spaces[PNSpace::Handshake].earliest_sent_time(),
            lr.spaces[PNSpace::ApplicationData].earliest_sent_time(),
        );
        assert_eq!(
            lr.spaces[PNSpace::Initial].earliest_sent_time(),
            initial,
            "Initial earliest sent time"
        );
        assert_eq!(
            lr.spaces[PNSpace::Handshake].earliest_sent_time(),
            handshake,
            "Handshake earliest sent time"
        );
        assert_eq!(
            lr.spaces[PNSpace::ApplicationData].earliest_sent_time(),
            app_data,
            "AppData earliest sent time"
        );
    }

    fn assert_no_sent_times(lr: &LossRecovery) {
        assert_sent_times(lr, None, None, None);
    }

    // Time in milliseconds.
    macro_rules! ms {
        ($t:expr) => {
            Duration::from_millis($t)
        };
    }

    // In most of the tests below, packets are sent at a fixed cadence, with PACING between each.
    const PACING: Duration = ms!(7);
    fn pn_time(pn: u64) -> Instant {
        ::test_fixture::now() + (PACING * pn.try_into().unwrap())
    }

    fn pace(lr: &mut LossRecovery, count: u64) {
        for pn in 0..count {
            lr.on_packet_sent(
                PNSpace::ApplicationData,
                pn,
                SentPacket::new(pn_time(pn), true, Vec::new(), ON_SENT_SIZE, true),
            );
        }
    }

    const ACK_DELAY: Duration = ms!(24);
    /// Acknowledge PN with the identified delay.
    fn ack(lr: &mut LossRecovery, pn: u64, delay: Duration) {
        lr.on_ack_received(
            PNSpace::ApplicationData,
            pn,
            vec![(pn, pn)],
            ACK_DELAY,
            pn_time(pn) + delay,
        );
    }

    #[test]
    fn initial_rtt() {
        let mut lr = LossRecovery::new();
        pace(&mut lr, 1);
        let rtt = ms!(100);
        ack(&mut lr, 0, rtt);
        assert_rtts(&lr, rtt, rtt, rtt / 2, rtt);
        assert_no_sent_times(&lr);
    }

    /// An INITIAL_RTT for using with setup_lr().
    const INITIAL_RTT: Duration = ms!(80);
    const INITIAL_RTTVAR: Duration = ms!(40);

    /// Send `n` packets (using PACING), then acknowledge the first.
    fn setup_lr(n: u64) -> LossRecovery {
        let mut lr = LossRecovery::new();
        pace(&mut lr, n);
        ack(&mut lr, 0, INITIAL_RTT);
        assert_rtts(&lr, INITIAL_RTT, INITIAL_RTT, INITIAL_RTTVAR, INITIAL_RTT);
        assert_no_sent_times(&lr);
        lr
    }

    // The ack delay is removed from any RTT estimate.
    #[test]
    fn ack_delay_adjusted() {
        let mut lr = setup_lr(2);
        ack(&mut lr, 1, INITIAL_RTT + ACK_DELAY);
        // RTT stays the same, but the RTTVAR is adjusted downwards.
        assert_rtts(
            &lr,
            INITIAL_RTT,
            INITIAL_RTT,
            INITIAL_RTTVAR * 3 / 4,
            INITIAL_RTT,
        );
        assert_no_sent_times(&lr);
    }

    // The ack delay is ignored when it would cause a sample to be less than min_rtt.
    #[test]
    fn ack_delay_ignored() {
        let mut lr = setup_lr(2);
        let extra = ms!(8);
        assert!(extra < ACK_DELAY);
        ack(&mut lr, 1, INITIAL_RTT + extra);
        let expected_rtt = INITIAL_RTT + (extra / 8);
        let expected_rttvar = (INITIAL_RTTVAR * 3 + extra) / 4;
        assert_rtts(
            &lr,
            INITIAL_RTT + extra,
            expected_rtt,
            expected_rttvar,
            INITIAL_RTT,
        );
        assert_no_sent_times(&lr);
    }

    // A lower observed RTT is used as min_rtt (and ack delay is ignored).
    #[test]
    fn reduce_min_rtt() {
        let mut lr = setup_lr(2);
        let delta = ms!(4);
        let reduced_rtt = INITIAL_RTT - delta;
        ack(&mut lr, 1, reduced_rtt);
        let expected_rtt = INITIAL_RTT - (delta / 8);
        let expected_rttvar = (INITIAL_RTTVAR * 3 + delta) / 4;
        assert_rtts(&lr, reduced_rtt, expected_rtt, expected_rttvar, reduced_rtt);
        assert_no_sent_times(&lr);
    }

    // Acknowledging something again has no effect.
    #[test]
    fn no_new_acks() {
        let mut lr = setup_lr(1);
        let check = |lr: &LossRecovery| {
            assert_rtts(&lr, INITIAL_RTT, INITIAL_RTT, INITIAL_RTTVAR, INITIAL_RTT);
            assert_no_sent_times(&lr);
        };
        check(&lr);

        ack(&mut lr, 0, ms!(1339)); // much delayed ACK
        check(&lr);

        ack(&mut lr, 0, ms!(3)); // time travel!
        check(&lr);
    }

    // Test time loss detection as part of handling a regular ACK.
    #[test]
    fn time_loss_detection_gap() {
        let mut lr = LossRecovery::new();
        // Create a single packet gap, and have pn 0 time out.
        // This can't use the default pacing, which is too tight.
        // So send two packets with 1/4 RTT between them.  Acknowledge pn 1 after 1 RTT.
        // pn 0 should then be marked lost because it is then outstanding for 5RTT/4
        // the loss time for packets is 9RTT/8.
        lr.on_packet_sent(
            PNSpace::ApplicationData,
            0,
            SentPacket::new(pn_time(0), true, Vec::new(), ON_SENT_SIZE, true),
        );
        lr.on_packet_sent(
            PNSpace::ApplicationData,
            1,
            SentPacket::new(
                pn_time(0) + INITIAL_RTT / 4,
                true,
                Vec::new(),
                ON_SENT_SIZE,
                true,
            ),
        );
        let (_, lost) = lr.on_ack_received(
            PNSpace::ApplicationData,
            1,
            vec![(1, 1)],
            ACK_DELAY,
            pn_time(0) + (INITIAL_RTT * 5 / 4),
        );
        assert_eq!(lost.len(), 1);
        assert_no_sent_times(&lr);
    }

    // Test time loss detection as part of an explicit timeout.
    #[test]
    fn time_loss_detection_timeout() {
        let mut lr = setup_lr(3);

        // We want to declare PN 2 as acknowledged before we declare PN 1 as lost.
        // For this to work, we need PACING above to be less than 1/8 of an RTT.
        let pn1_sent_time = pn_time(1);
        let pn1_loss_time = pn1_sent_time + (INITIAL_RTT * 9 / 8);
        let pn2_ack_time = pn_time(2) + INITIAL_RTT;
        assert!(pn1_loss_time > pn2_ack_time);

        let (_, lost) = lr.on_ack_received(
            PNSpace::ApplicationData,
            2,
            vec![(2, 2)],
            ACK_DELAY,
            pn2_ack_time,
        );
        assert!(lost.is_empty());
        // Run the timeout function here to force time-based loss recovery to be enabled.
        let lost = lr.timeout(pn2_ack_time);
        assert!(lost.is_empty());
        assert_sent_times(&lr, None, None, Some(pn1_sent_time));

        // After time elapses, pn 1 is marked lost.
        let callback_time = lr.next_timeout();
        assert_eq!(callback_time, Some(pn1_loss_time));
        let packets = lr.timeout(pn1_loss_time);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].time_declared_lost, callback_time);
        assert_no_sent_times(&lr);
    }

    #[test]
    fn big_gap_loss() {
        let mut lr = setup_lr(5); // This sends packets 0-4 and acknowledges pn 0.
                                  // Acknowledge just 2-4, which will cause pn 1 to be marked as lost.
        assert_eq!(super::PACKET_THRESHOLD, 3);
        let (_, lost) = lr.on_ack_received(
            PNSpace::ApplicationData,
            4,
            vec![(4, 2)],
            ACK_DELAY,
            pn_time(4),
        );
        assert_eq!(lost.len(), 1);
    }
}
