// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracking of sent packets and detecting their loss.

use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use smallvec::SmallVec;

use neqo_common::{qdebug, qinfo, qtrace};

use crate::frame::FrameGeneratorToken;
use crate::tracking::PNSpace;
use crate::Connection;

const GRANULARITY: Duration = Duration::from_millis(20);
// Defined in -recovery 6.2
const INITIAL_RTT: Duration = Duration::from_millis(500);

const PACKET_THRESHOLD: u64 = 3;

#[derive(Debug)]
pub struct SentPacket {
    ack_eliciting: bool,
    //in_flight: bool, // TODO needed only for cc
    is_crypto_packet: bool,
    //size: u64, // TODO needed only for cc
    time_sent: Instant,
    tokens: Vec<Box<FrameGeneratorToken>>, // a list of tokens.
}

impl SentPacket {
    pub fn mark_acked(&mut self, conn: &mut Connection) {
        for token in self.tokens.iter_mut() {
            token.acked(conn);
        }
    }

    pub fn mark_lost(&mut self, conn: &mut Connection) {
        for token in self.tokens.iter_mut() {
            token.lost(conn);
        }
    }
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

                self.rttvar = (self.rttvar * 3 / 4) + (rttvar_sample / 4);
                self.smoothed_rtt = Some((smoothed_rtt * 7 / 8) + (self.latest_rtt / 8));
            }
        }
    }

    fn pto(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(self.latest_rtt)
            + max(4 * self.rttvar, GRANULARITY)
            + self.max_ack_delay
    }

    fn timer_for_crypto_retransmission(&self, crypto_count: u32) -> Duration {
        let timeout = match self.smoothed_rtt {
            Some(smoothed_rtt) => 2 * smoothed_rtt,
            None => 2 * INITIAL_RTT,
        };

        let timeout = max(timeout, GRANULARITY);
        timeout * 2u32.pow(crypto_count)
    }
}

#[derive(Debug)]
pub(crate) enum LossRecoveryMode {
    None,
    LostPackets(Vec<SentPacket>),
    CryptoTimerExpired,
    PTO,
}

#[derive(Debug, Default)]
pub(crate) struct LossRecoverySpace {
    largest_acked: Option<u64>,
    sent_packets: BTreeMap<u64, SentPacket>,
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

    // Remove all the acked packets.
    fn remove_acked(&mut self, acked_ranges: Vec<(u64, u64)>) -> (BTreeMap<u64, SentPacket>, bool) {
        let mut acked_packets = BTreeMap::new();
        let mut eliciting = false;
        for (end, start) in acked_ranges {
            // ^^ Notabug: see Frame::decode_ack_frame()
            for pn in start..=end {
                if let Some(sent) = self.sent_packets.remove(&pn) {
                    qdebug!("acked={}", pn);
                    eliciting |= sent.ack_eliciting;
                    acked_packets.insert(pn, sent);
                }
            }
        }
        (acked_packets, eliciting)
    }

    /// Remove all tracked packets from the space.
    /// This is called when 0-RTT packets are dropped at a client.
    fn remove_ignored(&mut self) -> impl Iterator<Item = SentPacket> {
        // The largest acknowledged or loss_time should still be unset.
        // The client should not have received any ACK frames when it drops 0-RTT.
        assert!(self.largest_acked.is_none());
        std::mem::replace(&mut self.sent_packets, Default::default())
            .into_iter()
            .map(|(_, v)| v)
    }
}

#[derive(Debug, Default)]
pub(crate) struct LossRecoverySpaces([LossRecoverySpace; 3]);

impl LossRecoverySpaces {
    fn get(&self, pn_space: PNSpace) -> &LossRecoverySpace {
        &self.0[pn_space as usize]
    }

    fn get_mut(&mut self, pn_space: PNSpace) -> &mut LossRecoverySpace {
        &mut self.0[pn_space as usize]
    }
}

#[derive(Debug, Default)]
pub(crate) struct LossRecovery {
    crypto_count: u32,
    pto_count: u32,
    time_of_last_sent_ack_eliciting_packet: Option<Instant>,
    time_of_last_sent_crypto_packet: Option<Instant>,
    rtt_vals: RttVals,

    enable_timed_loss_detection: bool,
    spaces: LossRecoverySpaces,
}

impl LossRecovery {
    pub fn new() -> LossRecovery {
        LossRecovery {
            rtt_vals: RttVals {
                min_rtt: Duration::from_secs(u64::max_value()),
                max_ack_delay: Duration::from_millis(25),
                latest_rtt: INITIAL_RTT,
                ..RttVals::default()
            },

            ..LossRecovery::default()
        }
    }

    pub fn largest_acknowledged(&self, pn_space: PNSpace) -> Option<u64> {
        self.spaces.get(pn_space).largest_acked
    }

    pub fn pto(&self) -> Duration {
        self.rtt_vals.pto()
    }

    pub fn drop_0rtt(&mut self) -> impl Iterator<Item = SentPacket> {
        self.spaces
            .get_mut(PNSpace::ApplicationData)
            .remove_ignored()
    }

    pub fn on_packet_sent(
        &mut self,
        pn_space: PNSpace,
        packet_number: u64,
        ack_eliciting: bool,
        is_crypto_packet: bool,
        tokens: Vec<Box<FrameGeneratorToken>>,
        now: Instant,
    ) {
        qdebug!([self] "packet {:?}-{} sent.", pn_space, packet_number);
        self.spaces.get_mut(pn_space).sent_packets.insert(
            packet_number,
            SentPacket {
                time_sent: now,
                ack_eliciting,
                is_crypto_packet,
                tokens,
            },
        );
        if is_crypto_packet {
            self.time_of_last_sent_crypto_packet = Some(now);
        }
        if ack_eliciting {
            self.time_of_last_sent_ack_eliciting_packet = Some(now);
            // TODO implement cc
            //     cc.on_packet_sent(sent_bytes)
        }
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
        qdebug!([self] "ack received for {:?} - largest_acked={}.",
                pn_space, largest_acked);

        let (acked_packets, any_ack_eliciting) =
            self.spaces.get_mut(pn_space).remove_acked(acked_ranges);
        if acked_packets.is_empty() {
            // No new information.
            return (Vec::new(), Vec::new());
        }

        // Track largest PN acked per space
        let space = self.spaces.get_mut(pn_space);
        let largest_acked = max(space.largest_acked, Some(largest_acked)).expect("must be some");
        if Some(largest_acked) != space.largest_acked {
            space.largest_acked = Some(largest_acked);

            // If the largest acknowledged is newly acked and any newly acked
            // packet was ack-eliciting, update the RTT. (-recovery 5.1)
            let largest_acked_pkt = acked_packets.get(&largest_acked).expect("must be there");
            if any_ack_eliciting {
                let latest_rtt = now - largest_acked_pkt.time_sent;
                self.rtt_vals.update_rtt(latest_rtt, ack_delay);
            }
        }

        // TODO Process ECN information if present.

        let lost_packets = self.detect_lost_packets(pn_space, now);

        self.crypto_count = 0;
        self.pto_count = 0;

        let acked_packets = acked_packets
            .into_iter()
            .map(|(_k, v)| v)
            .collect::<Vec<_>>();

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

    fn detect_lost_packets(&mut self, pn_space: PNSpace, now: Instant) -> Vec<SentPacket> {
        self.enable_timed_loss_detection = false;
        let loss_delay = self.loss_delay();

        // Packets sent before this time are deemed lost.
        let lost_deadline = now - loss_delay;
        qdebug!([self]
            "detect lost packets = now {:?} loss delay {:?} lost_deadline {:?}",
            now, loss_delay, lost_deadline
        );

        let packet_space = self.spaces.get_mut(pn_space);

        let mut lost_pns = SmallVec::<[_; 8]>::new();
        for (pn, packet) in packet_space
            .sent_packets
            .iter()
            // BTreeMap iterates in order of ascending PN
            .take_while(|(&k, _)| Some(k) < packet_space.largest_acked)
        {
            if packet.time_sent <= lost_deadline {
                qdebug!(
                    "lost={}, time sent {:?} is before lost_deadline {:?}",
                    pn,
                    packet.time_sent,
                    lost_deadline
                );
                lost_pns.push(*pn);
            } else if packet_space.largest_acked >= Some(*pn + PACKET_THRESHOLD) {
                // Packets with packet numbers more than PACKET_THRESHOLD
                // before largest acked are deemed lost.
                qdebug!(
                    "lost={}, is >= {} from largest acked {:?}",
                    pn,
                    PACKET_THRESHOLD,
                    packet_space.largest_acked
                );
                lost_pns.push(*pn);
            } else {
                // OOO but not quite lost yet. Set the timed loss detect timer
                self.enable_timed_loss_detection = true;
            }
        }

        let mut lost_packets = Vec::with_capacity(lost_pns.len());
        for pn in lost_pns {
            let lost_packet = packet_space
                .sent_packets
                .remove(&pn)
                .expect("PN must be in sent_packets");
            lost_packets.push(lost_packet);
        }

        // TODO
        // Inform the congestion controller of lost packets.

        lost_packets
    }

    fn get_loss_detection_timer(&self) -> (LossRecoveryMode, Option<Instant>) {
        qdebug!([self] "get_loss_detection_timer.");

        let spaces = &[
            PNSpace::Initial,
            PNSpace::Handshake,
            PNSpace::ApplicationData,
        ];
        let mut has_crypto_out = false;
        let mut has_ack_eliciting_out = false;
        for sp in spaces
            .iter()
            .flat_map(|spc| self.spaces.get(*spc).sent_packets.values())
        {
            if sp.is_crypto_packet {
                has_crypto_out = true
            }

            if sp.ack_eliciting {
                has_ack_eliciting_out = true
            }

            if has_crypto_out && has_ack_eliciting_out {
                break;
            }
        }

        qdebug!(
            [self]
            "has_ack_eliciting_out={} has_crypto_out={}",
            has_ack_eliciting_out,
            has_crypto_out
        );

        if !has_ack_eliciting_out && !has_crypto_out {
            return (LossRecoveryMode::None, None);
        }

        qinfo!([self]
            "sent packets {} {} {}",
            self.spaces.get(PNSpace::Initial).sent_packets.len(),
            self.spaces.get(PNSpace::Handshake).sent_packets.len(),
            self.spaces.get(PNSpace::ApplicationData).sent_packets.len()
        );

        // QUIC only has one timer, but it does triple duty because it falls
        // back to other uses if first use is not needed: first the loss
        // detection timer, then the crypto retransmission timeout, and
        // finally probe timeout (PTO).

        let (mode, maybe_timer) = if let Some((_, earliest_time)) = self.get_earliest_loss_time() {
            (LossRecoveryMode::LostPackets(vec![]), Some(earliest_time))
        } else if has_crypto_out {
            assert!(self.time_of_last_sent_crypto_packet.is_some());
            (
                LossRecoveryMode::CryptoTimerExpired,
                self.time_of_last_sent_crypto_packet.map(|i| {
                    i + self
                        .rtt_vals
                        .timer_for_crypto_retransmission(self.crypto_count)
                }),
            )
        } else {
            // Calculate PTO duration
            let timeout = self.rtt_vals.pto() * 2u32.pow(self.pto_count);
            (
                LossRecoveryMode::PTO,
                self.time_of_last_sent_ack_eliciting_packet
                    .map(|i| i + timeout),
            )
        };

        qdebug!([self] "loss_detection_timer mode={:?} timer={:?}", mode, maybe_timer);
        (mode, maybe_timer)
    }

    /// Find when the earliest sent packed should be considered lost.
    fn get_earliest_loss_time(&self) -> Option<(PNSpace, Instant)> {
        if !self.enable_timed_loss_detection {
            return None;
        }

        let spaces = &[
            PNSpace::Initial,
            PNSpace::Handshake,
            PNSpace::ApplicationData,
        ];
        spaces
            .iter()
            .map(|spc| (*spc, self.spaces.get(*spc).earliest_sent_time()))
            .filter_map(|(spc, time)| {
                // None is ordered less than Some(_). Bad. Filter them out.
                if let Some(time) = time {
                    Some((spc, time))
                } else {
                    None
                }
            })
            .min_by_key(|&(_, time)| time)
            .map(|(spc, val)| (spc, val + self.loss_delay()))
    }

    /// This is when we'd like to be called back, so we can see if losses have
    /// occurred.
    pub fn get_timer(&self) -> Option<Instant> {
        let (mode, timer) = self.get_loss_detection_timer();
        qtrace!([self] "get_timer mode {:?} timer {:?}", mode, timer);
        timer
    }

    /// If timer was active and expired, figure out what to do.
    pub fn check_loss_timer(&mut self, now: Instant) -> LossRecoveryMode {
        let (mode, timer) = self.get_loss_detection_timer();

        if Some(now) < timer {
            // Timer, but hasn't expired.
            return LossRecoveryMode::None;
        }

        match mode {
            LossRecoveryMode::None => {
                assert_eq!(timer, None);
                LossRecoveryMode::None
            }
            LossRecoveryMode::LostPackets(_) => {
                // Time threshold loss detection
                let (pn_space, _) = self
                    .get_earliest_loss_time()
                    .expect("must be sent packets if in LostPackets mode");
                LossRecoveryMode::LostPackets(self.detect_lost_packets(pn_space, now))
            }
            LossRecoveryMode::CryptoTimerExpired => {
                // Crypto retransmission timeout.
                // Retransmit crypto data if no packets were lost
                // and there are still crypto packets in flight.
                self.crypto_count += 1;
                LossRecoveryMode::CryptoTimerExpired
            }
            LossRecoveryMode::PTO => {
                // PTO
                //send_one_or_two_packets = true;
                self.pto_count += 1;
                LossRecoveryMode::PTO
            }
        }
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
    use std::mem::discriminant;
    use std::time::{Duration, Instant};

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
            lr.spaces.get(PNSpace::Initial).earliest_sent_time(),
            lr.spaces.get(PNSpace::Handshake).earliest_sent_time(),
            lr.spaces.get(PNSpace::ApplicationData).earliest_sent_time(),
        );
        assert_eq!(
            lr.spaces.get(PNSpace::Initial).earliest_sent_time(),
            initial,
            "Initial earliest sent time"
        );
        assert_eq!(
            lr.spaces.get(PNSpace::Handshake).earliest_sent_time(),
            handshake,
            "Handshake earliest sent time"
        );
        assert_eq!(
            lr.spaces.get(PNSpace::ApplicationData).earliest_sent_time(),
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
                true,
                false,
                Vec::new(),
                pn_time(pn),
            );
        }
    }

    const ACK_DELAY: Duration = ms!(24);
    /// Acknowledge PN with the identified delay.
    fn ack(lr: &mut LossRecovery, pn: u64, delay: Duration) -> (Vec<SentPacket>, Vec<SentPacket>) {
        lr.on_ack_received(
            PNSpace::ApplicationData,
            pn,
            vec![(pn, pn)],
            ACK_DELAY,
            pn_time(pn) + delay,
        )
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

    // The crypto timer is set when sending crypto packets.
    #[test]
    fn crypto_timer() {
        let mut lr = LossRecovery::new();
        lr.on_packet_sent(PNSpace::ApplicationData, 0, true, true, vec![], pn_time(0));
        assert_eq!(lr.get_timer(), Some(pn_time(0) + (super::INITIAL_RTT * 2)));
        // Sending another crypto packet pushes the timer out.
        lr.on_packet_sent(PNSpace::ApplicationData, 1, true, true, vec![], pn_time(1));
        assert_eq!(lr.get_timer(), Some(pn_time(1) + (super::INITIAL_RTT * 2)));
        // Sending non-crypto packets doesn't move it.
        lr.on_packet_sent(PNSpace::ApplicationData, 2, true, false, vec![], pn_time(2));
        assert_eq!(lr.get_timer(), Some(pn_time(1) + (super::INITIAL_RTT * 2)));
    }

    #[test]
    fn crypto_timeout() {
        let mut lr = LossRecovery::new();
        lr.on_packet_sent(PNSpace::Initial, 0, true, true, vec![], pn_time(0));
        let crypto_time = lr.get_timer().expect("should have crypto timer");

        let mode = lr.check_loss_timer(crypto_time);
        assert_eq!(
            discriminant(&mode),
            discriminant(&LossRecoveryMode::CryptoTimerExpired)
        );
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
            true,
            false,
            Vec::new(),
            pn_time(0),
        );
        lr.on_packet_sent(
            PNSpace::ApplicationData,
            1,
            true,
            false,
            Vec::new(),
            pn_time(0) + INITIAL_RTT / 4,
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
        // Create a small gap so that pn 1 can be regarded as lost.
        // Make sure to provide this before the loss timer for pn 1 expires.
        // This relies on having `PACING < INITIAL_RTT/8`.  We want to keep the RTT constant,
        // but we also want to ensure that acknowledging pn 2 doesn't cause pn 1 to be lost.
        // Because pn 1 was sent at `pn_time(2) - PACING` and
        // `pn_time(2) - PACING + (INITIAL_RTT * 9 /8)` needs to be in the future.
        assert!(PACING < (INITIAL_RTT / 8));
        let (_, lost) = lr.on_ack_received(
            PNSpace::ApplicationData,
            2,
            vec![(2, 2)],
            ACK_DELAY,
            pn_time(2) + INITIAL_RTT,
        );
        assert!(lost.is_empty());
        let pn1_loss_time = pn_time(1);
        assert_sent_times(&lr, None, None, Some(pn1_loss_time));

        // After time elapses, pn 1 is marked lost.
        assert_eq!(lr.get_timer(), Some(pn1_loss_time + (INITIAL_RTT * 9 / 8)));
        let mode = lr.check_loss_timer(pn1_loss_time + (INITIAL_RTT * 9 / 8));
        match mode {
            LossRecoveryMode::LostPackets(lost) => assert_eq!(lost.len(), 1),
            _ => assert!(false),
        }
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
