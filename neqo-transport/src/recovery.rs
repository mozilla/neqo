// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::{max, min};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use neqo_common::qdebug;

use crate::frame::FrameGeneratorToken;
use crate::tracking::PNSpace;
use crate::Connection;

const GRANULARITY: Duration = Duration::from_millis(20);
const INITIAL_RTT: Duration = Duration::from_millis(100);

const TIME_THRESHOLD: f64 = 9.0 / 8.0;
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
        if self.latest_rtt - self.min_rtt > ack_delay {
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

                self.rttvar = Duration::from_micros(
                    (3.0 / 4.0 * (self.rttvar.as_micros() as f64)
                        + 1.0 / 4.0 * (rttvar_sample.as_micros() as f64))
                        as u64,
                );
                self.smoothed_rtt = Some(Duration::from_micros(
                    (7.0 / 8.0 * (smoothed_rtt.as_micros() as f64)
                        + 1.0 / 8.0 * (self.latest_rtt.as_micros() as f64))
                        as u64,
                ));
            }
        }
    }

    fn pto(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(self.latest_rtt)
            + max(4 * self.rttvar, GRANULARITY)
            + self.max_ack_delay
    }

    fn timer_for_crypto_retransmission(&mut self, crypto_count: u32) -> Duration {
        let timeout = match self.smoothed_rtt {
            Some(smoothed_rtt) => 2 * smoothed_rtt,
            None => 2 * INITIAL_RTT,
        };

        let timeout = max(timeout, GRANULARITY);
        timeout * 2u32.pow(crypto_count)
    }
}

#[derive(Debug, Default)]
struct LossRecoverySpace {
    largest_acked: Option<u64>,
    loss_time: Option<Instant>,
    sent_packets: HashMap<u64, SentPacket>,
}

impl LossRecoverySpace {
    // Update the largest acknowledged and return the packet that this corresponds to.
    fn update_largest_acked(&mut self, new_largest_acked: u64) -> Option<&SentPacket> {
        let largest_acked = if let Some(curr_largest_acked) = self.largest_acked {
            max(curr_largest_acked, new_largest_acked)
        } else {
            new_largest_acked
        };
        self.largest_acked = Some(largest_acked);

        // TODO(agrover@mozilla.com): Should this really return Some even if
        // largest_acked hasn't been updated?
        self.sent_packets.get(&largest_acked)
    }

    // Remove all the acked packets.
    fn remove_acked(&mut self, acked_ranges: Vec<(u64, u64)>) -> Vec<SentPacket> {
        let mut acked_packets = Vec::new();
        for (end, start) in acked_ranges {
            // ^^ Notabug: see Frame::decode_ack_frame()
            for pn in start..=end {
                if let Some(sent) = self.sent_packets.remove(&pn) {
                    qdebug!("acked={}", pn);
                    acked_packets.push(sent);
                }
            }
        }
        acked_packets
    }

    /// Remove all tracked packets from the space.
    /// This is called when 0-RTT packets are dropped at a client.
    fn remove_ignored(&mut self) -> impl Iterator<Item = SentPacket> {
        // The largest acknowledged or loss_time should still be unset.
        // The client should not have received any ACK frames when it drops 0-RTT.
        assert!(self.largest_acked.is_none());
        assert!(self.loss_time.is_none());
        std::mem::replace(&mut self.sent_packets, Default::default())
            .into_iter()
            .map(|(_, v)| v)
    }
}

#[derive(Debug, Default)]
pub struct LossRecovery {
    loss_detection_timer: Option<Instant>,
    crypto_count: u32,
    pto_count: u32,
    time_of_last_sent_ack_eliciting_packet: Option<Instant>,
    time_of_last_sent_crypto_packet: Option<Instant>,
    rtt_vals: RttVals,
    packet_spaces: [LossRecoverySpace; 3],
}

impl LossRecovery {
    pub fn new() -> LossRecovery {
        LossRecovery {
            rtt_vals: RttVals {
                min_rtt: Duration::from_secs(u64::max_value()),
                max_ack_delay: Duration::from_millis(25),
                ..RttVals::default()
            },

            ..LossRecovery::default()
        }
    }

    pub fn largest_acknowledged(&self, pn_space: PNSpace) -> Option<u64> {
        self.space(pn_space).largest_acked
    }

    pub fn pto(&self) -> Duration {
        self.rtt_vals.pto()
    }

    fn space(&self, pn_space: PNSpace) -> &LossRecoverySpace {
        &self.packet_spaces[pn_space as usize]
    }

    fn space_mut(&mut self, pn_space: PNSpace) -> &mut LossRecoverySpace {
        &mut self.packet_spaces[pn_space as usize]
    }

    pub fn drop_0rtt(&mut self) -> impl Iterator<Item = SentPacket> {
        self.space_mut(PNSpace::ApplicationData).remove_ignored()
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
        qdebug!([self] "packet {} sent.", packet_number);
        self.space_mut(pn_space).sent_packets.insert(
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

        self.set_loss_detection_timer();
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
        qdebug!([self] "ack received - largest_acked={}.", largest_acked);

        let new_largest = self.space_mut(pn_space).update_largest_acked(largest_acked);
        // If the largest acknowledged is newly acked and
        // ack-eliciting, update the RTT.
        if let Some(new_largest) = new_largest {
            if new_largest.ack_eliciting {
                let latest_rtt = now - new_largest.time_sent;
                self.rtt_vals.update_rtt(latest_rtt, ack_delay);
            }
        }

        // TODO Process ECN information if present.

        let acked_packets = self.space_mut(pn_space).remove_acked(acked_ranges);
        if acked_packets.is_empty() {
            return (acked_packets, Vec::new());
        }

        let lost_packets = self.detect_lost_packets(pn_space, now);

        self.crypto_count = 0;
        self.pto_count = 0;

        self.set_loss_detection_timer();

        (acked_packets, lost_packets)
    }

    fn detect_lost_packets(&mut self, pn_space: PNSpace, now: Instant) -> Vec<SentPacket> {
        self.space_mut(pn_space).loss_time = None;

        let loss_delay = Duration::from_micros(
            (TIME_THRESHOLD
                * (max(
                    match self.rtt_vals.smoothed_rtt {
                        None => self.rtt_vals.latest_rtt,
                        Some(smoothed_rtt) => max(self.rtt_vals.latest_rtt, smoothed_rtt),
                    },
                    GRANULARITY,
                ))
                .as_micros() as f64) as u64,
        );

        let loss_deadline = now - loss_delay;
        qdebug!([self]
            "detect lost packets = now {:?} loss delay {:?} loss_deadline {:?}",
            now, loss_delay, loss_deadline
        );

        // Packets with packet numbers before this are deemed lost.
        let packet_space = self.space_mut(pn_space);

        let mut lost = Vec::new();
        for (pn, packet) in &packet_space.sent_packets {
            if Some(*pn) <= packet_space.largest_acked {
                // Packets with packet numbers more than PACKET_THRESHOLD
                // before largest acked are deemed lost.
                if packet.time_sent <= loss_deadline
                    || Some(*pn + PACKET_THRESHOLD) <= packet_space.largest_acked
                {
                    qdebug!("lost={}", pn);
                    lost.push(*pn);
                } else if packet_space.loss_time.is_none() {
                    // Update loss_time when previously there was none
                    packet_space.loss_time = Some(packet.time_sent + loss_delay);
                } else {
                    // Update loss_time when there was an existing value. Take
                    // the lower.
                    packet_space.loss_time =
                        min(packet_space.loss_time, Some(packet.time_sent + loss_delay));
                }
            }
        }

        let mut lost_packets = Vec::new();
        for pn in lost {
            if let Some(sent_packet) = packet_space.sent_packets.remove(&pn) {
                lost_packets.push(sent_packet);
            }
        }

        // TODO
        // Inform the congestion controller of lost packets.

        lost_packets
    }

    fn set_loss_detection_timer(&mut self) {
        qdebug!([self] "set_loss_detection_timer.");
        let mut has_crypto_out = false;
        let mut has_ack_eliciting_out = false;

        for pn_space in &[
            PNSpace::Initial,
            PNSpace::Handshake,
            PNSpace::ApplicationData,
        ] {
            let packet_space = &mut self.packet_spaces[*pn_space as usize];

            if packet_space
                .sent_packets
                .values()
                .any(|sp| sp.is_crypto_packet)
            {
                has_crypto_out = true;
            }

            if packet_space
                .sent_packets
                .values()
                .any(|sp| sp.ack_eliciting)
            {
                has_ack_eliciting_out = true;
            }
        }

        qdebug!(
            [self]
            "has_ack_eliciting_out={} has_crypto_out={}",
            has_ack_eliciting_out,
            has_crypto_out
        );

        if !has_ack_eliciting_out && !has_crypto_out {
            self.loss_detection_timer = None;
            return;
        }

        let (loss_time, _) = self.get_earliest_loss_time();

        if loss_time.is_some() {
            self.loss_detection_timer = loss_time;
        } else if has_crypto_out {
            self.loss_detection_timer = self.time_of_last_sent_crypto_packet.map(|i| {
                i + self
                    .rtt_vals
                    .timer_for_crypto_retransmission(self.crypto_count)
            });
        } else {
            // Calculate PTO duration
            let timeout = self.rtt_vals.pto() * 2u32.pow(self.pto_count);
            self.loss_detection_timer = self
                .time_of_last_sent_ack_eliciting_packet
                .map(|i| i + timeout);
        }
        qdebug!([self] "loss_detection_timer={:?}", self.loss_detection_timer);
    }

    fn get_earliest_loss_time(&self) -> (Option<Instant>, PNSpace) {
        let mut loss_time = self.packet_spaces[PNSpace::Initial as usize].loss_time;
        let mut pn_space = PNSpace::Initial;
        for space in &[PNSpace::Handshake, PNSpace::ApplicationData] {
            let packet_space = self.space(*space);

            if let Some(new_loss_time) = packet_space.loss_time {
                if loss_time.map(|i| new_loss_time < i).unwrap_or(true) {
                    loss_time = Some(new_loss_time);
                    pn_space = *space;
                }
            }
        }

        (loss_time, pn_space)
    }

    /// This is when we'd like to be called back, so we can see if losses have
    /// occurred.
    pub fn get_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    //  The 3 return values for this function: (Vec<SentPacket>, bool, bool).
    //  1) A list of detected lost packets
    //  2) Crypto timer expired, crypto data should be retransmitted,
    //  3) PTO, one or two packets should be transmitted.
    pub fn on_loss_detection_timeout(&mut self, now: Instant) -> (Vec<SentPacket>, bool, bool) {
        let mut lost_packets = Vec::new();
        //TODO(dragana) enable retransmit_unacked_crypto and send_one_or_two_packets when functionanlity to send not-lost packet is there.
        //let mut retransmit_unacked_crypto = false;
        //let mut send_one_or_two_packets = false;
        if self
            .loss_detection_timer
            .map(|timer| now < timer)
            .unwrap_or(false)
        {
            return (
                lost_packets, false, false
                //retransmit_unacked_crypto,
                //send_one_or_two_packets,
            );
        }

        let (loss_time, pn_space) = self.get_earliest_loss_time();
        if loss_time.is_some() {
            // Time threshold loss Detection
            lost_packets = self.detect_lost_packets(pn_space, now);
        } else {
            let has_crypto_out = self
                .space(PNSpace::Initial)
                .sent_packets
                .values()
                .chain(self.space(PNSpace::Handshake).sent_packets.values())
                .any(|sp| sp.ack_eliciting);

            // Retransmit crypto data if no packets were lost
            // and there are still crypto packets in flight.
            if has_crypto_out {
                // Crypto retransmission timeout.
                //retransmit_unacked_crypto = true;
                //for now just call detect_lost_packets;
                lost_packets = self.detect_lost_packets(pn_space, now);
                self.crypto_count += 1;
            } else {
                // PTO
                //send_one_or_two_packets = true;
                //for now just call detect_lost_packets;
                lost_packets = self.detect_lost_packets(pn_space, now);
                self.pto_count += 1;
            }
        }
        self.set_loss_detection_timer();
        (
            lost_packets,
            false,
            false,
            //retransmit_unacked_crypto,
            //send_one_or_two_packets,
        )
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
    use std::time::Duration;
    use test_fixture::now;

    fn assert_values(
        lr: &LossRecovery,
        latest_rtt: Duration,
        smoothed_rtt: Duration,
        rttvar: Duration,
        min_rtt: Duration,
        loss_time: [Option<Instant>; 3],
    ) {
        println!(
            "{:?} {:?} {:?} {:?} {:?} {:?} {:?}",
            lr.rtt_vals.latest_rtt,
            lr.rtt_vals.smoothed_rtt,
            lr.rtt_vals.rttvar,
            lr.rtt_vals.min_rtt,
            lr.space(PNSpace::Initial).loss_time,
            lr.space(PNSpace::Handshake).loss_time,
            lr.space(PNSpace::ApplicationData).loss_time,
        );
        assert_eq!(lr.rtt_vals.latest_rtt, latest_rtt);
        assert_eq!(lr.rtt_vals.smoothed_rtt, Some(smoothed_rtt));
        assert_eq!(lr.rtt_vals.rttvar, rttvar);
        assert_eq!(lr.rtt_vals.min_rtt, min_rtt);
        assert_eq!(lr.space(PNSpace::Initial).loss_time, loss_time[0]);
        assert_eq!(lr.space(PNSpace::Handshake).loss_time, loss_time[1]);
        assert_eq!(lr.space(PNSpace::ApplicationData).loss_time, loss_time[2]);
    }

    #[test]
    fn test_loss_recovery1() {
        let mut lr_module = LossRecovery::new();

        let start = now();

        lr_module.on_packet_sent(PNSpace::ApplicationData, 0, true, false, Vec::new(), start);
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            1,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(10),
        );

        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            2,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(20),
        );

        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            3,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(30),
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            4,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(40),
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            5,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(50),
        );

        // Calculating rtt for the first ack
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            0,
            Vec::new(),
            Duration::from_micros(2000),
            start + Duration::from_millis(50),
        );
        assert_values(
            &lr_module,
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_millis(25),
            Duration::from_millis(50),
            [None, None, None],
        );

        // Calculating rtt for further acks
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            1,
            vec![(1, 0)],
            Duration::from_micros(2000),
            start + Duration::from_millis(60),
        );
        assert_values(
            &lr_module,
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_micros(18_750),
            Duration::from_millis(50),
            [None, None, None],
        );

        // Calculating rtt for further acks
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            2,
            vec![(2, 0)],
            Duration::from_micros(2000),
            start + Duration::from_millis(70),
        );
        assert_values(
            &lr_module,
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_micros(14_062),
            Duration::from_millis(50),
            [None, None, None],
        );

        // Calculating rtt for further acks; test min_rtt
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            3,
            vec![(3, 0)],
            Duration::from_micros(2000),
            start + Duration::from_millis(75),
        );
        assert_values(
            &lr_module,
            Duration::from_micros(45_000),
            Duration::from_micros(49_375),
            Duration::from_micros(11_796),
            Duration::from_micros(45_000),
            [None, None, None],
        );

        // Calculating rtt for further acks; test ack_delay
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            4,
            vec![(4, 0)],
            Duration::from_micros(2000),
            start + Duration::from_millis(95),
        );
        assert_values(
            &lr_module,
            Duration::from_micros(53_000),
            Duration::from_micros(49828),
            Duration::from_micros(9_753),
            Duration::from_micros(45_000),
            [None, None, None],
        );

        // Calculating rtt for further acks; test max_ack_delay
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            5,
            vec![(5, 0)],
            Duration::from_millis(28000),
            start + Duration::from_millis(150),
        );
        assert_values(
            &lr_module,
            Duration::from_micros(75000),
            Duration::from_micros(52974),
            Duration::from_micros(13607),
            Duration::from_micros(45000),
            [None, None, None],
        );

        // Calculating rtt for further acks; test acking already acked packet
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            5,
            vec![(5, 0)],
            Duration::from_millis(28000),
            start + Duration::from_millis(160),
        );
        assert_values(
            &lr_module,
            Duration::from_micros(75000),
            Duration::from_micros(52974),
            Duration::from_micros(13607),
            Duration::from_micros(45000),
            [None, None, None],
        );
    }

    // Test crypto timeout.
    #[test]
    fn test_loss_recovery2() {
        let mut lr_module = LossRecovery::new();

        let start = now();

        lr_module.on_packet_sent(PNSpace::ApplicationData, 0, true, true, Vec::new(), start);
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_millis(200))
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            1,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(10),
        );
        // Last crypto packet sent at time "start", so timeout at
        // start+10millis should be 190.
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_millis(200))
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            2,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(20),
        );
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_millis(200))
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            3,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(30),
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            4,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(40),
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            5,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(50),
        );

        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            6,
            true,
            false,
            Vec::new(),
            start + Duration::from_millis(60),
        );

        // This is a PTO for crypto packet.
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_millis(200))
        );

        // Receive an ack for packet 0.
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            0,
            vec![(0, 0)],
            Duration::from_micros(2000),
            start + Duration::from_millis(100),
        );
        assert_values(
            &lr_module,
            Duration::from_micros(100_000),
            Duration::from_micros(100_000),
            Duration::from_micros(50_000),
            Duration::from_micros(100_000),
            [None, None, None],
        );
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_millis(385))
        );

        // Receive an ack with a gap. acks 0 and 2.
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            2,
            vec![(0, 0), (2, 2)],
            Duration::from_micros(2000),
            start + Duration::from_millis(105),
        );
        assert_values(
            &lr_module,
            Duration::from_micros(85_000),
            Duration::from_micros(98_125),
            Duration::from_micros(41_250),
            Duration::from_micros(85_000),
            [None, None, Some(start + Duration::from_micros(120_390))],
        );
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_micros(120_390))
        );

        // Timer expires, packet 1 is lost.
        lr_module.on_loss_detection_timeout(start + Duration::from_micros(120_390));
        assert_values(
            &lr_module,
            Duration::from_micros(85_000),
            Duration::from_micros(98_125),
            Duration::from_micros(41_250),
            Duration::from_micros(85_000),
            [None, None, None],
        );
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_nanos(348_125_000))
        );

        // dupacks loss detection. ackes 0, 2 and 6, markes packet 3 as lost.
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            6,
            vec![(0, 0), (2, 2), (6, 6)],
            Duration::from_micros(2000),
            start + Duration::from_nanos(130_000_000),
        );
        assert_values(
            &lr_module,
            Duration::from_micros(70_000),
            Duration::from_micros(94_609),
            Duration::from_micros(37_968),
            Duration::from_micros(70_000),
            [None, None, Some(start + Duration::from_micros(146_435))],
        );
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_nanos(146_435_000))
        );

        // Timer expires, packet 4 is lost.
        lr_module.on_loss_detection_timeout(start + Duration::from_nanos(146_500_000));
        assert_values(
            &lr_module,
            Duration::from_micros(70_000),
            Duration::from_micros(94_609),
            Duration::from_micros(37_968),
            Duration::from_micros(70_000),
            [None, None, Some(start + Duration::from_micros(156_435))],
        );
        assert_eq!(
            lr_module.get_timer(),
            Some(start + Duration::from_nanos(156_435_000))
        );

        // Timer expires, packet 5 is lost.
        lr_module.on_loss_detection_timeout(start + Duration::from_nanos(156_500_000));
        assert_values(
            &lr_module,
            Duration::from_micros(70_000),
            Duration::from_micros(94_609),
            Duration::from_micros(37_968),
            Duration::from_micros(70_000),
            [None, None, None],
        );

        // there is no more outstanding data - timer is set to 0.
        assert_eq!(lr_module.get_timer(), None);
    }

}
