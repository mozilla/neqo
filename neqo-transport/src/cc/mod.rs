// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control
#![deny(clippy::pedantic)]

use crate::tracking::SentPacket;
use neqo_common::qlog::NeqoQlog;

use std::fmt::Debug;
use std::fmt::Display;
use std::time::{Duration, Instant};

mod new_reno_cc;

use new_reno_cc::NewReno;
pub use new_reno_cc::{CWND_INITIAL_PKTS, CWND_MIN, MAX_DATAGRAM_SIZE, PACING_BURST_SIZE};

pub trait CongestionControl: Display + Debug {
    fn set_qlog(&mut self, qlog: NeqoQlog);

    #[cfg(test)]
    fn cwnd(&self) -> usize;

    #[cfg(test)]
    fn ssthresh(&self) -> usize;

    #[cfg(test)]
    fn bif(&self) -> usize;

    fn cwnd_avail(&self) -> usize;

    fn on_packets_acked(&mut self, acked_pkts: &[SentPacket]);

    fn on_packets_lost(
        &mut self,
        now: Instant,
        first_rtt_sample_time: Option<Instant>,
        prev_largest_acked_sent: Option<Instant>,
        pto: Duration,
        lost_packets: &[SentPacket],
    );

    fn discard(&mut self, pkt: &SentPacket);

    fn on_packet_sent(&mut self, pkt: &SentPacket, rtt: Duration);

    fn start_pacer(&mut self, now: Instant);

    fn next_paced(&self, rtt: Duration) -> Option<Instant>;
}

pub enum CongestionControlAlgorithm {
    NewReno,
}

impl CongestionControlAlgorithm {
    pub fn create(&self) -> Box<dyn CongestionControl> {
        match self {
            Self::NewReno => Box::new(NewReno::default()),
        }
    }
}

impl Default for CongestionControlAlgorithm {
    fn default() -> Self {
        Self::NewReno
    }
}
