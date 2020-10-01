// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control
#![deny(clippy::pedantic)]
#![allow(clippy::cast_precision_loss)]
// CongestionControlAlgorithm::Cubic is currently not used. TODO add tests
#![allow(dead_code)]

use crate::tracking::SentPacket;
use neqo_common::qlog::NeqoQlog;

use std::fmt::Debug;
use std::fmt::Display;
use std::time::{Duration, Instant};

mod cubic;
mod new_reno_cubic;

use crate::path::PATH_MTU_V6;
use neqo_common::{const_max, const_min};
pub use new_reno_cubic::{NewRenoCubic, PACING_BURST_SIZE};

pub const MAX_DATAGRAM_SIZE: usize = PATH_MTU_V6;
pub const MAX_DATAGRAM_SIZE_F64: f64 = PATH_MTU_V6 as f64;
pub const CWND_INITIAL_PKTS: usize = 10;
pub const CWND_INITIAL: usize = const_min(
    CWND_INITIAL_PKTS * MAX_DATAGRAM_SIZE,
    const_max(2 * MAX_DATAGRAM_SIZE, 14720),
);
pub const CWND_MIN: usize = MAX_DATAGRAM_SIZE * 2;

pub trait CongestionControl: Display + Debug {
    fn set_qlog(&mut self, qlog: NeqoQlog);

    #[cfg(test)]
    fn cwnd(&self) -> usize;

    #[cfg(test)]
    fn ssthresh(&self) -> usize;

    #[cfg(test)]
    fn bif(&self) -> usize;

    fn cwnd_avail(&self) -> usize;

    fn on_packets_acked(&mut self, acked_pkts: &[SentPacket], now: Instant, rtt: Duration);

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
    Cubic,
}

impl CongestionControlAlgorithm {
    pub fn create(&self) -> Box<dyn CongestionControl> {
        Box::new(NewRenoCubic::new(&self))
    }
}

impl Default for CongestionControlAlgorithm {
    fn default() -> Self {
        Self::NewReno
    }
}

#[cfg(test)]
mod tests;
