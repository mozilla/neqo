// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

use std::cmp::max;
use std::fmt::{self, Display};
use std::time::{Duration, Instant};

use crate::cc::{classic_cc::WindowAdjustment, CWND_MIN, MAX_DATAGRAM_SIZE_F64};
use neqo_common::qtrace;
use std::convert::TryFrom;

// CUBIC congestion control

// C is a constant fixed to determine the aggressiveness of window
// increase  in high BDP networks.
pub const CUBIC_C: f64 = 0.4;
// beta_cubic is the CUBIC multiplication decrease factor
const CUBIC_BETA: f64 = 0.7;
pub const CUBIC_ALPHA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7);

pub const CUBIC_BETA_USIZE_QUOTIENT: usize = 7;
pub const CUBIC_BETA_USIZE_DIVISOR: usize = 10;

/// The fast convergence ratio further reduces the congestion window when a congestion event
/// occurs before reaching the previous `W_max`.
pub const CUBIC_FAST_CONVERGENCE: f64 = (1.0 + CUBIC_BETA) / 2.0;

#[derive(Debug)]
pub struct Cubic {
    last_max_cwnd: f64,
    estimated_tcp_cwnd: f64,
    k: f64,
    w_max: f64,
    ca_epoch_start: Option<Instant>,
    last_phase_was_tcp: bool,
    tcp_acked_bytes: f64,
}

impl Default for Cubic {
    fn default() -> Self {
        Self {
            last_max_cwnd: 0.0,
            estimated_tcp_cwnd: 0.0,
            k: 0.0,
            w_max: 0.0,
            ca_epoch_start: None,
            last_phase_was_tcp: false,
            tcp_acked_bytes: 0.0,
        }
    }
}

impl Display for Cubic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Cubic [last_max_cwnd: {}, k: {}, w_max: {}, ca_epoch_start: {:?}]",
            self.last_max_cwnd, self.k, self.w_max, self.ca_epoch_start
        )?;
        Ok(())
    }
}

#[allow(clippy::doc_markdown)]
impl Cubic {
    /// Original equations is:
    /// K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2 RFC8312)
    /// W_max is number of segments of the maximum segment size (MSS).
    ///
    /// K is actually the time that W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1) would
    /// take to increase to W_max. We use bytes not MSS units, therefore this
    /// equation will be: W_cubic(t) = C*MSS*(t-K)^3 + W_max.
    ///
    /// From that equation we can calculate K as:
    /// K = cubic_root((W_max - W_cubic) / C / MSS);
    fn calc_k(&self, curr_cwnd: f64) -> f64 {
        ((self.w_max - curr_cwnd) / CUBIC_C / MAX_DATAGRAM_SIZE_F64).cbrt()
    }

    /// W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
    fn w_cubic(&self, t: f64) -> f64 {
        CUBIC_C * (t - self.k).powi(3) * MAX_DATAGRAM_SIZE_F64 + self.w_max
    }
}

impl WindowAdjustment for Cubic {
    // This is because of the cast in the last line from f64 to usize.
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    fn on_packets_acked(
        &mut self,
        curr_cwnd: usize,
        acked_bytes: usize,
        min_rtt: Duration,
        now: Instant,
    ) -> usize {
        let curr_cwnd_f64 = f64::try_from(u32::try_from(curr_cwnd).unwrap()).unwrap();
        self.tcp_acked_bytes += f64::try_from(u32::try_from(acked_bytes).unwrap()).unwrap();
        if self.ca_epoch_start.is_none() {
            // This is a start of a new congestion avoidance phase.
            self.ca_epoch_start = Some(now);
            // reset acked_bytes and estimated_tcp_cwnd;
            self.tcp_acked_bytes = f64::try_from(u32::try_from(acked_bytes).unwrap()).unwrap();
            self.estimated_tcp_cwnd = curr_cwnd_f64;
            if self.last_max_cwnd <= curr_cwnd_f64 {
                self.w_max = curr_cwnd_f64;
                self.k = 0.0;
            } else {
                self.w_max = self.last_max_cwnd;
                self.k = self.calc_k(curr_cwnd_f64);
            }
            qtrace!([self], "New epoch");
        }

        let time_ca = (now + min_rtt
            - if let Some(t) = self.ca_epoch_start {
                t
            } else {
                now
            })
        .as_secs_f64();
        let target = self.w_cubic(time_ca);

        let mut cnt = if target > curr_cwnd_f64 {
            curr_cwnd_f64 / (target - curr_cwnd_f64) * MAX_DATAGRAM_SIZE_F64
        } else {
            100.0 * curr_cwnd_f64
        };

        let tcp_cnt = self.estimated_tcp_cwnd / CUBIC_ALPHA;
        while self.tcp_acked_bytes > tcp_cnt {
            self.tcp_acked_bytes -= tcp_cnt;
            self.estimated_tcp_cwnd += MAX_DATAGRAM_SIZE_F64;
        }

        if self.estimated_tcp_cwnd > curr_cwnd_f64 && self.estimated_tcp_cwnd > target {
            let cnt_tcp_equation =
                curr_cwnd_f64 / (self.estimated_tcp_cwnd - curr_cwnd_f64) * MAX_DATAGRAM_SIZE_F64;
            if cnt > cnt_tcp_equation {
                cnt = cnt_tcp_equation;
            }
        }

        // Limit increas to max 1 MSS per 2 ack packets.
        cnt = cnt.max(2.0 * MAX_DATAGRAM_SIZE_F64);
        cnt as usize
    }

    fn on_congestion_event(&mut self, curr_cwnd: usize, acked_bytes: usize) -> (usize, usize) {
        let curr_cwnd_f64 = f64::try_from(u32::try_from(curr_cwnd).unwrap()).unwrap();
        // Fast Convergence
        // check cwnd + MAX_DATAGRAM_SIZE instead of cwnd because with cwnd in bytes, cwnd may be slightly off.
        self.last_max_cwnd = if curr_cwnd_f64 + MAX_DATAGRAM_SIZE_F64 < self.last_max_cwnd {
            curr_cwnd_f64 * CUBIC_FAST_CONVERGENCE
        } else {
            curr_cwnd_f64
        };
        self.ca_epoch_start = None;
        (
            max(
                curr_cwnd * CUBIC_BETA_USIZE_QUOTIENT / CUBIC_BETA_USIZE_DIVISOR,
                CWND_MIN,
            ),
            acked_bytes * CUBIC_BETA_USIZE_QUOTIENT / CUBIC_BETA_USIZE_DIVISOR,
        )
    }

    #[cfg(test)]
    fn last_max_cwnd(&self) -> f64 {
        self.last_max_cwnd
    }

    #[cfg(test)]
    fn set_last_max_cwnd(&mut self, last_max_cwnd: f64) {
        self.last_max_cwnd = last_max_cwnd;
    }
}
