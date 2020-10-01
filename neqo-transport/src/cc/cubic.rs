// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// CUBIC congestion control
#![deny(clippy::pedantic)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

use std::cmp::{max, min};
use std::fmt::{self, Display};
use std::time::{Duration, Instant};

use crate::cc::{CWND_MIN, MAX_DATAGRAM_SIZE_F64};
use neqo_common::qtrace;

const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;
const CUBIC_FAST_CONERGENCE: f64 = 0.85; // (1 + CUBIC_BETA)/ 2
pub const CUBIC_BETA_USIZE: usize = 70;
pub const CUBIC_DIV: usize = 100;
const CUBIC_ALFA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7);

#[derive(Debug)]
pub struct Cubic {
    last_max_cwnd: f64,
    estimated_tcp_cwnd: f64,
    k: f64,
    w_max: f64,
    ca_epoch_start: Option<Instant>,
    last_phase_was_tcp: bool,
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

impl Cubic {
    // W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
    fn w_cubic(&self, t: f64) -> f64 {
        CUBIC_C * (t - self.k).powi(3) * MAX_DATAGRAM_SIZE_F64 + self.w_max
    }

    // K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2)
    fn calc_k(&mut self) {
        self.k = libm::cbrt(self.w_max / MAX_DATAGRAM_SIZE_F64 * (1.0 - CUBIC_BETA) / CUBIC_C);
    }

    pub fn calculate_cwnd_ca(
        &mut self,
        congestion_window: &mut usize,
        now: Instant,
        rtt: Duration,
        acked_bytes: &mut usize,
        newly_acked_bytes: usize,
    ) {
        let curr_cwnd = *congestion_window as f64;
        self.last_phase_was_tcp = false;
        let curr_cwnd_f64 = *congestion_window as f64;
        if self.ca_epoch_start.is_none() {
            // This is the first time the congestion avoidance has been entered.
            self.ca_epoch_start = Some(now);
            // reset acked_bytes and estimated_tcp_cwnd;
            *acked_bytes = newly_acked_bytes;
            self.estimated_tcp_cwnd = curr_cwnd_f64;
            if self.last_max_cwnd <= curr_cwnd {
                self.w_max = curr_cwnd;
                self.k = 0.0;
            } else {
                self.w_max = self.last_max_cwnd;
                self.calc_k();
            }
            qtrace!([self], "New epoh started");
        }

        self.estimated_tcp_cwnd +=
            *acked_bytes as f64 * CUBIC_ALFA * MAX_DATAGRAM_SIZE_F64 / self.estimated_tcp_cwnd;

        let time_ca = (now + rtt - self.ca_epoch_start.unwrap()).as_secs_f64();

        let w_cubic = self.w_cubic(time_ca);
        if w_cubic > curr_cwnd_f64 {
            let inc = ((w_cubic - curr_cwnd_f64) / curr_cwnd_f64 * MAX_DATAGRAM_SIZE_F64) as usize;
            let inc = min(inc, *acked_bytes / 2);
            *congestion_window += inc;
        }

        *acked_bytes = 0;
        let estimated_tcp_cwnd = self.estimated_tcp_cwnd as usize;
        if *congestion_window < estimated_tcp_cwnd {
            self.last_phase_was_tcp = true;
            *congestion_window = estimated_tcp_cwnd;
        }
        qtrace!([self], "New congestion_window is {}", *congestion_window);
    }

    #[cfg(test)]
    fn last_phase_was_tcp(&self) -> bool {
        self.last_phase_was_tcp
    }

    pub fn on_congestion_event(&mut self, congestion_window: &mut usize) {
        let curr_cwnd = *congestion_window as f64;
        // Fast Convergence
        self.last_max_cwnd = if curr_cwnd + MAX_DATAGRAM_SIZE_F64 < self.last_max_cwnd {
            curr_cwnd * CUBIC_FAST_CONERGENCE
        } else {
            curr_cwnd
        };

        *congestion_window = *congestion_window * CUBIC_BETA_USIZE / CUBIC_DIV;
        *congestion_window = max(*congestion_window, CWND_MIN);
        self.ca_epoch_start = None;
    }

    #[cfg(test)]
    fn set_last_max_cwnd(&mut self, v: f64) {
        self.last_max_cwnd = v;
    }
}

#[cfg(test)]
mod tests {
    use crate::cc::cubic::{Cubic, CUBIC_ALFA};
    use crate::cc::{CWND_INITIAL, MAX_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE_F64};
    use std::convert::TryFrom;
    use std::time::Duration;
    use test_fixture::now;

    const RTT: Duration = Duration::from_millis(100);

    fn assert_near(v1: usize, v2: usize, max_diff: usize) {
        if v1 > v2 {
            assert!(v1 - v2 < max_diff);
        } else {
            assert!(v2 - v1 < max_diff);
        }
    }

    #[test]
    fn tcp_epoch() {
        let mut cubic = Cubic::default();
        let mut cwnd = CWND_INITIAL;
        let mut acked_bytes = 0;
        let mut now = now();

        for _ in 0..20 {
            //Expected acks. In each round cwnd increases by MAX_DATAGRAM_SIZE.
            let acks = (cwnd as f64 / MAX_DATAGRAM_SIZE_F64 / CUBIC_ALFA) as u64;
            let time_increase = RTT / u32::try_from(acks).unwrap();
            let cwnd_rtt_start = cwnd;
            for _ in 0..acks {
                acked_bytes += MAX_DATAGRAM_SIZE;
                cubic.calculate_cwnd_ca(&mut cwnd, now, RTT, &mut acked_bytes, MAX_DATAGRAM_SIZE);
                assert!(cubic.last_phase_was_tcp());
                now += time_increase;
            }
            assert_near(cwnd - cwnd_rtt_start, MAX_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE);
        }
    }

    #[test]
    fn tcp_cubic() {
        let mut cubic = Cubic::default();
        cubic.set_last_max_cwnd(CWND_INITIAL as f64 * 2.0);
        let mut cwnd = CWND_INITIAL;
        let mut acked_bytes = 0;
        let mut now = now();

        for _ in 0..10 {
            //Expected acks
            let acks = cwnd / MAX_DATAGRAM_SIZE;
            let time_increase = RTT / u32::try_from(acks).unwrap();
            for _ in 0..acks {
                acked_bytes += MAX_DATAGRAM_SIZE;
                cubic.calculate_cwnd_ca(&mut cwnd, now, RTT, &mut acked_bytes, MAX_DATAGRAM_SIZE);
                assert!(!cubic.last_phase_was_tcp());
                now += time_increase;
            }
        }
    }
}
