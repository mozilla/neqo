// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control

use std::time::{Duration, Instant};

use derive_more::Display;

use crate::cc::{classic_cc::WindowAdjustment, CongestionEvent};

#[derive(Debug, Default, Display)]
#[display("NewReno")]
pub struct NewReno {}

impl WindowAdjustment for NewReno {
    fn bytes_for_cwnd_increase(
        &mut self,
        curr_cwnd: usize,
        _new_acked_bytes: usize,
        _min_rtt: Duration,
        _max_datagram_size: usize,

        _now: Instant,
    ) -> usize {
        curr_cwnd
    }

    fn reduce_cwnd(
        &mut self,
        curr_cwnd: usize,
        acked_bytes: usize,
        _max_datagram_size: usize,
        _congestion_event: CongestionEvent,
    ) -> (usize, usize) {
        (curr_cwnd / 2, acked_bytes / 2)
    }

    fn on_app_limited(&mut self) {}

    fn save_undo_state(&mut self) {}

    fn restore_undo_state(&mut self) {}
}
