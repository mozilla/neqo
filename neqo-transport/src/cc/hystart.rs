// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cmp::min,
    fmt::{self, Display},
};

use crate::cc::classic_cc::{SlowStart, SlowStartResult};

/// `HyStart` placeholder, this is just 2x'ing the classic slow start growth for testing purposes
/// currently
#[derive(Debug, Default)]
pub struct HyStart {}

impl Display for HyStart {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HyStart")
    }
}

impl SlowStart for HyStart {
    fn on_packets_acked(
        &mut self,
        curr_cwnd: usize,
        ssthresh: usize,
        acked_bytes: usize,
        new_acked: usize,
    ) -> SlowStartResult {
        debug_assert!(
            ssthresh >= curr_cwnd,
            "ssthresh {ssthresh} < curr_cwnd {curr_cwnd} while in slow start --> invalid state"
        );

        let cwnd_increase = min(ssthresh - curr_cwnd, 2 * (acked_bytes + new_acked));
        let unused_acked_bytes = (acked_bytes + new_acked).saturating_sub(cwnd_increase);

        // This doesn't look like it is necessary, but it can happen
        // after persistent congestion.
        let exit_slow_start = curr_cwnd + cwnd_increase == ssthresh;

        SlowStartResult {
            cwnd_increase,
            unused_acked_bytes,
            exit_slow_start,
        }
    }
}
