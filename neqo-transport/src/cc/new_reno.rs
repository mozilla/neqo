// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control

use std::{
    fmt::{self, Display},
    time::{Duration, Instant},
};

use crate::{
    cc::{CongestionTrigger, classic_cc::WindowAdjustment},
    stats::CongestionControlStats,
};

#[derive(Debug, Default)]
#[expect(unreachable_pub, reason = "re-exported via cc::NewReno")]
pub struct NewReno {}

impl Display for NewReno {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NewReno")?;
        Ok(())
    }
}

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
        _congestion_trigger: CongestionTrigger,
        _cc_stats: &mut CongestionControlStats,
    ) -> (usize, usize) {
        (curr_cwnd / 2, acked_bytes / 2)
    }

    fn on_app_limited(&mut self) {}

    fn save_undo_state(&mut self) {}

    fn restore_undo_state(&mut self, _cc_stats: &mut CongestionControlStats) {}
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::time::Duration;

    use test_fixture::now;

    use super::NewReno;
    use crate::{
        cc::{CongestionTrigger, classic_cc::WindowAdjustment as _},
        stats::CongestionControlStats,
    };

    #[test]
    fn reduce_cwnd_halves_both() {
        let mut nr = NewReno::default();
        let (cwnd, acked) = nr.reduce_cwnd(
            1000,
            200,
            1500,
            CongestionTrigger::Loss,
            &mut CongestionControlStats::default(),
        );
        assert_eq!(cwnd, 500);
        assert_eq!(acked, 100);
    }

    #[test]
    fn bytes_for_cwnd_increase_returns_cwnd() {
        let mut nr = NewReno::default();
        let result = nr.bytes_for_cwnd_increase(2000, 100, Duration::from_millis(50), 1500, now());
        assert_eq!(result, 2000);
    }
}
