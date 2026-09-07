// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Instant;

use crate::{cc::classic_cc::SlowStart, packet, rtt::RttEstimate, stats::CongestionControlStats};

/// Classic slow start as described in RFC 9002.
///
/// > While a sender is in slow start, the congestion window increases by the number of bytes
/// > acknowledged when each acknowledgment is processed. This results in exponential growth of the
/// > congestion window.
///
/// <https://datatracker.ietf.org/doc/html/rfc9002#section-7.3.1-2>
#[derive(Debug, Default, displaydoc::Display)]
#[displaydoc("ClassicSlowStart")]
pub struct ClassicSlowStart {}

impl SlowStart for ClassicSlowStart {
    fn on_packets_acked(
        &mut self,
        _rtt_est: &RttEstimate,
        _largest_acked: packet::Number,
        _curr_cwnd: usize,
        _cc_stats: &mut CongestionControlStats,
        _now: Instant,
    ) -> Option<usize> {
        // Classic slow start does not have any heuristic for exiting slow start. Always
        // returns `None`.
        None
    }
}
