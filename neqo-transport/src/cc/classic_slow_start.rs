// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cmp::min,
    fmt::{self, Display},
};

use crate::{
    cc::classic_cc::{SlowStart, SlowStartResult},
    packet,
    rtt::RttEstimate,
};

/// Classic slow start as described in RFC 9002.
///
/// > While a sender is in slow start, the congestion window increases by the number of bytes
/// > acknowledged when each acknowledgment is processed. This results in exponential growth of the
/// > congestion window.
///
/// <https://datatracker.ietf.org/doc/html/rfc9002#section-7.3.1-2>
#[derive(Debug, Default)]
pub struct ClassicSlowStart {}

impl Display for ClassicSlowStart {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ClassicSlowStart")
    }
}

impl SlowStart for ClassicSlowStart {
    fn on_packet_sent(&mut self, _sent_pn: packet::Number) {}

    fn on_packets_acked(
        &mut self,
        curr_cwnd: usize,
        ssthresh: usize,
        new_acked: usize,
        _rtt_est: &RttEstimate,
        _max_datagram_size: usize,
        _largest_acked: packet::Number,
    ) -> SlowStartResult {
        debug_assert!(
            ssthresh >= curr_cwnd,
            "ssthresh {ssthresh} < curr_cwnd {curr_cwnd} while in slow start --> invalid state"
        );

        // After persistent congestion we already have an established `ssthresh`, so we only grow
        // `cwnd` up to it.
        let cwnd_increase = min(ssthresh - curr_cwnd, new_acked);

        // This is only true if we come here after persistent congestion and have reached the
        // established `ssthresh`.
        let exit_slow_start = curr_cwnd + cwnd_increase == ssthresh;

        SlowStartResult {
            cwnd_increase,
            exit_slow_start,
        }
    }
}
