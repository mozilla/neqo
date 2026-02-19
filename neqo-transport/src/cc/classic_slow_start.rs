// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::{self, Display};

use crate::{cc::classic_cc::SlowStart, packet, rtt::RttEstimate};

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

    fn on_packets_acked(&mut self, _rtt_est: &RttEstimate, _largest_acked: packet::Number) -> bool {
        // Standard slow start does not have any heuristic for exiting initial slow start. Always
        // returns `exit_to_ca = false`.
        false
    }

    fn maybe_change_cwnd_increase(
        &mut self,
        cwnd_increase: usize,
        _max_datagram_size: usize,
    ) -> usize {
        // Standard slow start does not make changes to the exponential growth during initial slow
        // start, thus always return the same `cwnd_increase` value passed in.
        cwnd_increase
    }

    fn on_exit_to_ca(&mut self, _curr_cwnd: usize) -> usize {
        unreachable!(
            "Since standard slow start never exits initial slow start through a heuristic this function should never be called."
        );
    }
}
