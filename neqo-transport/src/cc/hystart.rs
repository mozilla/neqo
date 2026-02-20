// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cmp::{max, min},
    fmt::Display,
    time::Duration,
};

use neqo_common::{qdebug, qinfo};

use crate::{cc::classic_cc::SlowStart, packet, rtt::RttEstimate};

#[derive(Debug, Default, Clone, Copy)]
pub struct State {
    last_round_min_rtt: Duration,
    current_round_min_rtt: Duration,
    rtt_sample_count: usize,
    window_end: Option<packet::Number>,
    css_baseline_min_rtt: Duration,
    css_round_count: usize,
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "State [last_min: {:?}, current_min: {:?}, samples: {}, window_end: {:?}, css_baseline: {:?}, css_rounds: {}]",
            self.last_round_min_rtt,
            self.current_round_min_rtt,
            self.rtt_sample_count,
            self.window_end,
            self.css_baseline_min_rtt,
            self.css_round_count
        )
    }
}

impl State {
    pub const fn new() -> Self {
        Self {
            last_round_min_rtt: Duration::MAX,
            current_round_min_rtt: Duration::MAX,
            rtt_sample_count: 0,
            window_end: None,
            css_baseline_min_rtt: Duration::MAX,
            css_round_count: 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct HyStart {
    limit: usize,
    current: State,
}

impl Display for HyStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HyStart++",)
    }
}

impl HyStart {
    pub const MIN_RTT_THRESH: Duration = Duration::from_millis(4);

    pub const MAX_RTT_THRESH: Duration = Duration::from_millis(16);

    pub const MIN_RTT_DIVISOR: u32 = 8;

    pub const N_RTT_SAMPLE: usize = 8;

    pub const CSS_GROWTH_DIVISOR: usize = 4;

    pub const CSS_ROUNDS: usize = 5;

    pub const NON_PACED_L: usize = 8;

    pub const fn new(pacing: bool) -> Self {
        let limit = if pacing {
            usize::MAX
        } else {
            Self::NON_PACED_L
        };
        Self {
            limit,
            current: State::new(),
        }
    }

    /// > For each arriving ACK in slow start \[...\] keep track of the minimum observed RTT:
    /// >
    /// > ```pseudo
    /// > currentRoundMinRTT = min(currentRoundMinRTT, currRTT)
    /// > rttSampleCount += 1
    /// > ```
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9406#section-4.2-11>
    fn collect_rtt_sample(&mut self, rtt: Duration) {
        self.current.current_round_min_rtt = min(self.current.current_round_min_rtt, rtt);
        self.current.rtt_sample_count += 1;
    }

    /// > For each arriving ACK in slow start, where N is the number of previously unacknowledged
    /// > bytes acknowledged in the arriving ACK:
    /// >
    /// > Update the cwnd:
    /// >
    /// > `cwnd = cwnd + min(N, L*SMSS)`
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9406#section-4.2-8>
    ///
    /// > For each arriving ACK in CSS, where N is the number of previously unacknowledged
    /// > bytes acknowledged in the arriving ACK:
    /// >
    /// > Update the cwnd:
    /// >
    /// > `cwnd = cwnd + (min(N, L*SMSS) / CSS_GROWTH_DIVISOR)`
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9406#section-4.2-15>
    fn calc_cwnd_increase(&self, cwnd_increase: usize, max_datagram_size: usize) -> usize {
        let mut cwnd_increase = min(self.limit.saturating_mul(max_datagram_size), cwnd_increase);

        if self.in_css() {
            cwnd_increase /= Self::CSS_GROWTH_DIVISOR;
        }
        cwnd_increase
    }

    /// > HyStart++ measures rounds using sequence numbers, as follows:
    /// >
    /// > - Define windowEnd as a sequence number initialized to SND.NXT.
    /// > - When windowEnd is ACKed, the current round ends and windowEnd is set to SND.NXT.
    /// >
    /// > At the start of each round during standard slow start and CSS, initialize the
    /// > variables used to compute the last round's and current round's minimum RTT:
    /// >
    /// > ```pseudo
    /// > lastRoundMinRTT = currentRoundMinRTT
    /// > currentRoundMinRTT = infinity
    /// > rttSampleCount = 0
    /// > ```
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9406#section-4.2-4>
    ///
    /// Neqo sets `window_end` to `None` when it is acked and calls this function when packets are
    /// sent to conditionally start a new round.
    fn maybe_start_new_round(&mut self, sent_pn: packet::Number) {
        if self.current.window_end.is_some() {
            return;
        }
        self.current.window_end = Some(sent_pn);
        self.current.last_round_min_rtt = self.current.current_round_min_rtt;
        self.current.current_round_min_rtt = Duration::MAX;
        self.current.rtt_sample_count = 0;
        qdebug!("HyStart: maybe_start_new_round -> started new round");
    }

    pub fn in_css(&self) -> bool {
        self.current.css_baseline_min_rtt != Duration::MAX
    }

    const fn enough_samples(&self) -> bool {
        self.current.rtt_sample_count >= Self::N_RTT_SAMPLE
    }

    #[cfg(test)]
    pub const fn window_end(&self) -> Option<packet::Number> {
        self.current.window_end
    }

    #[cfg(test)]
    pub const fn rtt_sample_count(&self) -> usize {
        self.current.rtt_sample_count
    }

    #[cfg(test)]
    pub const fn current_round_min_rtt(&self) -> Duration {
        self.current.current_round_min_rtt
    }

    #[cfg(test)]
    pub const fn css_round_count(&self) -> usize {
        self.current.css_round_count
    }
}

impl SlowStart for HyStart {
    fn on_packet_sent(&mut self, sent_pn: packet::Number) {
        self.maybe_start_new_round(sent_pn);
    }

    fn on_packets_acked(&mut self, rtt_est: &RttEstimate, largest_acked: packet::Number) -> bool {
        self.collect_rtt_sample(rtt_est.latest());

        qdebug!(
            "HyStart: on_packets_acked -> pn={largest_acked}, rtt={:?}, cur_min={:?}, last_min={:?}, samples={}, in_css={}, css_rounds={}, window_end={:?}",
            rtt_est.latest(),
            self.current.current_round_min_rtt,
            self.current.last_round_min_rtt,
            self.current.rtt_sample_count,
            self.in_css(),
            self.current.css_round_count,
            self.current.window_end
        );

        // > For CSS rounds where at least N_RTT_SAMPLE RTT samples have been obtained, check to see
        // > if the current round's minRTT drops below baseline (cssBaselineMinRtt) indicating that
        // > slow start exit was spurious:
        // >
        // > ```
        // > if (currentRoundMinRTT < cssBaselineMinRtt)
        // > cssBaselineMinRtt = infinity
        // > resume slow start including HyStart++
        // > ```
        //
        // <https://datatracker.ietf.org/doc/html/rfc9406#section-4.2-20>
        if self.in_css()
            && self.enough_samples()
            && self.current.current_round_min_rtt < self.current.css_baseline_min_rtt
        {
            qinfo!(
                "HyStart: on_packets_acked -> exiting CSS after {} rounds because cur_min={:?} < baseline_min={:?}",
                self.current.css_round_count,
                self.current.current_round_min_rtt,
                self.current.css_baseline_min_rtt
            );

            self.current.css_baseline_min_rtt = Duration::MAX;
            self.current.css_round_count = 0;
        }

        // > For rounds where at least N_RTT_SAMPLE RTT samples have been obtained and
        // > currentRoundMinRTT and lastRoundMinRTT are valid, check to see if delay increase
        // > triggers slow start exit.
        //
        // <https://datatracker.ietf.org/doc/html/rfc9406#section-4.2-13>
        if !self.in_css()
            && self.enough_samples()
            && self.current.current_round_min_rtt != Duration::MAX
            && self.current.last_round_min_rtt != Duration::MAX
        {
            let rtt_thresh = max(
                Self::MIN_RTT_THRESH,
                min(
                    self.current.last_round_min_rtt / Self::MIN_RTT_DIVISOR,
                    Self::MAX_RTT_THRESH,
                ),
            );
            if self.current.current_round_min_rtt >= self.current.last_round_min_rtt + rtt_thresh {
                self.current.css_baseline_min_rtt = self.current.current_round_min_rtt;
                qinfo!(
                    "HyStart: on_packets_acked -> entered CSS because cur_min={:?} >= last_min={:?} + thresh={rtt_thresh:?}",
                    self.current.current_round_min_rtt,
                    self.current.last_round_min_rtt
                );
            }
        }

        let mut exit_to_ca = false;

        // Check for end of round. If `window_end` is acked it is set to `None` to indicate end of a
        // round. [`SlowStart::on_packet_sent`] will then set it to the next packet number we send
        // out to start a new round.
        if let Some(window_end) = self.current.window_end
            && largest_acked >= window_end
        {
            qdebug!(
                "HyStart: on_packets_acked -> round ended because largest_acked={largest_acked} >= window_end={window_end}"
            );
            self.current.window_end = None;

            // If a round ends while in CSS increase the counter and do a check if enough rounds
            // to exit to congestion avoidance have been completed.
            if self.in_css() {
                self.current.css_round_count += 1;
                exit_to_ca = self.current.css_round_count >= Self::CSS_ROUNDS;
                qinfo!(
                    "HyStart: on_packets_acked -> exit={exit_to_ca} because css_rounds={} >= {}",
                    self.current.css_round_count,
                    Self::CSS_ROUNDS
                );
            }
        }

        exit_to_ca
    }

    fn maybe_change_cwnd_increase(
        &mut self,
        cwnd_increase: usize,
        max_datagram_size: usize,
    ) -> usize {
        self.calc_cwnd_increase(cwnd_increase, max_datagram_size)
    }

    // > If CSS_ROUNDS rounds are complete, enter congestion avoidance by setting the ssthresh to
    // > the current cwnd.
    //
    // <https://datatracker.ietf.org/doc/html/rfc9406#section-4.2-23>
    fn on_exit_to_ca(&mut self, curr_cwnd: usize) -> usize {
        curr_cwnd
    }
}
