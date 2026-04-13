// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// Slow start Exit At Right CHokepoint (SEARCH) implementation as per
// <https://datatracker.ietf.org/doc/html/draft-chung-ccwg-search-09>

use std::{
    fmt::Display,
    time::{Duration, Instant},
};

use neqo_common::qdebug;

use crate::{cc::classic_cc::SlowStart, packet, rtt::RttEstimate, stats::CongestionControlStats};

/// Slow start Exit At Right CHokepoint (SEARCH).
///
/// Exits slow start when the delivery rate flattens, indicating the network is
/// near its bottleneck capacity.
///
/// <https://datatracker.ietf.org/doc/html/draft-chung-ccwg-search-09>
#[derive(Debug)]
pub struct Search {
    /// The circular array used to track acked bytes per bin.
    acked_bins: [usize; Self::NUM_ACKED_BINS],
    /// The circular array used to track sent bytes per bin.
    sent_bins: [usize; Self::NUM_SENT_BINS],
    /// The current index of the circular array. `None` if uninitialized.
    curr_idx: Option<usize>,
    /// Time at which the current bin will be passed and the next should start.
    bin_end: Option<Instant>,
    /// The duration of each bin.
    bin_duration: Duration,
    /// Tracking amount of acked bytes this connection. Is incremented on every ACK.
    acked_bytes: usize,
    /// Tracking amount of sent bytes this connection. Is incremented each sent packet.
    sent_bytes: usize,
}

impl Display for Search {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SEARCH")
    }
}

impl Search {
    /// Numerator of the factor for calculating the window size with the initial RTT (= 3.5).
    const WINDOW_SIZE_FACTOR_NUM: u32 = 35;
    /// Denominator of the factor for calculating the window size with the initial RTT (= 3.5).
    const WINDOW_SIZE_FACTOR_DEN: u32 = 10;
    /// Number of bins per window.
    const W: usize = 10;
    /// Additional bins needed to allow lookback by the current RTT for getting previously sent
    /// bytes, even if the RTT has increased since the initial RTT was used to set values.
    const EXTRA_BINS: usize = 15;
    /// Total number of bins in the circular buffer for acked bytes.
    const NUM_ACKED_BINS: usize = Self::W + 1;
    /// Total number of bins in the circular buffer for sent bytes.
    const NUM_SENT_BINS: usize = Self::NUM_ACKED_BINS + Self::EXTRA_BINS;
    /// Scale factor for integer approximations of fractional values (e.g. `THRESH`).
    const SCALE: usize = 100;
    /// The upper bound for the permissible normalized difference between previously sent bytes and
    /// current delivered bytes, as an integer out of `SCALE` (= 0.26).
    const THRESH: usize = 26;

    /// Creates a new SEARCH slow start instance.
    pub const fn new() -> Self {
        Self {
            acked_bins: [0; Self::NUM_ACKED_BINS],
            sent_bins: [0; Self::NUM_SENT_BINS],
            curr_idx: None,
            bin_end: None,
            bin_duration: Duration::from_millis(0),
            acked_bytes: 0,
            sent_bytes: 0,
        }
    }

    /// Initializes SEARCH state on the first ACK using the measured RTT.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "casting small constant usize to u32 for use in Duration::div"
    )]
    fn initialize(&mut self, initial_rtt: Duration, now: Instant) {
        // BIN_DURATION = WINDOW_SIZE / W = initial_rtt * WINDOW_SIZE_FACTOR / W
        self.bin_duration = initial_rtt * Self::WINDOW_SIZE_FACTOR_NUM
            / (Self::WINDOW_SIZE_FACTOR_DEN * Self::W as u32);
        self.bin_end = Some(now + self.bin_duration);
        self.curr_idx = Some(0);
        self.acked_bins[0] = self.acked_bytes;
        self.sent_bins[0] = self.sent_bytes;
    }

    /// Advances bin state when a bin boundary has been crossed.
    ///
    /// Returns the new bin index, or `None` if bins couldn't be updated.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "casting small usize to u32 for use in Duration::saturating_mul"
    )]
    fn update_bins(&mut self, now: Instant) -> Option<usize> {
        let mut curr_idx = self.curr_idx?;
        let mut bin_end = self.bin_end?;

        // passed_bins = (now - bin_end) / bin_duration + 1 -- integer division floors implicitly
        let passed_bins = (now.saturating_duration_since(bin_end).as_nanos()
            / self.bin_duration.as_nanos()
            + 1) as usize;

        // Reset if more than a full window of bins was skipped (e.g., app-limited or
        // flow-control-limited). The bin data is too stale for meaningful SEARCH detection.
        if passed_bins > Self::W {
            qdebug!(
                "SEARCH: update_bins: resetting because skipped {passed_bins} bins (limit {})",
                Self::W
            );
            self.reset();
            return None;
        }

        // For skipped bins propagate the previous bin value (usually `passed_bins` is just `1`, so
        // this doesn't run)
        for i in curr_idx + 1..curr_idx + passed_bins {
            self.acked_bins[i % Self::NUM_ACKED_BINS] =
                self.acked_bins[curr_idx % Self::NUM_ACKED_BINS];
            self.sent_bins[i % Self::NUM_SENT_BINS] =
                self.sent_bins[curr_idx % Self::NUM_SENT_BINS];
        }

        // Update the index and bin end
        curr_idx += passed_bins;
        bin_end += self.bin_duration.saturating_mul(passed_bins as u32);
        self.curr_idx = Some(curr_idx);
        self.bin_end = Some(bin_end);

        // NOTE: SEARCH suggests bit-shifting the values tracked in bins to keep a smaller memory
        // footprint. I suggest not taking on this extra complexity unless it can be seen as
        // impactful in profiles. That logic could potentially be sitting here.

        self.acked_bins[curr_idx % Self::NUM_ACKED_BINS] = self.acked_bytes;
        self.sent_bins[curr_idx % Self::NUM_SENT_BINS] = self.sent_bytes;
        Some(curr_idx)
    }

    /// Computes delivered bytes between two bin indices.
    const fn compute_delv(&self, old: usize, new: usize) -> usize {
        self.acked_bins[new % Self::NUM_ACKED_BINS]
            .saturating_sub(self.acked_bins[old % Self::NUM_ACKED_BINS])
    }

    /// Computes sent bytes between two (previous) bin indices. Interpolates a fraction of each bin
    /// on the ends to get the accurate value when actual previous timestamp is between two
    /// bins.
    const fn compute_sent(&self, old: usize, new: usize, fraction: usize) -> usize {
        let mut sent = (self.sent_bins[(new - 1) % Self::NUM_SENT_BINS]
            .saturating_sub(self.sent_bins[(old - 1) % Self::NUM_SENT_BINS]))
            * fraction;
        sent += (self.sent_bins[new % Self::NUM_SENT_BINS]
            .saturating_sub(self.sent_bins[old % Self::NUM_SENT_BINS]))
            * (Self::SCALE - fraction);
        sent / Self::SCALE
    }
}

impl SlowStart for Search {
    fn on_packets_acked(
        &mut self,
        rtt_est: &RttEstimate,
        _largest_acked: packet::Number,
        new_acked_bytes: usize,
        curr_cwnd: usize,
        _cc_stats: &mut CongestionControlStats,
        now: Instant,
    ) -> Option<usize> {
        let rtt = rtt_est.latest_rtt();
        // Store delivered bytes on every ACK
        self.acked_bytes += new_acked_bytes;

        // Initialize on first ACK.
        if self.curr_idx.is_none() {
            self.initialize(rtt, now);
        }

        // Early return if we haven't passed the current bin.
        if let Some(bin_end) = self.bin_end
            && now <= bin_end
        {
            qdebug!("SEARCH: on_packets_acked: haven't reached current bin_end");
            return None;
        }

        let curr_idx = self.update_bins(now)?;

        // Compute how many bins fit in the current RTT (integer quotient = floor), and the
        // fractional remainder scaled to 0..SCALE for interpolation in compute_sent.
        let rtt_nanos = rtt.as_nanos();
        let bin_nanos = self.bin_duration.as_nanos();
        let bins_last_rtt = (rtt_nanos / bin_nanos) as usize;
        let prev_idx = curr_idx.saturating_sub(bins_last_rtt);

        qdebug!("SEARCH: on_packets_acked: prev_idx {prev_idx} curr_idx {curr_idx}");
        // Early return if we don't have enough data for a SEARCH check.
        if prev_idx <= Self::W || curr_idx - prev_idx >= Self::EXTRA_BINS {
            qdebug!("SEARCH: on_packets_acked: not enough data for SEARCH check");
            return None;
        }
        let fraction = ((rtt_nanos % bin_nanos) * Self::SCALE as u128 / bin_nanos) as usize;

        let curr_delv = self.compute_delv(curr_idx - Self::W, curr_idx);
        let prev_sent = self.compute_sent(prev_idx - Self::W, prev_idx, fraction);
        qdebug!("SEARCH: on_packets_acked: curr_delv {curr_delv} prev_sent {prev_sent}");
        if prev_sent == 0 {
            return None;
        }
        let diff = prev_sent.saturating_sub(curr_delv);
        let norm_diff = diff * Self::SCALE / prev_sent;

        if norm_diff < Self::THRESH {
            qdebug!(
                "SEARCH: on_packets_acked: norm_diff {norm_diff} < THRESH {} --> continue",
                Self::THRESH
            );
            return None;
        }
        qdebug!(
            "SEARCH: on_packets_acked: norm_diff {norm_diff} >= THRESH {} --> exit",
            Self::THRESH
        );
        Some(curr_cwnd)
    }

    fn on_packet_sent(&mut self, _sent_pn: packet::Number, sent_bytes: usize) {
        self.sent_bytes += sent_bytes;
    }

    fn reset(&mut self) {
        self.curr_idx = None;
    }
}
