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
    ops::{Add as _, Div as _},
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
    bin_end: Instant,
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
    /// Factor for calculating the window size with the initial RTT.
    const WINDOW_SIZE_FACTOR: f64 = 3.5;
    /// Number of bins per window.
    const W: usize = 10;
    /// Additional bins needed to allow lookback by the current RTT for getting previously sent
    /// bytes, even if the RTT has increased since the initial RTT was used to set values.
    const EXTRA_BINS: usize = 15;
    /// Total number of bins in the circular buffer for acked bytes.
    const NUM_ACKED_BINS: usize = Self::W + 1;
    /// Total number of bins in the circular buffer for sent bytes.
    const NUM_SENT_BINS: usize = Self::NUM_ACKED_BINS + Self::EXTRA_BINS;
    /// The upper bound for the permissible normalized difference between previously sent bytes and
    /// current delivered bytes.
    const THRESH: f64 = 0.26;

    /// Creates a new SEARCH slow start instance.
    pub fn new() -> Self {
        Self {
            acked_bins: [0; Self::NUM_ACKED_BINS],
            sent_bins: [0; Self::NUM_SENT_BINS],
            curr_idx: None,
            bin_end: Instant::now(),
            bin_duration: Duration::from_millis(0),
            acked_bytes: 0,
            sent_bytes: 0,
        }
    }

    /// Initializes SEARCH state on the first ACK using the measured RTT.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "casting small constant usize to u32 for use in function"
    )]
    fn initialize(&mut self, initial_rtt: Duration, now: Instant) {
        // BIN_DURATION = WINDOW_SIZE / W = initial_rtt * WINDOW_SIZE_FACTOR / W
        self.bin_duration = initial_rtt
            .mul_f64(Self::WINDOW_SIZE_FACTOR)
            .div(Self::W as u32);
        self.bin_end = now + self.bin_duration;
        self.curr_idx = Some(0);
        self.acked_bins[0] = self.acked_bytes;
        self.sent_bins[0] = self.sent_bytes;
    }

    /// Advances bin state when a bin boundary has been crossed.
    ///
    /// Returns the new bin index, or `None` if bins couldn't be updated.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "casting small usize to u32 for use in a function"
    )]
    #[expect(
        clippy::cast_sign_loss,
        reason = "casting positive f64 to usize after flooring"
    )]
    fn update_bins(&mut self, now: Instant) -> Option<usize> {
        let mut curr_idx = self.curr_idx?;

        // passed_bins = (now - bin_end) / bin_duration + 1 -- we floor the division result to a
        // usize value
        let passed_bins = now
            .saturating_duration_since(self.bin_end)
            .div_duration_f64(self.bin_duration)
            .floor()
            .add(1.0) as usize;

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
        self.curr_idx = Some(curr_idx);
        self.bin_end += self.bin_duration.saturating_mul(passed_bins as u32);

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
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "casting usize to f64 and back to do f64 math"
    )]
    fn compute_sent(&self, old: usize, new: usize, fraction: f64) -> usize {
        let backward = self.sent_bins[(new - 1) % Self::NUM_SENT_BINS]
            .saturating_sub(self.sent_bins[(old - 1) % Self::NUM_SENT_BINS])
            as f64;

        // For testing -- the draft actually has forward interpolation instead of backwards, but
        // backwards makes sense logically.
        let _forward = self.sent_bins[(new + 1) % Self::NUM_SENT_BINS]
            .saturating_sub(self.sent_bins[(old + 1) % Self::NUM_SENT_BINS])
            as f64;

        let base = self.sent_bins[new % Self::NUM_SENT_BINS]
            .saturating_sub(self.sent_bins[old % Self::NUM_SENT_BINS]) as f64;

        backward.mul_add(fraction, base * (1.0 - fraction)) as usize
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
        if now <= self.bin_end {
            qdebug!("SEARCH: on_packets_acked: haven't reached current bin_end");
            return None;
        }

        let curr_idx = self.update_bins(now)?;

        // Floor the previous index value. If we have enough data for a SEARCH check we will
        // calculate the fraction remainder later to then interpolate when calculating the
        // previously sent bytes.
        let bins_last_rtt = rtt.div_duration_f64(self.bin_duration);
        #[expect(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "casting small positive f64 to usize"
        )]
        let prev_idx = curr_idx.saturating_sub(bins_last_rtt.floor() as usize);

        qdebug!("SEARCH: on_packets_acked: prev_idx {prev_idx} curr_idx {curr_idx}");
        // Early return if we don't have enough data for a SEARCH check.
        if prev_idx <= Self::W || curr_idx - prev_idx >= Self::EXTRA_BINS {
            qdebug!("SEARCH: on_packets_acked: not enough data for SEARCH check");
            return None;
        }
        let fraction = bins_last_rtt.fract();

        let curr_delv = self.compute_delv(curr_idx - Self::W, curr_idx);
        let prev_sent = self.compute_sent(prev_idx - Self::W, prev_idx, fraction);
        qdebug!("SEARCH: on_packets_acked: curr_delv {curr_delv} prev_sent {prev_sent}");
        if prev_sent == 0 {
            return None;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "casting usize that fits into 2^53 to f64"
        )]
        let norm_diff = (prev_sent.saturating_sub(curr_delv) as f64).div(prev_sent as f64);

        if norm_diff < Self::THRESH {
            qdebug!(
                "SEARCH: on_packets_acked: norm diff {norm_diff} < THRESH {} --> continue",
                Self::THRESH
            );
            return None;
        }
        qdebug!(
            "SEARCH: on_packets_acked: norm diff {norm_diff} > THRESH {} --> exit",
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
