// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
//! Slow start Exit At Right CHokepoint (SEARCH) implementation as per
//! <https://datatracker.ietf.org/doc/html/draft-chung-ccwg-search-09>

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
    /// Tracking amount of acked bytes on this connection. Is incremented on every ACK.
    acked_bytes: usize,
    /// Tracking amount of sent bytes on this connection. Is incremented on every sent packet.
    sent_bytes: usize,
}

impl Display for Search {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SEARCH")
    }
}

impl Search {
    /// Factor for calculating the window size with the initial RTT, as an integer
    /// out of [`Self::SCALE`] (= 3.50).
    const WINDOW_SIZE_FACTOR: u32 = 350;
    /// Number of bins per window.
    const W: usize = 10;
    /// Additional bins needed to allow lookback by the current RTT for getting previously sent
    /// bytes.
    ///
    /// A higher value allows for a bigger difference between `curr_idx` and `prev_idx`, which
    /// allows for bigger RTT inflation before SEARCH stops working.
    const EXTRA_BINS: usize = 15;
    /// Total number of bins in the circular buffer for acked bytes. Needs an extra index so the
    /// buffer can accommodate the whole range of `[i - W, i]`.
    const NUM_ACKED_BINS: usize = Self::W + 1;
    /// Total number of bins in the circular buffer for sent bytes.
    const NUM_SENT_BINS: usize = Self::NUM_ACKED_BINS + Self::EXTRA_BINS;
    /// The upper bound for the permissible normalized difference between previously sent bytes and
    /// current delivered bytes, as an integer out of [`Self::SCALE`] (= 0.26).
    const THRESH: usize = 26;
    /// Scale factor for integer approximation of fractional values.
    const SCALE: usize = 100;

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
        self.bin_duration =
            initial_rtt * Self::WINDOW_SIZE_FACTOR / Self::SCALE as u32 / Self::W as u32;
        if self.bin_duration.is_zero() {
            qdebug!(
                "skipping initialization because bin_duration.is_zero() but bin_duration must be non-zero - initial_rtt: {initial_rtt:?}",
            );
            debug_assert!(
                false,
                "bin_duration must be non-zero for correctness and to guard against div by zero -- initial_rtt was zero or too small"
            );
            return;
        }
        self.bin_end = Some(now + self.bin_duration);
        self.acked_bins[0] = self.acked_bytes;
        self.sent_bins[0] = self.sent_bytes;
        self.curr_idx = Some(0);
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
        let passed_bins = usize::try_from(
            now.saturating_duration_since(bin_end).as_nanos() / self.bin_duration.as_nanos() + 1,
        )
        .unwrap_or(usize::MAX);

        // Reset if more than a full window of bins was skipped (e.g. after being app-limited or
        // flow-control-limited). The bin data is too stale for meaningful SEARCH detection.
        //
        // NOTE: SEARCH draft-09 doesn't implement a reset mechanism for stale data anymore but
        // makes it optional instead. I think it makes sense, especially because it can also happen
        // if the sender is app-limited for a longer period of time, in which case both the data in
        // the bins, as well as the initial RTT value might not be representative anymore due to
        // path changes.
        //
        // <https://datatracker.ietf.org/doc/html/draft-chung-ccwg-search-09#name-handling-missed-bins-option>
        if passed_bins > Self::W {
            qdebug!(
                "SEARCH: update_bins: resetting because we skipped {passed_bins} bins (limit {})",
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

        // NOTE: SEARCH draft-09 suggests bit-shifting the values tracked in bins to keep a smaller
        // memory footprint for memory constrained devices at the cost of running some
        // additional computations roughly once per RTT. I suggest not taking on this extra
        // complexity for a minor memory saving (255 bytes going from `usize` to `u16` with
        // `EXTRA_BINS = 15`). That logic could be in this place, if implemented.

        self.acked_bins[curr_idx % Self::NUM_ACKED_BINS] = self.acked_bytes;
        self.sent_bins[curr_idx % Self::NUM_SENT_BINS] = self.sent_bytes;
        Some(curr_idx)
    }

    /// Computes the previous index one RTT ago and the remaining fraction if the previous index
    /// doesn't exactly land on a bin boundary.
    ///
    /// Returns `prev_idx` and `fraction` scaled to `0..[Self::SCALE]`. The `fraction` is returned
    /// as a `u64` because it will be used as such in [`Self::compute_sent`] to avoid `usize`
    /// saturation on 32-bit systems with large bandwidths.
    fn calc_prev_idx(&self, rtt: Duration, curr_idx: usize) -> (usize, u64) {
        let rtt_nanos = rtt.as_nanos();
        let bin_nanos = self.bin_duration.as_nanos();
        let bins_last_rtt = usize::try_from(rtt_nanos / bin_nanos).unwrap_or(usize::MAX);
        let prev_idx = curr_idx.saturating_sub(bins_last_rtt);
        let fraction =
            u64::try_from((rtt_nanos % bin_nanos) * Self::SCALE as u128 / bin_nanos).unwrap_or(0);

        (prev_idx, fraction)
    }

    /// Computes delivered bytes between two bin indices. Widens the result to `u64` to avoid
    /// saturation or overflow further down the line on 32-bit systems with large bandwidths.
    const fn compute_delv(&self, old: usize, new: usize) -> u64 {
        self.acked_bins[new % Self::NUM_ACKED_BINS]
            .saturating_sub(self.acked_bins[old % Self::NUM_ACKED_BINS]) as u64
    }

    /// Computes sent bytes between two (previous) bin indices. Interpolates a fraction of each bin
    /// on the ends to get the accurate value when the actual previous timestamp is between two
    /// bins. The fraction is an integer out of [`Self::SCALE`], i.e. a value between `0` and `99`.
    /// Widens intermittent results and returns `u64` to avoid saturation or overflow on 32-bit
    /// systems with large bandwidths.
    const fn compute_sent(&self, old: usize, new: usize, fraction: u64) -> u64 {
        // NOTE: SEARCH draft-09 does forward interpolation here, i.e. `new + 1`/`old + 1`. That is
        // a mistake in the draft and has been discussed with the SEARCH team. Subtracting
        // is correct.
        let low_idx = (self.sent_bins[(new - 1) % Self::NUM_SENT_BINS]
            .saturating_sub(self.sent_bins[(old - 1) % Self::NUM_SENT_BINS]))
            as u64;
        let high_idx = (self.sent_bins[new % Self::NUM_SENT_BINS]
            .saturating_sub(self.sent_bins[old % Self::NUM_SENT_BINS]))
            as u64;
        let sent = low_idx * fraction + high_idx * (Self::SCALE as u64 - fraction);
        sent / Self::SCALE as u64
    }

    #[cfg(test)]
    pub const fn curr_idx(&self) -> Option<usize> {
        self.curr_idx
    }

    #[cfg(test)]
    pub const fn bin_end(&self) -> Option<Instant> {
        self.bin_end
    }

    #[cfg(test)]
    pub const fn bin_duration(&self) -> Duration {
        self.bin_duration
    }

    #[cfg(test)]
    pub const fn acked_bin(&self, idx: usize) -> usize {
        self.acked_bins[idx % Self::NUM_ACKED_BINS]
    }

    #[cfg(test)]
    pub const fn sent_bin(&self, idx: usize) -> usize {
        self.sent_bins[idx % Self::NUM_SENT_BINS]
    }

    /// Re-exports the internal `calc_prev_idx` function for use in tests.
    #[cfg(test)]
    pub fn calc_prev_idx_test(&self, rtt: Duration, curr_idx: usize) -> (usize, u64) {
        self.calc_prev_idx(rtt, curr_idx)
    }

    /// Re-exports the internal `compute_sent` function for use in tests.
    #[cfg(test)]
    pub const fn compute_sent_test(&self, old: usize, new: usize, fraction: u64) -> u64 {
        self.compute_sent(old, new, fraction)
    }

    /// Re-exports the internal `compute_delv` function for use in tests.
    #[cfg(test)]
    pub const fn compute_delv_test(&self, old: usize, new: usize) -> u64 {
        self.compute_delv(old, new)
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
        self.acked_bytes = self.acked_bytes.saturating_add(new_acked_bytes);

        // Initialize on first ACK.
        if self.curr_idx.is_none() {
            self.initialize(rtt, now);
        }

        // Early return if we haven't passed the current bin. There is no new data to check.
        if let Some(bin_end) = self.bin_end
            && now <= bin_end
        {
            qdebug!("SEARCH: on_packets_acked: haven't reached current bin_end");
            return None;
        }

        let curr_idx = self.update_bins(now)?;

        // Compute how many bins fit in the last RTT. Integer division implicitly floors that value,
        // so `prev_idx` might be too recent by a fraction of a bin. Said fraction is scaled to
        // `0..[Self::SCALE]` for interpolation in `compute_sent`.
        let (prev_idx, fraction) = self.calc_prev_idx(rtt, curr_idx);
        qdebug!(
            "SEARCH: on_packets_acked: prev_idx {prev_idx} curr_idx {curr_idx} fraction {fraction}"
        );

        // Early return if we don't have enough data for a SEARCH check. This could be either
        // because there isn't enough data to look back by an RTT if we're early in the connection,
        // or because the difference between `curr_idx` and `prev_idx` is too big because of RTT
        // inflation. In the latter case we don't have data to look back far enough and SEARCH stops
        // working.
        if prev_idx <= Self::W || curr_idx - prev_idx >= Self::EXTRA_BINS {
            qdebug!("SEARCH: on_packets_acked: not enough data for SEARCH check");
            return None;
        }

        let curr_delv = self.compute_delv(curr_idx - Self::W, curr_idx);
        let prev_sent = self.compute_sent(prev_idx - Self::W, prev_idx, fraction);
        qdebug!("SEARCH: on_packets_acked: curr_delv {curr_delv} prev_sent {prev_sent}");

        // Avoid division by zero if we haven't sent anything.
        if prev_sent == 0 {
            return None;
        }
        let diff = prev_sent.saturating_sub(curr_delv);
        let norm_diff =
            usize::try_from(diff * Self::SCALE as u64 / prev_sent).unwrap_or(usize::MAX);

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
        // If SEARCH checks run and the normative difference is not beneath the threshold we return
        // the current congestion window to exit slow start with it at the call site.
        //
        // NOTE: SEARCH draft-09 implements a drain-phase to gradually lower the congestion window
        // towards the approximated empty-buffer BDP. I think that could be counter-intuitive while
        // using CUBIC in our case, as CUBIC tries to keep the buffers full and ideally we'd land
        // somewhere in CUBIC's cwnd-range after slow start. The drain-phase as implemented in
        // draft-09 undershoots CUBIC's cwnd range in my testing.
        //
        // For now I recommend just exiting slow start without the drain-phase and capturing the
        // drain-target in telemetry for further analysis (TODO).
        //
        // <https://datatracker.ietf.org/doc/html/draft-chung-ccwg-search-09#section-3.2-17>
        Some(curr_cwnd)
    }

    fn on_packet_sent(&mut self, _sent_pn: packet::Number, sent_bytes: usize) {
        self.sent_bytes = self.sent_bytes.saturating_add(sent_bytes);
    }

    fn reset(&mut self) {
        // `curr_idx.is_none()` triggers re-initialization on the next ACK, which overwrites all
        // other relevant fields with fresh data. The cumulative byte counters have to be reset
        // seperately so they can still grow while waiting for the first ACK after the reset.
        self.curr_idx = None;
        self.acked_bytes = 0;
        self.sent_bytes = 0;
    }
}
