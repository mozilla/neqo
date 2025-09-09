// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! CUBIC congestion control (RFC 9438)

use std::{
    fmt::{self, Display},
    time::{Duration, Instant},
};

use neqo_common::qtrace;

use crate::cc::classic_cc::WindowAdjustment;

/// > C is a constant fixed to determine the aggressiveness of window
/// > increase  in high BDP networks.
///
/// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.1>
///
/// See discussion for rational for concrete value.
///
/// <https://datatracker.ietf.org/doc/html/rfc8312#section-5.1>
pub const CUBIC_C: f64 = 0.4;
/// TCP-friendly region additive factor
///
/// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
pub const CUBIC_ALPHA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7);

/// > CUBIC multiplicative decrease factor
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// > To balance between the scalability and convergence speed, CUBIC sets the multiplicative window
/// > decrease factor to 0.7 while Standard TCP uses 0.5. While this improves the scalability of
/// > CUBIC, a side effect of this decision is slower convergence, especially under low statistical
/// > multiplexing environments.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-principle-4-for-the-cubic-d>
///
/// For implementation reasons neqo uses a dividend and divisor approach with `usize` typing to
/// construct `CUBIC_BETA = 0.7`.
pub const CUBIC_BETA_USIZE_DIVIDEND: usize = 7;
/// > CUBIC multiplicative decrease factor
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// > To balance between the scalability and convergence speed, CUBIC sets the multiplicative window
/// > decrease factor to 0.7 while Standard TCP uses 0.5. While this improves the scalability of
/// > CUBIC, a side effect of this decision is slower convergence, especially under low statistical
/// > multiplexing environments.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-principle-4-for-the-cubic-d>
///
/// For implementation reasons neqo uses a dividend and divisor approach with `usize` typing to
/// construct `CUBIC_BETA = 0.7`
pub const CUBIC_BETA_USIZE_DIVISOR: usize = 10;

/// This is the factor that is used by fast convergence to further reduce the next `W_max` when a
/// congestion event occurs while `cwnd < W_max`. This speeds up the bandwidth release for when a
/// new flow joins the network.
///
/// The calculation assumes `CUBIC_BETA = 0.7`.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-fast-convergence>
pub const CUBIC_FAST_CONVERGENCE_FACTOR: f64 = (1.0 + 0.7) / 2.0;

/// The minimum number of multiples of the datagram size that need
/// to be received to cause an increase in the congestion window.
/// When there is no loss, Cubic can return to exponential increase, but
/// this value reduces the magnitude of the resulting growth by a constant factor.
/// A value of 1.0 would mean a return to the rate used in slow start.
const EXPONENTIAL_GROWTH_REDUCTION: f64 = 2.0;

/// Convert an integer congestion window value into a floating point value.
/// This has the effect of reducing larger values to `1<<53`.
/// If you have a congestion window that large, something is probably wrong.
pub fn convert_to_f64(v: usize) -> f64 {
    let mut f_64 = f64::from(u32::try_from(v >> 21).unwrap_or(u32::MAX));
    f_64 *= 2_097_152.0; // f_64 <<= 21
    #[expect(clippy::cast_possible_truncation, reason = "The mask makes this safe.")]
    let v_trunc = (v & 0x1f_ffff) as u32;
    f_64 += f64::from(v_trunc);
    f_64
}

#[derive(Debug, Default)]
pub struct Cubic {
    /// > Size of cwnd in \[bytes\] at the time of setting `ssthresh` most recently, either upon
    /// > exiting the first slow start or just before `cwnd` was reduced in the last congestion
    /// > event.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#section-4.1.2-2.4>
    cwnd_prior: f64,
    /// Estimate of Standard TCP congestion window for Cubic's TCP-friendly
    /// Region.
    ///
    /// > Standard TCP performs well in certain types of networks, for example,
    /// > under short RTT and small bandwidth (or small BDP) networks.  In
    /// > these networks, we use the TCP-friendly region to ensure that CUBIC
    /// > achieves at least the same throughput as Standard TCP.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
    estimated_tcp_cwnd: f64,
    /// > K is the time period that the above function takes to increase the
    /// > current window size to W_max if there are no further congestion events
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.1>
    k: f64,
    /// > Size of `cwnd` in \[bytes\] just before `cwnd` was reduced in the last congestion
    /// > event \[...\]. \[With\] fast convergence enabled, `w_max` may be further reduced based on
    /// > the current saturation point.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// `w_max` acts as the plateau for the cubic function where it switches from the concave to
    /// the convex region.
    ///
    /// It is calculated with the following logic:
    ///
    /// ```pseudo
    /// if (w_max > cwnd) {
    ///     w_max = cwnd * FAST_CONVERGENCE_FACTOR;
    /// } else {
    ///     w_max = cwnd;
    /// }
    /// ```
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-fast-convergence>
    w_max: f64,
    /// > The time in seconds at which the current congestion avoidance stage started.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// This also is reset on being application limited
    t_epoch: Option<Instant>,
    /// Number of bytes acked since the last Standard TCP congestion window increase.
    tcp_acked_bytes: f64,
}

impl Display for Cubic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Cubic [w_max: {}, k: {}, cwnd_prior: {}, t_epoch: {:?}]",
            self.w_max, self.k, self.cwnd_prior, self.t_epoch
        )?;
        Ok(())
    }
}

#[expect(clippy::doc_markdown, reason = "Not doc items; names from RFC.")]
impl Cubic {
    /// Original equations is:
    /// K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2 RFC8312)
    /// W_max is number of segments of the maximum segment size (MSS).
    ///
    /// K is actually the time that W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1) would
    /// take to increase to W_max. We use bytes not MSS units, therefore this
    /// equation will be: W_cubic(t) = C*MSS*(t-K)^3 + W_max.
    ///
    /// From that equation we can calculate K as:
    /// K = cubic_root((W_max - W_cubic) / C / MSS);
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8312#section-4.1>
    fn calc_k(&self, curr_cwnd: f64, max_datagram_size: f64) -> f64 {
        ((self.w_max - curr_cwnd) / CUBIC_C / max_datagram_size).cbrt()
    }

    /// W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
    /// t is relative to the start of the congestion avoidance phase and it is in seconds.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8312#section-4.1>
    fn w_cubic(&self, t: f64, max_datagram_size: f64) -> f64 {
        (CUBIC_C * (t - self.k).powi(3)).mul_add(max_datagram_size, self.w_max)
    }

    /// Resets all relevant parameters at the start of a new epoch (new congestion
    /// avoidance stage) according to RFC 9438. The `w_max` variable is set in `reduce_cwnd()`. Also
    /// initializes `k` and `w_max` if we start an epoch without having ever had a congestion
    /// event, which can happen upon exiting slow start.
    ///
    /// > `w_est` is set equal to `cwnd_epoch` at the start of the congestion avoidance stage.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#section-4.3-9>
    fn start_epoch(
        &mut self,
        curr_cwnd: f64,
        new_acked: f64,
        max_datagram_size: f64,
        now: Instant,
    ) {
        self.t_epoch = Some(now);
        self.tcp_acked_bytes = new_acked;
        self.estimated_tcp_cwnd = curr_cwnd;
        // If `w_max < cwnd_epoch` we take the cubic root from a negative value in `calc_k()`. That
        // could only happen if somehow `cwnd` get's increased between calling `reduce_cwnd()` and
        // `start_epoch()`, which is only possible after persistent congestion or an app limited
        // period. It could also happen if we never had a congestion event, so never called
        // `reduce_cwnd()` thus `w_max` was never set (so is still it's default `0.0`
        // value). In any case we reset/initialize `w_max`, `cwnd_prior` and `k` here.
        self.k = if self.w_max <= curr_cwnd {
            self.cwnd_prior = curr_cwnd;
            self.w_max = curr_cwnd;
            0.0
        } else {
            self.calc_k(curr_cwnd, max_datagram_size)
        };
        qtrace!("[{self}] New epoch");
    }

    #[cfg(test)]
    pub const fn w_max(&self) -> f64 {
        self.w_max
    }

    #[cfg(test)]
    pub fn set_w_max(&mut self, w_max: f64) {
        self.w_max = w_max;
    }
}

impl WindowAdjustment for Cubic {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Cast from f64 to usize."
    )]
    fn bytes_for_cwnd_increase(
        &mut self,
        curr_cwnd: usize,
        new_acked_bytes: usize,
        min_rtt: Duration,
        max_datagram_size: usize,
        now: Instant,
    ) -> usize {
        let curr_cwnd_f64 = convert_to_f64(curr_cwnd);
        let new_acked_f64 = convert_to_f64(new_acked_bytes);
        let max_datagram_size_f64 = convert_to_f64(max_datagram_size);
        if self.t_epoch.is_none() {
            // This is a start of a new congestion avoidance phase.
            self.start_epoch(curr_cwnd_f64, new_acked_f64, max_datagram_size_f64, now);
        } else {
            self.tcp_acked_bytes += new_acked_f64;
        }

        // Cubic concave or convex region
        //
        // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.3>
        // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.4>
        let time_ca = self
            .t_epoch
            .map_or(min_rtt, |t| {
                if now + min_rtt < t {
                    // This only happens when processing old packets
                    // that were saved and replayed with old timestamps.
                    min_rtt
                } else {
                    now + min_rtt - t
                }
            })
            .as_secs_f64();
        let target_cubic = self.w_cubic(time_ca, max_datagram_size_f64);

        // Cubic TCP-friendly region
        //
        //  <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
        let tcp_cnt = self.estimated_tcp_cwnd / CUBIC_ALPHA;
        let incr = (self.tcp_acked_bytes / tcp_cnt).floor();
        if incr > 0.0 {
            self.tcp_acked_bytes -= incr * tcp_cnt;
            self.estimated_tcp_cwnd += incr * max_datagram_size_f64;
        }

        // Take the larger cwnd of Cubic concave or convex and Cubic
        // TCP-friendly region.
        //
        // > When receiving an ACK in congestion avoidance (cwnd could be
        // > greater than or less than W_max), CUBIC checks whether W_cubic(t) is
        // > less than W_est(t).  If so, CUBIC is in the TCP-friendly region and
        // > cwnd SHOULD be set to W_est(t) at each reception of an ACK.
        //
        // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
        let target_cwnd = target_cubic.max(self.estimated_tcp_cwnd);

        // Calculate the number of bytes that would need to be acknowledged for an increase
        // of `max_datagram_size_f64` to match the increase of `target - cwnd / cwnd` as defined
        // in the specification (Sections 4.4 and 4.5).
        // The amount of data required therefore reduces asymptotically as the target increases.
        // If the target is not significantly higher than the congestion window, require a very
        // large amount of acknowledged data (effectively block increases).
        let mut acked_to_increase =
            max_datagram_size_f64 * curr_cwnd_f64 / (target_cwnd - curr_cwnd_f64).max(1.0);

        // Limit increase to max 1 MSS per EXPONENTIAL_GROWTH_REDUCTION ack packets.
        // This effectively limits target_cwnd to (1 + 1 / EXPONENTIAL_GROWTH_REDUCTION) cwnd.
        acked_to_increase =
            acked_to_increase.max(EXPONENTIAL_GROWTH_REDUCTION * max_datagram_size_f64);
        acked_to_increase as usize
    }

    // CUBIC RFC 9438 changes the logic for multiplicative decrease, most notably setting the
    // minimum congestion window to 1*SMSS under some circumstances while keeping ssthresh at
    // 2*SMSS.
    //
    // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.6>
    //
    // QUIC has a minimum congestion window of 2*SMSS as per RFC 9002.
    //
    // <https://datatracker.ietf.org/doc/html/rfc9002#section-4.8>
    //
    // For that reason we diverge from CUBIC RFC 9438 here retaining the 2*SMSS minimum for the
    // congestion window.
    //
    // This function only returns the value for `cwnd * CUBIC_BETA` and sets some variables for the
    // start of a new congestion avoidance phase. Actually setting the congestion window happens in
    // [`super::ClassicCongestionControl::on_congestion_event`] where this function is called.
    fn reduce_cwnd(
        &mut self,
        curr_cwnd: usize,
        acked_bytes: usize,
        max_datagram_size: usize,
    ) -> (usize, usize) {
        let curr_cwnd_f64 = convert_to_f64(curr_cwnd);
        self.cwnd_prior = curr_cwnd_f64;
        // Fast Convergence
        //
        // > During a congestion event, if the current cwnd is less than w_max, this indicates
        // > that the saturation point experienced by this flow is getting reduced because of
        // > a change in available bandwidth. This flow can then release more bandwidth by
        // > reducing w_max further. This action effectively lengthens the time for this flow
        // > to increase its congestion window, because the reduced w_max forces the flow to
        // > plateau earlier. This allows more time for the new flow to catch up to its
        // > congestion window size.
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#name-fast-convergence>
        //
        // From the old implementation:
        //
        // "Check cwnd + MAX_DATAGRAM_SIZE instead of cwnd because with cwnd in bytes, cwnd may be
        // slightly off."
        self.w_max = if curr_cwnd_f64 + convert_to_f64(max_datagram_size) < self.w_max {
            curr_cwnd_f64 * CUBIC_FAST_CONVERGENCE_FACTOR
        } else {
            curr_cwnd_f64
        };

        // Reducing the congestion window and resetting time
        self.t_epoch = None;
        (
            curr_cwnd * CUBIC_BETA_USIZE_DIVIDEND / CUBIC_BETA_USIZE_DIVISOR,
            acked_bytes * CUBIC_BETA_USIZE_DIVIDEND / CUBIC_BETA_USIZE_DIVISOR,
        )
    }

    fn on_app_limited(&mut self) {
        // Reset t_epoch. Let it start again when the congestion controller
        // exits the app-limited period.
        self.t_epoch = None;
    }
}
