// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! CUBIC congestion control

use std::{
    fmt::{self, Display},
    time::{Duration, Instant},
};

use neqo_common::qtrace;

use crate::cc::classic_cc::WindowAdjustment;

/// > Constant that determines the aggressiveness of CUBIC in competing with other congestion
/// > control algorithms in high-BDP networks.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// See section 5.1 of RFC9438 for discussion on how to set the concrete value:
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-fairness-to-reno>
pub const CUBIC_C: f64 = 0.4;
/// TCP-friendly region additive factor
///
/// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
pub const CUBIC_ALPHA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7);

/// `CUBIC_BETA` = 0.7;
///
/// > Principle 4: To balance between the scalability and convergence speed,
/// > CUBIC sets the multiplicative window decrease factor to 0.7 while Standard
/// > TCP uses 0.5.  While this improves the scalability of CUBIC, a side effect
/// > of this decision is slower convergence, especially under low statistical
/// > multiplexing environments.
///
/// <https://datatracker.ietf.org/doc/html/rfc8312#section-3>
pub const CUBIC_BETA_USIZE_DIVIDEND: usize = 7;
pub const CUBIC_BETA_USIZE_DIVISOR: usize = 10;

/// The fast convergence ratio further reduces the congestion window when a
/// congestion event occurs before reaching the previous `W_max`.
///
/// See formula defined below.
///
/// <https://www.rfc-editor.org/rfc/rfc8312#section-4.6>
pub const CUBIC_FAST_CONVERGENCE: f64 = 0.85; // (1.0 + CUBIC_BETA) / 2.0;

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
    /// Maximum Window size two congestion events ago.
    ///
    /// > With fast convergence, when a congestion event occurs, before the
    /// > window reduction of the congestion window, a flow remembers the last
    /// > value of W_max before it updates W_max for the current congestion
    /// > event.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.6>
    last_max_cwnd: f64,
    /// > An estimate for the congestion window \[...\] in the Reno-friendly region -- that
    /// > is, an estimate for the congestion window of Reno.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// > Reno performs well in certain types of networks -- for example, under short RTTs and
    /// > small bandwidths (or small BDPs). In these networks, CUBIC remains in the Reno-friendly
    /// > region to achieve at least the same throughput as Reno.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-reno-friendly-region>
    w_est: f64,
    /// > The time period in seconds it takes to increase the congestion window size
    /// > at the beginning of the current congestion avoidance stage to `w_max`.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// Formula:
    ///
    /// `k = cubic_root((w_max - cwnd_epoch) / C)`
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-window-increase-function>
    k: f64,
    /// > W_max is the window size just before the window is reduced in the last
    /// > congestion event.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.1>
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
            "Cubic [last_max_cwnd: {}, k: {}, w_max: {}, t_epoch: {:?}]",
            self.last_max_cwnd, self.k, self.w_max, self.t_epoch
        )?;
        Ok(())
    }
}

#[expect(clippy::doc_markdown, reason = "Not doc items; names from RFC.")]
impl Cubic {
    /// Original equation is:
    ///
    /// `k = cubic_root((w_max - cwnd_epoch)/C)`
    ///
    /// with `cwnd_epoch` being the congestion window at the start of the current congestion
    /// avoidance stage (so at time `t_epoch`).
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#figure-2>
    ///
    /// Taking into account that neqo is using bytes but the formula assumes segments for both
    /// `w_max` and `cwnd_epoch` it becomes:
    ///
    /// `k = cubic_root((w_max - cwnd_epoch)/SMSS/C)`
    fn calc_k(&self, cwnd_epoch: f64, max_datagram_size_f64: f64) -> f64 {
        ((self.w_max - cwnd_epoch) / max_datagram_size_f64 / CUBIC_C).cbrt()
    }

    /// `w_cubic(t) = C*(t-K)^3 + w_max`
    ///
    /// with `t = t_current - t_epoch`.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#figure-1>
    ///
    /// Taking into account that neqo is using bytes and the formula returns segments and that
    /// `w_max` already is in bytes the formula becomes:
    ///
    /// `w_cubic(t) = (C*(t-K)^3) * SMSS + w_max`
    fn w_cubic(&self, t: f64, max_datagram_size_f64: f64) -> f64 {
        (CUBIC_C * (t - self.k).powi(3)).mul_add(max_datagram_size_f64, self.w_max)
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
        curr_cwnd_f64: f64,
        new_acked_f64: f64,
        max_datagram_size_f64: f64,
        now: Instant,
    ) {
        self.t_epoch = Some(now);
        // reset tcp_acked_bytes and w_est;
        self.tcp_acked_bytes = new_acked_f64;
        self.w_est = curr_cwnd_f64;
        // If `w_max < cwnd_epoch` we take the cubic root from a negative value in `calc_k()`. That
        // could only happen if somehow `cwnd` get's increased between calling `reduce_cwnd()` and
        // `start_epoch()`, which is only possible after persistent congestion or an app limited
        // period. It could also happen if we never had a congestion event, so never called
        // `reduce_cwnd()` thus `w_max` was never set (so is still it's default `0.0`
        // value). In any case we reset/initialize `w_max`, `cwnd_prior` and `k` here.
        if self.last_max_cwnd <= curr_cwnd_f64 {
            self.w_max = curr_cwnd_f64;
            self.k = 0.0;
        } else {
            self.w_max = self.last_max_cwnd;
            self.k = self.calc_k(curr_cwnd_f64, max_datagram_size_f64);
        }
        qtrace!("[{self}] New epoch");
    }

    #[cfg(test)]
    pub const fn last_max_cwnd(&self) -> f64 {
        self.last_max_cwnd
    }

    #[cfg(test)]
    pub fn set_last_max_cwnd(&mut self, last_max_cwnd: f64) {
        self.last_max_cwnd = last_max_cwnd;
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
        let max_datagram_size_f64 = convert_to_f64(max_datagram_size);
        let new_acked_f64 = convert_to_f64(new_acked_bytes);
        let t_epoch = self.t_epoch.unwrap_or_else(|| {
            // If we get here with `self.t_epoch == None` this is a new congestion avoidance stage.
            // It's been set to `None` by [`super::ClassicCongestionControl::reduce_cwnd`] or
            // needs to be initialized after slow start. It could also have been reset by
            // [`super::ClassicCongestionControl::on_app_limited`] in which case we also start a new
            // congestion avoidance stage for the purpose of resetting timing as per RFC 9438
            // section 5.8.
            //
            // <https://datatracker.ietf.org/doc/html/rfc9438#app-limited>
            self.start_epoch(curr_cwnd_f64, new_acked_f64, max_datagram_size_f64, now);
            now
        });
        if self.t_epoch.is_some() {
            self.tcp_acked_bytes += new_acked_f64;
        }

        // Calculate `target` for the concave or convex region
        //
        // > Upon receiving a new ACK during congestion avoidance, CUBIC computes the target
        // > congestion window size after the next RTT [...], where RTT is the
        // > smoothed round-trip time. The lower and upper bounds below ensure that CUBIC's
        // > congestion window increase rate is non-decreasing and is less than the increase rate of
        // > slow start.
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.2-10>
        //
        // In neqo target is in bytes.
        let t = now.saturating_duration_since(t_epoch);
        // cwnd <= target <= cwnd * 1.5
        let mut target = f64::clamp(
            self.w_cubic((t + min_rtt).as_secs_f64(), max_datagram_size_f64),
            curr_cwnd_f64,
            curr_cwnd_f64 * 1.5,
        );

        // Cubic TCP-friendly region
        //
        //  <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
        let max_datagram_size = convert_to_f64(max_datagram_size);
        let tcp_cnt = self.w_est / CUBIC_ALPHA;
        let incr = (self.tcp_acked_bytes / tcp_cnt).floor();
        if incr > 0.0 {
            self.tcp_acked_bytes -= incr * tcp_cnt;
            self.w_est += incr * max_datagram_size;
        }

        // > When receiving a new ACK in congestion avoidance (where cwnd could be greater than
        // > or less than w_max), CUBIC checks whether W_cubic(t) is less than w_est.  If so, CUBIC
        // > is in the Reno-friendly region and cwnd SHOULD be set to w_est at each reception of a
        // > new ACK.
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.3-8>
        //
        // While the RFC specifies that we should compare W_cubic(t) with w_est we are rather
        // comparing the previously calculated target here, since that is the value that would
        // actually be used when deciding whether it's the cubic region.
        //
        // That is in line with what e.g. the Linux Kernel CUBIC implementation is doing.
        if target < self.w_est {
            // Reno-friendly region sets cwnd = w_est
            target = self.w_est;
        }

        let cwnd_increase = target - curr_cwnd_f64;

        // Calculate the number of bytes that would need to be acknowledged for an increase
        // of `max_datagram_size` to match `cwnd_increase`, that is the increase from the current
        // congestion window to `target`.
        // The amount of acked data required therefore reduces asymptotically as the target
        // increases.
        //
        // RFC 9438 tells us to increase cwnd by `cwnd_increase/cwnd` which would amount to the
        // increase in segments per congestion window acked.
        // (https://datatracker.ietf.org/doc/html/rfc9438#section-4.4-2.1)
        //
        // Since we want to know how much we need to ack to increase by 1 segment we need the
        // inverse of that, which would be `cwnd/cwnd_increase`.
        // (E.g. if we'd increase by `1/4 * mss` per cwnd acked then we need to ack `4 * cwnd` to
        // increase by `1 * mss`)
        //
        // The RFC only applies this increase per acked cwnd to the Cubic (concave/convex) region.
        // We also apply it to the Reno region, as that is what the Linux Kernel CUBIC
        // implementation does, too.
        //
        // We multiply by 1*mss as our `curr_cwnd_f64` value is in bytes.
        (max_datagram_size_f64 * curr_cwnd_f64 / cwnd_increase) as usize
    }

    fn reduce_cwnd(
        &mut self,
        curr_cwnd: usize,
        acked_bytes: usize,
        max_datagram_size: usize,
    ) -> (usize, usize) {
        let curr_cwnd_f64 = convert_to_f64(curr_cwnd);
        // Fast Convergence
        //
        // If congestion event occurs before the maximum congestion window before the last
        // congestion event, we reduce the the maximum congestion window and thereby W_max.
        // check cwnd + MAX_DATAGRAM_SIZE instead of cwnd because with cwnd in bytes, cwnd may be
        // slightly off.
        //
        // <https://www.rfc-editor.org/rfc/rfc8312#section-4.6>
        self.last_max_cwnd =
            if curr_cwnd_f64 + convert_to_f64(max_datagram_size) < self.last_max_cwnd {
                curr_cwnd_f64 * CUBIC_FAST_CONVERGENCE
            } else {
                curr_cwnd_f64
            };
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
