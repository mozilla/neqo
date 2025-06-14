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

/// > Constant that determines the aggressiveness of CUBIC in competing with other congestion
/// > control algorithms in high-BDP networks.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// See section 5.1 of RFC9438 for discussion on how to set the concrete value:
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-fairness-to-reno>
pub const CUBIC_C: f64 = 0.4;

/// > CUBIC additive increase factor used in the Reno-friendly region \[to achieve approximately the
/// > same average congestion window size as Reno\].
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// > The model used to calculate CUBIC_ALPHA is not absolutely precise,
/// > but analysis and simulation \[...\], as well as over a decade of experience with
/// > CUBIC in the public Internet, show that this approach produces acceptable
/// > levels of rate fairness between CUBIC and Reno flows.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-reno-friendly-region>
pub const CUBIC_ALPHA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7); // with CUBIC_BETA = 0.7

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
// TODO: Check use of f64 vs usize here (and in our CCA in general)
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
///
/// UPDATE/TODO: This makes sure we have to ack at least 2 datagrams to increase by 1 MSS, which
/// means we can at most increase cwnd * 1.5 per RTT. That's equivalent for the `target = 1.5 *
/// target` cap in the new RFC.
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
    t_epoch: Option<Instant>,
    /// Number of bytes acked since the last Standard TCP congestion window increase.
    ///
    /// UPDATE: We are using bytes but the spec recommends using segments.
    ///
    /// > Implementations can use bytes to express window sizes, which would require
    /// > factoring in the SMSS wherever necessary and replacing segments_acked (Figure 4)
    /// > with the number of acknowledged bytes.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-definitions>
    ///
    /// ACTIONS: Discuss if we want to switch to segments, confirm we are doing all conversions.
    /// Research why this is prefaced with `tcp_` and clean up docs.
    tcp_acked_bytes: f64,
}

// TODO: Maybe add `cwnd_prior` variable so we can record it here (we recorded last_max_cwnd before,
// but that was removed with RFC 9438)
impl Display for Cubic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Cubic [k: {}, w_max: {}, t_epoch: {:?}]",
            self.k, self.w_max, self.t_epoch
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
    /// Taking into account that we're using bytes not MSS units, the formula becomes:
    ///
    /// `k = cubic_root((w_max - cwnd_epoch)/C/MSS)`
    fn calc_k(&self, cwnd_epoch: f64, max_datagram_size: usize) -> f64 {
        ((self.w_max - cwnd_epoch) / CUBIC_C / convert_to_f64(max_datagram_size)).cbrt()
    }

    /// `w_cubic(t) = C*(t-K)^3 + w_max`
    ///
    /// with `t = t_current - t_epoch`.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#figure-1>
    ///
    /// Taking into account that we're using bytes not MSS units, the formula becomes:
    ///
    /// `w_cubic(t) = (C*(t-K)^3) * MSS + w_max`
    fn w_cubic(&self, t: f64, max_datagram_size: usize) -> f64 {
        (CUBIC_C * (t - self.k).powi(3)).mul_add(convert_to_f64(max_datagram_size), self.w_max)
    }

    /// This function resets all relevant parameters at the start of a new epoch (new congestion
    /// avoidance stage) according to RFC 9438. The `w_max` variable is set in `reduce_cwnd()` as it
    /// needs the prior congestion window for it's calculation. It also initializes `k` and `w_max`
    /// if we start an epoch without having ever had a congestion event.
    ///
    /// > `w_est` is set equal to `cwnd_epoch` at the start of the congestion avoidance stage.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#section-4.3-9>
    fn start_epoch(
        &mut self,
        cwnd_epoch: f64,
        new_acked_f64: f64,
        max_datagram_size: usize,
        now: Instant,
    ) {
        self.t_epoch = Some(now);
        self.w_est = cwnd_epoch;
        self.tcp_acked_bytes = new_acked_f64;
        // If `w_max > cwnd_epoch` we take the cubic root from a negative value in `calc_k()`. That
        // could only happen if somehow `cwnd` get's increased between calling `reduce_cwnd()` and
        // `start_epoch()`, which is only possible if we go through slow start in between. It could
        // also happen if we never had a congestion event, so never called `reduce_cwnd()` thus
        // `w_max` was never set (so is still it's default `0.0` value). In any
        // case we reset/initialize `w_max` and `k` here.
        self.k = if self.w_max < cwnd_epoch {
            self.w_max = cwnd_epoch;
            0.0
        } else {
            self.calc_k(cwnd_epoch, max_datagram_size)
        };
        qtrace!("[{self}] New epoch");
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
        if self.t_epoch.is_none() {
            // This is a start of a new congestion avoidance phase.
            self.start_epoch(curr_cwnd_f64, new_acked_f64, max_datagram_size, now);
        } else {
            self.tcp_acked_bytes += new_acked_f64;
        }

        // Calculate `target` for the concave or convex region
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#name-concave-region>
        // <https://datatracker.ietf.org/doc/html/rfc9438#name-convex-region>
        //
        // UPDATE: New logic for how `target` is calculated.
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.2-11.1>
        //
        // And the `cwnd` increase of `target - cwnd / cwnd` only applies here,
        // not in the Reno-friendly region. So that needs to be adjusted. Right now
        // we are doing the `target - cwnd / cwnd` part for all regions I think.
        // See wording:
        //
        // > cwnd SHOULD be set to w_est ("set to")
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.3-8>
        //
        // vs.
        //
        // > cwnd MUST be incremented by `target - cwnd / cwnd` ("incremented by")
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#name-convex-region>
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
        let target_cubic = self.w_cubic(time_ca, max_datagram_size);

        // Reno-friendly region
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#name-reno-friendly-region>
        //
        // UPDATE/QUESTION: This is handled differently in the new RFC, but our implementation is
        // also different from the original RFC. Still need to understand what exactly is
        // going on here.
        //
        // Also note:
        //
        // > Once w_est has grown to reach the cwnd at the time of most recently setting
        // > ssthresh -- that is, w_est >= cwnd_prior -- the sender SHOULD set CUBIC_ALPHA to
        // > 1 to ensure that it can achieve the same congestion window increment rate
        // > as Reno, which uses AIMD(1, 0.5).
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.3-11>
        let max_datagram_size = convert_to_f64(max_datagram_size);
        let tcp_cnt = self.w_est / CUBIC_ALPHA;
        let incr = (self.tcp_acked_bytes / tcp_cnt).floor();
        if incr > 0.0 {
            self.tcp_acked_bytes -= incr * tcp_cnt;
            self.w_est += incr * max_datagram_size;
        }

        // Take the larger cwnd of Cubic concave or convex and Cubic Reno-friendly region.
        //
        // > When receiving a new ACK in congestion avoidance (where cwnd could be greater than
        // > or less than w_max), CUBIC checks whether W_cubic(t) is less than w_est.  If so, CUBIC
        // > is in the Reno-friendly region and cwnd SHOULD be set to w_est at each reception of a
        // > new ACK.
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.3-8>
        //
        // UPDATE: We should compare `w_cubic` (not `target`) and `w_est` here.
        // Maybe it might make sense to change the order of things a bit:
        // 1. Calculate `w_cubic` and `w_est`
        // 2. Compare `w_cubic` and `w_est`
        // 2.b. Maybe get `target` from `w_cubic`
        // 3.a. Either get `acked_to_increase` from `target` (with `target - cwnd / cwnd`) OR
        // 3.b. Get `acked_to_increase` from `w_est` by calculating the difference between
        // `curr_cwnd` and `w_est`.
        let target_cwnd = target_cubic.max(self.w_est);

        // Calculate the number of bytes that would need to be acknowledged for an increase
        // of `max_datagram_size` to match the increase of `target - cwnd / cwnd` as defined
        // in the specification (Sections 4.4 and 4.5).
        // The amount of data required therefore reduces asymptotically as the target increases.
        // If the target is not significantly higher than the congestion window, require a very
        // large amount of acknowledged data (effectively block increases).
        //
        // UPDATE: See above.
        let mut acked_to_increase =
            max_datagram_size * curr_cwnd_f64 / (target_cwnd - curr_cwnd_f64).max(1.0);

        // Limit increase to max 1 MSS per EXPONENTIAL_GROWTH_REDUCTION ack packets.
        // This effectively limits target_cwnd to (1 + 1 / EXPONENTIAL_GROWTH_REDUCTION) cwnd.
        acked_to_increase = acked_to_increase.max(EXPONENTIAL_GROWTH_REDUCTION * max_datagram_size);
        acked_to_increase as usize
    }

    // UPDATE: CUBIC RFC 9438 changes the logic for multiplicative decrease and uses
    // `bytes_in_flight` instead of `cwnd` for it's calculation:
    //
    // > ssthresh = bytes_in_flight * CUBIC_BETA
    // > cwnd_prior = cwnd
    // > if (reduction_on_loss) {
    // > cwnd = max(ssthresh, 2*MSS)
    // > } else if (reduction_on_ece) {
    // > cwnd = max(ssthresh, 1*MSS)
    // > }
    // > ssthresh = max(ssthresh, 2*MSS)
    //
    // <https://datatracker.ietf.org/doc/html/rfc9438#figure-5>
    //
    // With the note:
    //
    // > A QUIC sender that uses a cwnd value to calculate new values for cwnd and ssthresh after
    // > detecting a congestion event is REQUIRED to apply similar mechanisms [RFC9002].
    //
    // "similar mechanisms" refering to taking "measures to prevent cwnd from growing when the
    // volume of bytes in flight is smaller than cwnd".
    //
    // QUESTION: Do we already do this somewhere?
    //
    // <https://datatracker.ietf.org/doc/html/rfc9438#section-4.6>
    //
    // We are setting ssthresh in `on_congestion_event()` in `classic_cc.rs` after having returned
    // `cwnd` from `reduce_cwnd()` below. That is code that isn't CUBIC specific though, so we
    // can add a condition there to check which cc algorithm we're using and do the
    // `ssthresh|cwnd = max(...)` outlined above for CUBIC only.
    //
    // (or maybe don't do it at all because QUIC has a minimum congestion window of 2*MSS, as
    // mentioned further below)
    // QUESTION: Which takes precedence? The minimum congestion window of 2*MSS for QUIC or CUBIC
    // wanting to set cwnd to 1*MSS on reduction by ECE?
    fn reduce_cwnd(
        &mut self,
        curr_cwnd: usize,
        acked_bytes: usize,
        max_datagram_size: usize,
    ) -> (usize, usize) {
        let curr_cwnd_f64 = convert_to_f64(curr_cwnd);
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
        // TODO: From the old implementation:
        //
        // "Check cwnd + MAX_DATAGRAM_SIZE instead of cwnd because with cwnd in bytes, cwnd may be
        // slightly off."
        //
        // Implemented it like that, too. Maybe should be double checked if it really is necessary
        // and how that statement was reasoned.
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
        // Reset ca_epoch_start. Let it start again when the congestion controller
        // exits the app-limited period.
        self.t_epoch = None;
    }

    #[cfg(test)]
    fn w_max(&self) -> f64 {
        self.w_max
    }

    #[cfg(test)]
    fn set_w_max(&mut self, w_max: f64) {
        self.w_max = w_max;
    }
}

// UPDATE: Things to remember that didn't make it anywhere else:
//
// 1. Minimum congestion window:
//
// > Note that CUBIC MUST continue to reduce cwnd in response to congestion events
// > detected by ECN-Echo ACKs until it reaches a value of 1 SMSS. If congestion events
// > indicated by ECN-Echo ACKs persist, a sender with a cwnd of 1 SMSS MUST reduce its
// > sending rate even further. This can be achieved by using a retransmission timer
// > with exponential backoff, as described in [RFC3168].
//
// <https://datatracker.ietf.org/doc/html/rfc9438#section-4.6-7> VERSUS
//
// > QUIC therefore recommends that the minimum congestion window be two packets.
//
// <https://datatracker.ietf.org/doc/html/rfc9002#section-4.8>
//
// QUESTION: So this probably does not apply to CUBIC on QUIC and we never go below 2*MSS
// (as is currently implemented)?
//
// 2. Timeout: <https://datatracker.ietf.org/doc/html/rfc9438#section-4.8>
//
// > QUIC does not collapse the congestion window when the PTO expires, since a single
// > packet loss at the tail does not indicate persistent congestion.
//
// <https://datatracker.ietf.org/doc/html/rfc9002#section-4.7>
//
// QUESTION: Timeout (RTO/PTO) does not apply to us then?
//
// 3. Spurious fast retransmits: <https://datatracker.ietf.org/doc/html/rfc9438#section-4.9.2>
//
// QUESTION: Do we want to implement this? If yes then we may be able to do it in a follow up PR.
