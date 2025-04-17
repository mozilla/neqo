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

/// > Constant that determines the aggressiveness of CUBIC in
/// > competing with other congestion control algorithms in high-BDP networks.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// See section 5.1 for discussion on how to set the concrete value.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-fairness-to-reno>
///
/// UPDATE: no change to C.
pub const CUBIC_C: f64 = 0.4;

/// > CUBIC additive increase factor used in the Reno-friendly region
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// > The model used to calculate CUBIC_ALPHA is not absolutely precise,
/// > but analysis and simulation \[...\], as well as over a decade of experience with
/// > CUBIC in the public Internet, show that this approach produces acceptable
/// > levels of rate fairness between CUBIC and Reno flows.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-reno-friendly-region>
///
/// UPDATE: no change to alpha.
pub const CUBIC_ALPHA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7); // with CUBIC_BETA = 0.7

/// > CUBIC multiplicative decrease factor
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-constants-of-interest>
///
/// > Principle 4: To balance between the scalability and convergence speed,
/// > CUBIC sets the multiplicative window decrease factor to 0.7 while Standard
/// > TCP uses 0.5.  While this improves the scalability of CUBIC, a side effect
/// > of this decision is slower convergence, especially under low statistical
/// > multiplexing environments.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-principle-4-for-the-cubic-d>
///
/// `CUBIC_BETA` = 0.7;
///
/// UPDATE: no change to beta.
pub const CUBIC_BETA_USIZE_DIVIDEND: usize = 7;
pub const CUBIC_BETA_USIZE_DIVISOR: usize = 10;

/// The fast convergence ratio further reduces the next `W_max` when a
/// congestion event occurs while `cwnd < W_max`.
///
/// See formula defined below.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#name-fast-convergence>
///
/// UPDATE: no change to fast convergence ratio.
pub const CUBIC_FAST_CONVERGENCE: f64 = 0.85; // (1.0 + CUBIC_BETA) / 2.0;

/// The minimum number of multiples of the datagram size that need
/// to be received to cause an increase in the congestion window.
/// When there is no loss, Cubic can return to exponential increase, but
/// this value reduces the magnitude of the resulting growth by a constant factor.
/// A value of 1.0 would mean a return to the rate used in slow start.
///
/// UPDATE: Not found in RFC. I don't exactly understand why we're doing this?
const EXPONENTIAL_GROWTH_REDUCTION: f64 = 2.0;

/// Convert an integer congestion window value into a floating point value.
/// This has the effect of reducing larger values to `1<<53`.
/// If you have a congestion window that large, something is probably wrong.
///
/// UPDATE: not part of RFC.
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
    ///
    /// UPDATE: The algorithm for fast convergence was improved in RFC 9438
    /// to not need the extra variable anymore.
    ///
    /// ACTION: Delete variable when algorithm is adapted.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-fast-convergence>
    last_max_cwnd: f64,
    /// > An estimate for the congestion window in segments in the Reno-friendly region -- that
    /// > is, an estimate for the congestion window of Reno.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// > Reno performs well in certain types of networks -- for example, under short RTTs and small
    /// > bandwidths (or small BDPs). In these networks, CUBIC remains in the Reno-friendly region to
    /// > achieve at least the same throughput as Reno.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-reno-friendly-region>
    ///
    /// ACTION: Rename to `w_est` to conform with spec.
    estimated_tcp_cwnd: f64,
    /// > The time period in seconds it takes to increase the congestion window size
    /// > at the beginning of the current congestion avoidance stage to `w_max`.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// For formula definition see:
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-window-increase-function>
    k: f64,
    /// > Size of `cwnd` in segments just before `cwnd` was reduced in the last congestion
    /// > event when fast convergence is disabled (same as `cwnd_prior` on a congestion event).
    /// > However, if fast convergence is enabled, `w_max` may be further reduced based on
    /// > the current saturation point.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// This acts as the plateau for the cubic function where it switches from the concave to the
    /// convex region.
    ///
    /// For formula definition see:
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-fast-convergence>
    w_max: f64,
    /// > The time in seconds at which the current congestion avoidance stage started.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-variables-of-interest>
    ///
    /// UPDATE/ACTION: Rename to `t_epoch` to adhere to spec.
    ca_epoch_start: Option<Instant>,
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
    tcp_acked_bytes: f64,
}

impl Display for Cubic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Cubic [last_max_cwnd: {}, k: {}, w_max: {}, ca_epoch_start: {:?}]",
            self.last_max_cwnd, self.k, self.w_max, self.ca_epoch_start
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
    ///
    /// UPDATE: Formula for K changed.
    ///
    /// Original equation is:
    /// `k = cubic_root((w_max - cwnd_epoch)/C)` with `cwnd_epoch` being the congestion
    /// window at the start of the current congestion avoidance stage (so at time t_epoch).
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#figure-2>
    ///
    /// Taking into account that we're using bytes not MSS units, the formula becomes:
    ///
    /// `k = cubic_root((w_max - cwnd_epoch)/C/MSS)`
    ///
    /// ACTION: change `calc_k`, add `cwnd_epoch`
    fn calc_k(&self, curr_cwnd: f64, max_datagram_size: usize) -> f64 {
        ((self.w_max - curr_cwnd) / CUBIC_C / convert_to_f64(max_datagram_size)).cbrt()
    }

    /// `w_cubic(t) = C*(t-K)^3 + w_max`
    ///
    /// with `t = t_current - t_epoch`.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#figure-1>
    ///
    /// We're using bytes not MSS units so we need to convert.
    ///
    /// UPDATE: Nothing changed.
    fn w_cubic(&self, t: f64, max_datagram_size: usize) -> f64 {
        (CUBIC_C * (t - self.k).powi(3)).mul_add(convert_to_f64(max_datagram_size), self.w_max)
    }

    /// > w_est is set equal to cwnd_epoch at the start of the congestion avoidance stage.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9438#name-reno-friendly-region>
    ///
    /// UPDATE: With the change to fast convergence, we can remove the `last_max_cwnd` logic here.
    /// We also must set `w_max` and `k`. I think `k` should be here but `w_max` should happen in
    /// `reduce_cwnd()` where we currently do fast convergence. Also need to set `w_est` here,
    /// see above. I don't think we need a `cwnd_epoch` variable, as it's only used here and equals
    /// `curr_cwnd_f64`. Might rename the parameter.
    ///
    /// Not sure about the `last_max_cwnd <= curr_cwnd_f64` logic and how that relates to the new
    /// fast convergence. Need to look into that.
    fn start_epoch(
        &mut self,
        curr_cwnd_f64: f64,
        new_acked_f64: f64,
        max_datagram_size: usize,
        now: Instant,
    ) {
        self.ca_epoch_start = Some(now);
        // reset tcp_acked_bytes and estimated_tcp_cwnd;
        self.tcp_acked_bytes = new_acked_f64;
        self.estimated_tcp_cwnd = curr_cwnd_f64;
        if self.last_max_cwnd <= curr_cwnd_f64 {
            self.w_max = curr_cwnd_f64;
            self.k = 0.0;
        } else {
            self.w_max = self.last_max_cwnd;
            self.k = self.calc_k(curr_cwnd_f64, max_datagram_size);
        }
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
        if self.ca_epoch_start.is_none() {
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
            .ca_epoch_start
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
        // UPDATE/QUESTION: This is handled differently in the new RFC, but our implementation is also
        // different from the original RFC. Still need to understand what exactly is going on here.
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
        let tcp_cnt = self.estimated_tcp_cwnd / CUBIC_ALPHA;
        let incr = (self.tcp_acked_bytes / tcp_cnt).floor();
        if incr > 0.0 {
            self.tcp_acked_bytes -= incr * tcp_cnt;
            self.estimated_tcp_cwnd += incr * max_datagram_size;
        }

        // Take the larger cwnd of Cubic concave or convex and Cubic Reno-friendly region.
        //
        // > When receiving a new ACK in congestion avoidance (where cwnd could be greater than
        // > or less than w_max), CUBIC checks whether W_cubic(t) is less than w_est.  If so, CUBIC
        // > is in the Reno-friendly region and cwnd SHOULD be set to w_est at each reception of a new ACK.
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
        let target_cwnd = target_cubic.max(self.estimated_tcp_cwnd);

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
    // >     cwnd = max(ssthresh, 2*MSS)
    // > } else if (reduction_on_ece) {
    // >     cwnd = max(ssthresh, 1*MSS)
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
    // We are setting ssthresh in `on_congestion_event()` in `classic_cc.rs` after having returned `cwnd`
    // from `reduce_cwnd()` below. That is code that isn't CUBIC specific though, so we can add a condition
    // there to check which cc algorithm we're using and do the `ssthresh|cwnd = max(...)` outlined above
    // for CUBIC only.
    //
    // (or maybe don't do it at all because QUIC has a minimum congestion window of 2*MSS, as mentioned
    // further below)
    // QUESTION: Which takes precedence? The minimum congestion window of 2*MSS for QUIC or CUBIC wanting to set
    // cwnd to 1*MSS on reduction by ECE?
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
        // Check cwnd + MAX_DATAGRAM_SIZE instead of cwnd because with cwnd in bytes, cwnd may be
        // slightly off.
        //
        // UPDATE: New logic for fast convergence.
        //
        // if (cwnd < w_max AND fast_convergence_enabled) {
        //     w_max = cwnd * CUBIC_FAST_CONVERGENCE;
        // } else {
        //     w_max = cwnd;
        // }
        //
        // <https://datatracker.ietf.org/doc/html/rfc9438#name-fast-convergence>
        self.last_max_cwnd =
            if curr_cwnd_f64 + convert_to_f64(max_datagram_size) < self.last_max_cwnd {
                curr_cwnd_f64 * CUBIC_FAST_CONVERGENCE
            } else {
                curr_cwnd_f64
            };
        self.ca_epoch_start = None;
        (
            curr_cwnd * CUBIC_BETA_USIZE_DIVIDEND / CUBIC_BETA_USIZE_DIVISOR,
            acked_bytes * CUBIC_BETA_USIZE_DIVIDEND / CUBIC_BETA_USIZE_DIVISOR,
        )
    }

    fn on_app_limited(&mut self) {
        // Reset ca_epoch_start. Let it start again when the congestion controller
        // exits the app-limited period.
        self.ca_epoch_start = None;
    }

    #[cfg(test)]
    fn last_max_cwnd(&self) -> f64 {
        self.last_max_cwnd
    }

    #[cfg(test)]
    fn set_last_max_cwnd(&mut self, last_max_cwnd: f64) {
        self.last_max_cwnd = last_max_cwnd;
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
