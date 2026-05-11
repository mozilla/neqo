// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Pacer

use std::{
    cmp::min,
    fmt::{self, Debug, Display, Formatter},
    time::{Duration, Instant},
};

use neqo_common::qtrace;

use crate::rtt::GRANULARITY;

/// Scale factor for [`Pacer::SPEEDUP_SLOW_START`] and [`Pacer::SPEEDUP`].
pub(crate) const SPEEDUP_SCALE: usize = 10;

/// A pacer that uses a leaky bucket.
pub struct Pacer {
    /// Whether pacing is enabled.
    enabled: bool,
    /// The last update time.
    t: Instant,
    /// The maximum capacity, or burst size, in bytes.
    m: usize,
    /// The current capacity, in bytes. When negative, represents accumulated debt
    /// from sub-granularity sends that will be paid off in future pacing calculations.
    c: isize,
    /// The packet size or minimum capacity for sending, in bytes.
    p: usize,
    /// The current pacing speedup multiplier, scaled by [`SPEEDUP_SCALE`].
    /// Use [`Pacer::SPEEDUP_SLOW_START`] during slow start and [`Pacer::SPEEDUP`] otherwise.
    speedup: usize,
}

impl Pacer {
    /// Speedup factor during slow start: 2.0 × [`SPEEDUP_SCALE`].
    ///
    /// Spaces packets over half the congestion window, matching the window doubling rate
    /// of slow start.
    pub(crate) const SPEEDUP_SLOW_START: usize = 20;

    /// Speedup factor outside slow start: 1.2 × [`SPEEDUP_SCALE`].
    ///
    /// A value of [`SPEEDUP_SCALE`] would space packets over the entire RTT.
    /// This small headroom keeps pacing from becoming an artificial bottleneck
    /// during congestion avoidance.
    pub(crate) const SPEEDUP: usize = 12;

    /// Create a new `Pacer`.  This takes the current time, the maximum burst size,
    /// and the packet size.
    ///
    /// The value of `m` is the maximum capacity in bytes.  `m` primes the pacer
    /// with credit and determines the burst size.  `m` must not exceed
    /// the initial congestion window, but it should probably be lower.
    ///
    /// The value of `p` is the packet size in bytes, which determines the minimum
    /// credit needed before a packet is sent.  This should be a substantial
    /// fraction of the maximum packet size, if not the packet size.
    pub fn new(enabled: bool, now: Instant, m: usize, p: usize) -> Self {
        assert!(m >= p, "maximum capacity has to be at least one packet");
        assert!(isize::try_from(p).is_ok(), "p ({p}) exceeds isize::MAX");
        Self {
            enabled,
            t: now,
            m,
            c: isize::try_from(m).expect("maximum capacity fits into isize"),
            p,
            speedup: Self::SPEEDUP_SLOW_START,
        }
    }

    pub const fn mtu(&self) -> usize {
        self.p
    }

    pub const fn set_mtu(&mut self, mtu: usize) {
        self.p = mtu;
    }

    pub(crate) fn set_speedup(&mut self, speedup: usize) {
        self.speedup = speedup;
    }

    /// Bytes sendable at `speedup / SPEEDUP_SCALE * cwnd / rtt` pace over `elapsed`.
    /// Returns `None` if `rtt` is zero.
    #[allow(
        clippy::allow_attributes,
        clippy::unwrap_in_result,
        reason = "Check if this can be removed with MSRV > 1.90"
    )]
    fn bytes_for(&self, cwnd: usize, rtt: Duration, elapsed: Duration) -> Option<u128> {
        let factor = u128::try_from(cwnd)
            .expect("usize fits into u128")
            .saturating_mul(u128::try_from(self.speedup).expect("usize fits into u128"));
        let scaled_rtt = rtt
            .as_nanos()
            .saturating_mul(u128::try_from(SPEEDUP_SCALE).expect("usize fits into u128"));
        elapsed
            .as_nanos()
            .saturating_mul(factor)
            .checked_div(scaled_rtt)
    }

    /// Compute the effective pacing rate in bytes per second.
    ///
    /// Returns `None` if `rtt` is zero or the rate exceeds `u64::MAX`.
    pub(crate) fn rate(&self, cwnd: usize, rtt: Duration) -> Option<u64> {
        u64::try_from(self.bytes_for(cwnd, rtt, Duration::from_secs(1))?).ok()
    }

    /// Determine when the next packet will be available based on the provided
    /// RTT, provided congestion window and accumulated credit or debt.  This
    /// doesn't update state.  This returns a time, which could be in the past
    /// (this object doesn't know what the current time is).
    pub fn next(&self, rtt: Duration, cwnd: usize) -> Instant {
        let packet = isize::try_from(self.p).expect("packet size fits into isize");

        if self.c >= packet {
            qtrace!("[{self}] next {cwnd}/{rtt:?} no wait = {:?}", self.t);
            return self.t;
        }

        // This is the inverse of the function in `spend`:
        // self.t + rtt * (self.p - self.c) * SPEEDUP_SCALE / (self.speedup * cwnd)
        let r = rtt.as_nanos();
        let deficit =
            u128::try_from(packet - self.c).expect("packet is larger than current credit");
        let scale = u128::try_from(SPEEDUP_SCALE).expect("usize fits into u128");
        let d = r.saturating_mul(deficit).saturating_mul(scale);
        let divisor = u128::try_from(cwnd)
            .expect("usize fits into u128")
            .saturating_mul(u128::try_from(self.speedup).expect("usize fits into u128"));
        let add = d / divisor;
        let w = u64::try_from(add).map_or(rtt, Duration::from_nanos);

        // If the increment is below the timer granularity, send immediately.
        if w < GRANULARITY {
            qtrace!("[{self}] next {cwnd}/{rtt:?} below granularity ({w:?})");
            return self.t;
        }

        let nxt = self.t + w;
        qtrace!("[{self}] next {cwnd}/{rtt:?} wait {w:?} = {nxt:?}");
        nxt
    }

    /// Spend credit. This cannot fail, but instead may carry debt into the
    /// future (see [`Pacer::c`]). Users of this API are expected to call
    /// [`Pacer::next`] to determine when to spend.
    ///
    /// This function takes the current time (`now`), an estimate of the round
    /// trip time (`rtt`), the estimated congestion window (`cwnd`), and the
    /// number of bytes that were sent (`count`).
    pub fn spend(&mut self, now: Instant, rtt: Duration, cwnd: usize, count: usize) {
        if !self.enabled {
            self.t = now;
            return;
        }

        qtrace!("[{self}] spend {count} over {cwnd}, {rtt:?}");
        // Increase the capacity by the elapsed fraction of the RTT times the
        // pacing rate, i.e. `(now - self.t) * speedup * cwnd / (rtt * SPEEDUP_SCALE)`.
        let incr = self
            .bytes_for(cwnd, rtt, now.saturating_duration_since(self.t))
            .and_then(|b| usize::try_from(b).ok())
            .unwrap_or(self.m);

        // Add the capacity up to a limit of `self.m`, then subtract `count`.
        self.c = min(
            isize::try_from(self.m).unwrap_or(isize::MAX),
            self.c
                .saturating_add(isize::try_from(incr).unwrap_or(isize::MAX))
                .saturating_sub(isize::try_from(count).unwrap_or(isize::MAX)),
        );
        self.t = now;
    }
}

impl Display for Pacer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Pacer {}/{}", self.c, self.p)
    }
}

impl Debug for Pacer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Pacer@{:?} {}/{}..{}", self.t, self.c, self.p, self.m)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::time::Duration;

    use test_fixture::now;

    use super::{Pacer, SPEEDUP_SCALE};

    const RTT: Duration = Duration::from_secs(1);
    const PACKET: usize = 1000;
    const CWND: usize = PACKET * 10;

    fn pacer_slow_start() -> Pacer {
        Pacer::new(true, now(), PACKET, PACKET)
        // speedup defaults to SPEEDUP_SLOW_START
    }

    fn pacer_ca() -> Pacer {
        let mut p = Pacer::new(true, now(), PACKET, PACKET);
        p.set_speedup(Pacer::SPEEDUP);
        p
    }

    #[test]
    fn even() {
        // Slow start: 2x speedup → pacing interval = RTT * PACKET / (2 * CWND) = RTT/20
        let n = now();
        let mut p = Pacer::new(true, n, PACKET, PACKET);
        assert_eq!(p.next(RTT, CWND), n);
        p.spend(n, RTT, CWND, PACKET);
        assert_eq!(p.next(RTT, CWND), n + (RTT / 20));
    }

    #[test]
    fn backwards_in_time() {
        let n = now();
        let mut p = Pacer::new(true, n + RTT, PACKET, PACKET);
        assert_eq!(p.next(RTT, CWND), n + RTT);
        // Now spend some credit in the past using a time machine.
        p.spend(n, RTT, CWND, PACKET);
        assert_eq!(p.next(RTT, CWND), n + (RTT / 20));
    }

    #[test]
    fn pacing_disabled() {
        let n = now();
        let mut p = Pacer::new(false, n, PACKET, PACKET);
        assert_eq!(p.next(RTT, CWND), n);
        p.spend(n, RTT, CWND, PACKET);
        assert_eq!(p.next(RTT, CWND), n);
    }

    #[test]
    fn send_immediately_below_granularity() {
        const SHORT_RTT: Duration = Duration::from_millis(10);
        let n = now();
        let mut p = Pacer::new(true, n, PACKET, PACKET);
        assert_eq!(p.next(SHORT_RTT, CWND), n);
        p.spend(n, SHORT_RTT, CWND, PACKET);
        assert_eq!(
            p.next(SHORT_RTT, CWND),
            n,
            "Expect packet to be sent immediately, instead of being paced below timer granularity"
        );
    }

    #[test]
    fn sends_below_granularity_accumulate_eventually() {
        const RTT: Duration = Duration::from_millis(100);
        const BW: usize = 50 * 1_000_000;
        let bdp = usize::try_from(
            u128::try_from(BW / 8).expect("usize fits in u128") * RTT.as_nanos()
                / Duration::from_secs(1).as_nanos(),
        )
        .expect("cwnd fits in usize");
        let mut n = now();
        let mut p = Pacer::new(true, n, 2 * PACKET, PACKET);
        let start = n;
        let packet_count = 10_000;
        for _ in 0..packet_count {
            n = p.next(RTT, bdp);
            p.spend(n, RTT, bdp, PACKET);
        }
        // We expect _some_ time to have progressed after sending all the packets.
        assert!(n - start > Duration::ZERO);
    }

    #[test]
    fn rate_basic() {
        // Slow start: 2x speedup.
        // 10 KB cwnd, 100 ms RTT → 20 * 10_000 * 1e9 / (100_000_000 * 10) = 200_000 B/s
        let p = pacer_slow_start();
        assert_eq!(p.rate(10_000, Duration::from_millis(100)), Some(200_000));
    }

    #[test]
    fn rate_congestion_avoidance() {
        // Congestion avoidance: 1.2x speedup.
        // 10 KB cwnd, 100 ms RTT → 12 * 10_000 * 1e9 / (100_000_000 * 10) = 120_000 B/s
        let p = pacer_ca();
        assert_eq!(p.rate(10_000, Duration::from_millis(100)), Some(120_000));
    }

    #[test]
    fn rate_zero_rtt() {
        let p = pacer_slow_start();
        assert_eq!(p.rate(10_000, Duration::ZERO), None);
    }

    /// When the computed wait equals GRANULARITY exactly, pacing should NOT
    /// send immediately; only strictly sub-granularity waits are suppressed.
    #[test]
    fn not_immediately_at_exact_granularity() {
        // Slow start: 2x speedup (SPEEDUP_SLOW_START=20, SPEEDUP_SCALE=10).
        // w = rtt * PACKET * SPEEDUP_SCALE / (SPEEDUP_SLOW_START * cwnd) = 1ms = GRANULARITY.
        // rtt=10ms: cwnd = 10_000_000 * 1000 * 10 / (20 * 1_000_000) = 5000.
        const SHORT_RTT: Duration = Duration::from_millis(10);
        const CWND_AT_GRANULARITY: usize = 5000; // yields w = 1ms = GRANULARITY
        let n = now();
        let mut p = Pacer::new(true, n, PACKET, PACKET);
        p.spend(n, SHORT_RTT, CWND_AT_GRANULARITY, PACKET);
        // w == GRANULARITY: should schedule for later, not send immediately.
        assert_ne!(
            p.next(SHORT_RTT, CWND_AT_GRANULARITY),
            n,
            "at exactly GRANULARITY should not send immediately"
        );
    }

    #[test]
    fn congestion_avoidance_pacing_slower_than_slow_start() {
        // Congestion avoidance (1.2x) should pace more slowly than slow start (2x):
        // longer inter-packet interval for the same cwnd and RTT.
        let n = now();
        let mut p_ss = Pacer::new(true, n, PACKET, PACKET);
        let mut p_ca = Pacer::new(true, n, PACKET, PACKET);
        p_ca.set_speedup(Pacer::SPEEDUP);

        p_ss.spend(n, RTT, CWND, PACKET);
        p_ca.spend(n, RTT, CWND, PACKET);

        assert!(p_ca.next(RTT, CWND) > p_ss.next(RTT, CWND));
    }

    #[test]
    fn speedup_scale_sanity() {
        // Verify the constants are consistent with their intended ratios.
        assert_eq!(Pacer::SPEEDUP_SLOW_START, 2 * SPEEDUP_SCALE);
        assert_eq!(Pacer::SPEEDUP * 10, 12 * SPEEDUP_SCALE);
    }

    #[test]
    fn pacer_display_and_debug() {
        let mut p = Pacer::new(true, now(), PACKET, PACKET);
        assert_eq!(p.mtu(), PACKET);
        p.set_mtu(500);
        assert_eq!(p.mtu(), 500);
        p.set_mtu(PACKET);
        assert_eq!(p.to_string(), "Pacer 1000/1000");
        assert!(format!("{p:?}").starts_with("Pacer@"));
    }
}
