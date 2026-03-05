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

/// A pacer that uses a leaky bucket.
pub struct Pacer {
    /// Whether pacing is enabled.
    enabled: bool,
    /// The last update time.
    t: Instant,
    /// The maximum capacity, or burst size, in bytes.
    m: usize,
    /// The current capacity, in bytes. When negative, represents accumulated debt
    /// that will be paid off in future pacing calculations.
    c: isize,
    /// The packet size or minimum capacity for sending, in bytes.
    p: usize,
    /// The single-packet MTU, before GSO scaling.
    mtu: usize,
    /// Number of GSO segments per batch. The pacer uses this to scale `p` and
    /// `m` so it paces between GSO batches rather than individual packets.
    gso: usize,
    /// The burst allowance in number of GSO batches.
    burst: usize,
}

impl Pacer {
    /// This value determines how much faster the pacer operates than the
    /// congestion window. A value of 1 spaces packets over the entire RTT,
    /// avoiding bursty traffic that causes tail losses at bottleneck queues.
    const SPEEDUP: usize = 1;

    /// Create a new `Pacer`.  This takes the current time, the burst allowance
    /// in number of GSO batches, and the packet size.
    pub fn new(enabled: bool, now: Instant, burst: usize, p: usize) -> Self {
        assert!(burst >= 1, "burst must be at least 1");
        assert!(isize::try_from(p).is_ok(), "p ({p}) exceeds isize::MAX");
        Self {
            enabled,
            t: now,
            m: p * burst,
            c: isize::try_from(p * burst).expect("capacity fits into isize"),
            p,
            mtu: p,
            gso: 1,
            burst,
        }
    }

    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    pub const fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
        self.update_p_m();
    }

    pub const fn set_gso_segments(&mut self, gso: usize) {
        self.gso = gso;
        self.update_p_m();
    }

    const fn update_p_m(&mut self) {
        self.p = self.mtu * self.gso;
        self.m = self.p * self.burst;
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
        // self.t + rtt * (self.p - self.c) / (Self::SPEEDUP * cwnd)
        let r = rtt.as_nanos();
        let deficit =
            u128::try_from(packet - self.c).expect("packet is larger than current credit");
        let d = r.saturating_mul(deficit);
        let add = d / u128::try_from(cwnd * Self::SPEEDUP).expect("usize fits into u128");
        let w = u64::try_from(add).map_or(rtt, Duration::from_nanos);

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
        // Increase the capacity by:
        //    `(now - self.t) * Self::SPEEDUP * cwnd / rtt`
        // That is, the elapsed fraction of the RTT times rate that data is added.
        let incr = now
            .saturating_duration_since(self.t)
            .as_nanos()
            .saturating_mul(u128::try_from(cwnd * Self::SPEEDUP).expect("usize fits into u128"))
            .checked_div(rtt.as_nanos())
            .and_then(|i| usize::try_from(i).ok())
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

    use super::Pacer;

    const RTT: Duration = Duration::from_secs(1);
    const PACKET: usize = 1000;
    const CWND: usize = PACKET * 10;

    #[test]
    fn even() {
        let n = now();
        let mut p = Pacer::new(true, n, 1, PACKET);
        assert_eq!(p.next(RTT, CWND), n);
        p.spend(n, RTT, CWND, PACKET);
        assert_eq!(
            p.next(RTT, CWND),
            n + (RTT / u32::try_from(Pacer::SPEEDUP * CWND / PACKET).unwrap())
        );
    }

    #[test]
    fn backwards_in_time() {
        let n = now();
        let mut p = Pacer::new(true, n + RTT, 1, PACKET);
        assert_eq!(p.next(RTT, CWND), n + RTT);
        // Now spend some credit in the past using a time machine.
        p.spend(n, RTT, CWND, PACKET);
        assert_eq!(
            p.next(RTT, CWND),
            n + (RTT / u32::try_from(Pacer::SPEEDUP * CWND / PACKET).unwrap())
        );
    }

    #[test]
    fn pacing_disabled() {
        let n = now();
        let mut p = Pacer::new(false, n, 1, PACKET);
        assert_eq!(p.next(RTT, CWND), n);
        p.spend(n, RTT, CWND, PACKET);
        assert_eq!(p.next(RTT, CWND), n);
    }

    #[test]
    fn gso_batch_pacing() {
        const GSO: usize = 10;
        let n = now();
        let mut p = Pacer::new(true, n, 2, PACKET);
        p.set_gso_segments(GSO);
        // p is now PACKET * GSO = 10000, m = 20000 (2 batches)
        assert_eq!(p.next(RTT, CWND), n);
        // Spend one full GSO batch
        for _ in 0..GSO {
            p.spend(n, RTT, CWND, PACKET);
        }
        // Still have credit for one more batch
        assert_eq!(p.next(RTT, CWND), n);
        // Spend second batch
        for _ in 0..GSO {
            p.spend(n, RTT, CWND, PACKET);
        }
        // Now should need to wait
        let next = p.next(RTT, CWND);
        assert!(next > n, "Should pace after two GSO batches");
    }

    #[test]
    fn sub_ms_pacing_accumulates_debt() {
        const SHORT_RTT: Duration = Duration::from_millis(10);
        let n = now();
        let mut p = Pacer::new(true, n, 1, PACKET);
        assert_eq!(p.next(SHORT_RTT, CWND), n);
        p.spend(n, SHORT_RTT, CWND, PACKET);
        let next = p.next(SHORT_RTT, CWND);
        assert!(next > n, "Pacer should return a future time after spending");
    }

    #[test]
    fn sends_accumulate_debt() {
        const RTT: Duration = Duration::from_millis(100);
        const BW: usize = 50 * 1_000_000;
        let bdp = usize::try_from(
            u128::try_from(BW / 8).expect("usize fits in u128") * RTT.as_nanos()
                / Duration::from_secs(1).as_nanos(),
        )
        .expect("cwnd fits in usize");
        let mut n = now();
        let mut p = Pacer::new(true, n, 2, PACKET);
        let start = n;
        let packet_count = 10_000;
        for _ in 0..packet_count {
            n = p.next(RTT, bdp);
            p.spend(n, RTT, bdp, PACKET);
        }
        assert!(n - start > Duration::ZERO);
    }

    #[test]
    fn pacer_display_and_debug() {
        let mut p = Pacer::new(true, now(), 1, PACKET);
        assert_eq!(p.mtu(), PACKET);
        p.set_mtu(500);
        assert_eq!(p.mtu(), 500);
        p.set_mtu(PACKET);
        assert_eq!(p.to_string(), "Pacer 1000/1000");
        assert!(format!("{p:?}").starts_with("Pacer@"));
    }
}
