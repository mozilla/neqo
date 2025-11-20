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
}

impl Pacer {
    /// This value determines how much faster the pacer operates than the
    /// congestion window.
    ///
    /// A value of 1 would cause all packets to be spaced over the entire RTT,
    /// which is a little slow and might act as an additional restriction in
    /// the case the congestion controller increases the congestion window.
    /// This value spaces packets over half the congestion window, which matches
    /// our current congestion controller, which double the window every RTT.
    const SPEEDUP: usize = 2;

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
        }
    }

    pub const fn mtu(&self) -> usize {
        self.p
    }

    pub fn set_mtu(&mut self, mtu: usize) {
        self.p = mtu;
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
        let w = u64::try_from(add).map(Duration::from_nanos).unwrap_or(rtt);

        // If the increment is below the timer granularity, send immediately.
        if w < GRANULARITY {
            qtrace!("[{self}] next {cwnd}/{rtt:?} below granularity ({w:?})",);
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

    const RTT: Duration = Duration::from_millis(1000);
    const PACKET: usize = 1000;
    const CWND: usize = PACKET * 10;

    #[test]
    fn even() {
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
}
