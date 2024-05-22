// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Pacer

use std::{
    cmp::min,
    fmt::{Debug, Display},
    time::{Duration, Instant},
};

use neqo_common::qtrace;

use crate::Pmtud;

/// This value determines how much faster the pacer operates than the
/// congestion window.
///
/// A value of 1 would cause all packets to be spaced over the entire RTT,
/// which is a little slow and might act as an additional restriction in
/// the case the congestion controller increases the congestion window.
/// This value spaces packets over half the congestion window, which matches
/// our current congestion controller, which double the window every RTT.
const PACER_SPEEDUP: usize = 2;

/// A pacer that uses a leaky bucket.
pub struct Pacer {
    /// Whether pacing is enabled.
    enabled: bool,
    /// The last update time.
    t: Instant,
    /// The maximum capacity, or burst size, in bytes.
    m: usize,
    /// The current capacity, in bytes.
    c: usize,
    /// The PMTUD state.
    pmtud: Pmtud,
}

impl Pacer {
    /// Create a new `Pacer`.  This takes the current time, the maximum burst size,
    /// and the packet size.
    ///
    /// The value of `m` is the maximum capacity in MTUs.  `m` primes the pacer
    /// with credit and determines the burst size.  `m` * MTU must not exceed
    /// the initial congestion window, but it should probably be lower.
    ///
    /// The value of `p` is the packet size in bytes, which determines the minimum
    /// credit needed before a packet is sent.  This should be a substantial
    /// fraction of the maximum packet size, if not the packet size.
    pub fn new(enabled: bool, now: Instant, m: usize, pmtud: Pmtud) -> Self {
        assert!(m >= 1, "maximum capacity has to be at least one packet");
        let m = m * pmtud.plpmtu();
        Self {
            enabled,
            t: now,
            m,
            c: m,
            pmtud,
        }
    }

    pub fn pmtud(&self) -> &Pmtud {
        &self.pmtud
    }

    pub fn pmtud_mut(&mut self) -> &mut Pmtud {
        &mut self.pmtud
    }

    fn p(&self) -> usize {
        self.pmtud.plpmtu()
    }

    /// Determine when the next packet will be available based on the provided RTT
    /// and congestion window.  This doesn't update state.
    /// This returns a time, which could be in the past (this object doesn't know what
    /// the current time is).
    pub fn next(&self, rtt: Duration, cwnd: usize) -> Instant {
        if self.c >= self.p() {
            qtrace!([self], "next {}/{:?} no wait = {:?}", cwnd, rtt, self.t);
            self.t
        } else {
            // This is the inverse of the function in `spend`:
            // self.t + rtt * (self.p() - self.c) / (PACER_SPEEDUP * cwnd)
            let r = rtt.as_nanos();
            let d = r.saturating_mul(u128::try_from(self.p() - self.c).unwrap());
            let add = d / u128::try_from(cwnd * PACER_SPEEDUP).unwrap();
            let w = u64::try_from(add).map(Duration::from_nanos).unwrap_or(rtt);
            let nxt = self.t + w;
            qtrace!([self], "next {}/{:?} wait {:?} = {:?}", cwnd, rtt, w, nxt);
            nxt
        }
    }

    /// Spend credit.  This cannot fail; users of this API are expected to call
    /// `next()` to determine when to spend.  This takes the current time (`now`),
    /// an estimate of the round trip time (`rtt`), the estimated congestion
    /// window (`cwnd`), and the number of bytes that were sent (`count`).
    pub fn spend(&mut self, now: Instant, rtt: Duration, cwnd: usize, count: usize) {
        if !self.enabled {
            self.t = now;
            return;
        }

        qtrace!([self], "spend {} over {}, {:?}", count, cwnd, rtt);
        // Increase the capacity by:
        //    `(now - self.t) * PACER_SPEEDUP * cwnd / rtt`
        // That is, the elapsed fraction of the RTT times rate that data is added.
        let incr = now
            .saturating_duration_since(self.t)
            .as_nanos()
            .saturating_mul(u128::try_from(cwnd * PACER_SPEEDUP).unwrap())
            .checked_div(rtt.as_nanos())
            .and_then(|i| usize::try_from(i).ok())
            .unwrap_or(self.m);

        // Add the capacity up to a limit of `self.m`, then subtract `count`.
        self.c = min(self.m, (self.c + incr).saturating_sub(count));
        self.t = now;
    }
}

impl Display for Pacer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Pacer {}/{}", self.c, self.p())
    }
}

impl Debug for Pacer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Pacer@{:?} {}/{}..{}", self.t, self.c, self.p(), self.m)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use test_fixture::now;

    use super::Pacer;
    use crate::Pmtud;

    const RTT: Duration = Duration::from_millis(1000);
    const IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

    #[test]
    fn even() {
        let n = now();
        let mut p = Pacer::new(true, n, 1, Pmtud::new(IP_ADDR));
        let mtu = p.pmtud().plpmtu();
        let cwnd = mtu * 10;
        assert_eq!(p.next(RTT, cwnd), n);
        p.spend(n, RTT, cwnd, mtu);
        assert_eq!(p.next(RTT, cwnd), n + (RTT / 20));
    }

    #[test]
    fn backwards_in_time() {
        let n = now();
        let mut p = Pacer::new(true, n + RTT, 1, Pmtud::new(IP_ADDR));
        let mtu = p.pmtud().plpmtu();
        let cwnd = mtu * 10;
        assert_eq!(p.next(RTT, cwnd), n + RTT);
        // Now spend some credit in the past using a time machine.
        p.spend(n, RTT, cwnd, mtu);
        assert_eq!(p.next(RTT, cwnd), n + (RTT / 20));
    }

    #[test]
    fn pacing_disabled() {
        let n = now();
        let mut p = Pacer::new(false, n, 1, Pmtud::new(IP_ADDR));
        let mtu = p.pmtud().plpmtu();
        let cwnd = mtu * 10;
        assert_eq!(p.next(RTT, cwnd), n);
        p.spend(n, RTT, cwnd, mtu);
        assert_eq!(p.next(RTT, cwnd), n);
    }
}
