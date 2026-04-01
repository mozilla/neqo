// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct Scone {
    updated: Instant,
    rate: Bitrate,
}

impl Scone {
    const PERIOD: Duration = Duration::from_secs(67);

    #[must_use]
    pub const fn new(updated: Instant, rate: Bitrate) -> Self {
        Self { updated, rate }
    }

    /// Update the value, return true if updated.
    pub fn update(&mut self, now: Instant, rate: Bitrate) -> bool {
        // This uses the simplest form of update, to keep it simple.
        // A fancier method would remember some number of higher-rate updates
        // and switch to those when the lower rate expires.
        if (rate.is_set() && rate.0 <= self.rate.0) || self.updated + Self::PERIOD <= now {
            let changed = rate != self.rate;
            self.updated = now;
            self.rate = rate;
            changed
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bitrate(u8);

impl Bitrate {
    const UNKNOWN: Self = Self(0x7f);

    pub const fn is_set(self) -> bool {
        self.0 != Self::UNKNOWN.0
    }
}

impl From<(u8, u32)> for Bitrate {
    fn from((first, version): (u8, u32)) -> Self {
        Self(u8::try_from(version >> 31).expect("always u8") | ((first & 0x3f) << 1))
    }
}

impl From<Bitrate> for Option<NonZeroU64> {
    #[expect(clippy::cast_possible_truncation, reason = "We want truncation here")]
    #[expect(clippy::cast_sign_loss, reason = "negative values are impossible")]
    fn from(value: Bitrate) -> Self {
        value.is_set().then(|| {
            // Bitrate formula is 100_000 * 10^(n/20),
            // log10(100_000) is 5, and 10^(1/20) is 1.122...
            NonZeroU64::new(1.122_018_454_301_963_3_f64.powi(100 + i32::from(value.0)) as u64)
        }).flatten()
    }
}

#[cfg(test)]
mod test {
    use std::{
        num::NonZeroU64,
        time::{Duration, Instant},
    };

    use crate::scone::{Bitrate, Scone};

    const SEC: Duration = Duration::from_secs(1);
    const BASE_RATE: Bitrate = Bitrate(0x10);

    #[test]
    fn unknown() {
        assert!(!Bitrate(0x7f).is_set());

        assert_eq!(Bitrate::UNKNOWN, Bitrate(0x7f));
        let now = Instant::now();
        let mut base = Scone::new(now, BASE_RATE);
        let mut other = base.clone();
        assert!(!other.update(now + SEC, Bitrate::UNKNOWN));
        assert_eq!(other.rate, BASE_RATE);

        let rollover = now + Scone::PERIOD;
        assert!(base.update(rollover, Bitrate::UNKNOWN));
        assert_eq!(base.rate, Bitrate::UNKNOWN);
    }

    #[test]
    fn reduce() {
        let now = Instant::now();
        let mut base = Scone::new(now, BASE_RATE);
        assert!(base.update(now + SEC, Bitrate(0x09)));
        assert_eq!(base.rate, Bitrate(0x09));
    }

    #[test]
    fn increase() {
        let now = Instant::now();
        let mut base = Scone::new(now, BASE_RATE);
        assert!(!base.update(now + SEC, Bitrate(0x17)));
        assert_eq!(base.rate, BASE_RATE);
        assert!(base.update(now + Scone::PERIOD, Bitrate(0x17)));
        assert_eq!(base.rate, Bitrate(0x17));
    }

    #[test]
    fn to_rate() {
        let rate = Option::<NonZeroU64>::from(Bitrate::UNKNOWN);
        assert!(rate.is_none());
        let rate = Option::from(Bitrate(0x55));
        assert_eq!(rate, NonZeroU64::new(1_778_279_410));
    }
}
