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
    pub(crate) const PERIOD: Duration = Duration::from_secs(67);

    #[must_use]
    pub const fn new(updated: Instant, rate: Bitrate) -> Self {
        Self { updated, rate }
    }

    /// Determine if the advice has expired.
    #[must_use]
    pub fn expired(&self, now: Instant) -> bool {
        self.updated + Self::PERIOD <= now
    }

    #[must_use]
    pub const fn rate(&self) -> Bitrate {
        self.rate
    }

    /// Update the value, return true if updated.
    pub fn update(&mut self, now: Instant, rate: Option<Bitrate>) -> bool {
        // This uses the simplest form of update, to keep it simple.
        // A fancier method would remember some number of higher-rate updates
        // and switch to those when the lower rate expires.
        if rate.is_some_and(|r| r <= self.rate) || self.expired(now) {
            self.updated = now;
            let rate = rate.unwrap_or_default();
            let changed = rate != self.rate;
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
    pub const UNKNOWN: Self = Self(0x7f);

    pub const fn is_set(self) -> bool {
        self.0 != Self::UNKNOWN.0
    }
}

impl Default for Bitrate {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl PartialOrd for Bitrate {
    // This compares `UNKNOWN` as higher than all other values.
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl From<(u8, u32)> for Bitrate {
    fn from((first, version): (u8, u32)) -> Self {
        // 7-bit signal: bits [6:1] from first byte, bit [0] from version MSB.
        Self(u8::try_from(version >> 31).expect("always u8") | ((first & 0x3f) << 1))
    }
}

impl From<Bitrate> for Option<NonZeroU64> {
    #[expect(clippy::cast_possible_truncation, reason = "We want truncation here")]
    #[expect(clippy::cast_sign_loss, reason = "negative values are impossible")]
    fn from(value: Bitrate) -> Self {
        value
            .is_set()
            .then(|| {
                // Bitrate formula is 100_000 * 10^(n/20),
                // log10(100_000) is 5, and 10^(1/20) is 1.122...
                NonZeroU64::new(1.122_018_454_301_963_3_f64.powi(100 + i32::from(value.0)) as u64)
            })
            .flatten()
    }
}

#[cfg(test)]
mod test {
    use std::{num::NonZeroU64, time::Duration};

    use test_fixture::now;

    use crate::scone::{Bitrate, Scone};

    const SEC: Duration = Duration::from_secs(1);
    const BASE_RATE: Bitrate = Bitrate(0x10);

    /// Update works the same whether `v` is `None` or `UNKNOWN`.
    fn none_or_unknown(v: Option<Bitrate>) {
        assert!(!Bitrate(0x7f).is_set());

        assert_eq!(Bitrate::UNKNOWN, Bitrate(0x7f));
        let now = now();
        let mut base = Scone::new(now, BASE_RATE);
        let mut other = base.clone();
        assert!(!other.update(now + SEC, v));
        assert_eq!(other.rate, BASE_RATE);

        assert!(base.update(now + Scone::PERIOD, v));
        assert_eq!(base.rate, Bitrate::UNKNOWN);
    }

    #[test]
    fn unknown() {
        none_or_unknown(Some(Bitrate::UNKNOWN));
    }

    #[test]
    fn none() {
        none_or_unknown(None);
    }

    #[test]
    fn reduce() {
        const LOWER_RATE: Bitrate = Bitrate(0x09);

        assert!(LOWER_RATE < BASE_RATE);

        let now = now();
        let mut base = Scone::new(now, BASE_RATE);
        assert!(base.update(now + SEC, Some(LOWER_RATE)));
        assert_eq!(base.rate, LOWER_RATE);
    }

    #[test]
    fn increase() {
        const HIGHER_RATE: Bitrate = Bitrate(0x17);

        assert!(HIGHER_RATE > BASE_RATE);

        let now = now();
        let mut base = Scone::new(now, BASE_RATE);
        assert!(!base.update(now + SEC, Some(HIGHER_RATE)));
        assert_eq!(base.rate, BASE_RATE);
        assert!(base.update(now + Scone::PERIOD, Some(HIGHER_RATE)));
        assert_eq!(base.rate, HIGHER_RATE);
    }

    #[test]
    fn to_rate() {
        let rate = Option::<NonZeroU64>::from(Bitrate::UNKNOWN);
        assert!(rate.is_none());
        let rate = Option::from(Bitrate(0x55));
        assert_eq!(rate, NonZeroU64::new(1_778_279_410));
    }

    #[test]
    fn bitrate_cmp() {
        assert!(Bitrate(0x55) < Bitrate(0x56));
        assert!(Bitrate(0x55) <= Bitrate(0x55));
        assert!(Bitrate(0x55) > Bitrate(0x54));
        assert!(Bitrate(0x55) >= Bitrate(0x55));
        assert!(Bitrate(0x55) < Bitrate::UNKNOWN);
    }
}
