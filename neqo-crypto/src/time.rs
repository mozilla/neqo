// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::err::{Error, Res};

use neqo_common::once::OnceResult;

use std::convert::{TryFrom, TryInto};
use std::ops::Deref;
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/nspr_time.rs"));

/// This struct holds the zero time used for converting between Instant and PRTime.
#[derive(Debug)]
struct TimeZero {
    instant: Instant,
    prtime: PRTime,
}

impl TimeZero {
    /// This function sets a baseline from an instance of `Instant`.
    /// This allows for the possibility that code that uses these APIs will create
    /// instances of `Instant` before any of this code is run.  If `Instant`s older than
    /// `BASE_TIME` are used with these conversion functions, they will fail.
    /// To avoid that, we make sure that this sets the base time using the first value
    /// it sees if it is in the past.  If it is not, then use `Instant::now()` instead.
    pub fn baseline(t: Instant) -> TimeZero {
        let now = Instant::now();
        let prnow = unsafe { PR_Now() };

        if now <= t {
            // `t` is in the future, just use `now`.
            TimeZero {
                instant: now,
                prtime: prnow,
            }
        } else {
            let elapsed = Interval::from(now.duration_since(now));
            // An error from these unwrap functions would require
            // ridiculously long application running time.
            let prelapsed: PRTime = elapsed.try_into().unwrap();
            TimeZero {
                instant: t,
                prtime: prnow.checked_sub(prelapsed).unwrap(),
            }
        }
    }
}

static mut BASE_TIME: OnceResult<TimeZero> = OnceResult::new();

fn get_base() -> &'static TimeZero {
    let f = || TimeZero {
        instant: Instant::now(),
        prtime: unsafe { PR_Now() },
    };
    unsafe { BASE_TIME.call_once(f) }
}

pub(crate) fn init() {
    let _ = get_base();
}

/// Time wraps Instant and provides conversion functions into PRTime.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Time {
    t: Instant,
}

impl Deref for Time {
    type Target = Instant;
    fn deref(&self) -> &Self::Target {
        &self.t
    }
}

impl From<Instant> for Time {
    /// Convert from an Instant into a Time.
    fn from(t: Instant) -> Self {
        // Call `TimeZero::baseline(t)` so that time zero can be set.
        let f = || TimeZero::baseline(t);
        let _ = unsafe { BASE_TIME.call_once(f) };
        Time { t }
    }
}

impl TryFrom<PRTime> for Time {
    type Error = Error;
    fn try_from(prtime: PRTime) -> Res<Time> {
        let base = get_base();
        if let Some(delta) = prtime.checked_sub(base.prtime) {
            if !delta.is_negative() {
                let d = Duration::from_nanos(delta as u64);
                if let Some(t) = base.instant.checked_add(d) {
                    Ok(Time { t })
                } else {
                    Err(Error::TimeTravelError)
                }
            } else {
                Err(Error::TimeTravelError)
            }
        } else {
            Err(Error::TimeTravelError)
        }
    }
}

impl TryInto<PRTime> for Time {
    type Error = Error;
    fn try_into(self) -> Res<PRTime> {
        let base = get_base();
        // TODO(mt) use checked_duration_since when that is available.
        let delta = self.t.duration_since(base.instant);
        if let Ok(d) = PRTime::try_from(delta.as_nanos()) {
            if let Some(v) = d.checked_add(base.prtime) {
                Ok(v)
            } else {
                Err(Error::TimeTravelError)
            }
        } else {
            Err(Error::TimeTravelError)
        }
    }
}

impl Into<Instant> for Time {
    fn into(self) -> Instant {
        self.t
    }
}

/// Interval wraps Duration and provides conversion functions into PRTime.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Interval {
    d: Duration,
}

impl Deref for Interval {
    type Target = Duration;
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

impl TryFrom<PRTime> for Interval {
    type Error = Error;
    fn try_from(prtime: PRTime) -> Res<Interval> {
        Ok(Interval {
            d: Duration::from_nanos(u64::try_from(prtime)?),
        })
    }
}

impl From<Duration> for Interval {
    fn from(d: Duration) -> Interval {
        Interval { d }
    }
}

impl TryInto<PRTime> for Interval {
    type Error = Error;
    fn try_into(self) -> Res<PRTime> {
        Ok(PRTime::try_from(self.d.as_nanos())?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn convert_stable() {
        init();
        let now = Time::from(Instant::now());
        let pr: PRTime = now.try_into().expect("should convert successfully");
        println!("now {:?}", now);
        println!("pr {:?}", pr);
        println!("Time::try_from(pr) {:?}", Time::try_from(pr));
        let t2 = Time::try_from(pr).expect("should convert back too");
        assert_eq!(t2, now);
    }

    #[test]
    fn past_time() {
        init();
        let base = get_base();
        assert!(Time::try_from(base.prtime - 1).is_err());
    }

    #[test]
    fn negative_time() {
        init();
        assert!(Time::try_from(-1).is_err());
    }

    #[test]
    fn negative_interval() {
        init();
        assert!(Interval::try_from(-1).is_err());
    }

    #[test]
    fn overflow_interval() {
        init();
        let interval = Interval::from(Duration::from_nanos(std::u64::MAX));
        let res: Res<PRTime> = interval.try_into();
        assert!(res.is_err());
    }
}
