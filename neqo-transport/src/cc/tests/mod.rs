// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use super::{CongestionControlAlgorithm, SlowStartAlgorithm};
use crate::{
    cc::{classic_cc::ClassicCongestionControl, cubic::Cubic, new_reno::NewReno, ClassicSlowStart},
    Pmtud,
};

mod cubic;
mod new_reno;

pub const IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const MTU: Option<usize> = Some(1_500);
pub const RTT: Duration = Duration::from_millis(100);

#[test]
fn congestion_control_algorithm_from_str() {
    assert_eq!("cubic".parse(), Ok(CongestionControlAlgorithm::Cubic));
    assert_eq!("reno".parse(), Ok(CongestionControlAlgorithm::NewReno));
    assert!("invalid".parse::<CongestionControlAlgorithm>().is_err());
}

#[test]
fn slow_start_algorithm_from_str() {
    assert_eq!("classic".parse(), Ok(SlowStartAlgorithm::Classic));
    assert_eq!("hystart".parse(), Ok(SlowStartAlgorithm::HyStart));
    assert!("invalid".parse::<CongestionControlAlgorithm>().is_err());
}

/// Helper to create `ClassicCongestionControl` with New Reno for tests.
pub fn make_cc_newreno() -> ClassicCongestionControl<ClassicSlowStart, NewReno> {
    ClassicCongestionControl::new(
        ClassicSlowStart::default(),
        NewReno::default(),
        Pmtud::new(IP_ADDR, MTU),
    )
}

/// Helper to create `ClassicCongestionControl` with Cubic for tests.
pub fn make_cc_cubic() -> ClassicCongestionControl<ClassicSlowStart, Cubic> {
    ClassicCongestionControl::new(
        ClassicSlowStart::default(),
        Cubic::default(),
        Pmtud::new(IP_ADDR, MTU),
    )
}
