// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use crate::{
    Pmtud,
    cc::{
        ClassicSlowStart, classic_cc::ClassicCongestionControl, cubic::Cubic, hystart::HyStart,
        new_reno::NewReno,
    },
};

mod cubic;
mod hystart;
mod new_reno;

pub const IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const MTU: Option<usize> = Some(1_500);
pub const RTT: Duration = Duration::from_millis(100);

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

/// Helper to create `ClassicCongestionControl` with HyStart++ for tests.
pub fn make_cc_hystart(paced: bool) -> ClassicCongestionControl<HyStart, NewReno> {
    ClassicCongestionControl::new(
        HyStart::new(paced),
        NewReno::default(),
        Pmtud::new(IP_ADDR, MTU),
    )
}
