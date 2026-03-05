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
        ClassicSlowStart, classic_cc::ClassicCongestionController, cubic::Cubic, hystart::HyStart,
        new_reno::NewReno,
    },
};

mod cubic;
mod hystart;
mod new_reno;

pub const IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const MTU: Option<usize> = Some(1_500);
pub const RTT: Duration = Duration::from_millis(100);

/// Helper to create `ClassicCongestionController` with New Reno for tests.
pub fn make_cc_newreno() -> ClassicCongestionController<ClassicSlowStart, NewReno> {
    ClassicCongestionController::new(
        ClassicSlowStart::default(),
        NewReno::default(),
        Pmtud::new(IP_ADDR, MTU),
    )
}

/// Helper to create `ClassicCongestionController` with Cubic for tests.
pub fn make_cc_cubic() -> ClassicCongestionController<ClassicSlowStart, Cubic> {
    ClassicCongestionController::new(
        ClassicSlowStart::default(),
        Cubic::default(),
        Pmtud::new(IP_ADDR, MTU),
    )
}

/// Helper to create `ClassicCongestionController` with HyStart++ for tests.
pub fn make_cc_hystart(paced: bool) -> ClassicCongestionController<HyStart, Cubic> {
    ClassicCongestionController::new(
        HyStart::new(paced),
        Cubic::default(),
        Pmtud::new(IP_ADDR, MTU),
    )
}
