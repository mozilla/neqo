// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{net::IpAddr, time::Instant};

use neqo_common::Datagram;
use neqo_transport::Output;

use super::{Node, Rng};

/// Drops all datagrams larger than the configured MTU.
///
/// The limit includes IP and UDP header size.
#[derive(Debug, derive_more::Constructor)]
#[must_use]
pub struct Mtu {
    mtu: usize,
}

impl Node for Mtu {
    fn init(&mut self, _rng: Rng, _now: Instant) {}

    fn process(&mut self, d: Option<Datagram>, _now: Instant) -> Output {
        d.filter(|dgram| {
            let header = match dgram.destination().ip() {
                IpAddr::V4(_) => 20 + 8,
                IpAddr::V6(_) => 40 + 8,
            };

            header + dgram.len() <= self.mtu
        })
        .into()
    }
}
