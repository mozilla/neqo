// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Instant;

use neqo_common::Datagram;
use neqo_transport::{Output, header_size};

use super::{Node, Rng};

/// Drops all datagrams larger than the configured MTU.
#[derive(Debug)]
pub struct Mtu {
    mtu: usize,
}

impl Mtu {
    /// Creates new [`Mtu`].
    ///
    /// Limit includes IP and UDP header size.
    #[must_use]
    pub const fn new(mtu: usize) -> Self {
        Self { mtu }
    }
}

impl Node for Mtu {
    fn init(&mut self, _rng: Rng, _now: Instant) {}

    fn process(&mut self, d: Option<Datagram>, _now: Instant) -> Output {
        d.filter(|dgram| header_size(dgram.destination().ip()) + dgram.len() <= self.mtu)
            .into()
    }
}

/// Drops all datagrams larger than the configured MTU, with the ability to
/// change MTU after a specified number of packets have passed.
#[derive(Debug)]
pub struct DynamicMtu {
    initial_mtu: usize,
    new_mtu: usize,
    /// Number of packets to pass before switching to `new_mtu`.
    switch_after: usize,
    packet_count: usize,
}

impl DynamicMtu {
    /// Creates a new [`DynamicMtu`] that starts at `initial_mtu` and switches
    /// to `new_mtu` after `switch_after` packets have passed.
    ///
    /// Both MTU values include IP and UDP header size.
    #[must_use]
    pub const fn new(initial_mtu: usize, new_mtu: usize, switch_after: usize) -> Self {
        Self {
            initial_mtu,
            new_mtu,
            switch_after,
            packet_count: 0,
        }
    }

    const fn current_mtu(&self) -> usize {
        if self.packet_count >= self.switch_after {
            self.new_mtu
        } else {
            self.initial_mtu
        }
    }
}

impl Node for DynamicMtu {
    fn init(&mut self, _rng: Rng, _now: Instant) {}

    fn prepare(&mut self, _now: Instant) {
        // Reset packet count so MTU switch happens during main test, not setup.
        self.packet_count = 0;
    }

    fn process(&mut self, d: Option<Datagram>, _now: Instant) -> Output {
        d.filter(|dgram| {
            self.packet_count += 1;
            header_size(dgram.destination().ip()) + dgram.len() <= self.current_mtu()
        })
        .into()
    }
}
