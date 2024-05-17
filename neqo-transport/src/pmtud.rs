// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, net::IpAddr, rc::Rc};

use neqo_common::{const_max, qdebug};

/// This is the MTU that we assume when using IPv6.
/// We use this size for Initial packets, so we don't need to worry about probing for support.
/// If the path doesn't support this MTU, we will assume that it doesn't support QUIC.
///
/// This is a multiple of 16 greater than the largest possible short header (1 + 20 + 4).
const PATH_MTU_V6: usize = 1337;
/// The path MTU for IPv4 can be 20 bytes larger than for v6.
const PATH_MTU_V4: usize = PATH_MTU_V6 + 20;

// From https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2
// const MAX_PROBES: usize = 3;
// const MIN_PLPMTU: usize = MIN_INITIAL_PACKET_SIZE;
// const MAX_PLPMTU: usize = 9202; // TODO: Get from interface.
// const BASE_PLPMTU: usize = MIN_PLPMTU;

#[derive(Debug)]
pub(crate) enum PmtudState {
    Disabled,
    // Base,
    Searching,
    // SearchComplete,
    // Error,
}

#[derive(Debug)]
pub struct Pmtud {
    remote_ip: IpAddr,
    state: PmtudState,
    probed_size: usize,
    probed_count: usize,
}

pub(crate) type PmtudRef = Rc<RefCell<Pmtud>>;

impl Pmtud {
    pub(crate) fn new(remote_ip: IpAddr) -> PmtudRef {
        Rc::new(RefCell::new(Pmtud {
            remote_ip,
            state: PmtudState::Disabled,
            probed_size: Pmtud::default_mtu(remote_ip),
            probed_count: 0,
        }))
    }

    pub(crate) fn mtu(&self) -> usize {
        self.probed_size
    }

    pub(crate) fn set_state(&mut self, state: PmtudState) {
        qdebug!("PMTUD state now {:?}", state);
        self.state = state;
        match self.state {
            PmtudState::Searching => {
                self.probed_count = 0;
            }
            _ => {}
        }
    }

    #[must_use]
    pub const fn default_mtu(remote_ip: IpAddr) -> usize {
        match remote_ip {
            IpAddr::V4(_) => PATH_MTU_V4,
            IpAddr::V6(_) => PATH_MTU_V6,
        }
    }

    #[must_use]
    pub const fn max_default_mtu() -> usize {
        const_max(PATH_MTU_V4, PATH_MTU_V6)
    }
}
