// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, net::IpAddr, rc::Rc};

use neqo_common::{const_max, qdebug, qtrace};

use crate::{recovery::SentPacket, Stats};

/// This is the MTU that we assume when using IPv6.
/// We use this size for Initial packets, so we don't need to worry about probing for support.
/// If the path doesn't support this MTU, we will assume that it doesn't support QUIC.
///
/// This is a multiple of 16 greater than the largest possible short header (1 + 20 + 4).
const PATH_MTU_V6: usize = 1337;
/// The path MTU for IPv4 can be 20 bytes larger than for v6.
const PATH_MTU_V4: usize = PATH_MTU_V6 + 20;

// From https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2
const MAX_PROBES: usize = 1;
// const MIN_PLPMTU: usize = MIN_INITIAL_PACKET_SIZE;
const MAX_PLPMTU: usize = 16384; // TODO: Get from interface.
                                 // const BASE_PLPMTU: usize = MIN_PLPMTU;

#[derive(Debug, PartialEq)]
pub enum PmtudState {
    Disabled,
    // Base,
    Searching,
    // SearchComplete,
    // Error,
}

#[derive(Debug, PartialEq)]
pub enum Probe {
    NotNeeded,
    Needed,
    Prepared,
    Sent,
}

#[derive(Debug)]
pub struct Pmtud {
    // remote_ip: IpAddr,
    state: PmtudState,
    mtu: usize,
    probed_size: usize,
    probe_count: usize,
    probe_state: Probe,
    low: usize,
    high: usize,
}

pub type PmtudRef = Rc<RefCell<Pmtud>>;

impl Pmtud {
    #[must_use]
    pub fn new(remote_ip: IpAddr) -> PmtudRef {
        Rc::new(RefCell::new(Pmtud {
            // remote_ip,
            state: PmtudState::Disabled,
            mtu: Pmtud::default_mtu(remote_ip),
            probed_size: 0,
            probe_count: 0,
            probe_state: Probe::NotNeeded,
            low: Pmtud::default_mtu(remote_ip),
            high: MAX_PLPMTU,
        }))
    }

    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    #[must_use]
    pub fn needs_probe(&self) -> bool {
        match self.state {
            PmtudState::Searching => self.probe_state == Probe::Needed,
            PmtudState::Disabled => false,
        }
    }

    #[must_use]
    pub fn is_probe_prepared(&self) -> bool {
        self.probe_state == Probe::Prepared
    }

    pub fn probe_prepared(&mut self) {
        self.probe_state = Probe::Prepared;
        qtrace!("PMTUD probe of size {} prepared", self.probed_size);
    }

    pub fn probe_sent(&mut self, stats: &mut Stats) -> bool {
        self.probe_state = Probe::Sent;
        self.probe_count += 1;
        stats.pmtud_tx += 1;
        qdebug!(
            "PMTUD probe of size {} sent, count {}",
            self.probed_size,
            self.probe_count
        );
        true
    }

    #[must_use]
    pub fn is_pmtud_probe(&self, p: &SentPacket) -> bool {
        p.len() == self.probed_size + p.aead_expansion()
    }

    pub fn on_packets_acked(&mut self, acked_pkts: &[SentPacket], stats: &mut Stats) {
        if self.state != PmtudState::Searching || acked_pkts.is_empty() {
            return;
        }
        if !acked_pkts.iter().any(|p| self.is_pmtud_probe(p)) {
            return;
        }
        qdebug!(
            "PMTUD probe of size {} succeeded, setting as new MTU",
            self.probed_size
        );
        stats.pmtud_ack += 1;
        self.mtu = self.probed_size;
        self.low = self.probed_size;
        self.set_state(PmtudState::Searching);
    }

    pub fn on_packets_lost(&mut self, lost_packets: &[SentPacket], stats: &mut Stats) {
        if self.state != PmtudState::Searching || lost_packets.is_empty() {
            return;
        }
        if !lost_packets.iter().any(|p| self.is_pmtud_probe(p)) {
            return;
        }
        stats.pmtud_lost += 1;
        if self.probe_count < MAX_PROBES {
            self.probe_state = Probe::Needed;
            qdebug!("PMTUD probe of size {} lost, retrying", self.probed_size);
            return;
        }
        qdebug!(
            "PMTUD probe of size {} lost {} times",
            self.probed_size,
            self.probe_count
        );
        self.high = self.probed_size;
        self.set_state(PmtudState::Searching);
    }

    #[must_use]
    pub fn probe_size(&self) -> usize {
        self.probed_size
    }

    pub fn set_state(&mut self, state: PmtudState) {
        qdebug!(
            "PMTUD state {:?} -> {:?}, current MTU {}",
            self.state,
            state,
            self.mtu
        );
        self.state = state;
        match self.state {
            PmtudState::Searching => {
                if self.probed_size == 0 {
                    self.probe_state = Probe::Needed;
                    self.probe_count = 0;
                    self.probed_size = MAX_PLPMTU;
                } else if self.low == self.high {
                    self.set_state(PmtudState::Disabled);
                    return;
                } else {
                    self.probe_state = Probe::Needed;
                    self.probe_count = 0;
                    self.probed_size = self.low + (self.high - self.low) / 2;
                }
                qdebug!(
                    "PMTUD search started in range [{}..{}], probed_size={}",
                    self.low,
                    self.high,
                    self.probed_size
                );
            }
            PmtudState::Disabled => {
                self.probe_state = Probe::NotNeeded;
            }
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
