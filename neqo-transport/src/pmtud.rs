// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, net::IpAddr, rc::Rc};

use neqo_common::{qdebug, qtrace};

use crate::{recovery::SentPacket, Stats};

// From https://datatracker.ietf.org/doc/html/rfc1191#section-7.1, with a few modifications.
const MTU_SIZES: [usize; 12] = [
    65535, // Hyperchannel                  RFC 1044
    17914, // 16Mb IBM Token Ring           ref. [6]
    16384, // macOS loopback
    8166,  // IEEE 802.4                    RFC 1042
    4464,  // IEEE 802.5 (4Mb max)          RFC 1042
    4352,  // FDDI (Revised)                RFC 1188
    2048,  // Wideband Network              RFC 907
    2002,  // IEEE 802.5 (4Mb recommended)  RFC 1042
    1536,  // Exp. Ethernet Nets            RFC 895
    1500,  // Ethernet Networks             RFC 894
    1492,  // IEEE 802.3                    RFC 1042
    1280,  // IPv6 minimum MTU              RFC 2460
];

// From https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2
const MAX_PROBES: usize = 3;

// const PATH_MTU_V6: usize = 1337;
// const PATH_MTU_V4: usize = PATH_MTU_V6 + 20;

#[derive(Debug, PartialEq)]
pub enum Probe {
    NotNeeded,
    Needed,
    Prepared,
    Sent,
}

#[derive(Debug)]
pub struct Pmtud {
    header_size: usize,
    mtu: usize,
    probed_index: usize,
    probe_count: usize,
    probe_state: Probe,
}

pub type PmtudRef = Rc<RefCell<Pmtud>>;

impl Pmtud {
    #[must_use]
    pub fn new(remote_ip: IpAddr) -> PmtudRef {
        Rc::new(RefCell::new(Pmtud {
            header_size: Self::header_size(remote_ip),
            mtu: MTU_SIZES[MTU_SIZES.len() - 1],
            probed_index: MTU_SIZES.len() - 1,
            probe_count: 0,
            probe_state: Probe::NotNeeded,
        }))
    }

    #[must_use]
    pub fn plpmtu(&self) -> usize {
        self.mtu - self.header_size
    }

    #[must_use]
    pub fn needs_probe(&self) -> bool {
        self.probe_state == Probe::Needed
    }

    #[must_use]
    pub fn is_probe_prepared(&self) -> bool {
        self.probe_state == Probe::Prepared
    }

    pub fn probe_prepared(&mut self) {
        self.probe_state = Probe::Prepared;
        qtrace!(
            "PMTUD probe of size {} prepared",
            MTU_SIZES[self.probed_index]
        );
    }

    pub fn probe_sent(&mut self, stats: &mut Stats) -> bool {
        self.probe_state = Probe::Sent;
        self.probe_count += 1;
        stats.pmtud_tx += 1;
        qdebug!(
            "PMTUD probe of size {} sent, count {}",
            MTU_SIZES[self.probed_index],
            self.probe_count
        );
        true
    }

    #[must_use]
    pub fn is_pmtud_probe(&self, p: &SentPacket) -> bool {
        self.probe_state == Probe::Sent
            && p.len() == self.probe_size()
    }

    pub fn on_packets_acked(&mut self, acked_pkts: &[SentPacket], stats: &mut Stats) {
        if self.probe_state != Probe::Sent
            || acked_pkts.is_empty()
            || !acked_pkts.iter().any(|p| self.is_pmtud_probe(p))
        {
            return;
        }
        stats.pmtud_ack += 1;
        self.mtu = MTU_SIZES[self.probed_index];
        qdebug!(
            "PMTUD probe of size {} succeeded",
            MTU_SIZES[self.probed_index]
        );
        self.start_pmtud();
    }

    pub fn on_packets_lost(&mut self, lost_packets: &[SentPacket], stats: &mut Stats) {
        if self.probe_state != Probe::Sent
            || lost_packets.is_empty()
            || !lost_packets.iter().any(|p| self.is_pmtud_probe(p))
        {
            return;
        }
        stats.pmtud_lost += 1;
        if self.probe_count < MAX_PROBES {
            self.probe_state = Probe::Needed;
            qdebug!(
                "PMTUD probe of size {} lost, retrying",
                MTU_SIZES[self.probed_index]
            );
        } else {
            self.probe_state = Probe::NotNeeded;
            qdebug!(
                "PMTUD probe of size {} lost {} times, stopping PMTUD, PLPMTU is {}",
                MTU_SIZES[self.probed_index],
                self.probe_count,
                self.plpmtu()
            );
        }
    }

    #[must_use]
    pub fn probe_size(&self) -> usize {
        MTU_SIZES[self.probed_index] - self.header_size
    }

    pub fn start_pmtud(&mut self) {
        if self.probed_index > 0 {
            self.probe_state = Probe::Needed;
            self.probe_count = 0;
            self.probed_index -= 1;
            qdebug!(
                "PMTUD started with probe size {}",
                MTU_SIZES[self.probed_index],
            );
        } else {
            self.probe_state = Probe::NotNeeded;
            qdebug!("PMTUD already completed, MTU is {}", self.mtu);
        }
    }

    const fn header_size(remote_ip: IpAddr) -> usize {
        match remote_ip {
            IpAddr::V4(_) => 20 + 8,
            IpAddr::V6(_) => 40 + 8,
        }
    }

    pub const fn default_plpmtu(remote_ip: IpAddr) -> usize {
        MTU_SIZES[MTU_SIZES.len() - 1] - Self::header_size(remote_ip)
    }
}
