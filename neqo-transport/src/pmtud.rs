// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::IpAddr;

use neqo_common::{qdebug, qtrace};

use crate::{
    frame::FRAME_TYPE_PING, packet::PacketBuilder, recovery::SentPacket, stats::FrameStats, Stats,
};

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

// pub type Pmtud = Rc<RefCell<Pmtud>>;

impl Pmtud {
    #[must_use]
    pub fn new(remote_ip: IpAddr) -> Self {
        Self {
            header_size: Self::header_size(remote_ip),
            mtu: MTU_SIZES[MTU_SIZES.len() - 1],
            probed_index: MTU_SIZES.len() - 1,
            probe_count: 0,
            probe_state: Probe::NotNeeded,
        }
    }

    /// Returns the Packetization Layer Path MTU, i.e., the maximum UDP payload that can be sent.
    #[must_use]
    pub fn plpmtu(&self) -> usize {
        self.mtu - self.header_size
    }

    /// Returns true if a PMTUD probe should be sent.
    #[must_use]
    pub fn needs_probe(&self) -> bool {
        self.probe_state == Probe::Needed
    }

    /// Returns true if a PMTUD probe is prepared for sending.
    #[must_use]
    pub fn is_probe_prepared(&self) -> bool {
        self.probe_state == Probe::Prepared
    }

    /// Returns the size of the current PMTUD probe.
    fn probe_size(&self) -> usize {
        MTU_SIZES[self.probed_index] - self.header_size
    }

    /// Prepares a PMTUD probe for sending.
    pub fn prepare_probe(
        &mut self,
        builder: &mut PacketBuilder,
        stats: &mut FrameStats,
        aead_expansion: usize,
    ) {
        builder.set_limit(self.probe_size() - aead_expansion);
        builder.encode_varint(FRAME_TYPE_PING);
        stats.ping += 1;
        stats.all += 1;

        self.probe_state = Probe::Prepared;
        qtrace!(
            "PMTUD probe of size {} prepared",
            MTU_SIZES[self.probed_index]
        );
    }

    /// Records that a PMTUD probe has been sent.
    pub fn probe_sent(&mut self, stats: &mut Stats) {
        self.probe_state = Probe::Sent;
        self.probe_count += 1;
        stats.pmtud_tx += 1;
        qdebug!(
            "PMTUD probe of size {} sent, count {}",
            MTU_SIZES[self.probed_index],
            self.probe_count
        );
    }

    /// Returns true if the packet is a PMTUD probe.
    fn is_pmtud_probe(&self, p: &SentPacket) -> bool {
        p.len() == self.probe_size()
    }

    /// Returns true if no PMTUD action is needed for the given packets.
    fn no_pmtud_action_needed(&self, pkts: &[SentPacket]) -> bool {
        self.probe_state != Probe::Sent
            || pkts.is_empty()
            || !pkts.iter().any(|p| self.is_pmtud_probe(p))
    }

    /// Checks whether a PMTUD probe has been acknowledged, and if so, updates the PMTUD state.
    /// May also initiate a new probe process for a larger MTU.
    pub fn on_packets_acked(&mut self, acked_pkts: &[SentPacket], stats: &mut Stats) {
        if self.no_pmtud_action_needed(acked_pkts) {
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

    /// Checks whether a PMTUD probe has been lost. If it has been lost more than `MAX_PROBES`
    /// times, the PMTUD process is stopped.
    pub fn on_packets_lost(&mut self, lost_packets: &[SentPacket], stats: &mut Stats) {
        if self.no_pmtud_action_needed(lost_packets) {
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

    /// Starts the PMTUD process.
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

    /// Size of the IPv4/IPv6 and UDP headers, in bytes.
    const fn header_size(remote_ip: IpAddr) -> usize {
        match remote_ip {
            IpAddr::V4(_) => 20 + 8,
            IpAddr::V6(_) => 40 + 8,
        }
    }

    /// Returns the default PLPMTU for the given remote IP address.
    #[must_use]
    pub const fn default_plpmtu(remote_ip: IpAddr) -> usize {
        MTU_SIZES[MTU_SIZES.len() - 1] - Self::header_size(remote_ip)
    }
}
