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

// Based on: A. Custura, G. Fairhurst and I. Learmonth, "Exploring Usable Path MTU in the Internet,"
// 2018 Network Traffic Measurement and Analysis Conference (TMA), Vienna, Austria, 2018, pp. 1-8,
// doi: 10.23919/TMA.2018.8506538. keywords: {Servers;Probes;Tools;Clamps;Middleboxes;Standards},
const MTU_SIZES_V4: [usize; 11] = [
    1280, 1380, 1420, 1472, 1500, 2047, 4095, 8191, 16383, 32767, 65535,
];
const MTU_SIZES_V6: [usize; 10] = [
    1280, 1380, 1470, 1500, 2047, 4095, 8191, 16383, 32767, 65535,
];

// From https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2
const MAX_PROBES: usize = 3;

#[derive(Debug, PartialEq)]
enum Probe {
    NotNeeded,
    Needed,
    Prepared,
    Sent,
}

#[derive(Debug)]
pub struct Pmtud {
    search_table: &'static [usize],
    header_size: usize,
    mtu: usize,
    probed_index: usize,
    probe_count: usize,
    probe_state: Probe,
}

impl Pmtud {
    /// Returns the MTU search table for the given remote IP address family.
    const fn search_table(remote_ip: IpAddr) -> &'static [usize] {
        match remote_ip {
            IpAddr::V4(_) => &MTU_SIZES_V4,
            IpAddr::V6(_) => &MTU_SIZES_V6,
        }
    }

    /// Size of the IPv4/IPv6 and UDP headers, in bytes.
    const fn header_size(remote_ip: IpAddr) -> usize {
        match remote_ip {
            IpAddr::V4(_) => 20 + 8,
            IpAddr::V6(_) => 40 + 8,
        }
    }

    #[must_use]
    pub fn new(remote_ip: IpAddr) -> Self {
        let search_table = Self::search_table(remote_ip);
        let probed_index = 0;
        Self {
            search_table,
            header_size: Self::header_size(remote_ip),
            mtu: search_table[probed_index],
            probed_index,
            probe_count: 0,
            probe_state: Probe::NotNeeded,
        }
    }

    /// Returns the current Packetization Layer Path MTU, i.e., the maximum UDP payload that can be
    /// sent. During probing, this may be smaller than the actual path MTU.
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
        self.search_table[self.probed_index] - self.header_size
    }

    /// Prepares a PMTUD probe for sending.
    pub fn prepare_probe(
        &mut self,
        builder: &mut PacketBuilder,
        stats: &mut FrameStats,
        aead_expansion: usize,
    ) {
        builder.set_limit(self.probe_size() - aead_expansion);
        // The packet may include ACK-elicitng data already, but rather than check for that, it
        // seems OK to burn one byte here to simply include a PING.
        builder.encode_varint(FRAME_TYPE_PING);
        stats.ping += 1;
        stats.all += 1;

        self.probe_state = Probe::Prepared;
        qtrace!(
            "PMTUD probe of size {} prepared",
            self.search_table[self.probed_index]
        );
    }

    /// Records that a PMTUD probe has been sent.
    pub fn probe_sent(&mut self, stats: &mut Stats) {
        self.probe_state = Probe::Sent;
        self.probe_count += 1;
        stats.pmtud_tx += 1;
        qdebug!(
            "PMTUD probe of size {} sent, count {}",
            self.search_table[self.probed_index],
            self.probe_count
        );
    }

    /// Returns true if the packet is a PMTUD probe.
    fn is_pmtud_probe(&self, p: &SentPacket) -> bool {
        p.len() == self.probe_size()
    }

    /// Returns true if any PMTUD probes are included in `pkts`.
    fn has_pmtud_probes(&self, pkts: &[SentPacket]) -> bool {
        self.probe_state == Probe::Sent
            && !pkts.is_empty()
            && pkts.iter().any(|p| self.is_pmtud_probe(p))
    }

    /// Checks whether a PMTUD probe has been acknowledged, and if so, updates the PMTUD state.
    /// May also initiate a new probe process for a larger MTU.
    pub fn on_packets_acked(&mut self, acked_pkts: &[SentPacket], stats: &mut Stats) {
        if !self.has_pmtud_probes(acked_pkts) {
            return;
        }
        stats.pmtud_ack += 1;
        self.mtu = self.search_table[self.probed_index];
        qdebug!(
            "PMTUD probe of size {} succeeded",
            self.search_table[self.probed_index]
        );
        self.start_pmtud();
    }

    /// Checks whether a PMTUD probe has been lost. If it has been lost more than `MAX_PROBES`
    /// times, the PMTUD process is stopped.
    pub fn on_packets_lost(&mut self, lost_packets: &[SentPacket], stats: &mut Stats) {
        if !self.has_pmtud_probes(lost_packets) {
            return;
        }
        stats.pmtud_lost += 1;
        if self.probe_count < MAX_PROBES {
            self.probe_state = Probe::Needed;
            qdebug!(
                "PMTUD probe of size {} lost, retrying",
                self.search_table[self.probed_index]
            );
        } else {
            self.probe_state = Probe::NotNeeded;
            qdebug!(
                "PMTUD probe of size {} lost {} times, stopping PMTUD, PLPMTU is {}",
                self.search_table[self.probed_index],
                self.probe_count,
                self.plpmtu()
            );
        }
    }

    /// Starts the PMTUD process.
    pub fn start_pmtud(&mut self) {
        if self.probed_index < self.search_table.len() - 1 {
            self.probe_state = Probe::Needed;
            self.probe_count = 0;
            self.probed_index += 1;
            qdebug!(
                "PMTUD started with probe size {}",
                self.search_table[self.probed_index],
            );
        } else {
            self.probe_state = Probe::NotNeeded;
            qdebug!("PMTUD already completed, MTU is {}", self.mtu);
        }
    }

    /// Returns the default PLPMTU for the given remote IP address.
    #[must_use]
    pub const fn default_plpmtu(remote_ip: IpAddr) -> usize {
        let search_table = Self::search_table(remote_ip);
        search_table[0] - Self::header_size(remote_ip)
    }
}

#[cfg(all(not(feature = "disable-encryption"), test))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use neqo_common::{Encoder, IpTosEcn};
    use test_fixture::{fixture_init, now};

    use crate::{
        crypto::CryptoDxState,
        packet::{PacketBuilder, PacketType},
        recovery::SentPacket,
        Pmtud, Stats,
    };

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

    fn make_sentpacket(pn: u64, len: usize) -> SentPacket {
        SentPacket::new(
            PacketType::Short,
            pn,
            IpTosEcn::default(),
            now(),
            true,
            Vec::new(),
            len,
        )
    }

    fn find_pmtu(addr: IpAddr, mtu: usize) {
        fixture_init();
        let mut pmtud = Pmtud::new(addr);
        let mut stats = Stats::default();
        let mut prot = CryptoDxState::test_default();

        pmtud.start_pmtud();
        assert!(pmtud.needs_probe());

        while pmtud.needs_probe() {
            let stats_before = stats.clone();

            // Fake a packet number, so the builder logic works.
            let mut builder = PacketBuilder::short(Encoder::new(), false, []);
            let pn = prot.next_pn();
            builder.pn(pn, 4);
            pmtud.prepare_probe(&mut builder, &mut stats.frame_tx, prot.expansion());
            // Add padding, which Connection::output_path normally does.
            builder.enable_padding(true);
            builder.pad();
            let encoder = builder.build(&mut prot).unwrap();
            assert_eq!(encoder.len(), pmtud.probe_size());
            assert!(pmtud.is_probe_prepared());
            assert!(!pmtud.needs_probe());

            pmtud.probe_sent(&mut stats);
            assert!(stats_before.pmtud_tx + 1 == stats.pmtud_tx);
            assert!(!pmtud.needs_probe());

            let packet = make_sentpacket(pn, encoder.len());
            if encoder.len() + Pmtud::header_size(addr) <= mtu {
                pmtud.on_packets_acked(&[packet], &mut stats);
                assert!(stats_before.pmtud_ack + 1 == stats.pmtud_ack);
            } else {
                pmtud.on_packets_lost(&[packet], &mut stats);
                assert!(stats_before.pmtud_lost + 1 == stats.pmtud_lost);
            }
        }
        assert_eq!(mtu, pmtud.mtu);
    }

    #[test]
    fn test_pmtud_v4_max() {
        find_pmtu(V4, u16::MAX.into());
    }

    #[test]
    fn test_pmtud_v6_max() {
        find_pmtu(V6, u16::MAX.into());
    }

    #[test]
    fn test_pmtud_v4_1500() {
        find_pmtu(V4, 1500);
    }

    #[test]
    fn test_pmtud_v6_1500() {
        find_pmtu(V6, 1500);
    }
}
