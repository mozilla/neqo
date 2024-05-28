// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use neqo_common::{qdebug, qtrace};

use crate::{
    frame::FRAME_TYPE_PING, packet::PacketBuilder, recovery::SentPacket, stats::FrameStats, Stats,
};

// Values <= 1500 based on: A. Custura, G. Fairhurst and I. Learmonth, "Exploring Usable Path MTU in
// the Internet," 2018 Network Traffic Measurement and Analysis Conference (TMA), Vienna, Austria,
// 2018, pp. 1-8, doi: 10.23919/TMA.2018.8506538. keywords:
// {Servers;Probes;Tools;Clamps;Middleboxes;Standards},
const MTU_SIZES_V4: [usize; 11] = [
    1280, 1380, 1420, 1472, 1500, 2047, 4095, 8191, 16383, 32767, 65535,
];
const MTU_SIZES_V6: [usize; 10] = [
    1280, 1380, 1470, 1500, 2047, 4095, 8191, 16383, 32767, 65535,
];

// From https://datatracker.ietf.org/doc/html/rfc8899#section-5.1
const MAX_PROBES: usize = 3;
const PMTU_RAISE_TIMER: Duration = Duration::from_secs(600);

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
    probe_index: usize,
    probe_count: usize,
    probe_state: Probe,
    loss_counts: Vec<usize>,
    raise_timer: Option<Instant>,
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
        let probe_index = 0;
        Self {
            search_table,
            header_size: Self::header_size(remote_ip),
            mtu: search_table[probe_index],
            probe_index,
            probe_count: 0,
            probe_state: Probe::NotNeeded,
            loss_counts: vec![0; search_table.len()],
            raise_timer: None,
        }
    }

    /// Checks whether the PMTUD raise timer should be fired, and does so if needed.
    pub fn maybe_fire_pmtud_raise_timer(&mut self, now: Instant) {
        if let Some(raise_timer) = self.raise_timer {
            if self.probe_state == Probe::NotNeeded && now >= raise_timer {
                qdebug!("PMTUD raise timer fired");
                self.start_pmtud();
            }
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
        self.search_table[self.probe_index] - self.header_size
    }

    /// Prepares a PMTUD probe for sending.
    pub fn prepare_probe(
        &mut self,
        builder: &mut PacketBuilder,
        stats: &mut FrameStats,
        aead_expansion: usize,
    ) {
        builder.set_limit(self.probe_size() - aead_expansion);
        // The packet may include ACK-eliciting data already, but rather than check for that, it
        // seems OK to burn one byte here to simply include a PING.
        builder.encode_varint(FRAME_TYPE_PING);
        stats.ping += 1;
        stats.all += 1;

        self.probe_state = Probe::Prepared;
        qtrace!(
            "PMTUD probe of size {} prepared",
            self.search_table[self.probe_index]
        );
    }

    /// Records that a PMTUD probe has been sent.
    pub fn probe_sent(&mut self, stats: &mut Stats) {
        self.probe_state = Probe::Sent;
        self.probe_count += 1;
        stats.pmtud_tx += 1;
        qdebug!(
            "PMTUD probe of size {} sent, count {}",
            self.search_table[self.probe_index],
            self.probe_count
        );
    }

    /// Returns true if the packet is a PMTUD probe.
    #[must_use]
    pub fn is_pmtud_probe(&self, p: &SentPacket) -> bool {
        self.probe_state == Probe::Sent && p.len() == self.probe_size()
    }

    /// Count the PMTUD probes included in `pkts`.
    fn count_pmtud_probes(&self, pkts: &[SentPacket]) -> usize {
        pkts.iter().filter(|p| self.is_pmtud_probe(p)).count()
    }

    /// Checks whether a PMTUD probe has been acknowledged, and if so, updates the PMTUD state.
    /// May also initiate a new probe process for a larger MTU.
    pub fn on_packets_acked(&mut self, acked_pkts: &[SentPacket], stats: &mut Stats) {
        let acked = self.count_pmtud_probes(acked_pkts);
        if acked == 0 {
            return;
        }
        // A probe was ACKed, confirm the new MTU and try to probe upwards further.
        stats.pmtud_ack += acked;
        self.mtu = self.search_table[self.probe_index];
        qdebug!("PMTUD probe of size {} succeeded", self.mtu);
        self.start_pmtud();
    }

    /// Stops the PMTUD process, setting the MTU to the largest successful probe size.
    fn stop_pmtud(&mut self, idx: usize, now: Instant) {
        self.probe_state = Probe::NotNeeded; // We don't need to send any more probes
        self.probe_index = idx; // Index of the last successful probe
        self.mtu = self.search_table[idx]; // Leading to this MTU
        self.probe_count = 0; // Reset the count
        self.loss_counts = vec![0; self.search_table.len()]; // Reset the loss counts
        self.raise_timer = Some(now + PMTU_RAISE_TIMER);
        qdebug!(
            "PMTUD stopped, PLPMTU is now {}, raise timer {:?}",
            self.mtu,
            self.raise_timer.unwrap()
        );
    }

    /// Checks whether a PMTUD probe has been lost. If it has been lost more than `MAX_PROBES`
    /// times, the PMTUD process is stopped.
    pub fn on_packets_lost(
        &mut self,
        lost_packets: &[SentPacket],
        stats: &mut Stats,
        now: Instant,
    ) {
        // Track lost probes
        let lost = self.count_pmtud_probes(lost_packets);
        stats.pmtud_lost += lost;

        // Increase loss counts for all sizes included in the lost packets.
        for (count, inc) in self.loss_counts.iter_mut().zip(
            self.search_table
                .iter()
                .map(|len| lost_packets.iter().filter(|p| p.len() > *len).count()),
        ) {
            *count += inc;
        }

        // Check if any packet of size > MTU has been lost MAX_PROBES times or more.
        let Some(last_good) = self.loss_counts.iter().rposition(|&c| c >= MAX_PROBES) else {
            // If not, keep going.
            if lost > 0 {
                // Don't stop the PMTUD process.
                self.probe_state = Probe::Needed;
            }
            return;
        };

        qdebug!("Packet of size > {} lost {} times", self.mtu, MAX_PROBES);
        self.stop_pmtud(last_good, now);
    }

    /// Starts the next upward PMTUD probe.
    pub fn start_pmtud(&mut self) {
        if self.probe_index < self.search_table.len() - 1 {
            self.probe_state = Probe::Needed; // We need to send a probe
            self.probe_count = 0; // For the first time
            self.probe_index += 1; // At this size
            qdebug!(
                "PMTUD started with probe size {}",
                self.search_table[self.probe_index],
            );
        } else {
            // If we're at the end of the search table, we're done.
            self.probe_state = Probe::NotNeeded;
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
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Instant,
    };

    use neqo_common::{qdebug, Encoder, IpTosEcn};
    use test_fixture::{fixture_init, now};

    use crate::{
        crypto::CryptoDxState,
        packet::{PacketBuilder, PacketType},
        pmtud::PMTU_RAISE_TIMER,
        recovery::SentPacket,
        Pmtud, Stats,
    };

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

    fn make_sentpacket(pn: u64, now: Instant, len: usize) -> SentPacket {
        SentPacket::new(
            PacketType::Short,
            pn,
            IpTosEcn::default(),
            now,
            true,
            Vec::new(),
            len,
        )
    }

    fn assert_mtu(pmtud: &Pmtud, mtu: usize) {
        let idx = pmtud
            .search_table
            .iter()
            .position(|x| *x == pmtud.mtu)
            .unwrap();
        assert!(mtu >= pmtud.search_table[idx]);
        if idx < pmtud.search_table.len() - 1 {
            assert!(mtu < pmtud.search_table[idx + 1]);
        }
    }

    fn pmtud_step(
        pmtud: &mut Pmtud,
        stats: &mut Stats,
        prot: &mut CryptoDxState,
        addr: IpAddr,
        mtu: usize,
        now: Instant,
    ) {
        let stats_before = stats.clone();

        // Fake a packet number, so the builder logic works.
        let mut builder = PacketBuilder::short(Encoder::new(), false, []);
        let pn = prot.next_pn();
        builder.pn(pn, 4);
        pmtud.prepare_probe(&mut builder, &mut stats.frame_tx, prot.expansion());
        // Add padding, which Connection::output_path normally does.
        builder.enable_padding(true);
        builder.pad();
        let encoder = builder.build(prot).unwrap();
        assert_eq!(encoder.len(), pmtud.probe_size());
        assert!(pmtud.is_probe_prepared());
        assert!(!pmtud.needs_probe());

        pmtud.probe_sent(stats);
        assert_eq!(stats_before.pmtud_tx + 1, stats.pmtud_tx);
        assert!(!pmtud.needs_probe());

        let packet = make_sentpacket(pn, now, encoder.len());
        if encoder.len() + Pmtud::header_size(addr) <= mtu {
            pmtud.on_packets_acked(&[packet], stats);
            assert_eq!(stats_before.pmtud_ack + 1, stats.pmtud_ack);
        } else {
            pmtud.on_packets_lost(&[packet], stats, now);
            assert_eq!(stats_before.pmtud_lost + 1, stats.pmtud_lost);
        }
    }

    fn find_pmtu(addr: IpAddr, mtu: usize) {
        fixture_init();
        let now = now();
        let mut pmtud = Pmtud::new(addr);
        let mut stats = Stats::default();
        let mut prot = CryptoDxState::test_default();

        pmtud.start_pmtud();
        assert!(pmtud.needs_probe());

        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, addr, mtu, now);
        }
        assert_mtu(&pmtud, mtu);
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

    fn find_pmtu_with_reduction(addr: IpAddr, mtu: usize, smaller_mtu: usize) {
        assert!(mtu > smaller_mtu);

        fixture_init();
        let now = now();
        let mut pmtud = Pmtud::new(addr);
        let mut stats = Stats::default();
        let mut prot = CryptoDxState::test_default();

        assert!(smaller_mtu >= pmtud.search_table[0]);
        pmtud.start_pmtud();
        assert!(pmtud.needs_probe());

        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, addr, mtu, now);
        }
        assert_mtu(&pmtud, mtu);

        qdebug!("Reducing MTU to {}", smaller_mtu);
        while pmtud.mtu > smaller_mtu {
            let pn = prot.next_pn();
            let packet = make_sentpacket(pn, now, pmtud.mtu);
            pmtud.on_packets_lost(&[packet], &mut stats, now);
        }
        assert_mtu(&pmtud, smaller_mtu);
    }

    #[test]
    fn test_pmtud_v4_max_1300() {
        find_pmtu_with_reduction(V4, u16::MAX.into(), 1300);
    }

    #[test]
    fn test_pmtud_v6_max_1280() {
        find_pmtu_with_reduction(V6, u16::MAX.into(), 1300);
    }

    #[test]
    fn test_pmtud_v4_1500_1300() {
        find_pmtu_with_reduction(V4, 1500, 1300);
    }

    #[test]
    fn test_pmtud_v6_1500_1280() {
        find_pmtu_with_reduction(V6, 1500, 1280);
    }
    fn find_pmtu_with_increase(addr: IpAddr, mtu: usize, larger_mtu: usize) {
        assert!(mtu < larger_mtu);

        fixture_init();
        let now = now();
        let mut pmtud = Pmtud::new(addr);
        let mut stats = Stats::default();
        let mut prot = CryptoDxState::test_default();

        assert!(larger_mtu >= pmtud.search_table[0]);
        pmtud.start_pmtud();
        assert!(pmtud.needs_probe());

        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, addr, mtu, now);
        }
        assert_mtu(&pmtud, mtu);

        qdebug!("Increasing MTU to {}", larger_mtu);
        let now = now + PMTU_RAISE_TIMER;
        pmtud.maybe_fire_pmtud_raise_timer(now);
        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, addr, larger_mtu, now);
        }
        assert_mtu(&pmtud, larger_mtu);
    }

    #[test]
    fn test_pmtud_v4_1300_max() {
        find_pmtu_with_increase(V4, 1300, u16::MAX.into());
    }

    #[test]
    fn test_pmtud_v6_1280_max() {
        find_pmtu_with_increase(V6, 1280, u16::MAX.into());
    }

    #[test]
    fn test_pmtud_v4_1300_1500() {
        find_pmtu_with_increase(V4, 1300, 1500);
    }

    #[test]
    fn test_pmtud_v6_1280_1500() {
        find_pmtu_with_increase(V6, 1280, 1500);
    }
}
