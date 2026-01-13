// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use neqo_common::{qdebug, qinfo, Buffer};
use static_assertions::const_assert;

use crate::{
    frame::{FrameEncoder as _, FrameType},
    packet,
    recovery::{self, sent},
    Stats,
};

// Values <= 1500 based on: A. Custura, G. Fairhurst and I. Learmonth, "Exploring Usable Path MTU in
// the Internet," 2018 Network Traffic Measurement and Analysis Conference (TMA), Vienna, Austria,
// 2018, pp. 1-8, doi: 10.23919/TMA.2018.8506538. keywords:
// {Servers;Probes;Tools;Clamps;Middleboxes;Standards},
const MTU_SIZES_V4: &[usize] = &[
    1280, 1380, 1420, 1472, 1500, 2047, 4095, 8191, 16383, 32767, 65535,
];
const MTU_SIZES_V6: &[usize] = &[
    1280, 1380,
    1420, // 1420 is not in the paper for v6, but adding it makes the arrays the same length
    1470, 1500, 2047, 4095, 8191, 16383, 32767, 65535,
];
const_assert!(MTU_SIZES_V4.len() == MTU_SIZES_V6.len());
const SEARCH_TABLE_LEN: usize = MTU_SIZES_V4.len();

// From https://datatracker.ietf.org/doc/html/rfc8899#section-5.1
const MAX_PROBES: usize = 3;
const PMTU_RAISE_TIMER: Duration = Duration::from_secs(600);

#[derive(Debug, PartialEq, Clone, Copy)]
enum Probe {
    NotNeeded,
    Needed,
    Sent,
}

#[derive(Debug)]
pub struct Pmtud {
    search_table: &'static [usize],
    header_size: usize,
    mtu: usize,
    iface_mtu: usize,
    probe_index: usize,
    probe_count: usize,
    probe_state: Probe,
    raise_timer: Option<Instant>,
}

impl Pmtud {
    /// Returns the MTU search table for the given remote IP address family.
    const fn search_table(remote_ip: IpAddr) -> &'static [usize] {
        match remote_ip {
            IpAddr::V4(_) => MTU_SIZES_V4,
            IpAddr::V6(_) => MTU_SIZES_V6,
        }
    }

    /// Size of the IPv4/IPv6 and UDP headers, in bytes.
    #[must_use]
    pub const fn header_size(remote_ip: IpAddr) -> usize {
        match remote_ip {
            IpAddr::V4(_) => 20 + 8,
            IpAddr::V6(_) => 40 + 8,
        }
    }

    #[must_use]
    pub fn new(remote_ip: IpAddr, iface_mtu: Option<usize>) -> Self {
        let search_table = Self::search_table(remote_ip);
        let probe_index = 0;
        Self {
            search_table,
            header_size: Self::header_size(remote_ip),
            mtu: search_table[probe_index],
            iface_mtu: iface_mtu.unwrap_or(usize::MAX),
            probe_index,
            probe_count: 0,
            probe_state: Probe::NotNeeded,
            raise_timer: None,
        }
    }

    /// Checks whether the PMTUD raise timer should be fired, and does so if needed.
    pub fn maybe_fire_raise_timer(&mut self, now: Instant, stats: &mut Stats) {
        if self.probe_state == Probe::NotNeeded && self.raise_timer.is_some_and(|t| now >= t) {
            qdebug!("PMTUD raise timer fired");
            self.raise_timer = None;
            self.next(now, stats);
        }
    }

    /// Returns the current Packetization Layer Path MTU, i.e., the maximum UDP payload that can be
    /// sent. During probing, this may be larger than the actual path MTU.
    #[must_use]
    pub const fn plpmtu(&self) -> usize {
        self.mtu - self.header_size
    }

    /// Returns true if a PMTUD probe should be sent.
    #[must_use]
    pub fn needs_probe(&self) -> bool {
        self.probe_state == Probe::Needed
    }

    /// Returns the size of the current PMTUD probe.
    #[must_use]
    pub const fn probe_size(&self) -> usize {
        self.search_table[self.probe_index] - self.header_size
    }

    /// Sends a PMTUD probe.
    pub fn send_probe<B: Buffer>(
        &mut self,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
    ) {
        // The packet may include ACK-eliciting data already, but rather than check for that, it
        // seems OK to burn one byte here to simply include a PING.
        builder.encode_frame(FrameType::Ping, |_| {});
        tokens.push(recovery::Token::PmtudProbe);
        stats.frame_tx.ping += 1;
        stats.pmtud_tx += 1;
        self.probe_count += 1;
        self.probe_state = Probe::Sent;
        qdebug!(
            "Sending PMTUD probe of size {}, count {}",
            self.search_table[self.probe_index],
            self.probe_count
        );
    }

    /// Returns the maximum Packetization Layer Path MTU for the configured
    /// address family. Note that this ignores the interface MTU.
    #[expect(clippy::missing_panics_doc, reason = "search table is never empty")]
    #[must_use]
    pub const fn address_family_max_mtu(&self) -> usize {
        *self.search_table.last().expect("search table is empty")
    }

    /// Count the PMTUD probes included in `pkts`.
    fn count_probes(pkts: &[sent::Packet]) -> usize {
        pkts.iter().filter(|p| p.is_pmtud_probe()).count()
    }

    /// Checks whether a PMTUD probe has been acknowledged, and if so, updates the PMTUD state.
    /// May also initiate a new probe process for a larger MTU.
    pub fn on_packets_acked(
        &mut self,
        acked_pkts: &[sent::Packet],
        now: Instant,
        stats: &mut Stats,
    ) {
        let acked = Self::count_probes(acked_pkts);
        if acked == 0 {
            return;
        }

        // A probe was ACKed, confirm the new MTU and try to probe upwards further.
        stats.pmtud_ack += acked;
        self.mtu = self.search_table[self.probe_index];
        stats.pmtud_pmtu = self.mtu;
        qdebug!("PMTUD probe of size {} succeeded", self.mtu);
        self.next(now, stats);
    }

    /// Stops the PMTUD process, setting the MTU to the largest successful probe size.
    fn stop(&mut self, idx: usize, now: Instant, stats: &mut Stats) {
        self.probe_state = Probe::NotNeeded; // We don't need to send any more probes
        self.probe_index = idx; // Index of the last successful probe
        self.mtu = self.search_table[idx]; // Leading to this MTU
        stats.pmtud_pmtu = self.mtu;
        self.probe_count = 0; // Reset the count
        self.raise_timer = Some(now + PMTU_RAISE_TIMER);
        qinfo!(
            "PMTUD stopped, PLPMTU is now {}, raise timer {:?}",
            self.mtu,
            self.raise_timer
        );
    }

    /// Checks whether a PMTUD probe has been lost. If it has been lost more than `MAX_PROBES`
    /// times, the PMTUD process is stopped at the current MTU.
    pub fn on_packets_lost(
        &mut self,
        lost_packets: &[sent::Packet],
        stats: &mut Stats,
        now: Instant,
    ) {
        let lost = Self::count_probes(lost_packets);
        if lost == 0 {
            return;
        }
        stats.pmtud_lost += lost;

        if self.probe_count >= MAX_PROBES {
            // We've sent MAX_PROBES probes and they were all lost. Stop probing at the
            // previous successful MTU.
            let ok_idx = self.probe_index.saturating_sub(1);
            qdebug!(
                "PMTUD probe of size {} failed after {MAX_PROBES} attempts",
                self.search_table[self.probe_index]
            );
            self.stop(ok_idx, now, stats);
        } else {
            // Probe was lost but we haven't exhausted retries yet.
            self.probe_state = Probe::Needed;
        }
    }

    /// Starts PMTUD from the minimum MTU, probing upward.
    pub fn start(&mut self, now: Instant, stats: &mut Stats) {
        self.probe_index = 0;
        self.mtu = self.search_table[self.probe_index];
        stats.pmtud_pmtu = self.mtu;
        self.raise_timer = None;
        qdebug!("PMTUD started, PLPMTU is now {}", self.mtu);
        self.next(now, stats);
    }

    /// Starts the next upward PMTUD probe.
    pub fn next(&mut self, now: Instant, stats: &mut Stats) {
        if self.probe_index == SEARCH_TABLE_LEN - 1 {
            qdebug!(
                "PMTUD reached end of search table, i.e. {}, stopping upwards search",
                self.mtu,
            );
            self.stop(self.probe_index, now, stats);
            return;
        }

        if self.search_table[self.probe_index + 1] > self.iface_mtu {
            qdebug!(
                "PMTUD reached interface MTU limit {}, stopping upwards search at {}",
                self.iface_mtu,
                self.mtu
            );
            self.stop(self.probe_index, now, stats);
            return;
        }

        self.probe_state = Probe::Needed; // We need to send a probe
        self.probe_count = 0; // For the first time
        self.probe_index += 1; // At this size
        qdebug!(
            "PMTUD started with probe size {}",
            self.search_table[self.probe_index],
        );
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
        cmp::min,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Instant,
    };

    use neqo_common::{qdebug, qinfo, Encoder};
    use test_fixture::{fixture_init, now};

    use crate::{
        crypto::CryptoDxState,
        packet,
        pmtud::{Probe, PMTU_RAISE_TIMER, SEARCH_TABLE_LEN},
        recovery::{self, sent, SendProfile},
        Pmtud, Stats,
    };

    /// Test helper to create a sent PMTUD probe packet.
    fn make_pmtud_probe(pn: packet::Number, sent_time: Instant, len: usize) -> sent::Packet {
        sent::Packet::new(
            packet::Type::Short,
            pn,
            sent_time,
            true,
            vec![recovery::Token::PmtudProbe],
            len,
        )
    }

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    const IFACE_MTUS: &[Option<usize>] = &[
        None,
        Some(1300),
        Some(1500),
        Some(5000),
        Some(u16::MAX as usize),
    ];

    /// Asserts that the PMTUD process has stopped at the given MTU.
    #[cfg(test)]
    fn assert_mtu(pmtud: &Pmtud, mtu: usize) {
        let idx = pmtud
            .search_table
            .iter()
            .position(|mtu| *mtu == pmtud.mtu)
            .unwrap();
        assert!((idx == 0 && mtu <= pmtud.search_table[idx]) || (mtu >= pmtud.search_table[idx]));
        if idx < SEARCH_TABLE_LEN - 1 {
            assert!(mtu < pmtud.search_table[idx + 1]);
        }
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);
    }

    #[cfg(test)]
    fn pmtud_step(
        pmtud: &mut Pmtud,
        stats: &mut Stats,
        prot: &mut CryptoDxState,
        addr: IpAddr,
        mtu: usize,
        now: Instant,
    ) {
        const AEAD_EXPANSION: usize = 16;

        let stats_before = stats.clone();

        // Fake a packet number, so the builder logic works.
        let profile = SendProfile::new_limited(pmtud.plpmtu());
        let limit = if pmtud.needs_probe() {
            pmtud.probe_size() - AEAD_EXPANSION
        } else {
            profile.limit() - AEAD_EXPANSION
        };
        let mut builder = packet::Builder::short(Encoder::default(), false, None::<&[u8]>, limit);
        let pn = prot.next_pn();
        builder.pn(pn, 4);
        builder.enable_padding(true);
        pmtud.send_probe(&mut builder, &mut Vec::new(), stats);
        builder.pad();
        let encoder = builder.build(prot).unwrap();
        assert_eq!(encoder.len(), pmtud.probe_size());
        assert!(!pmtud.needs_probe());
        assert_eq!(stats_before.pmtud_tx + 1, stats.pmtud_tx);

        let packet = make_pmtud_probe(pn, now, encoder.len());
        if encoder.len() + Pmtud::header_size(addr) <= mtu {
            pmtud.on_packets_acked(&[packet], now, stats);
            assert_eq!(stats_before.pmtud_ack + 1, stats.pmtud_ack);
        } else {
            pmtud.on_packets_lost(&[packet], stats, now);
            assert_eq!(stats_before.pmtud_lost + 1, stats.pmtud_lost);
        }
    }

    fn find_pmtu(
        addr: IpAddr,
        mtu: usize,
        iface_mtu: Option<usize>,
    ) -> (Pmtud, Stats, CryptoDxState, Instant) {
        fixture_init();
        let now = now();
        let mut pmtud = Pmtud::new(addr, iface_mtu);
        let mut stats = Stats::default();
        let mut prot = CryptoDxState::test_default();

        pmtud.next(now, &mut stats);

        if let Some(iface_mtu) = iface_mtu {
            assert!(iface_mtu <= pmtud.search_table[1] || pmtud.needs_probe());
        } else {
            assert!(pmtud.needs_probe());
        }

        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, addr, mtu, now);
        }

        let final_mtu = iface_mtu.map_or(mtu, |iface_mtu| min(mtu, iface_mtu));
        assert_mtu(&pmtud, final_mtu);

        (pmtud, stats, prot, now)
    }

    /// Tests that when the path MTU decreases, PMTUD does not automatically reprobe downward.
    /// The raise timer only triggers probing for *larger* MTUs. MTU reductions are not
    /// automatically detected by PMTUD; the connection will continue using the old MTU
    /// and packets will be lost until the raise timer fires and probing completes at
    /// the same or a higher MTU (depending on path conditions).
    fn find_pmtu_no_reduction_detection(addr: IpAddr, mtu: usize) {
        let (mut pmtud, mut stats, _prot, now) = find_pmtu(addr, mtu, None);

        // The current MTU is set.
        let current_mtu = pmtud.mtu;
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);

        // Fire the raise timer - this only triggers probing for *higher* MTUs.
        qdebug!("Firing raise timer after reaching MTU {current_mtu}");
        let now = now + PMTU_RAISE_TIMER;
        pmtud.maybe_fire_raise_timer(now, &mut stats);

        // If we're not at the max MTU, the timer should trigger a probe for a higher MTU.
        // If we're at the max MTU (or interface limit), no probe is needed.
        if pmtud.probe_index < SEARCH_TABLE_LEN - 1
            && pmtud.search_table[pmtud.probe_index + 1] <= pmtud.iface_mtu
        {
            // Timer should have started probing for a larger MTU.
            assert_eq!(Probe::Needed, pmtud.probe_state);
        } else {
            // At max MTU, timer doesn't change state.
            assert_eq!(Probe::NotNeeded, pmtud.probe_state);
        }

        // Regardless, the current MTU should be unchanged.
        assert_eq!(current_mtu, pmtud.mtu);
    }

    fn find_pmtu_with_increase(addr: IpAddr, mtu: usize, larger_mtu: usize) {
        assert!(mtu < larger_mtu);
        let (mut pmtud, mut stats, mut prot, now) = find_pmtu(addr, mtu, None);

        assert!(larger_mtu >= pmtud.search_table[0]);
        pmtud.next(now, &mut stats);
        assert!(pmtud.needs_probe());

        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, addr, mtu, now);
        }
        assert_mtu(&pmtud, mtu);

        qdebug!("Increasing MTU to {larger_mtu}");
        let now = now + PMTU_RAISE_TIMER;
        pmtud.maybe_fire_raise_timer(now, &mut stats);
        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, addr, larger_mtu, now);
        }
        assert_mtu(&pmtud, larger_mtu);
    }

    fn path_mtus() -> Vec<usize> {
        IFACE_MTUS.iter().flatten().copied().collect()
    }

    #[test]
    fn pmtud() {
        for &addr in &[V4, V6] {
            for path_mtu in path_mtus() {
                for &iface_mtu in IFACE_MTUS {
                    qinfo!("PMTUD for {addr}, path MTU {path_mtu}, iface MTU {iface_mtu:?}");
                    find_pmtu(addr, path_mtu, iface_mtu);
                }
            }
        }
    }

    /// Tests that the raise timer only probes upward, not downward.
    #[test]
    fn raise_timer_probes_upward_only() {
        for &addr in &[V4, V6] {
            for path_mtu in path_mtus() {
                qinfo!("Testing raise timer behavior for {addr}, path MTU {path_mtu}");
                find_pmtu_no_reduction_detection(addr, path_mtu);
            }
        }
    }

    #[test]
    fn pmtud_with_increase() {
        for &addr in &[V4, V6] {
            for path_mtu in path_mtus() {
                let path_mtus = path_mtus();
                let larger_mtus = path_mtus.iter().filter(|&mtu| *mtu > path_mtu);
                for &larger_mtu in larger_mtus {
                    qinfo!("PMTUD for {addr}, path MTU {path_mtu}, larger path MTU {larger_mtu}");
                    find_pmtu_with_increase(addr, path_mtu, larger_mtu);
                }
            }
        }
    }

    /// Tests that losing non-probe packets does not affect PMTUD state.
    #[test]
    fn non_probe_loss_ignored() {
        const MTU: usize = 1500;
        let now = now();
        let mut pmtud = Pmtud::new(V4, Some(MTU));
        let mut stats = Stats::default();

        // Complete PMTUD at MTU 1500.
        pmtud.stop(
            pmtud
                .search_table
                .iter()
                .position(|&mtu| mtu == MTU)
                .unwrap(),
            now,
            &mut stats,
        );
        assert_mtu(&pmtud, MTU);
        let initial_lost = stats.pmtud_lost;

        // Lose various non-probe packets - should not change PMTUD state.
        pmtud.on_packets_lost(&[], &mut stats, now);
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);

        pmtud.on_packets_lost(&[sent::make_packet(0, now, 100)], &mut stats, now);
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);

        pmtud.on_packets_lost(&[sent::make_packet(1, now, 1000)], &mut stats, now);
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);

        // No probe losses should have been recorded.
        assert_eq!(initial_lost, stats.pmtud_lost);
    }

    /// Tests that `ACK`ing non-probe packets does not affect PMTUD state.
    #[test]
    fn non_probe_ack_ignored() {
        const MTU: usize = 1500;
        let now = now();
        let mut pmtud = Pmtud::new(V4, Some(MTU));
        let mut stats = Stats::default();

        // Complete PMTUD at MTU 1500.
        pmtud.stop(
            pmtud
                .search_table
                .iter()
                .position(|&mtu| mtu == MTU)
                .unwrap(),
            now,
            &mut stats,
        );
        assert_mtu(&pmtud, MTU);
        let initial_ack = stats.pmtud_ack;

        // ACK various non-probe packets - should not change PMTUD state.
        pmtud.on_packets_acked(&[], now, &mut stats);
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);

        pmtud.on_packets_acked(&[sent::make_packet(0, now, 100)], now, &mut stats);
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);

        pmtud.on_packets_acked(&[sent::make_packet(1, now, 5000)], now, &mut stats);
        assert_eq!(Probe::NotNeeded, pmtud.probe_state);

        // No probe ACKs should have been recorded.
        assert_eq!(initial_ack, stats.pmtud_ack);
    }
}
