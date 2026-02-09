// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use neqo_common::{Buffer, qdebug, qinfo, qtrace};
use static_assertions::const_assert;

use crate::{
    Stats,
    frame::{FrameEncoder as _, FrameType},
    packet,
    recovery::{self, sent},
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

/// Returns the size of the IP and UDP headers for the given IP address family.
#[must_use]
pub const fn header_size(remote_ip: IpAddr) -> usize {
    match remote_ip {
        IpAddr::V4(_) => 20 + 8,
        IpAddr::V6(_) => 40 + 8,
    }
}

/// Returns the MTU search table for the given remote IP address family.
const fn search_table(remote_ip: IpAddr) -> &'static [usize] {
    match remote_ip {
        IpAddr::V4(_) => MTU_SIZES_V4,
        IpAddr::V6(_) => MTU_SIZES_V6,
    }
}

/// Returns the default PLPMTU for the given remote IP address.
#[must_use]
pub const fn default_plpmtu(remote_ip: IpAddr) -> usize {
    search_table(remote_ip)[0] - header_size(remote_ip)
}

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
    black_hole: BlackHoleDetector,
}

impl Pmtud {
    /// Number of probe attempts before giving up on a size.
    /// From <https://datatracker.ietf.org/doc/html/rfc8899#section-5.1>.
    const MAX_PROBES: usize = 3;

    /// Time to wait before probing for a larger MTU after a probe failure.
    const RAISE_TIMER: Duration = Duration::from_secs(600);

    #[must_use]
    #[allow(
        clippy::allow_attributes,
        clippy::missing_asserts_for_indexing,
        reason = "FIXME: False positive with MSRV 1.87"
    )]
    pub fn new(remote_ip: IpAddr, iface_mtu: Option<usize>) -> Self {
        let search_table = search_table(remote_ip);
        let header_size = header_size(remote_ip);
        let probe_index = 0;
        let min_mtu = search_table[probe_index];
        Self {
            search_table,
            header_size,
            mtu: min_mtu,
            iface_mtu: iface_mtu.unwrap_or(usize::MAX),
            probe_index,
            probe_count: 0,
            probe_state: Probe::NotNeeded,
            raise_timer: None,
            black_hole: BlackHoleDetector::new(min_mtu - header_size),
        }
    }

    /// Checks whether the PMTUD raise timer should be fired, and does so if needed.
    pub fn maybe_fire_raise_timer(&mut self, now: Instant, stats: &mut Stats) {
        if self.probe_state == Probe::NotNeeded && self.raise_timer.is_some_and(|t| now >= t) {
            qdebug!("PMTUD raise timer fired");
            self.raise_timer = None;
            self.black_hole.clear_mtu_limit();
            self.next(now, stats);
        }
    }

    /// Returns the minimum MTU from the search table.
    pub(crate) const fn min_mtu(&self) -> usize {
        self.search_table[0]
    }

    /// Returns the MTU currently being probed.
    const fn probe_mtu(&self) -> usize {
        self.search_table[self.probe_index]
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
        self.probe_mtu() - self.header_size
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
            self.probe_mtu(),
            self.probe_count
        );
    }

    /// Returns the maximum Packetization Layer Path MTU for the configured
    /// address family. Note that this ignores the interface MTU.
    #[must_use]
    pub const fn address_family_max_mtu(&self) -> usize {
        *self.search_table.last().expect("search table is empty")
    }

    /// Count the PMTUD probes included in `pkts`.
    fn count_probes(pkts: &[sent::Packet]) -> usize {
        pkts.iter().filter(|p| p.is_pmtud_probe()).count()
    }

    /// Checks whether a PMTUD probe has been acknowledged, and if so, updates the PMTUD state.
    /// May also initiate a new probe process for a larger MTU. Also checks for black holes.
    pub fn on_packets_acked(
        &mut self,
        acked_pkts: &[sent::Packet],
        now: Instant,
        stats: &mut Stats,
    ) {
        self.black_hole.on_ack(acked_pkts);

        let acked = Self::count_probes(acked_pkts);
        if acked == 0 {
            return;
        }

        // A probe was ACKed, confirm the new MTU and try to probe upwards further.
        stats.pmtud_ack += acked;
        self.mtu = self.probe_mtu();
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
        self.raise_timer = Some(now + Self::RAISE_TIMER);
        qinfo!(
            "PMTUD stopped, PLPMTU is now {}, raise timer {:?}",
            self.mtu,
            self.raise_timer
        );
    }

    /// Checks whether a PMTUD probe has been lost. If it has been lost more than `Self::MAX_PROBES`
    /// times, the PMTUD process is stopped at the current MTU. Also checks for black holes via
    /// the [`BlackHoleDetector`], restarting PMTUD from minimum if one is detected.
    pub fn on_packets_lost(
        &mut self,
        lost_packets: &[sent::Packet],
        stats: &mut Stats,
        now: Instant,
    ) {
        // Only restart PMTUD if we aren't already at the minimum MTU.
        if self.mtu > self.min_mtu() && self.black_hole.on_loss(lost_packets, now, self.mtu) {
            stats.pmtud_restarts += 1;
            self.start(now, stats);
            return;
        }

        let lost = Self::count_probes(lost_packets);
        if lost == 0 {
            return;
        }
        stats.pmtud_lost += lost;

        if self.probe_count >= Self::MAX_PROBES {
            // We've exhausted probe attempts. Stop probing at the previous successful MTU.
            let ok_idx = self.probe_index.saturating_sub(1);
            qdebug!(
                "PMTUD probe of size {} failed after {} attempts",
                self.probe_mtu(),
                Self::MAX_PROBES,
            );
            self.stop(ok_idx, now, stats);
        } else {
            // Probe was lost but we haven't exhausted retries yet.
            self.probe_state = Probe::Needed;
        }
    }

    /// Fallback for when ACK-based black hole detection fails due to no ACKs having come in.
    pub fn on_pto(&mut self, pto_packets: &[sent::Packet], stats: &mut Stats, now: Instant) {
        // Only restart PMTUD if we aren't already at the minimum MTU.
        if self.mtu > self.min_mtu() && self.black_hole.on_pto(pto_packets, now, self.mtu) {
            stats.pmtud_restarts += 1;
            self.start(now, stats);
        }
    }

    /// Starts PMTUD from the minimum MTU, probing upward.
    pub fn start(&mut self, now: Instant, stats: &mut Stats) {
        self.probe_index = 0;
        self.mtu = self.min_mtu();
        stats.pmtud_pmtu = self.mtu;
        self.raise_timer = None;
        self.black_hole.reset();
        qdebug!("PMTUD started, PLPMTU is now {}", self.plpmtu());
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

        if self
            .black_hole
            .mtu_limit()
            .is_some_and(|limit| self.search_table[self.probe_index + 1] >= limit)
        {
            qdebug!(
                "PMTUD reached black hole limit {:?}, stopping upwards search at {}",
                self.black_hole.mtu_limit(),
                self.mtu
            );
            self.stop(self.probe_index, now, stats);
            return;
        }

        self.probe_state = Probe::Needed; // We need to send a probe
        self.probe_count = 0; // For the first time
        self.probe_index += 1; // At this size
        qdebug!("PMTUD started with probe size {}", self.probe_mtu());
    }
}

/// Detects PMTUD black holes by tracking losses of large packets and PTO events.
///
/// A black hole is declared when we see repeated losses of packets larger than
/// the base PLPMTU while the connection remains alive (implying smaller packets
/// are getting through), OR when PTO fires for large packets (indicating that
/// no ACKs are being received at all).
#[derive(Debug)]
struct BlackHoleDetector {
    /// Minimum PLPMTU - packets larger than this are considered "large".
    base_plpmtu: usize,
    /// Smallest packet size among lost large packets.
    min_lost_size: Option<usize>,
    /// Count of consecutive loss events for large packets (ACK-based detection).
    loss_count: usize,
    /// Ignore losses/PTOs of packets sent before this time.
    /// Set when we restart PMTUD to avoid counting stale events.
    ignore_before: Option<Instant>,
    /// MTU limit from last black hole detection. Probing should not exceed this
    /// until cleared. This helps with "grey holes" that cause higher packet loss
    /// at larger sizes without completely blocking them.
    mtu_limit: Option<usize>,
}

impl BlackHoleDetector {
    /// Number of consecutive ACK-based loss events before declaring a black hole.
    const THRESHOLD: usize = 3;

    const fn new(base_plpmtu: usize) -> Self {
        Self {
            base_plpmtu,
            min_lost_size: None,
            loss_count: 0,
            ignore_before: None,
            mtu_limit: None,
        }
    }

    /// Reset detection state (but not the time filter or MTU limit).
    const fn reset(&mut self) {
        self.min_lost_size = None;
        self.loss_count = 0;
    }

    /// Trigger black hole detection: set time filter, remember MTU limit, reset state.
    const fn trigger(&mut self, now: Instant, current_mtu: usize) {
        self.ignore_before = Some(now);
        self.mtu_limit = Some(current_mtu);
        self.reset();
    }

    /// Clear the MTU limit, allowing probing to higher values.
    const fn clear_mtu_limit(&mut self) {
        self.mtu_limit = None;
    }

    /// Returns the MTU limit if set.
    const fn mtu_limit(&self) -> Option<usize> {
        self.mtu_limit
    }

    /// Returns true if this packet is a candidate for black hole detection:
    /// - On primary path
    /// - Not a PMTUD probe (those have their own loss handling)
    /// - Larger than base PLPMTU
    /// - Sent after any restart (`ignore_before` filter)
    fn is_large_data_packet(&self, p: &sent::Packet) -> bool {
        p.on_primary_path()
            && !p.is_pmtud_probe()
            && p.len() > self.base_plpmtu
            && self.ignore_before.is_none_or(|t| p.time_sent() >= t)
    }

    /// Handle ACK of packets. If a large packet was acknowledged,
    /// the path is working for that size, so reset detection.
    ///
    /// Unlike loss detection, we include probe packets here since their ACKs
    /// prove the path works at that size. We only filter by primary path.
    fn on_ack(&mut self, acked_pkts: &[sent::Packet]) {
        if self.min_lost_size.is_none() {
            return;
        }

        let Some(max_acked) = acked_pkts
            .iter()
            .filter(|p| p.on_primary_path())
            .map(sent::Packet::len)
            .max()
        else {
            return;
        };

        if self.min_lost_size.is_some_and(|min| max_acked >= min) {
            qtrace!(
                "PMTUD black hole detection reset: ACK for {max_acked} bytes >= min_lost {:?}",
                self.min_lost_size
            );
            self.reset();
        }
    }

    /// Record loss events. Returns `true` if a black hole is detected.
    /// When detected, `current_mtu` is stored as the limit for future probing.
    fn on_loss(&mut self, lost_pkts: &[sent::Packet], now: Instant, current_mtu: usize) -> bool {
        let Some(min_lost) = lost_pkts
            .iter()
            .filter(|p| self.is_large_data_packet(p))
            .map(sent::Packet::len)
            .min()
        else {
            return false;
        };

        let new_min = self
            .min_lost_size
            .map_or(min_lost, |current| current.min(min_lost));
        self.min_lost_size = Some(new_min);
        self.loss_count += 1;

        qtrace!(
            "PMTUD black hole detection: min_lost_size={new_min}, loss_count={}",
            self.loss_count
        );

        if self.loss_count >= Self::THRESHOLD {
            qinfo!(
                "PMTUD black hole detected: {} losses of packets >= {new_min} bytes",
                self.loss_count,
            );
            self.trigger(now, current_mtu);
            return true;
        }

        false
    }

    /// Record PTO events. Returns `true` if a black hole is detected.
    /// When detected, `current_mtu` is stored as the limit for future probing.
    ///
    /// When PTO fires for large packets, it means we haven't received any ACKs
    /// for an extended period. This is a strong signal that large packets are
    /// being dropped, so we immediately trigger black hole detection.
    fn on_pto(&mut self, pto_pkts: &[sent::Packet], now: Instant, current_mtu: usize) -> bool {
        if !pto_pkts.iter().any(|p| self.is_large_data_packet(p)) {
            return false;
        }

        qinfo!("PMTUD black hole detected: PTO for large packets");
        self.trigger(now, current_mtu);
        true
    }
}

#[cfg(all(not(feature = "disable-encryption"), test))]
mod tests {
    use std::{
        cmp::min,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Instant,
    };

    use neqo_common::{Encoder, qdebug, qinfo};
    use test_fixture::{fixture_init, now};

    use super::{Pmtud, header_size};
    use crate::{
        Stats,
        crypto::CryptoDxState,
        packet,
        pmtud::{BlackHoleDetector, Probe, SEARCH_TABLE_LEN},
        recovery::{self, SendProfile, sent},
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

    /// Triggers black hole detection by losing large packets.
    fn trigger_black_hole(pmtud: &mut Pmtud, stats: &mut Stats, now: Instant) {
        for i in 0..BlackHoleDetector::THRESHOLD {
            let pkt = sent::make_packet(i as u64, now, 1400);
            pmtud.on_packets_lost(&[pkt], stats, now);
        }
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
        if encoder.len() + header_size(addr) <= mtu {
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
        let now = now + Pmtud::RAISE_TIMER;
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
        let now = now + Pmtud::RAISE_TIMER;
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

    /// Tests that black hole detection does NOT restart PMTUD when already at minimum MTU.
    /// There's no point restarting at `min_mtu` since we can't go any lower.
    #[test]
    fn black_hole_at_min_mtu_no_restart() {
        let now = now();
        let mut pmtud = Pmtud::new(V4, None);
        let mut stats = Stats::default();

        // Set PMTUD to minimum MTU.
        pmtud.start(now, &mut stats);
        assert_eq!(pmtud.mtu, pmtud.min_mtu());
        let initial_pmtud_restarts = stats.pmtud_restarts;

        trigger_black_hole(&mut pmtud, &mut stats, now);

        // pmtud_restarts should NOT have incremented because we're at min_mtu.
        assert_eq!(
            initial_pmtud_restarts, stats.pmtud_restarts,
            "Black hole detection should not trigger restart when at min_mtu"
        );
        assert_eq!(pmtud.mtu, pmtud.min_mtu());
    }

    /// Tests that black hole detection increments `pmtud_restarts` when triggered above `min_mtu`.
    #[test]
    fn black_hole_increments_pmtud_restarts() {
        let now = now();
        let mut pmtud = Pmtud::new(V4, None);
        let mut stats = Stats::default();

        // Complete PMTUD at MTU 1500 (above min_mtu).
        let idx = pmtud.search_table.iter().position(|&m| m == 1500).unwrap();
        pmtud.stop(idx, now, &mut stats);
        assert_eq!(pmtud.mtu, 1500);
        assert!(pmtud.mtu > pmtud.min_mtu());
        assert_eq!(stats.pmtud_restarts, 0);

        trigger_black_hole(&mut pmtud, &mut stats, now);

        assert_eq!(
            stats.pmtud_restarts, 1,
            "pmtud_restarts should be exactly 1 after one black hole detection"
        );
    }

    /// Tests that black hole detection remembers problematic MTUs.
    #[test]
    fn black_hole_limits_probing() {
        const PATH_MTU: usize = 1500;
        let (mut pmtud, mut stats, mut prot, now) = find_pmtu(V4, PATH_MTU, None);
        assert_eq!(pmtud.mtu, PATH_MTU);
        let idx = pmtud
            .search_table
            .iter()
            .position(|&m| m == PATH_MTU)
            .unwrap();

        // Black hole detected at PATH_MTU.
        trigger_black_hole(&mut pmtud, &mut stats, now);
        assert_eq!(pmtud.mtu, pmtud.min_mtu());
        assert_eq!(stats.pmtud_restarts, 1);

        // Probe back up - should stop one step below PATH_MTU.
        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, V4, PATH_MTU, now);
        }
        assert_eq!(pmtud.mtu, pmtud.search_table[idx - 1]);

        // Another black hole at one step below PATH_MTU lowers the limit further.
        trigger_black_hole(&mut pmtud, &mut stats, now);
        assert_eq!(stats.pmtud_restarts, 2);
        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, V4, PATH_MTU, now);
        }
        assert_eq!(pmtud.mtu, pmtud.search_table[idx - 2]);

        // After raise timer fires, the limit is cleared.
        let after_raise = now + Pmtud::RAISE_TIMER;
        pmtud.maybe_fire_raise_timer(after_raise, &mut stats);
        while pmtud.needs_probe() {
            pmtud_step(&mut pmtud, &mut stats, &mut prot, V4, PATH_MTU, after_raise);
        }
        assert_eq!(pmtud.mtu, PATH_MTU);
    }

    /// Tests that probe loss counting works correctly up to `MAX_PROBES`.
    #[test]
    fn probe_loss_stops_at_max_probes() {
        let now = now();
        let mut pmtud = Pmtud::new(V4, None);
        let mut stats = Stats::default();

        pmtud.next(now, &mut stats);
        assert!(pmtud.needs_probe());

        for probe_num in 0..Pmtud::MAX_PROBES {
            pmtud.probe_state = Probe::Sent;
            pmtud.probe_count = probe_num + 1;

            let pn = u64::try_from(probe_num).unwrap();
            let probe = make_pmtud_probe(pn, now, pmtud.probe_size());
            pmtud.on_packets_lost(&[probe], &mut stats, now);

            let expected = if probe_num < Pmtud::MAX_PROBES - 1 {
                Probe::Needed
            } else {
                Probe::NotNeeded
            };
            assert_eq!(
                expected,
                pmtud.probe_state,
                "probe_state after {} probe losses",
                probe_num + 1
            );
        }
    }

    mod black_hole {
        use std::{
            net::{IpAddr, Ipv6Addr},
            time::{Duration, Instant},
        };

        use test_fixture::now;

        use super::super::default_plpmtu;
        use crate::{
            pmtud::BlackHoleDetector,
            recovery::{Token, sent},
        };

        const BASE_PLPMTU: usize = default_plpmtu(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        const TEST_MTU: usize = 1500;

        fn make_packet(pn: u64, sent_time: Instant, len: usize) -> sent::Packet {
            sent::make_packet(pn, sent_time, len)
        }

        fn make_probe(pn: u64, sent_time: Instant, len: usize) -> sent::Packet {
            sent::Packet::new(
                crate::packet::Type::Short,
                pn,
                sent_time,
                true,
                vec![Token::PmtudProbe],
                len,
            )
        }

        #[test]
        fn no_detection_below_threshold() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Lose packets below threshold.
            for i in 0..BlackHoleDetector::THRESHOLD - 1 {
                let pkt = make_packet(u64::try_from(i).unwrap(), now, 1400);
                assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            }

            assert_eq!(detector.loss_count, BlackHoleDetector::THRESHOLD - 1);
            assert!(detector.min_lost_size.is_some());
        }

        #[test]
        fn detection_at_threshold() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Lose packets up to threshold.
            for i in 0..BlackHoleDetector::THRESHOLD - 1 {
                let pkt = make_packet(u64::try_from(i).unwrap(), now, 1400);
                assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            }

            // This loss triggers detection.
            let pkt = make_packet(
                u64::try_from(BlackHoleDetector::THRESHOLD).unwrap(),
                now,
                1400,
            );
            assert!(detector.on_loss(&[pkt], now, TEST_MTU));

            // State should be reset after detection.
            assert_eq!(detector.loss_count, 0);
            assert!(detector.min_lost_size.is_none());
            // But ignore_before should be set.
            assert!(detector.ignore_before.is_some());
        }

        #[test]
        fn ack_resets_detection() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Lose packets below threshold.
            for i in 0..BlackHoleDetector::THRESHOLD - 1 {
                let pkt = make_packet(u64::try_from(i).unwrap(), now, 1400);
                assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            }
            assert_eq!(detector.loss_count, BlackHoleDetector::THRESHOLD - 1);
            assert_eq!(detector.min_lost_size, Some(1400));

            // ACK a packet >= min_lost_size resets detection.
            let ack_pkt = make_packet(10, now, 1400);
            detector.on_ack(&[ack_pkt]);

            assert_eq!(detector.loss_count, 0);
            assert!(detector.min_lost_size.is_none());
        }

        #[test]
        fn ack_smaller_than_min_lost_no_reset() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Lose a large packet.
            let pkt = make_packet(0, now, 1400);
            assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            assert_eq!(detector.min_lost_size, Some(1400));

            // ACK a smaller packet - should not reset.
            let ack_pkt = make_packet(10, now, 1300);
            detector.on_ack(&[ack_pkt]);

            assert_eq!(detector.loss_count, 1);
            assert_eq!(detector.min_lost_size, Some(1400));
        }

        #[test]
        fn small_packets_ignored() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Lose packets at or below base_plpmtu - should be ignored.
            for i in 0..5 {
                let pkt = make_packet(i, now, BASE_PLPMTU);
                assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            }

            assert_eq!(detector.loss_count, 0);
            assert!(detector.min_lost_size.is_none());
        }

        #[test]
        fn probe_packets_ignored() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Lose probe packets - should be ignored.
            for i in 0..5 {
                let pkt = make_probe(i, now, 1400);
                assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            }

            assert_eq!(detector.loss_count, 0);
            assert!(detector.min_lost_size.is_none());
        }

        #[test]
        fn old_packets_ignored_after_restart() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Trigger detection.
            for i in 0..BlackHoleDetector::THRESHOLD {
                let pkt = make_packet(u64::try_from(i).unwrap(), now, 1400);
                detector.on_loss(&[pkt], now, TEST_MTU);
            }
            assert!(detector.ignore_before.is_some());

            // Packets sent before ignore_before should be ignored.
            let old_time = now.checked_sub(Duration::from_millis(100)).unwrap();
            for i in 10..15 {
                let pkt = make_packet(i, old_time, 1400);
                assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            }
            assert_eq!(detector.loss_count, 0);

            // But new packets should count.
            let new_time = now + Duration::from_millis(100);
            let pkt = make_packet(20, new_time, 1400);
            assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            assert_eq!(detector.loss_count, 1);
        }

        #[test]
        fn tracks_minimum_lost_size() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Lose packets of different sizes.
            let pkt = make_packet(0, now, 1500);
            assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            assert_eq!(detector.min_lost_size, Some(1500));

            let pkt = make_packet(1, now, 1400);
            assert!(!detector.on_loss(&[pkt], now, TEST_MTU));
            assert_eq!(detector.min_lost_size, Some(1400));

            // Larger packet doesn't change min.
            let pkt = make_packet(2, now, 1450);
            assert!(detector.on_loss(&[pkt], now, TEST_MTU)); // Triggers detection
            // After reset, min_lost_size is None.
            assert!(detector.min_lost_size.is_none());
        }

        #[test]
        fn pto_triggers_immediately() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // First PTO with large packets triggers detection immediately.
            let pkt = make_packet(0, now, 1400);
            assert!(detector.on_pto(&[pkt], now, TEST_MTU));
            assert!(detector.ignore_before.is_some());
        }

        #[test]
        fn pto_small_packets_ignored() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // PTO with small packets - should be ignored.
            for i in 0..5 {
                let pkt = make_packet(i, now, BASE_PLPMTU);
                assert!(!detector.on_pto(&[pkt], now, TEST_MTU));
            }
        }

        #[test]
        fn pto_probe_packets_ignored() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // PTO with probe packets - should be ignored.
            for i in 0..5 {
                let pkt = make_probe(i, now, 1400);
                assert!(!detector.on_pto(&[pkt], now, TEST_MTU));
            }
        }

        #[test]
        fn pto_old_packets_ignored_after_restart() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Trigger detection via PTO.
            let pkt = make_packet(0, now, 1400);
            assert!(detector.on_pto(&[pkt], now, TEST_MTU));
            assert!(detector.ignore_before.is_some());

            // PTOs for packets sent before ignore_before should be ignored.
            let old_time = now.checked_sub(Duration::from_millis(100)).unwrap();
            for i in 10..15 {
                let pkt = make_packet(i, old_time, 1400);
                assert!(!detector.on_pto(&[pkt], now, TEST_MTU));
            }

            // But new packets trigger detection again.
            let new_time = now + Duration::from_millis(100);
            let pkt = make_packet(20, new_time, 1400);
            assert!(detector.on_pto(&[pkt], now, TEST_MTU));
        }

        #[test]
        fn burst_loss_counts_as_single_event() {
            let now = now();
            let mut detector = BlackHoleDetector::new(BASE_PLPMTU);

            // Simulate losing two bursts of 10 large packets in a single loss event.
            for i in 1..=2 {
                let burst: Vec<_> = (0..10).map(|i| make_packet(i, now, 1400)).collect();
                assert!(!detector.on_loss(&burst, now, TEST_MTU));
                assert_eq!(detector.loss_count, i);
                assert_eq!(detector.min_lost_size, Some(1400));
            }

            // A third burst triggers detection.
            let burst: Vec<_> = (20..30).map(|i| make_packet(i, now, 1400)).collect();
            assert!(detector.on_loss(&burst, now, TEST_MTU));
            assert_eq!(detector.loss_count, 0);
            assert!(detector.min_lost_size.is_none());
        }
    }
}
