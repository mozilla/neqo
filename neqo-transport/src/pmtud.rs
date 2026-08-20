// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Parallel Probing DPLPMTUD, per [draft-seemann-quic-ppdplpmtud].
//!
//! Rather than searching for the path MTU one size at a time, probes for several distinct sizes
//! are sent at once, using congestion window headroom during the handshake. This finds a confirmed
//! lower bound on the usable packet size, not the maximum, and is restricted to Internet paths,
//! i.e., to [`MAX_PROBE_MTU`]. Each path is probed exactly once.
//!
//! [draft-seemann-quic-ppdplpmtud]: https://datatracker.ietf.org/doc/draft-seemann-quic-ppdplpmtud/

use std::{cmp::max, net::IpAddr, time::Instant};

use neqo_common::{Buffer, qdebug, qinfo, qlog::Qlog, qtrace};

use crate::{
    Stats,
    frame::{FrameEncoder as _, FrameType},
    packet, qlog,
    recovery::{self, sent},
};

/// The packet size an endpoint uses before any probe is confirmed. This is the smallest MTU any
/// IPv6 path is required to support, and is below what IPv4 paths commonly support.
pub const BASE_MTU: usize = 1280;

/// The largest size probed for. Probing is restricted to Internet paths, so this is the common
/// 1500-byte Ethernet MTU; detection of larger packet sizes is out of scope.
pub const MAX_PROBE_MTU: usize = 1500;

/// Detects a path that has stopped carrying packets larger than the base MTU.
///
/// draft-seemann-quic-ppdplpmtud has no such mechanism, but probing runs once per path and never
/// repeats, so a size that is confirmed and then becomes unusable -- a VPN or tunnel that lowers
/// the MTU without changing addresses, say -- would otherwise persist for the life of the
/// connection.
#[derive(Debug)]
struct BlackHoleDetector {
    /// Packets larger than this are "large"; smaller ones say nothing about the path MTU.
    base_plpmtu: usize,
    /// Smallest packet size among the large packets lost so far.
    min_lost_size: Option<usize>,
    /// Consecutive loss events that involved large packets.
    loss_count: usize,
    /// Ignore packets sent before this. Set whenever probing is planned, so that packets sized for
    /// a path we no longer use -- after a migration, say -- are not taken as evidence.
    ignore_before: Option<Instant>,
    /// When the last event was counted, so that one batch of losses reported by several calls
    /// counts once.
    last_event: Option<Instant>,
}

impl BlackHoleDetector {
    /// Consecutive loss events before a black hole is declared.
    const THRESHOLD: usize = 3;

    const fn new(base_plpmtu: usize) -> Self {
        Self {
            base_plpmtu,
            min_lost_size: None,
            loss_count: 0,
            ignore_before: None,
            last_event: None,
        }
    }

    const fn clear(&mut self) {
        self.min_lost_size = None;
        self.loss_count = 0;
        self.last_event = None;
    }

    /// Disregard everything sent before `now`, and anything already recorded.
    const fn restart(&mut self, now: Instant) {
        self.clear();
        self.ignore_before = Some(now);
    }

    /// Whether a packet says anything about whether the path still carries the size we are using.
    fn is_large_data_packet(&self, p: &sent::Packet, plpmtu: usize) -> bool {
        p.on_primary_path()
            && !p.is_pmtud_probe() // Probes are excluded: their loss is not evidence
            && p.len() > self.base_plpmtu // So are packets > current PLPMTU, which were for a different path
            && p.len() <= plpmtu
            && self.ignore_before.is_none_or(|t| p.time_sent() >= t)
    }

    /// An ACK for a size at least as large as the smallest lost means the path can carry that.
    fn on_ack(&mut self, acked_pkts: &[sent::Packet]) {
        let Some(min_lost) = self.min_lost_size else {
            return;
        };
        let acked_large = acked_pkts
            .iter()
            .filter(|p| p.on_primary_path())
            .any(|p| p.len() >= min_lost);
        if acked_large {
            qtrace!("PMTUD black hole detection reset: ACK for >= {min_lost} bytes");
            self.clear();
        }
    }

    /// Record a loss event for large packets. Returns `true` once we think it's a black hole.
    fn on_evidence(&mut self, pkts: &[sent::Packet], plpmtu: usize, now: Instant) -> bool {
        let Some(min_lost) = pkts
            .iter()
            .filter(|p| self.is_large_data_packet(p, plpmtu))
            .map(sent::Packet::len)
            .min()
        else {
            return false;
        };

        self.min_lost_size = Some(self.min_lost_size.map_or(min_lost, |m| m.min(min_lost)));
        if self.last_event == Some(now) {
            return false; // Batches of losses are one event, not several.
        }
        self.last_event = Some(now);
        self.loss_count += 1;
        qtrace!(
            "PMTUD black hole detection: min_lost_size={:?}, loss_count={}",
            self.min_lost_size,
            self.loss_count
        );
        self.loss_count >= Self::THRESHOLD
    }
}

/// A datagram that is being sent as a PMTUD probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// The full IP MTU being probed, which is what an ACK confirms.
    mtu: usize,
    /// The UDP payload size the datagram has to be expanded to.
    limit: usize,
}

impl Probe {
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

#[derive(Debug)]
pub struct Pmtud {
    /// Size of the IP and UDP headers, in bytes.
    header_size: usize,
    /// The largest confirmed MTU, i.e., the largest size an ACK has proven the path carries.
    mtu: usize,
    /// The MTU of the local interface towards the destination.
    iface_mtu: usize,
    /// The peer's [`max_udp_payload_size`](https://www.rfc-editor.org/rfc/rfc9000#section-18.2)
    /// transport parameter, i.e., the maximum UDP payload (not including IP and UDP headers)
    /// the peer is willing to receive.
    peer_max_udp_payload: Option<usize>,
    /// The sizes remaining to be probed, largest first.
    probes: Vec<usize>,
    /// Whether probing has been planned for this path, which happens exactly once.
    probed: bool,
    black_hole: BlackHoleDetector,
    /// Latched once a black hole is detected: MTU stays at [`BASE_MTU`] and probing is disabled.
    black_holed: bool,
    qlog: Qlog,
}

impl Pmtud {
    /// Size of the IPv4/IPv6 and UDP headers, in bytes.
    #[must_use]
    pub const fn header_size(remote_ip: IpAddr) -> usize {
        match remote_ip {
            IpAddr::V4(_) => 20 + 8,
            IpAddr::V6(_) => 40 + 8,
        }
    }

    /// Returns the default PLPMTU for the given remote IP address.
    #[must_use]
    pub const fn default_plpmtu(remote_ip: IpAddr) -> usize {
        BASE_MTU - Self::header_size(remote_ip)
    }

    #[must_use]
    pub fn new(remote_ip: IpAddr, iface_mtu: Option<usize>) -> Self {
        let header_size = Self::header_size(remote_ip);
        Self {
            header_size,
            mtu: BASE_MTU,
            iface_mtu: iface_mtu.unwrap_or(usize::MAX),
            peer_max_udp_payload: None,
            probes: Vec::new(),
            probed: false,
            black_hole: BlackHoleDetector::new(BASE_MTU - header_size),
            black_holed: false,
            qlog: Qlog::disabled(),
        }
    }

    pub fn set_qlog(&mut self, qlog: Qlog) {
        self.qlog = qlog;
    }

    /// Returns the current Packetization Layer Path MTU, i.e., the maximum UDP payload that can be
    /// sent.
    #[must_use]
    pub const fn plpmtu(&self) -> usize {
        self.mtu - self.header_size
    }

    fn set_mtu(&mut self, mtu: usize, stats: &mut Stats, now: Instant) {
        let old_plpmtu = self.plpmtu();
        self.mtu = mtu;
        stats.pmtud_pmtu = self.mtu;
        let new_plpmtu = self.plpmtu();
        if old_plpmtu != new_plpmtu {
            let done = self.probes.is_empty();
            qlog::mtu_updated(&mut self.qlog, old_plpmtu, new_plpmtu, done, now);
        }
    }

    /// The largest MTU worth probing for.
    fn upper_bound(&self) -> usize {
        let peer = self
            .peer_max_udp_payload
            .map_or(usize::MAX, |p| p.saturating_add(self.header_size));
        MAX_PROBE_MTU.min(self.iface_mtu).min(peer)
    }

    /// Set the peer's `max_udp_payload_size` transport parameter.
    pub fn set_peer_max_udp_payload(
        &mut self,
        peer_max_udp_payload: usize,
        now: Instant,
        stats: &mut Stats,
    ) {
        self.peer_max_udp_payload = Some(peer_max_udp_payload);
        let bound = self.upper_bound();
        self.probes.retain(|&m| m <= bound);
        if self.mtu > bound {
            qdebug!(
                "PMTUD capping MTU {} at peer max_udp_payload_size {peer_max_udp_payload}",
                self.mtu
            );
            self.set_mtu(max(bound, BASE_MTU), stats, now);
        }
    }

    /// Returns the peer's `max_udp_payload_size`, if known.
    #[must_use]
    pub const fn peer_max_udp_payload(&self) -> Option<usize> {
        self.peer_max_udp_payload
    }

    /// Plan a set of equally-spaced probes, per draft-seemann-quic-ppdplpmtud.
    ///
    /// `budget` is the number of bytes available for probing, i.e., the congestion window headroom
    /// left after reserving for the data that has to be sent anyway. `max_probes` caps how many
    /// probes this may produce, so a caller can limit how much of that headroom probing consumes.
    pub fn plan_probes(&mut self, budget: usize, max_probes: Option<usize>, now: Instant) {
        self.probes.clear();
        self.probed = true;
        if self.black_holed {
            return;
        }
        self.black_hole.restart(now);
        let upper = self.upper_bound();
        if upper <= self.mtu {
            qdebug!("PMTUD nothing to probe for, MTU {} is at {upper}", self.mtu);
            return;
        }

        let range = upper - self.mtu;
        let count = max_probes
            .unwrap_or(usize::MAX)
            .min(budget / upper)
            .min(range);
        if count == 0 {
            qdebug!(
                "PMTUD budget {budget} too small to probe above {}",
                self.mtu
            );
            return;
        }

        // `step` is rounded up, so the last of `count` probes can land at or below the current
        // MTU. Those are pointless, so stop before them.
        let step = range.div_ceil(count);
        self.probes = (0..count)
            .map_while(|i| (i * step < range).then(|| upper - i * step))
            .collect();
        debug_assert!(self.probes.iter().all(|&mtu| mtu > self.mtu));
        qdebug!("PMTUD planned probes {:?}", self.probes);
    }

    /// Whether a probe remains to be sent.
    #[must_use]
    pub const fn needs_probe(&self) -> bool {
        !self.probes.is_empty()
    }

    /// The largest planned probe whose UDP payload fits into `avail` bytes of congestion window.
    #[must_use]
    pub fn probe(&self, avail: usize) -> Option<Probe> {
        self.probes
            .iter()
            .find(|&&m| m - self.header_size <= avail)
            .map(|&mtu| Probe {
                mtu,
                limit: mtu - self.header_size,
            })
    }

    /// Write a probe, which must have come from [`Self::probe`].
    ///
    /// The caller has already set the packet size limit and is responsible for expanding the
    /// datagram to [`Probe::limit`].
    pub fn send_probe<B: Buffer>(
        &mut self,
        probe: Probe,
        ping: bool,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
    ) {
        let mtu = probe.mtu;
        self.probes.retain(|&m| m != mtu);
        if ping {
            builder.encode_frame(FrameType::Ping, |_| {});
            stats.frame_tx.ping += 1;
        }
        tokens.push(recovery::Token::PmtudProbe(mtu));
        stats.pmtud_tx += 1;
        qdebug!("Sending PMTUD probe of size {mtu}");
    }

    /// Checks whether PMTUD probes have been acknowledged, and if so, raises the MTU.
    pub fn on_packets_acked(
        &mut self,
        acked_pkts: &[sent::Packet],
        now: Instant,
        stats: &mut Stats,
    ) {
        self.black_hole.on_ack(acked_pkts);

        // Disregard ACKs on old paths.
        let (count, largest) = acked_pkts
            .iter()
            .filter(|p| p.on_primary_path())
            .filter_map(sent::Packet::pmtud_probe_size)
            .fold((0_usize, 0), |(n, largest), m| (n + 1, largest.max(m)));
        if count == 0 {
            return;
        }
        stats.pmtud_ack += count;

        let largest = largest.min(self.upper_bound());
        if largest > self.mtu && !self.black_holed {
            qdebug!("PMTUD probe of size {largest} succeeded");
            // An ACK confirms this size and all smaller sizes.
            self.probes.retain(|&m| m > largest);
            self.set_mtu(largest, stats, now);
        }
    }

    /// Checks whether PMTUD probes have been lost, and whether the path has become a black hole.
    pub fn on_packets_lost(
        &mut self,
        lost_packets: &[sent::Packet],
        stats: &mut Stats,
        now: Instant,
    ) {
        stats.pmtud_lost += lost_packets.iter().filter(|p| p.is_pmtud_probe()).count();
        if self
            .black_hole
            .on_evidence(lost_packets, self.plpmtu(), now)
        {
            qinfo!("PMTUD black hole detected from repeated loss of large packets");
            self.declare_black_hole(now, stats);
        }
    }

    /// Counts consecutive PTOs towards black hole detection.
    pub fn on_pto(
        &mut self,
        pto_count: usize,
        pto_packets: &[sent::Packet],
        stats: &mut Stats,
        now: Instant,
    ) {
        let large_outstanding = pto_packets
            .iter()
            .any(|p| self.black_hole.is_large_data_packet(p, self.plpmtu()));
        if pto_count >= BlackHoleDetector::THRESHOLD && self.mtu > BASE_MTU && large_outstanding {
            qinfo!("PMTUD black hole detected from {pto_count} consecutive PTOs");
            self.declare_black_hole(now, stats);
        }
    }

    /// Fall back to [`BASE_MTU`] and stay there for the life of this path.
    fn declare_black_hole(&mut self, now: Instant, stats: &mut Stats) {
        if self.black_holed {
            return;
        }
        self.black_holed = true;
        self.probes.clear();
        stats.pmtud_black_hole += 1;
        self.set_mtu(BASE_MTU, stats, now);
    }

    /// Whether this path has been probed, whether or not that produced any probes.
    #[must_use]
    pub const fn probed(&self) -> bool {
        self.probed
    }

    /// Whether a black hole has been detected on this path.
    #[must_use]
    pub const fn black_holed(&self) -> bool {
        self.black_holed
    }

    #[cfg(test)]
    fn take_probe(&mut self, avail: usize) -> Option<usize> {
        let mtu = self.probe(avail)?.mtu;
        self.probes.retain(|&m| m != mtu);
        Some(mtu)
    }
}

#[cfg(all(not(feature = "disable-encryption"), test))]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::{Duration, Instant},
    };

    use test_fixture::{fixture_init, now};

    use crate::{
        Pmtud, Stats, packet,
        pmtud::{BASE_MTU, BlackHoleDetector, MAX_PROBE_MTU},
        recovery::{self, sent},
    };

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    /// Enough for eight 1500-byte probes.
    const BUDGET: usize = 12_000;

    fn probe(
        pn: packet::Number,
        sent_time: Instant,
        mtu: usize,
        header_size: usize,
    ) -> sent::Packet {
        sent::Packet::new(
            packet::Type::Short,
            pn,
            sent_time,
            true,
            vec![recovery::Token::PmtudProbe(mtu)],
            mtu - header_size,
        )
    }

    const fn data(pn: packet::Number, sent_time: Instant, len: usize) -> sent::Packet {
        sent::Packet::new(packet::Type::Short, pn, sent_time, true, vec![], len)
    }

    fn setup(addr: IpAddr, iface_mtu: Option<usize>) -> (Pmtud, Stats, Instant) {
        fixture_init();
        (Pmtud::new(addr, iface_mtu), Stats::default(), now())
    }

    /// Send every planned probe, acking those that fit `path_mtu` and losing the rest.
    fn drain_probes(pmtud: &mut Pmtud, stats: &mut Stats, now: Instant, path_mtu: usize) {
        let header_size = pmtud.header_size;
        let mut pn = 0;
        let mut acked = Vec::new();
        let mut lost = Vec::new();
        while let Some(mtu) = pmtud.take_probe(usize::MAX) {
            let p = probe(pn, now, mtu, header_size);
            pn += 1;
            if mtu <= path_mtu {
                &mut acked
            } else {
                &mut lost
            }
            .push(p);
        }
        // Smaller probes have larger packet numbers, so their ACKs arrive alongside.
        pmtud.on_packets_lost(&lost, stats, now);
        pmtud.on_packets_acked(&acked, now, stats);
    }

    #[test]
    fn plan_probes_descending_and_bounded() {
        for &addr in &[V4, V6] {
            let (mut pmtud, _stats, now) = setup(addr, None);
            pmtud.plan_probes(BUDGET, None, now);
            assert_eq!(
                pmtud.probes,
                [1500, 1472, 1444, 1416, 1388, 1360, 1332, 1304],
                "for {addr}"
            );
            // The smallest probe is within one step of the base MTU.
            assert!(pmtud.probes[7] - BASE_MTU <= pmtud.probes[0] - pmtud.probes[1]);
        }
    }

    /// There is no point in more probes than there are distinct sizes to probe.
    #[test]
    fn plan_probes_bounded_by_range() {
        let (mut pmtud, _stats, now) = setup(V4, Some(BASE_MTU + 2));
        pmtud.plan_probes(BUDGET, None, now);
        assert_eq!(pmtud.probes, [BASE_MTU + 2, BASE_MTU + 1]);
    }

    /// Rounding the step up must not plan probes at or below the current MTU.
    #[test]
    fn plan_probes_stay_above_mtu() {
        let (mut pmtud, _stats, now) = setup(V4, Some(1300));
        pmtud.plan_probes(BUDGET, None, now);
        assert_eq!(pmtud.probes, [1300, 1297, 1294, 1291, 1288, 1285, 1282]);
    }

    #[test]
    fn plan_probes_respects_max_probes() {
        // A small `max_probes` still spans the full range, just more coarsely.
        let (mut pmtud, _stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, Some(3), now);
        assert_eq!(pmtud.probes, [1500, 1426, 1352]);
    }

    #[test]
    fn plan_probes_respects_budget() {
        let (mut pmtud, _stats, now) = setup(V4, None);
        pmtud.plan_probes(2 * MAX_PROBE_MTU, None, now);
        assert_eq!(pmtud.probes, [1500, 1390]);

        let (mut pmtud, _stats, now) = setup(V4, None);
        pmtud.plan_probes(100, None, now);
        assert!(pmtud.probes.is_empty());
    }

    #[test]
    fn plan_probes_respects_iface_mtu() {
        let (mut pmtud, _stats, now) = setup(V4, Some(1400));
        pmtud.plan_probes(BUDGET, None, now);
        assert_eq!(
            pmtud.probes,
            [1400, 1385, 1370, 1355, 1340, 1325, 1310, 1295]
        );
    }

    #[test]
    fn plan_probes_respects_peer_max_udp_payload() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.set_peer_max_udp_payload(1350, now, &mut stats);
        pmtud.plan_probes(BUDGET, None, now);
        // 1350 plus the 28-byte IPv4 and UDP headers.
        assert_eq!(
            pmtud.probes,
            [1378, 1365, 1352, 1339, 1326, 1313, 1300, 1287]
        );
    }

    #[test]
    fn plan_probes_nothing_to_probe() {
        let (mut pmtud, _stats, now) = setup(V4, Some(BASE_MTU));
        pmtud.plan_probes(BUDGET, None, now);
        assert!(pmtud.probes.is_empty());
        assert_eq!(pmtud.plpmtu(), Pmtud::default_plpmtu(V4));
    }

    #[test]
    fn take_probe_largest_that_fits() {
        let (mut pmtud, _stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        let planned = pmtud.probes.clone();
        // Nothing fits.
        assert!(pmtud.take_probe(0).is_none());
        // Only the smallest fits.
        let smallest = *planned.last().unwrap();
        assert_eq!(
            pmtud.take_probe(smallest - Pmtud::header_size(V4)),
            Some(smallest)
        );
        // Now the largest fits.
        assert_eq!(pmtud.take_probe(usize::MAX), Some(planned[0]));
    }

    #[test]
    fn ack_confirms_size_and_all_smaller() {
        for &addr in &[V4, V6] {
            for path_mtu in [BASE_MTU, 1300, 1400, MAX_PROBE_MTU, 9000] {
                let (mut pmtud, mut stats, now) = setup(addr, None);
                pmtud.plan_probes(BUDGET, None, now);
                let planned = pmtud.probes.clone();
                drain_probes(&mut pmtud, &mut stats, now, path_mtu);

                let expected = planned
                    .iter()
                    .copied()
                    .filter(|&m| m <= path_mtu)
                    .max()
                    .unwrap_or(BASE_MTU);
                assert_eq!(pmtud.mtu, expected, "path MTU {path_mtu} for {addr}");
                assert!(!pmtud.needs_probe());
            }
        }
    }

    #[test]
    fn ack_of_smaller_probe_does_not_lower_mtu() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        let planned = pmtud.probes.clone();
        let hs = Pmtud::header_size(V4);

        pmtud.on_packets_acked(&[probe(0, now, planned[0], hs)], now, &mut stats);
        assert_eq!(pmtud.mtu, planned[0]);
        pmtud.on_packets_acked(&[probe(1, now, planned[3], hs)], now, &mut stats);
        assert_eq!(pmtud.mtu, planned[0]);
    }

    #[test]
    fn all_probes_lost_keeps_base_mtu() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        let count = pmtud.probes.len();
        drain_probes(&mut pmtud, &mut stats, now, BASE_MTU);
        assert_eq!(pmtud.mtu, BASE_MTU);
        assert_eq!(stats.pmtud_lost, count);
        assert_eq!(stats.pmtud_ack, 0);
        // Lost probes never count towards black hole detection.
        assert!(!pmtud.black_holed());
    }

    #[test]
    fn peer_max_udp_payload_lowers_confirmed_mtu() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        drain_probes(&mut pmtud, &mut stats, now, MAX_PROBE_MTU);
        assert_eq!(pmtud.mtu, MAX_PROBE_MTU);

        // An ACK does not override the transport parameter.
        pmtud.set_peer_max_udp_payload(1300, now, &mut stats);
        assert_eq!(pmtud.mtu, 1300 + Pmtud::header_size(V4));
        assert_eq!(stats.pmtud_pmtu, pmtud.mtu);
    }

    #[test]
    fn ack_does_not_override_peer_max_udp_payload() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        // The largest probe is in flight when the transport parameter arrives, so it is not
        // pruned, and it is larger than the 1378 the parameter allows.
        let mtu = pmtud.take_probe(usize::MAX).unwrap();
        assert_eq!(mtu, MAX_PROBE_MTU);
        pmtud.set_peer_max_udp_payload(1350, now, &mut stats);
        pmtud.on_packets_acked(&[probe(0, now, mtu, pmtud.header_size)], now, &mut stats);
        assert_eq!(pmtud.mtu, 1350 + Pmtud::header_size(V4));
    }

    #[test]
    fn ack_of_probe_from_another_path_is_ignored() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        let mtu = pmtud.take_probe(usize::MAX).unwrap();

        // A probe still in flight on a path we migrated away from says nothing about this path.
        let mut p = probe(0, now, mtu, pmtud.header_size);
        p.clear_primary_path();
        pmtud.on_packets_acked(&[p], now, &mut stats);
        assert_eq!(pmtud.mtu, BASE_MTU);
        assert_eq!(stats.pmtud_ack, 0);
    }

    #[test]
    fn peer_max_udp_payload_never_below_base_mtu() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.set_peer_max_udp_payload(1200, now, &mut stats);
        assert_eq!(pmtud.mtu, BASE_MTU);
    }

    #[test]
    fn black_hole_after_repeated_loss() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        drain_probes(&mut pmtud, &mut stats, now, MAX_PROBE_MTU);
        assert_eq!(pmtud.mtu, MAX_PROBE_MTU);

        // Separate loss events, since losses reported at one instant count once however many
        // calls report them.
        let large = pmtud.plpmtu();
        for i in 0..BlackHoleDetector::THRESHOLD {
            assert!(!pmtud.black_holed());
            let at = now + Duration::from_millis(i as u64 + 1);
            pmtud.on_packets_lost(&[data(i as u64, at, large)], &mut stats, at);
        }
        assert!(pmtud.black_holed());
        assert_eq!(pmtud.mtu, BASE_MTU);
        assert_eq!(stats.pmtud_black_hole, 1);

        // And it stays there.
        pmtud.plan_probes(BUDGET, None, now);
        assert!(!pmtud.needs_probe());
    }

    #[test]
    fn black_hole_reset_by_ack_of_large_packet() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        drain_probes(&mut pmtud, &mut stats, now, MAX_PROBE_MTU);

        let large = pmtud.plpmtu();
        for i in 0..BlackHoleDetector::THRESHOLD - 1 {
            let at = now + Duration::from_millis(i as u64 + 1);
            pmtud.on_packets_lost(&[data(i as u64, at, large)], &mut stats, at);
        }
        // Ordinary congestion loss: the path still carries this size.
        pmtud.on_packets_acked(&[data(100, now, large)], now, &mut stats);
        for i in 0..BlackHoleDetector::THRESHOLD - 1 {
            let at = now + Duration::from_millis(i as u64 + 10);
            pmtud.on_packets_lost(&[data(200 + i as u64, at, large)], &mut stats, at);
        }
        assert!(!pmtud.black_holed());
        assert_eq!(pmtud.mtu, MAX_PROBE_MTU);
    }

    #[test]
    fn black_hole_after_repeated_pto() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        drain_probes(&mut pmtud, &mut stats, now, MAX_PROBE_MTU);

        let large = [data(0, now, pmtud.plpmtu())];
        for i in 1..BlackHoleDetector::THRESHOLD {
            pmtud.on_pto(i, &large, &mut stats, now);
            assert!(!pmtud.black_holed());
        }
        pmtud.on_pto(BlackHoleDetector::THRESHOLD, &large, &mut stats, now);
        assert!(pmtud.black_holed());
        assert_eq!(pmtud.mtu, BASE_MTU);
    }

    #[test]
    fn pto_without_large_packets_is_not_a_black_hole() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        drain_probes(&mut pmtud, &mut stats, now, MAX_PROBE_MTU);

        // An outage produces consecutive PTOs too, and while the peer is silent nothing discards
        // the evidence an earlier loss left behind. Only what this PTO is retransmitting counts.
        pmtud.on_packets_lost(&[data(0, now, pmtud.plpmtu())], &mut stats, now);
        let small = [data(1, now, Pmtud::default_plpmtu(V4))];
        for i in 1..=2 * BlackHoleDetector::THRESHOLD {
            pmtud.on_pto(i, &small, &mut stats, now);
        }
        assert!(!pmtud.black_holed());
        assert_eq!(pmtud.mtu, MAX_PROBE_MTU);
    }

    #[test]
    fn black_hole_ignores_small_packets() {
        let (mut pmtud, mut stats, now) = setup(V4, None);
        pmtud.plan_probes(BUDGET, None, now);
        drain_probes(&mut pmtud, &mut stats, now, MAX_PROBE_MTU);

        let small = Pmtud::default_plpmtu(V4);
        for i in 0..(2 * BlackHoleDetector::THRESHOLD) {
            let at = now + Duration::from_millis(i as u64 + 1);
            pmtud.on_packets_lost(&[data(i as u64, at, small)], &mut stats, at);
        }
        assert!(!pmtud.black_holed());
    }
}
