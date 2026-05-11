// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control

use std::time::{Duration, Instant};

use neqo_common::{qdebug, qlog::Qlog};

use crate::{
    ConnectionParameters, SlowStart, Stats,
    cc::{
        ClassicCongestionController, ClassicSlowStart, CongestionControl,
        CongestionControlImplementation, CongestionController as _, Cubic, HyStart, NewReno,
        Search,
    },
    pace::Pacer,
    pmtud::Pmtud,
    qlog,
    recovery::sent,
    rtt::RttEstimate,
    stats::CongestionControlStats,
};

/// The number of packets we allow to burst from the pacer.
pub const PACING_BURST_SIZE: usize = 2;

#[derive(Debug)]
pub struct PacketSender {
    cc: CongestionControlImplementation,
    pacer: Pacer,
    qlog: Qlog,
}

impl PacketSender {
    #[must_use]
    pub fn new(conn_params: &ConnectionParameters, pmtud: Pmtud, now: Instant) -> Self {
        let mtu = pmtud.plpmtu();
        let spurious_recovery = conn_params.spurious_recovery_enabled();
        Self {
            cc: match (
                conn_params.get_congestion_control(),
                conn_params.get_slow_start(),
            ) {
                (CongestionControl::NewReno, SlowStart::Classic) => {
                    CongestionControlImplementation::ClassicNewReno(
                        ClassicCongestionController::new(
                            ClassicSlowStart::default(),
                            NewReno::default(),
                            pmtud,
                            spurious_recovery,
                        ),
                    )
                }
                (CongestionControl::NewReno, SlowStart::HyStart) => {
                    CongestionControlImplementation::HyStartNewReno(
                        ClassicCongestionController::new(
                            HyStart::new(
                                conn_params.pacing_enabled(),
                                conn_params.get_hystart_css_baseline(),
                            ),
                            NewReno::default(),
                            pmtud,
                            spurious_recovery,
                        ),
                    )
                }
                (CongestionControl::NewReno, SlowStart::Search) => {
                    CongestionControlImplementation::SearchNewReno(
                        ClassicCongestionController::new(
                            Search::new(),
                            NewReno::default(),
                            pmtud,
                            spurious_recovery,
                        ),
                    )
                }
                (CongestionControl::Cubic, SlowStart::Classic) => {
                    CongestionControlImplementation::ClassicCubic(ClassicCongestionController::new(
                        ClassicSlowStart::default(),
                        Cubic::default(),
                        pmtud,
                        spurious_recovery,
                    ))
                }
                (CongestionControl::Cubic, SlowStart::HyStart) => {
                    CongestionControlImplementation::HyStartCubic(ClassicCongestionController::new(
                        HyStart::new(
                            conn_params.pacing_enabled(),
                            conn_params.get_hystart_css_baseline(),
                        ),
                        Cubic::default(),
                        pmtud,
                        spurious_recovery,
                    ))
                }
                (CongestionControl::Cubic, SlowStart::Search) => {
                    CongestionControlImplementation::SearchCubic(ClassicCongestionController::new(
                        Search::new(),
                        Cubic::default(),
                        pmtud,
                        spurious_recovery,
                    ))
                }
            },
            pacer: Pacer::new(
                conn_params.pacing_enabled(),
                now,
                mtu * PACING_BURST_SIZE,
                mtu,
            ),
            qlog: Qlog::default(),
        }
    }

    pub fn set_qlog(&mut self, qlog: Qlog) {
        self.qlog = qlog.clone();
        self.cc.set_qlog(qlog);
    }

    pub fn pmtud(&self) -> &Pmtud {
        self.cc.pmtud()
    }

    pub fn pmtud_mut(&mut self) -> &mut Pmtud {
        self.cc.pmtud_mut()
    }

    #[must_use]
    pub fn cwnd(&self) -> usize {
        self.cc.cwnd()
    }

    #[must_use]
    pub fn cwnd_avail(&self) -> usize {
        self.cc.cwnd_avail()
    }

    #[cfg(test)]
    #[must_use]
    pub fn cwnd_min(&self) -> usize {
        self.cc.cwnd_min()
    }

    /// Emit a `PacingRate` qlog metric.
    fn maybe_qlog_pacing_rate(&mut self, rtt: Duration, now: Instant) {
        if let Some(rate) = Pacer::rate(self.cc.cwnd(), rtt) {
            qlog::metrics_updated(&mut self.qlog, [qlog::Metric::PacingRate(rate)], now);
        }
    }

    fn maybe_update_pacer_mtu(&mut self) {
        let current_mtu = self.pmtud().plpmtu();
        if current_mtu != self.pacer.mtu() {
            qdebug!(
                "PLPMTU changed from {} to {current_mtu}, updating pacer",
                self.pacer.mtu()
            );
            self.pacer.set_mtu(current_mtu);
        }
    }

    pub fn on_packets_acked(
        &mut self,
        acked_pkts: &[sent::Packet],
        rtt_est: &RttEstimate,
        now: Instant,
        stats: &mut Stats,
    ) {
        self.cc
            .on_packets_acked(acked_pkts, rtt_est, now, &mut stats.cc);
        self.maybe_qlog_pacing_rate(rtt_est.estimate(), now);
        self.pmtud_mut().on_packets_acked(acked_pkts, now, stats);
        self.maybe_update_pacer_mtu();
    }

    /// Called when packets are lost.  Returns true if the congestion window was reduced.
    pub fn on_packets_lost(
        &mut self,
        first_rtt_sample_time: Option<Instant>,
        prev_largest_acked_sent: Option<Instant>,
        pto: Duration,
        lost_packets: &[sent::Packet],
        stats: &mut Stats,
        now: Instant,
    ) -> bool {
        let ret = self.cc.on_packets_lost(
            first_rtt_sample_time,
            prev_largest_acked_sent,
            pto,
            lost_packets,
            now,
            &mut stats.cc,
        );
        // Call below may change the size of MTU probes, so it needs to happen after the CC
        // reaction above, which needs to ignore probes based on their size.
        self.pmtud_mut().on_packets_lost(lost_packets, stats, now);
        self.maybe_update_pacer_mtu();
        ret
    }

    /// Called when ECN CE mark received.  Returns true if the congestion window was reduced.
    pub fn on_ecn_ce_received(
        &mut self,
        largest_acked_pkt: &sent::Packet,
        now: Instant,
        cc_stats: &mut CongestionControlStats,
    ) -> bool {
        self.cc.on_ecn_ce_received(largest_acked_pkt, now, cc_stats)
    }

    pub fn discard(&mut self, pkt: &sent::Packet, now: Instant) {
        self.cc.discard(pkt, now);
    }

    /// When we migrate, the congestion controller for the previously active path drops
    /// all bytes in flight.
    pub fn discard_in_flight(&mut self, now: Instant) {
        self.cc.discard_in_flight(now);
    }

    pub fn on_packet_sent(&mut self, pkt: &sent::Packet, rtt: Duration, now: Instant) {
        self.pacer
            .spend(pkt.time_sent(), rtt, self.cc.cwnd(), pkt.len());
        self.cc.on_packet_sent(pkt, now);
    }

    #[must_use]
    pub fn next_paced(&self, rtt: Duration) -> Option<Instant> {
        // Only pace if there are bytes in flight.
        (self.cc.bytes_in_flight() > 0).then(|| self.pacer.next(rtt, self.cc.cwnd()))
    }

    #[must_use]
    pub fn recovery_packet(&self) -> bool {
        self.cc.recovery_packet()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use test_fixture::now;

    use super::PacketSender;
    use crate::{ConnectionParameters, SlowStart, cc::CongestionControl, pmtud::Pmtud};

    #[test]
    fn packet_sender_creation_and_display() {
        let now = now();
        let cases = [
            (
                CongestionControl::NewReno,
                SlowStart::Classic,
                "ClassicSlowStart/NewReno",
            ),
            (
                CongestionControl::NewReno,
                SlowStart::HyStart,
                "HyStart++/NewReno",
            ),
            (
                CongestionControl::NewReno,
                SlowStart::Search,
                "SEARCH/NewReno",
            ),
            (
                CongestionControl::Cubic,
                SlowStart::Classic,
                "ClassicSlowStart/Cubic",
            ),
            (
                CongestionControl::Cubic,
                SlowStart::HyStart,
                "HyStart++/Cubic",
            ),
            (CongestionControl::Cubic, SlowStart::Search, "SEARCH/Cubic"),
        ];
        for (cc, ss, expected_prefix) in cases {
            let params = ConnectionParameters::default()
                .congestion_control(cc)
                .slow_start(ss);
            let sender = PacketSender::new(
                &params,
                Pmtud::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(1500)),
                now,
            );
            let description = sender.cc.to_string();
            assert!(
                description.starts_with(expected_prefix),
                "expected prefix {expected_prefix:?}, got {description:?}",
            );
        }
    }
}
