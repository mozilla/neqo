// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control
#![deny(clippy::pedantic)]

use std::cmp::{max, min};
use std::fmt::{self, Display};
use std::time::{Duration, Instant};

use crate::cc::cubic::Cubic;
use crate::cc::{
    CongestionControl, CongestionControlAlgorithm, CWND_INITIAL, CWND_MIN, MAX_DATAGRAM_SIZE,
};
use crate::pace::Pacer;
use crate::qlog::{self, CongestionState, QlogMetric};
use crate::tracking::SentPacket;
use neqo_common::{qdebug, qinfo, qlog::NeqoQlog, qtrace};

/// The number of packets we allow to burst from the pacer.
pub const PACING_BURST_SIZE: usize = 2;
pub const PERSISTENT_CONG_THRESH: u32 = 3;

#[derive(Debug)]
pub enum CcVersion {
    NewReno,
    Cubic(Cubic),
}

impl CcVersion {
    pub fn new(cc: &CongestionControlAlgorithm) -> Self {
        match cc {
            CongestionControlAlgorithm::NewReno => Self::NewReno,
            CongestionControlAlgorithm::Cubic => Self::Cubic(Cubic::default()),
        }
    }
}

impl Display for CcVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::NewReno => "NewReno",
                Self::Cubic(..) => "Cubic",
            }
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NewRenoCubic {
    cc_version: CcVersion,
    congestion_window: usize, // = kInitialWindow
    bytes_in_flight: usize,
    acked_bytes: usize,
    congestion_recovery_start_time: Option<Instant>,
    ssthresh: usize,
    pacer: Option<Pacer>,
    in_recovery: bool,

    qlog: NeqoQlog,
    qlog_curr_cong_state: CongestionState,
}

impl Display for NewRenoCubic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CongCtrl {} {}/{} ssthresh {}",
            self.cc_version, self.bytes_in_flight, self.congestion_window, self.ssthresh,
        )?;
        if let Some(p) = &self.pacer {
            write!(f, " {}", p)?;
        }
        Ok(())
    }
}

impl CongestionControl for NewRenoCubic {
    fn set_qlog(&mut self, qlog: NeqoQlog) {
        self.qlog = qlog;
    }

    #[cfg(test)]
    #[must_use]
    fn cwnd(&self) -> usize {
        self.congestion_window
    }

    #[cfg(test)]
    #[must_use]
    fn ssthresh(&self) -> usize {
        self.ssthresh
    }

    #[cfg(test)]
    #[must_use]
    fn bif(&self) -> usize {
        self.bytes_in_flight
    }

    #[must_use]
    fn cwnd_avail(&self) -> usize {
        // BIF can be higher than cwnd due to PTO packets, which are sent even
        // if avail is 0, but still count towards BIF.
        self.congestion_window.saturating_sub(self.bytes_in_flight)
    }

    // Multi-packet version of OnPacketAckedCC
    fn on_packets_acked(&mut self, acked_pkts: &[SentPacket], now: Instant, rtt: Duration) {
        let mut acked_bytes = 0;
        for pkt in acked_pkts.iter().filter(|pkt| pkt.cc_outstanding()) {
            assert!(self.bytes_in_flight >= pkt.size);
            self.bytes_in_flight -= pkt.size;

            if !self.after_recovery_start(pkt.time_sent) {
                // Do not increase congestion window for packets sent before
                // recovery start.
                continue;
            }

            if self.in_recovery {
                self.in_recovery = false;
                qlog::metrics_updated(&mut self.qlog, &[QlogMetric::InRecovery(false)]);
            }

            if self.app_limited() {
                // Do not increase congestion_window if application limited.
                qlog::congestion_state_updated(
                    &mut self.qlog,
                    &mut self.qlog_curr_cong_state,
                    CongestionState::ApplicationLimited,
                );
                continue;
            }

            acked_bytes += pkt.size;
        }
        qtrace!([self], "ACK received, acked_bytes = {}", self.acked_bytes);

        self.acked_bytes += acked_bytes;
        // Slow start, up to the slow start threshold.
        if self.congestion_window < self.ssthresh {
            let increase = min(self.ssthresh - self.congestion_window, self.acked_bytes);
            self.congestion_window += increase;
            self.acked_bytes -= increase;
            qinfo!([self], "slow start += {}", increase);
            qlog::congestion_state_updated(
                &mut self.qlog,
                &mut self.qlog_curr_cong_state,
                CongestionState::SlowStart,
            );
        } else {
            // Congestion avoidance, above the slow start threshold.
            match self.cc_version {
                CcVersion::NewReno => {
                    if self.acked_bytes >= self.congestion_window {
                        self.acked_bytes -= self.congestion_window;
                        self.congestion_window += MAX_DATAGRAM_SIZE;
                        qinfo!([self], "congestion avoidance += {}", MAX_DATAGRAM_SIZE);
                        qlog::congestion_state_updated(
                            &mut self.qlog,
                            &mut self.qlog_curr_cong_state,
                            CongestionState::CongestionAvoidance,
                        );
                    }
                }
                CcVersion::Cubic(ref mut c) => c.calculate_cwnd_ca(
                    &mut self.congestion_window,
                    now,
                    rtt,
                    &mut self.acked_bytes,
                    acked_bytes,
                ),
            }
        }
        qlog::metrics_updated(
            &mut self.qlog,
            &[
                QlogMetric::CongestionWindow(self.congestion_window),
                QlogMetric::BytesInFlight(self.bytes_in_flight),
            ],
        );
    }

    fn on_packets_lost(
        &mut self,
        now: Instant,
        first_rtt_sample_time: Option<Instant>,
        prev_largest_acked_sent: Option<Instant>,
        pto: Duration,
        lost_packets: &[SentPacket],
    ) {
        if lost_packets.is_empty() {
            return;
        }

        for pkt in lost_packets.iter().filter(|pkt| pkt.ack_eliciting()) {
            assert!(self.bytes_in_flight >= pkt.size);
            self.bytes_in_flight -= pkt.size;
        }
        qlog::metrics_updated(
            &mut self.qlog,
            &[QlogMetric::BytesInFlight(self.bytes_in_flight)],
        );

        qdebug!([self], "Pkts lost {}", lost_packets.len());

        let last_lost_pkt = lost_packets.last().unwrap();
        self.on_congestion_event(now, last_lost_pkt.time_sent);
        self.detect_persistent_congestion(
            first_rtt_sample_time,
            prev_largest_acked_sent,
            pto,
            lost_packets,
        );
    }

    fn discard(&mut self, pkt: &SentPacket) {
        if pkt.cc_outstanding() {
            assert!(self.bytes_in_flight >= pkt.size);
            self.bytes_in_flight -= pkt.size;
            qlog::metrics_updated(
                &mut self.qlog,
                &[QlogMetric::BytesInFlight(self.bytes_in_flight)],
            );
            qtrace!([self], "Ignore pkt with size {}", pkt.size);
        }
    }

    fn on_packet_sent(&mut self, pkt: &SentPacket, rtt: Duration) {
        self.pacer
            .as_mut()
            .unwrap()
            .spend(pkt.time_sent, rtt, self.congestion_window, pkt.size);

        if !pkt.ack_eliciting() {
            return;
        }

        self.bytes_in_flight += pkt.size;
        qdebug!(
            [self],
            "Pkt Sent len {}, bif {}, cwnd {}",
            pkt.size,
            self.bytes_in_flight,
            self.congestion_window
        );
        qlog::metrics_updated(
            &mut self.qlog,
            &[QlogMetric::BytesInFlight(self.bytes_in_flight)],
        );
    }

    fn start_pacer(&mut self, now: Instant) {
        // Start the pacer with a small burst size.
        self.pacer = Some(Pacer::new(
            now,
            MAX_DATAGRAM_SIZE * PACING_BURST_SIZE,
            MAX_DATAGRAM_SIZE,
        ));
    }

    fn next_paced(&self, rtt: Duration) -> Option<Instant> {
        // Only pace if there are bytes in flight.
        if self.bytes_in_flight > 0 {
            Some(
                self.pacer
                    .as_ref()
                    .unwrap()
                    .next(rtt, self.congestion_window),
            )
        } else {
            None
        }
    }
}

impl NewRenoCubic {
    pub fn new(cc: &CongestionControlAlgorithm) -> Self {
        Self {
            cc_version: CcVersion::new(cc),
            congestion_window: CWND_INITIAL,
            bytes_in_flight: 0,
            acked_bytes: 0,
            congestion_recovery_start_time: None,
            ssthresh: usize::MAX,
            pacer: None,
            in_recovery: false,
            qlog: NeqoQlog::disabled(),
            qlog_curr_cong_state: CongestionState::SlowStart,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn acked_bytes(&self) -> usize {
        self.acked_bytes
    }

    #[cfg(test)]
    pub fn detect_persistent_congestion_test(
        &mut self,
        first_rtt_sample_time: Option<Instant>,
        prev_largest_acked_sent: Option<Instant>,
        pto: Duration,
        lost_packets: &[SentPacket],
    ) {
        self.detect_persistent_congestion(
            first_rtt_sample_time,
            prev_largest_acked_sent,
            pto,
            lost_packets,
        );
    }

    fn detect_persistent_congestion(
        &mut self,
        first_rtt_sample_time: Option<Instant>,
        prev_largest_acked_sent: Option<Instant>,
        pto: Duration,
        lost_packets: &[SentPacket],
    ) {
        if first_rtt_sample_time.is_none() {
            return;
        }

        let pc_period = pto * PERSISTENT_CONG_THRESH;

        let mut last_pn = 1 << 62; // Impossibly large, but not enough to overflow.
        let mut start = None;

        // Look for the first lost packet after the previous largest acknowledged.
        // Ignore packets that weren't ack-eliciting for the start of this range.
        // Also, make sure to ignore any packets sent before we got an RTT estimate
        // as we might not have sent PTO packets soon enough after those.
        let cutoff = max(first_rtt_sample_time, prev_largest_acked_sent);
        for p in lost_packets
            .iter()
            .skip_while(|p| Some(p.time_sent) < cutoff)
        {
            if p.pn != last_pn + 1 {
                // Not a contiguous range of lost packets, start over.
                start = None;
            }
            last_pn = p.pn;
            if !p.ack_eliciting() {
                // Not interesting, keep looking.
                continue;
            }
            if let Some(t) = start {
                if p.time_sent.duration_since(t) > pc_period {
                    self.congestion_window = CWND_MIN;
                    self.acked_bytes = 0;
                    qlog::metrics_updated(
                        &mut self.qlog,
                        &[QlogMetric::CongestionWindow(self.congestion_window)],
                    );
                    qinfo!([self], "persistent congestion");
                    return;
                }
            } else {
                start = Some(p.time_sent);
            }
        }
    }

    #[must_use]
    fn after_recovery_start(&mut self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start_time {
            Some(crst) => sent_time > crst,
            None => true,
        }
    }

    fn on_congestion_event(&mut self, now: Instant, sent_time: Instant) {
        // Start a new congestion event if lost packet was sent after the start
        // of the previous congestion recovery period.
        if self.after_recovery_start(sent_time) {
            self.congestion_recovery_start_time = Some(now);
            match self.cc_version {
                CcVersion::NewReno => {
                    self.congestion_window /= 2; // kLossReductionFactor = 0.5
                    self.acked_bytes /= 2;
                    self.congestion_window = max(self.congestion_window, CWND_MIN);
                }
                CcVersion::Cubic(ref mut c) => {
                    c.on_congestion_event(&mut self.congestion_window);
                    self.acked_bytes = 0;
                }
            }
            self.ssthresh = self.congestion_window;
            qinfo!(
                [self],
                "Cong event -> recovery; cwnd {}, ssthresh {}",
                self.congestion_window,
                self.ssthresh
            );
            qlog::metrics_updated(
                &mut self.qlog,
                &[
                    QlogMetric::CongestionWindow(self.congestion_window),
                    QlogMetric::SsThresh(self.ssthresh),
                    QlogMetric::InRecovery(true),
                ],
            );
            self.in_recovery = true;
            qlog::congestion_state_updated(
                &mut self.qlog,
                &mut self.qlog_curr_cong_state,
                CongestionState::Recovery,
            );
        }
    }

    #[allow(clippy::unused_self)]
    fn app_limited(&self) -> bool {
        //TODO(agrover): how do we get this info??
        false
    }
}
