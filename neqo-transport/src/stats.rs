// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracking of some useful statistics.

use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    rc::Rc,
    time::Duration,
};

use enum_map::EnumMap;
use neqo_common::{Dscp, Ecn, qdebug};
use serde::{Serialize, Serializer, ser::SerializeMap as _};
use serde_with::skip_serializing_none;
use strum::IntoEnumIterator as _;

use crate::{cc::CongestionTrigger, ecn, packet, version::Version};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct FrameStats {
    pub ack: usize,
    pub largest_acknowledged: packet::Number,

    pub crypto: usize,
    pub stream: usize,
    pub reset_stream: usize,
    pub reset_stream_at: usize,
    pub stop_sending: usize,

    pub ping: usize,
    pub padding: usize,

    pub max_streams: usize,
    pub streams_blocked: usize,
    pub max_data: usize,
    pub data_blocked: usize,
    pub max_stream_data: usize,
    pub stream_data_blocked: usize,

    pub new_connection_id: usize,
    pub retire_connection_id: usize,

    pub path_challenge: usize,
    pub path_response: usize,

    pub connection_close: usize,
    pub handshake_done: usize,
    pub new_token: usize,

    pub ack_frequency: usize,
    pub datagram: usize,
}

#[cfg(test)]
impl FrameStats {
    pub const fn all(&self) -> usize {
        self.ack
            + self.crypto
            + self.stream
            + self.reset_stream
            + self.reset_stream_at
            + self.stop_sending
            + self.ping
            + self.padding
            + self.max_streams
            + self.streams_blocked
            + self.max_data
            + self.data_blocked
            + self.max_stream_data
            + self.stream_data_blocked
            + self.new_connection_id
            + self.retire_connection_id
            + self.path_challenge
            + self.path_response
            + self.connection_close
            + self.handshake_done
            + self.new_token
            + self.ack_frequency
            + self.datagram
    }
}

/// Datagram stats
#[derive(Default, Clone, PartialEq, Eq, Serialize)]
pub struct DatagramStats {
    /// The number of datagrams declared lost.
    pub lost: usize,
    /// The number of datagrams dropped due to being too large.
    pub dropped_too_big: usize,
    /// The number of datagrams dropped due to reaching the limit of the
    /// outgoing queue.
    pub dropped_queue_full: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SlowStartExitReason {
    /// Exited due to a congestion event. Carries the trigger (loss or ECN).
    CongestionEvent(CongestionTrigger),
    /// Exited due to a heuristic algorithm.
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlowStartExitStats {
    /// The reason slow start was exited. The `CongestionEvent` variant carries a
    /// `CongestionTrigger` (`Loss` or `Ecn`) and `Loss` carries the amount of lost packets.
    pub reason: SlowStartExitReason,
    /// The congestion window when the exit was detected. For a congestion event this is the cwnd
    /// BEFORE the reduction.
    pub detection_cwnd: usize,
    /// The congestion window after exiting. For a congestion event this is the cwnd AFTER the
    /// reduction.
    pub exit_cwnd: usize,
    /// Bytes in flight when the exit was detected. For an exit by packet loss this is the bytes in
    /// flight BEFORE subtracting the lost bytes, i.e. the path saturation at the moment of loss.
    pub bytes_in_flight: usize,
}

/// Congestion event counters.
///
/// `loss` and `ecn` are mutually exclusive triggers (their sum equals the total number of
/// congestion events). `spurious` is an orthogonal category that applies to a subset of
/// loss-triggered congestion events.
#[derive(Default, Clone, PartialEq, Eq, Serialize)]
pub struct CongestionEventStats {
    /// Congestion events triggered by packet loss.
    pub loss: usize,
    /// Congestion events triggered by ECN-CE marks.
    pub ecn: usize,
    /// Congestion events later found to be spurious, due to packets which were initially
    /// considered lost but later got acknowledged.
    pub spurious: usize,
}

/// Tracks SEARCH reset occurrences: how many times SEARCH reset and the maximum number of bins
/// skipped across all resets.
#[skip_serializing_none]
#[derive(Default, Clone, PartialEq, Eq, Serialize)]
pub struct SearchResetStats {
    pub count: usize,
    pub max_passed_bins: Option<usize>,
}

/// Congestion Control stats
#[skip_serializing_none]
#[derive(Default, Clone, PartialEq, Serialize)]
pub struct CongestionControlStats {
    /// Congestion event counters. Includes trigger type and other qualifier flags.
    pub congestion_events: CongestionEventStats,
    /// Statistics captured at the moment a connection exits slow start. Set once on exit and is
    /// reset to `None` if the triggering congestion event is later found to be spurious.
    pub slow_start_exit: Option<SlowStartExitStats>,
    /// Number of times HyStart++ entered CSS (Conservative Slow Start). Only meaningful when
    /// HyStart++ is enabled. Higher values indicate that HyStart++ had many spurious CSS
    /// entries, spending more time throttling slow start growth.
    pub hystart_css_entries: usize,
    /// Number of CSS (Conservative Slow Start) rounds completed. Only meaningful when HyStart++ is
    /// enabled. Higher values indicate the heuristic spent more time throttling slow start growth.
    pub hystart_css_rounds_finished: usize,
    /// Drain-phase target estimate for the BDP with empty buffers. None if we haven't exited slow
    /// start through SEARCH. Is `u64` because Firefox uses it as such.
    pub search_empty_buffer_target: Option<u64>,
    /// Drain-phase target estimate for the BDP with full buffers. None if we haven't exited slow
    /// start through SEARCH. Is `u64` because Firefox uses it as such.
    pub search_full_buffer_target: Option<u64>,
    /// Records the maximum value of lookback bins needed due to RTT inflation. Fires whenever
    /// SEARCH can't run because there is not enough data for lookback. Is `None` if SEARCH never
    /// ran into this issue.
    pub search_lookback_bins_needed: Option<usize>,
    /// Records the maximum non-exiting value that the normalized difference between sent and acked
    /// bytes ever reached. Can be used to tune the exit threshold. `None` means that the SEARCH
    /// check never ran.
    pub search_max_norm_diff: Option<usize>,
    /// Records SEARCH reset occurrences.
    pub search_reset: SearchResetStats,
    /// Records the number of times per connection that SEARCH calculated zero bytes sent in the
    /// previous RTT. This exists to gain deeper understanding into app-limited behaviour.
    pub search_zero_sent_bytes: usize,
    /// The `latest_rtt` from the first ACK that initialized SEARCH. Used to evaluate whether the
    /// initial RTT sample (which sets `bin_duration`) is inflated relative to `min_rtt`.
    pub search_first_rtt: Option<Duration>,
    /// The `latest_rtt` from the second ACK processed by SEARCH. Together with `search_first_rtt`,
    /// allows evaluating whether `min(first, second)` would be a better initialization value.
    pub search_second_rtt: Option<Duration>,
    /// Cubic's `w_max`: the congestion window (in bytes) just before the most recent
    /// congestion reduction (with fast convergence applied). `None` if no congestion event has
    /// occurred or Cubic is not in use. Recorded as a stat to approximate a connection's ideal
    /// congestion window in metrics.
    pub w_max: Option<f64>,
    /// The current congestion window size (in bytes). Updated throughout the connection
    /// lifetime.
    pub cwnd: Option<usize>,
}

/// ECN counts by QUIC [`packet::Type`].
#[derive(Default, Clone, PartialEq, Eq)]
pub struct EcnCount(EnumMap<packet::Type, ecn::Count>);

impl Serialize for EcnCount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (pt, count) in self.0 {
            // Don't show all-zero rows.
            if count.is_empty() {
                continue;
            }
            map.serialize_entry(&pt, &count)?;
        }
        map.end()
    }
}

impl Deref for EcnCount {
    type Target = EnumMap<packet::Type, ecn::Count>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EcnCount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Packet types and numbers of the first ECN mark transition between two marks.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct EcnTransitions(EnumMap<Ecn, EnumMap<Ecn, Option<(packet::Type, packet::Number)>>>);

impl Deref for EcnTransitions {
    type Target = EnumMap<Ecn, EnumMap<Ecn, Option<(packet::Type, packet::Number)>>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EcnTransitions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Transitions recorded for a single "from" ECN mark, keyed by "to" mark.
struct EcnTransitionRow<'a>(&'a EnumMap<Ecn, Option<(packet::Type, packet::Number)>>);

impl Serialize for EcnTransitionRow<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for to in Ecn::iter() {
            if let Some(pkt) = self.0[to] {
                map.serialize_entry(&to, &pkt)?;
            }
        }
        map.end()
    }
}

impl Serialize for EcnTransitions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut outer = serializer.serialize_map(None)?;
        for from in Ecn::iter() {
            // Don't show all-None rows.
            if self.0[from].iter().all(|(_, v)| v.is_none()) {
                continue;
            }
            outer.serialize_entry(&from, &EcnTransitionRow(&self.0[from]))?;
        }
        outer.end()
    }
}

/// Received packet counts by DSCP value.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct DscpCount(EnumMap<Dscp, usize>);

impl Serialize for DscpCount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (dscp, count) in self.0 {
            // Don't show zero counts.
            if count == 0 {
                continue;
            }
            map.serialize_entry(&dscp, &count)?;
        }
        map.end()
    }
}

impl Deref for DscpCount {
    type Target = EnumMap<Dscp, usize>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DscpCount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Connection statistics
#[skip_serializing_none]
#[derive(Default, Clone, PartialEq, Serialize)]
pub struct Stats {
    pub info: String,

    /// The QUIC version in use. After the handshake completes this reflects the
    /// version negotiated via compatible version negotiation (RFC 9368).
    pub version: Version,

    /// Total packets received, including all the bad ones.
    pub packets_rx: usize,
    /// Duplicate packets received.
    pub dups_rx: usize,
    /// Dropped packets or dropped garbage.
    pub dropped_rx: usize,
    /// The number of packet that were saved for later processing.
    pub saved_datagrams: usize,

    /// Total packets sent.
    pub packets_tx: usize,
    /// Total number of packets that are declared lost.
    pub lost: usize,
    /// Late acknowledgments, for packets that were declared lost already.
    pub late_ack: usize,
    /// Acknowledgments for packets that contained data that was marked
    /// for retransmission when the PTO timer popped.
    pub pto_ack: usize,
    /// Number of times we had to drop an unacknowledged ACK range.
    pub unacked_range_dropped: usize,
    /// Number of PMTUD probes sent.
    pub pmtud_tx: usize,
    /// Number of PMTUD probes ACK'ed.
    pub pmtud_ack: usize,
    /// Number of PMTUD probes lost.
    pub pmtud_lost: usize,
    /// MTU of the local interface used for the most recent path.
    pub pmtud_iface_mtu: usize,
    /// The peer's `max_udp_payload_size` transport parameter.
    pub pmtud_peer_max_udp_payload: Option<usize>,
    /// Probed PMTU of the current path.
    pub pmtud_pmtu: usize,

    /// Whether the connection was resumed successfully.
    pub resumed: bool,

    /// The current, estimated round-trip time on the primary path.
    pub rtt: Duration,
    /// The current, estimated round-trip time variation on the primary path.
    pub rttvar: Duration,
    /// The current minimum RTT observed on the primary path.
    pub min_rtt: Duration,
    /// Whether the first RTT sample was guessed from a discarded packet.
    pub rtt_init_guess: bool,

    /// Count PTOs. Single PTOs, 2 PTOs in a row, 3 PTOs in row, etc. are counted
    /// separately.
    pub pto_counts: [usize; Self::MAX_PTO_COUNTS],

    /// Count frames received.
    pub frame_rx: FrameStats,
    /// Count frames sent.
    pub frame_tx: FrameStats,

    pub datagram_tx: DatagramStats,

    pub cc: CongestionControlStats,

    /// ECN path validation count, indexed by validation outcome.
    pub ecn_path_validation: ecn::ValidationCount,
    /// ECN counts for outgoing UDP datagrams, recorded locally. For coalesced packets,
    /// counts increase for all packet types in the coalesced datagram.
    pub ecn_tx: EcnCount,
    /// ECN counts for outgoing UDP datagrams, returned by remote through QUIC ACKs.
    ///
    /// Note: Given that QUIC ACKs only carry [`Ect0`], [`Ect1`] and [`Ce`], but
    /// never [`NotEct`], the [`NotEct`] value will always be 0.
    ///
    /// See also <https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.2>.
    ///
    /// [`Ect0`]: neqo_common::tos::Ecn::Ect0
    /// [`Ect1`]: neqo_common::tos::Ecn::Ect1
    /// [`Ce`]: neqo_common::tos::Ecn::Ce
    /// [`NotEct`]: neqo_common::tos::Ecn::NotEct
    pub ecn_tx_acked: EcnCount,
    /// ECN counts for incoming UDP datagrams, read from IP TOS header. For coalesced packets,
    /// counts increase for all packet types in the coalesced datagram.
    pub ecn_rx: EcnCount,
    /// Packet numbers of the first observed (received) ECN mark transition between two marks.
    pub ecn_last_mark: Option<Ecn>,
    pub ecn_rx_transition: EcnTransitions,

    /// Counters for DSCP values received.
    pub dscp_rx: DscpCount,
}

impl Stats {
    pub const MAX_PTO_COUNTS: usize = 16;

    pub fn init(&mut self, info: String) {
        self.info = info;
    }

    pub fn pkt_dropped<A: AsRef<str>>(&mut self, reason: A) {
        self.dropped_rx += 1;
        qdebug!(
            "[{}] Dropped received packet: {}; Total: {}",
            self.info,
            reason.as_ref(),
            self.dropped_rx
        );
    }

    /// # Panics
    ///
    /// When preconditions are violated.
    pub fn add_pto_count(&mut self, count: usize) {
        debug_assert!(count > 0);
        if count >= Self::MAX_PTO_COUNTS {
            // We can't move this count any further, so stop.
            return;
        }
        self.pto_counts[count - 1] += 1;
        if count > 1 {
            debug_assert!(self.pto_counts[count - 2] > 0);
            self.pto_counts[count - 2] -= 1;
        }
    }
}

#[derive(Default, Clone)]
pub struct StatsCell {
    stats: Rc<RefCell<Stats>>,
}

impl Deref for StatsCell {
    type Target = RefCell<Stats>;
    fn deref(&self) -> &Self::Target {
        &self.stats
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neqo_common::{Ecn, json};

    use super::{EcnCount, EcnTransitions, Stats, StatsCell};
    use crate::{
        packet,
        stats::{CongestionControlStats, DscpCount, SearchResetStats},
    };

    #[test]
    fn stats_init_sets_info() {
        let mut stats = Stats::default();
        stats.init("conn-1".into());
        assert_eq!(stats.info, "conn-1");
    }

    #[test]
    fn stats_cell_init_sets_info() {
        let cell = StatsCell::default();
        cell.borrow_mut().init("cell-test".into());
        assert_eq!(cell.borrow().info, "cell-test");
    }

    #[test]
    fn ecn_count_deref_mut_and_deref() {
        let mut counts = EcnCount::default();
        // Write through DerefMut, read through Deref.
        counts[packet::Type::Short][Ecn::Ect0] = 7;
        assert_eq!(counts[packet::Type::Short][Ecn::Ect0], 7);
    }

    #[test]
    fn ecn_transitions_deref_mut_and_deref() {
        let mut trans = EcnTransitions::default();
        trans[Ecn::Ect0][Ecn::Ce] = Some((packet::Type::Short, 42));
        assert_eq!(trans[Ecn::Ect0][Ecn::Ce], Some((packet::Type::Short, 42)));
    }

    #[test]
    fn ecn_count_json_skips_only_empty_rows() {
        assert_eq!(json::compact(&EcnCount::default()), "{}");

        let mut counts = EcnCount::default();
        counts[packet::Type::Short][Ecn::Ce] = 3;
        let json = json::compact(&counts);
        assert!(json.contains("Short"));
        assert!(!json.contains("Initial") && !json.contains("Handshake"));
    }

    #[test]
    fn ecn_transitions_json_skips_rows_with_no_transitions() {
        assert_eq!(json::compact(&EcnTransitions::default()), "{}");
    }

    #[test]
    fn dscp_count_json_skips_zero_entries() {
        assert_eq!(json::compact(&DscpCount::default()), "{}");
    }

    #[test]
    fn skip_serializing_none_omits_none_and_keeps_some() {
        let stats = Stats {
            ecn_last_mark: Some(Ecn::Ect0),
            pmtud_peer_max_udp_payload: None,
            cc: CongestionControlStats {
                w_max: Some(1.0),
                search_reset: SearchResetStats {
                    max_passed_bins: None,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let json = json::compact(&stats);

        for field in ["ecn_last_mark", "w_max"] {
            assert!(json.contains(&format!("\"{field}\"")));
        }
        for field in ["pmtud_peer_max_udp_payload", "max_passed_bins"] {
            assert!(!json.contains(&format!("\"{field}\"")));
        }
    }
}
