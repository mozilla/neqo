// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracking of some useful statistics.

use std::{
    cell::RefCell,
    fmt::{self, Debug},
    ops::{Deref, DerefMut},
    rc::Rc,
    time::Duration,
};

use enum_map::EnumMap;
use neqo_common::{qwarn, Dscp, Ecn};
use strum::IntoEnumIterator as _;

use crate::{ecn, packet};

pub const MAX_PTO_COUNTS: usize = 16;

#[derive(Default, Clone, PartialEq, Eq)]
pub struct FrameStats {
    pub ack: usize,
    pub largest_acknowledged: packet::Number,

    pub crypto: usize,
    pub stream: usize,
    pub reset_stream: usize,
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

impl Debug for FrameStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "    crypto {} done {} token {} close {}",
            self.crypto, self.handshake_done, self.new_token, self.connection_close,
        )?;
        writeln!(
            f,
            "    ack {} (max {}) ping {} padding {}",
            self.ack, self.largest_acknowledged, self.ping, self.padding
        )?;
        writeln!(
            f,
            "    stream {} reset {} stop {}",
            self.stream, self.reset_stream, self.stop_sending,
        )?;
        writeln!(
            f,
            "    max: stream {} data {} stream_data {}",
            self.max_streams, self.max_data, self.max_stream_data,
        )?;
        writeln!(
            f,
            "    blocked: stream {} data {} stream_data {}",
            self.streams_blocked, self.data_blocked, self.stream_data_blocked,
        )?;
        writeln!(f, "    datagram {}", self.datagram)?;
        writeln!(
            f,
            "    ncid {} rcid {} pchallenge {} presponse {}",
            self.new_connection_id,
            self.retire_connection_id,
            self.path_challenge,
            self.path_response,
        )?;
        writeln!(f, "    ack_frequency {}", self.ack_frequency)
    }
}

#[cfg(test)]
impl FrameStats {
    pub const fn all(&self) -> usize {
        self.ack
            + self.crypto
            + self.stream
            + self.reset_stream
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
#[derive(Default, Clone, PartialEq, Eq)]
pub struct DatagramStats {
    /// The number of datagrams declared lost.
    pub lost: usize,
    /// The number of datagrams dropped due to being too large.
    pub dropped_too_big: usize,
    /// The number of datagrams dropped due to reaching the limit of the
    /// outgoing queue.
    pub dropped_queue_full: usize,
}

/// ECN counts by QUIC [`packet::Type`].
#[derive(Default, Clone, PartialEq, Eq)]
pub struct EcnCount(EnumMap<packet::Type, ecn::Count>);

impl Debug for EcnCount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (pt, count) in self.0 {
            // Don't show all-zero rows.
            if count.is_empty() {
                continue;
            }
            writeln!(f, "      {pt:?} {count:?}")?;
        }
        Ok(())
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

impl Debug for EcnTransitions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for from in Ecn::iter() {
            // Don't show all-None rows.
            if self.0[from].iter().all(|(_, v)| v.is_none()) {
                continue;
            }
            write!(f, "      First {from:?} ")?;
            for to in Ecn::iter() {
                // Don't show transitions that were not recorded.
                if let Some(pkt) = self.0[from][to] {
                    write!(f, "to {to:?} {pkt:?} ")?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Received packet counts by DSCP value.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct DscpCount(EnumMap<Dscp, usize>);

impl Debug for DscpCount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (dscp, count) in self.0 {
            // Don't show zero counts.
            if count == 0 {
                continue;
            }
            write!(f, "{dscp:?}: {count} ")?;
        }
        Ok(())
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
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub info: String,

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
    /// Number of times a path MTU changed unexpectedly.
    pub pmtud_change: usize,
    /// MTU of the local interface used for the most recent path.
    pub pmtud_iface_mtu: usize,
    /// Probed PMTU of the current path.
    pub pmtud_pmtu: usize,

    /// Whether the connection was resumed successfully.
    pub resumed: bool,

    /// The current, estimated round-trip time on the primary path.
    pub rtt: Duration,
    /// The current, estimated round-trip time variation on the primary path.
    pub rttvar: Duration,
    /// Whether the first RTT sample was guessed from a discarded packet.
    pub rtt_init_guess: bool,

    /// Count PTOs. Single PTOs, 2 PTOs in a row, 3 PTOs in row, etc. are counted
    /// separately.
    pub pto_counts: [usize; MAX_PTO_COUNTS],

    /// Count frames received.
    pub frame_rx: FrameStats,
    /// Count frames sent.
    pub frame_tx: FrameStats,

    /// The number of incoming datagrams dropped due to reaching the limit
    /// of the incoming queue.
    pub incoming_datagram_dropped: usize,

    pub datagram_tx: DatagramStats,

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
    pub fn init(&mut self, info: String) {
        self.info = info;
    }

    pub fn pkt_dropped<A: AsRef<str>>(&mut self, reason: A) {
        self.dropped_rx += 1;
        qwarn!(
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
        if count >= MAX_PTO_COUNTS {
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

impl Debug for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "stats for {}", self.info)?;
        writeln!(
            f,
            "  rx: {} drop {} dup {} saved {}",
            self.packets_rx, self.dropped_rx, self.dups_rx, self.saved_datagrams
        )?;
        writeln!(
            f,
            "  tx: {} lost {} lateack {} ptoack {} unackdrop {}",
            self.packets_tx, self.lost, self.late_ack, self.pto_ack, self.unacked_range_dropped
        )?;
        writeln!(
            f,
            "  pmtud: {} sent {} acked {} lost {} change {} iface_mtu {} pmtu",
            self.pmtud_tx,
            self.pmtud_ack,
            self.pmtud_lost,
            self.pmtud_change,
            self.pmtud_iface_mtu,
            self.pmtud_pmtu
        )?;
        writeln!(f, "  resumed: {}", self.resumed)?;
        writeln!(f, "  frames rx:")?;
        self.frame_rx.fmt(f)?;
        writeln!(f, "  frames tx:")?;
        self.frame_tx.fmt(f)?;
        writeln!(f, "  ecn:\n    tx:")?;
        self.ecn_tx.fmt(f)?;
        writeln!(f, "    acked:")?;
        self.ecn_tx_acked.fmt(f)?;
        writeln!(f, "    rx:")?;
        self.ecn_rx.fmt(f)?;
        writeln!(
            f,
            "    path validation outcomes: {:?}",
            self.ecn_path_validation
        )?;
        writeln!(f, "    mark transitions:")?;
        self.ecn_rx_transition.fmt(f)?;
        writeln!(f, "  dscp: {:?}", self.dscp_rx)
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

impl Debug for StatsCell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.stats.borrow().fmt(f)
    }
}
