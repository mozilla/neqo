// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::{
    ops::{Deref as _, RangeInclusive},
    time::{Duration, Instant},
};

use neqo_common::{Decoder, Ecn, hex, qinfo, qlog::Qlog};
use qlog::events::{
    ApplicationErrorCode, ConnectionErrorCode, EventData, RawInfo,
    connectivity::{
        ConnectionClosed, ConnectionClosedTrigger, ConnectionStarted, ConnectionState,
        ConnectionStateUpdated, MtuUpdated, TransportOwner,
    },
    quic::{
        AckedRanges, CongestionStateUpdated, CongestionStateUpdatedTrigger, ErrorSpace,
        LossTimerEventType, LossTimerUpdated, MetricsUpdated, PacketDropped, PacketDroppedTrigger,
        PacketHeader, PacketLost, PacketLostTrigger, PacketNumberSpace as QlogPacketNumberSpace,
        PacketReceived, PacketSent, PacketsAcked, QuicFrame, RecoveryParametersSet, StreamType,
        TimerType, VersionInformation,
    },
};
use smallvec::SmallVec;

use crate::{
    CloseReason,
    cc::{CWND_INITIAL_PKTS, CongestionControl, Cubic, PERSISTENT_CONG_THRESH},
    connection::State,
    frame::{CloseError, Frame},
    packet::{self, metadata::Direction},
    path::PathRef,
    recovery::sent,
    rtt::{DEFAULT_INITIAL_RTT, GRANULARITY},
    stream_id::StreamType as NeqoStreamType,
    tparams::{
        TransportParameterId::{
            self, AckDelayExponent, ActiveConnectionIdLimit, DisableMigration, InitialMaxData,
            InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni,
            InitialMaxStreamsBidi, InitialMaxStreamsUni, MaxAckDelay, MaxUdpPayloadSize,
            OriginalDestinationConnectionId, StatelessResetToken,
        },
        TransportParametersHandler,
    },
    tracking::PacketNumberSpace,
    version::{self, Version},
};

pub fn connection_tparams_set(qlog: &mut Qlog, tph: &TransportParametersHandler, now: Instant) {
    qlog.add_event_at(
        || {
            let remote = tph.remote();
            #[expect(clippy::cast_possible_truncation, reason = "These are OK.")]
            let ev_data =
                EventData::TransportParametersSet(qlog::events::quic::TransportParametersSet {
                    owner: Some(TransportOwner::Remote),
                    original_destination_connection_id: remote
                        .get_bytes(OriginalDestinationConnectionId)
                        .map(hex),
                    stateless_reset_token: remote.get_bytes(StatelessResetToken).map(hex),
                    disable_active_migration: remote.get_empty(DisableMigration).then_some(true),
                    max_idle_timeout: Some(remote.get_integer(TransportParameterId::IdleTimeout)),
                    max_udp_payload_size: Some(remote.get_integer(MaxUdpPayloadSize) as u32),
                    ack_delay_exponent: Some(remote.get_integer(AckDelayExponent) as u16),
                    max_ack_delay: Some(remote.get_integer(MaxAckDelay) as u16),
                    active_connection_id_limit: Some(
                        remote.get_integer(ActiveConnectionIdLimit) as u32
                    ),
                    initial_max_data: Some(remote.get_integer(InitialMaxData)),
                    initial_max_stream_data_bidi_local: Some(
                        remote.get_integer(InitialMaxStreamDataBidiLocal),
                    ),
                    initial_max_stream_data_bidi_remote: Some(
                        remote.get_integer(InitialMaxStreamDataBidiRemote),
                    ),
                    initial_max_stream_data_uni: Some(remote.get_integer(InitialMaxStreamDataUni)),
                    initial_max_streams_bidi: Some(remote.get_integer(InitialMaxStreamsBidi)),
                    initial_max_streams_uni: Some(remote.get_integer(InitialMaxStreamsUni)),
                    preferred_address: remote.get_preferred_address().and_then(|(paddr, cid)| {
                        Some(qlog::events::quic::PreferredAddress {
                            ip_v4: paddr.ipv4()?.ip().to_string(),
                            ip_v6: paddr.ipv6()?.ip().to_string(),
                            port_v4: paddr.ipv4()?.port(),
                            port_v6: paddr.ipv6()?.port(),
                            connection_id: cid.connection_id().to_string(),
                            stateless_reset_token: hex(cid.reset_token()),
                        })
                    }),
                    ..Default::default()
                });

            Some(ev_data)
        },
        now,
    );
}

pub fn server_connection_started(qlog: &mut Qlog, path: &PathRef, now: Instant) {
    connection_started(qlog, path, now);
}

pub fn client_connection_started(qlog: &mut Qlog, path: &PathRef, now: Instant) {
    connection_started(qlog, path, now);
}

fn connection_started(qlog: &mut Qlog, path: &PathRef, now: Instant) {
    qlog.add_event_at(
        || {
            let p = path.deref().borrow();
            let ev_data = EventData::ConnectionStarted(ConnectionStarted {
                ip_version: if p.local_address().ip().is_ipv4() {
                    Some("ipv4".into())
                } else {
                    Some("ipv6".into())
                },
                src_ip: format!("{}", p.local_address().ip()),
                dst_ip: format!("{}", p.remote_address().ip()),
                protocol: Some("QUIC".into()),
                src_port: p.local_address().port().into(),
                dst_port: p.remote_address().port().into(),
                src_cid: p.local_cid().map(ToString::to_string),
                dst_cid: p.remote_cid().map(ToString::to_string),
            });

            Some(ev_data)
        },
        now,
    );
}

pub fn connection_state_updated(
    qlog: &mut Qlog,
    old_state: &State,
    new_state: &State,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::ConnectionStateUpdated(ConnectionStateUpdated {
                old: Some(old_state.into()),
                new: new_state.into(),
            }))
        },
        now,
    );
}

pub fn client_version_information_initiated(
    qlog: &mut Qlog,
    version_config: &version::Config,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::VersionInformation(VersionInformation {
                client_versions: Some(
                    version_config
                        .all()
                        .iter()
                        .map(|v| format!("{:02x}", v.wire_version()))
                        .collect(),
                ),
                chosen_version: Some(format!("{:02x}", version_config.initial().wire_version())),
                ..Default::default()
            }))
        },
        now,
    );
}

pub fn client_version_information_negotiated(
    qlog: &mut Qlog,
    client: &[Version],
    server: &[version::Wire],
    chosen: Version,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::VersionInformation(VersionInformation {
                client_versions: Some(
                    client
                        .iter()
                        .map(|v| format!("{:02x}", v.wire_version()))
                        .collect(),
                ),
                server_versions: Some(server.iter().map(|v| format!("{v:02x}")).collect()),
                chosen_version: Some(format!("{:02x}", chosen.wire_version())),
            }))
        },
        now,
    );
}

pub fn server_version_information_failed(
    qlog: &mut Qlog,
    server: &[Version],
    client: version::Wire,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::VersionInformation(VersionInformation {
                client_versions: Some(vec![format!("{client:02x}")]),
                server_versions: Some(
                    server
                        .iter()
                        .map(|v| format!("{:02x}", v.wire_version()))
                        .collect(),
                ),
                ..Default::default()
            }))
        },
        now,
    );
}

pub fn packet_io(qlog: &mut Qlog, meta: packet::MetaData, now: Instant) {
    qlog.add_event_at(
        || {
            let mut d = Decoder::from(meta.payload());
            let raw = RawInfo {
                length: Some(meta.length() as u64),
                payload_length: None,
                data: None,
            };

            let mut frames = SmallVec::new();
            while d.remaining() > 0 {
                if let Ok(f) = Frame::decode(&mut d) {
                    frames.push(QuicFrame::from(f));
                } else {
                    qinfo!("qlog: invalid frame");
                    break;
                }
            }

            match meta.direction() {
                Direction::Tx => Some(EventData::PacketSent(PacketSent {
                    header: meta.into(),
                    frames: Some(frames),
                    raw: Some(raw),
                    ..Default::default()
                })),
                Direction::Rx => Some(EventData::PacketReceived(PacketReceived {
                    header: meta.into(),
                    frames: Some(frames.to_vec()),
                    raw: Some(raw),
                    ..Default::default()
                })),
            }
        },
        now,
    );
}
pub fn packet_dropped(qlog: &mut Qlog, decrypt_err: &packet::DecryptionError, now: Instant) {
    qlog.add_event_at(
        || {
            let header =
                PacketHeader::with_type(decrypt_err.packet_type().into(), None, None, None, None);
            let raw = RawInfo {
                length: Some(decrypt_err.len() as u64),
                ..Default::default()
            };

            let ev_data = EventData::PacketDropped(PacketDropped {
                header: Some(header),
                raw: Some(raw),
                details: Some(decrypt_err.error.to_string()),
                trigger: Some(PacketDroppedTrigger::DecryptionFailure),
                ..Default::default()
            });

            Some(ev_data)
        },
        now,
    );
}

pub fn packets_lost(qlog: &mut Qlog, pkts: &[sent::Packet], now: Instant) {
    qlog.add_event_with_stream(|stream| {
        for pkt in pkts {
            let header =
                PacketHeader::with_type(pkt.packet_type().into(), Some(pkt.pn()), None, None, None);

            let trigger = pkt
                .loss_info()
                .map(|info| PacketLostTrigger::from(info.trigger))
                .or_else(|| pkt.pto_fired().then_some(PacketLostTrigger::PtoExpired));

            let ev_data = EventData::PacketLost(PacketLost {
                header: Some(header),
                trigger,
                ..Default::default()
            });

            stream.add_event_data_with_instant(ev_data, now)?;
        }
        Ok(())
    });
}

pub fn recovery_parameters_set(
    qlog: &mut Qlog,
    plpmtu: usize,
    cc: CongestionControl,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            let loss_reduction_factor = match cc {
                CongestionControl::NewReno => 0.5,
                CongestionControl::Cubic => {
                    f32::from(u8::try_from(Cubic::BETA_USIZE_DIVIDEND).expect("fits"))
                        / f32::from(u8::try_from(Cubic::BETA_USIZE_DIVISOR).expect("fits"))
                }
            };
            Some(EventData::RecoveryParametersSet(RecoveryParametersSet {
                reordering_threshold: Some(
                    u16::try_from(crate::recovery::PACKET_THRESHOLD).expect("fits"),
                ),
                time_threshold: Some(9.0 / 8.0),
                timer_granularity: Some(u16::try_from(GRANULARITY.as_millis()).expect("fits")),
                initial_rtt: Some(DEFAULT_INITIAL_RTT.as_secs_f32() * 1000.0),
                max_datagram_size: Some(u32::try_from(plpmtu).expect("MTU fits in u32")),
                initial_congestion_window: Some(
                    u64::try_from(CWND_INITIAL_PKTS * plpmtu).expect("fits"),
                ),
                minimum_congestion_window: Some(
                    u32::try_from(2 * plpmtu).expect("MTU fits in u32"),
                ),
                loss_reduction_factor: Some(loss_reduction_factor),
                persistent_congestion_threshold: Some(
                    u16::try_from(PERSISTENT_CONG_THRESH).expect("fits"),
                ),
            }))
        },
        now,
    );
}

pub fn connection_closed(qlog: &mut Qlog, close_reason: &CloseReason, now: Instant) {
    qlog.add_event_at(
        || Some(EventData::ConnectionClosed(close_reason.into())),
        now,
    );
}

pub fn packets_acked(
    qlog: &mut Qlog,
    space: PacketNumberSpace,
    acked_pkts: &[sent::Packet],
    now: Instant,
) {
    if acked_pkts.is_empty() {
        return;
    }
    qlog.add_event_at(
        || {
            let packet_number_space = Some(QlogPacketNumberSpace::from(space));
            let packet_numbers = Some(acked_pkts.iter().map(sent::Packet::pn).collect::<Vec<_>>());
            Some(EventData::PacketsAcked(PacketsAcked {
                packet_number_space,
                packet_numbers,
            }))
        },
        now,
    );
}

pub fn mtu_updated(qlog: &mut Qlog, old_mtu: usize, new_mtu: usize, done: bool, now: Instant) {
    qlog.add_event_at(
        || {
            Some(EventData::MtuUpdated(MtuUpdated {
                old: Some(u16::try_from(old_mtu).expect("MTU fits in u16")),
                new: u16::try_from(new_mtu).expect("MTU fits in u16"),
                done: Some(done),
            }))
        },
        now,
    );
}

#[expect(dead_code, reason = "TODO: Construct all variants.")]
pub enum Metric {
    MinRtt(Duration),
    SmoothedRtt(Duration),
    LatestRtt(Duration),
    RttVariance(Duration),
    PtoCount(usize),
    CongestionWindow(usize),
    BytesInFlight(usize),
    SsThresh(usize),
    PacketsInFlight(u64),
    PacingRate(u64),
}

pub fn metrics_updated(qlog: &mut Qlog, updated_metrics: &[Metric], now: Instant) {
    debug_assert!(!updated_metrics.is_empty());

    qlog.add_event_at(
        || {
            let mut min_rtt: Option<f32> = None;
            let mut smoothed_rtt: Option<f32> = None;
            let mut latest_rtt: Option<f32> = None;
            let mut rtt_variance: Option<f32> = None;
            let mut pto_count: Option<u16> = None;
            let mut congestion_window: Option<u64> = None;
            let mut bytes_in_flight: Option<u64> = None;
            let mut ssthresh: Option<u64> = None;
            let mut packets_in_flight: Option<u64> = None;
            let mut pacing_rate: Option<u64> = None;

            for metric in updated_metrics {
                match metric {
                    Metric::MinRtt(v) => min_rtt = Some(v.as_secs_f32() * 1000.0),
                    Metric::SmoothedRtt(v) => smoothed_rtt = Some(v.as_secs_f32() * 1000.0),
                    Metric::LatestRtt(v) => latest_rtt = Some(v.as_secs_f32() * 1000.0),
                    Metric::RttVariance(v) => rtt_variance = Some(v.as_secs_f32() * 1000.0),
                    Metric::PtoCount(v) => {
                        pto_count = Some(u16::try_from(*v).expect("fits in u16"));
                    }
                    Metric::CongestionWindow(v) => {
                        congestion_window = Some(u64::try_from(*v).expect("fits in u64"));
                    }
                    Metric::BytesInFlight(v) => {
                        bytes_in_flight = Some(u64::try_from(*v).expect("fits in u64"));
                    }
                    Metric::SsThresh(v) => {
                        ssthresh = Some(u64::try_from(*v).expect("fits in u64"));
                    }
                    Metric::PacketsInFlight(v) => packets_in_flight = Some(*v),
                    Metric::PacingRate(v) => pacing_rate = Some(*v),
                }
            }

            let ev_data = EventData::MetricsUpdated(MetricsUpdated {
                min_rtt,
                smoothed_rtt,
                latest_rtt,
                rtt_variance,
                pto_count,
                congestion_window,
                bytes_in_flight,
                ssthresh,
                packets_in_flight,
                pacing_rate,
                ..Default::default()
            });

            Some(ev_data)
        },
        now,
    );
}

/// Trigger for a `recovery:congestion_state_updated` qlog event.
#[derive(Clone, Copy)]
pub enum CongestionStateTrigger {
    /// The congestion state change was triggered by an ECN mark.
    Ecn,
    /// The congestion state change was triggered by persistent congestion.
    PersistentCongestion,
}

impl From<CongestionStateTrigger> for CongestionStateUpdatedTrigger {
    fn from(value: CongestionStateTrigger) -> Self {
        match value {
            CongestionStateTrigger::Ecn => Self::Ecn,
            CongestionStateTrigger::PersistentCongestion => Self::PersistentCongestion,
        }
    }
}

pub fn congestion_state_updated(
    qlog: &mut Qlog,
    old_state: &'static str,
    new_state: &'static str,
    trigger: Option<CongestionStateTrigger>,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::CongestionStateUpdated(CongestionStateUpdated {
                old: Some(old_state.to_owned()),
                new: new_state.to_owned(),
                trigger: trigger.map(Into::into),
            }))
        },
        now,
    );
}

/// The type of loss recovery timer that fired or was updated.
#[derive(Clone, Copy)]
pub enum LossTimerType {
    /// The reordering/loss-detection timer (ACK-based).
    Ack,
    /// The Probe Timeout timer.
    Pto,
}

/// Emit a `loss_timer_updated` Set event.
///
/// Only the PTO timer has explicit set/cancel lifecycle in neqo. The
/// loss-detection (Ack) timer is derived lazily from packet state on every
/// call to [`crate::recovery::Loss::next_timeout`] and has no single arm or
/// cancel point to instrument.
pub fn loss_timer_set(qlog: &mut Qlog, now: Instant) {
    loss_timer_updated(qlog, LossTimerEventType::Set, Some(TimerType::Pto), now);
}

pub fn loss_timer_expired(qlog: &mut Qlog, timer_type: LossTimerType, now: Instant) {
    loss_timer_updated(
        qlog,
        LossTimerEventType::Expired,
        Some(timer_type.into()),
        now,
    );
}

/// Emit a `loss_timer_updated` Cancelled event.
///
/// See [`loss_timer_set`] for why only `TimerType::Pto` is used here.
pub fn loss_timer_cancelled(qlog: &mut Qlog, now: Instant) {
    loss_timer_updated(
        qlog,
        LossTimerEventType::Cancelled,
        Some(TimerType::Pto),
        now,
    );
}

fn loss_timer_updated(
    qlog: &mut Qlog,
    event_type: LossTimerEventType,
    timer_type: Option<TimerType>,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::LossTimerUpdated(LossTimerUpdated {
                timer_type,
                packet_number_space: None,
                event_type,
                delta: None,
            }))
        },
        now,
    );
}

// Helper functions

#[expect(clippy::too_many_lines, reason = "Yeah, but it's a nice match.")]
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "We need to truncate here."
)]
impl From<Frame<'_>> for QuicFrame {
    fn from(frame: Frame) -> Self {
        match frame {
            Frame::Padding(len) => Self::Padding {
                length: None,
                payload_length: u32::from(len),
            },
            Frame::Ping => Self::Ping {
                length: None,
                payload_length: None,
            },
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
                ecn_count,
            } => {
                let ranges =
                    Frame::decode_ack_frame(largest_acknowledged, first_ack_range, &ack_ranges)
                        .ok();

                let acked_ranges = ranges.map(|all| {
                    AckedRanges::Double(
                        all.into_iter()
                            .map(RangeInclusive::into_inner)
                            .collect::<Vec<_>>(),
                    )
                });

                Self::Ack {
                    ack_delay: Some(ack_delay as f32 / 1000.0),
                    acked_ranges,
                    ect1: ecn_count.map(|c| c[Ecn::Ect1]),
                    ect0: ecn_count.map(|c| c[Ecn::Ect0]),
                    ce: ecn_count.map(|c| c[Ecn::Ce]),
                    length: None,
                    payload_length: None,
                }
            }
            Frame::ResetStream {
                stream_id,
                application_error_code,
                final_size,
            } => Self::ResetStream {
                stream_id: stream_id.as_u64(),
                error_code: application_error_code,
                final_size,
                length: None,
                payload_length: None,
            },
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => Self::StopSending {
                stream_id: stream_id.as_u64(),
                error_code: application_error_code,
                length: None,
                payload_length: None,
            },
            Frame::Crypto { offset, data } => Self::Crypto {
                offset,
                length: data.len() as u64,
            },
            Frame::NewToken { token } => Self::NewToken {
                token: qlog::Token {
                    ty: None,
                    details: None,
                    raw: Some(RawInfo {
                        data: Some(hex(token)),
                        length: Some(token.len() as u64),
                        payload_length: None,
                    }),
                },
            },
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
                ..
            } => Self::Stream {
                stream_id: stream_id.as_u64(),
                offset,
                length: data.len() as u64,
                fin: Some(fin),
                raw: None,
            },
            Frame::MaxData { maximum_data } => Self::MaxData {
                maximum: maximum_data,
            },
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => Self::MaxStreamData {
                stream_id: stream_id.as_u64(),
                maximum: maximum_stream_data,
            },
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => Self::MaxStreams {
                stream_type: stream_type.into(),
                maximum: maximum_streams,
            },
            Frame::DataBlocked { data_limit } => Self::DataBlocked { limit: data_limit },
            Frame::StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => Self::StreamDataBlocked {
                stream_id: stream_id.as_u64(),
                limit: stream_data_limit,
            },
            Frame::StreamsBlocked {
                stream_type,
                stream_limit,
            } => Self::StreamsBlocked {
                stream_type: stream_type.into(),
                limit: stream_limit,
            },
            Frame::NewConnectionId {
                sequence_number,
                retire_prior,
                connection_id,
                stateless_reset_token,
            } => Self::NewConnectionId {
                sequence_number: sequence_number as u32,
                retire_prior_to: retire_prior as u32,
                connection_id_length: Some(connection_id.len() as u8),
                connection_id: hex(connection_id),
                stateless_reset_token: Some(hex(stateless_reset_token)),
            },
            Frame::RetireConnectionId { sequence_number } => Self::RetireConnectionId {
                sequence_number: sequence_number as u32,
            },
            Frame::PathChallenge { data } => Self::PathChallenge {
                data: Some(hex(data)),
            },
            Frame::PathResponse { data } => Self::PathResponse {
                data: Some(hex(data)),
            },
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason_phrase,
            } => Self::ConnectionClose {
                error_space: Some((&error_code).into()),
                error_code: Some(error_code.code()),
                error_code_value: Some(error_code.code()),
                reason: Some(reason_phrase),
                trigger_frame_type: Some(frame_type),
            },
            Frame::HandshakeDone => Self::HandshakeDone,
            Frame::AckFrequency { .. } => Self::Unknown {
                frame_type_value: None,
                raw_frame_type: frame.get_type().into(),
                raw: None,
            },
            Frame::Datagram { data, .. } => Self::Datagram {
                length: data.len() as u64,
                raw: None,
            },
        }
    }
}

impl From<&State> for ConnectionState {
    fn from(state: &State) -> Self {
        match state {
            State::Init | State::WaitInitial => Self::Attempted,
            State::WaitVersion | State::Handshaking => Self::HandshakeStarted,
            State::Connected => Self::HandshakeCompleted,
            State::Confirmed => Self::HandshakeConfirmed,
            State::Closing { .. } => Self::Closing,
            State::Draining { .. } => Self::Draining,
            State::Closed { .. } => Self::Closed,
        }
    }
}

impl From<PacketNumberSpace> for QlogPacketNumberSpace {
    fn from(space: PacketNumberSpace) -> Self {
        match space {
            PacketNumberSpace::Initial => Self::Initial,
            PacketNumberSpace::Handshake => Self::Handshake,
            PacketNumberSpace::ApplicationData => Self::ApplicationData,
        }
    }
}

impl From<NeqoStreamType> for StreamType {
    fn from(stream_type: NeqoStreamType) -> Self {
        match stream_type {
            NeqoStreamType::BiDi => Self::Bidirectional,
            NeqoStreamType::UniDi => Self::Unidirectional,
        }
    }
}

impl From<&CloseError> for ErrorSpace {
    fn from(error: &CloseError) -> Self {
        match error {
            CloseError::Transport(_) => Self::TransportError,
            CloseError::Application(_) => Self::ApplicationError,
        }
    }
}

impl From<&CloseReason> for ConnectionClosed {
    fn from(close_reason: &CloseReason) -> Self {
        let (connection_code, application_code, trigger) = match close_reason {
            CloseReason::Transport(e) if *e == crate::Error::IdleTimeout => {
                (None, None, Some(ConnectionClosedTrigger::IdleTimeout))
            }
            CloseReason::Transport(e) if *e == crate::Error::StatelessReset => {
                (None, None, Some(ConnectionClosedTrigger::StatelessReset))
            }
            CloseReason::Transport(e) if *e == crate::Error::VersionNegotiation => {
                (None, None, Some(ConnectionClosedTrigger::VersionMismatch))
            }
            CloseReason::Transport(e) if *e == crate::Error::None => {
                (None, None, Some(ConnectionClosedTrigger::Clean))
            }
            CloseReason::Transport(crate::Error::Peer(code)) => (
                Some(ConnectionErrorCode::Value(*code)),
                None,
                Some(ConnectionClosedTrigger::Error),
            ),
            CloseReason::Application(code)
            | CloseReason::Transport(crate::Error::PeerApplication(code)) => (
                None,
                Some(ApplicationErrorCode::Value(*code)),
                Some(ConnectionClosedTrigger::Application),
            ),
            CloseReason::Transport(e) => (
                Some(ConnectionErrorCode::Value(e.code())),
                None,
                Some(ConnectionClosedTrigger::Error),
            ),
        };
        Self {
            owner: None,
            connection_code,
            application_code,
            internal_code: None,
            reason: None,
            trigger,
        }
    }
}

impl From<LossTimerType> for TimerType {
    fn from(value: LossTimerType) -> Self {
        match value {
            LossTimerType::Ack => Self::Ack,
            LossTimerType::Pto => Self::Pto,
        }
    }
}

impl From<sent::LossTrigger> for PacketLostTrigger {
    fn from(value: sent::LossTrigger) -> Self {
        match value {
            sent::LossTrigger::TimeThreshold => Self::TimeThreshold,
            sent::LossTrigger::ReorderingThreshold => Self::ReorderingThreshold,
        }
    }
}

impl From<packet::Type> for qlog::events::quic::PacketType {
    fn from(value: packet::Type) -> Self {
        match value {
            packet::Type::Initial => Self::Initial,
            packet::Type::Handshake => Self::Handshake,
            packet::Type::ZeroRtt => Self::ZeroRtt,
            packet::Type::Short => Self::OneRtt,
            packet::Type::Retry => Self::Retry,
            packet::Type::VersionNegotiation => Self::VersionNegotiation,
            packet::Type::OtherVersion => Self::Unknown,
        }
    }
}
