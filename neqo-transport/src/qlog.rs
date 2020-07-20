// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::convert::TryFrom;
use std::string::String;
use std::time::Duration;

use qlog::{self, event::Event, PacketHeader, QuicFrame};

use neqo_common::{hex, qinfo, qlog::NeqoQlog, Decoder};

use crate::frame::{self, Frame};
use crate::packet::{DecryptedPacket, PacketNumber, PacketType, PublicPacket};
use crate::path::Path;
use crate::tparams::{self, TransportParametersHandler};
use crate::tracking::SentPacket;
use crate::QuicVersion;

pub fn connection_tparams_set(qlog: &mut NeqoQlog, tph: &TransportParametersHandler) {
    qlog.add_event(|| {
        let remote = tph.remote();
        Some(Event::transport_parameters_set(
            None,
            None,
            None,
            None,
            None,
            None,
            if let Some(ocid) = remote.get_bytes(tparams::ORIGINAL_DESTINATION_CONNECTION_ID) {
                // Cannot use packet::ConnectionId's Display trait implementation
                // because it does not include the 0x prefix.
                Some(hex(ocid))
            } else {
                None
            },
            if let Some(srt) = remote.get_bytes(tparams::STATELESS_RESET_TOKEN) {
                Some(hex(srt))
            } else {
                None
            },
            if remote.get_empty(tparams::DISABLE_MIGRATION).is_some() {
                Some(true)
            } else {
                None
            },
            Some(remote.get_integer(tparams::IDLE_TIMEOUT)),
            Some(remote.get_integer(tparams::MAX_UDP_PAYLOAD_SIZE)),
            Some(remote.get_integer(tparams::ACK_DELAY_EXPONENT)),
            Some(remote.get_integer(tparams::MAX_ACK_DELAY)),
            // TODO(hawkinsw@obs.cr): We do not yet handle ACTIVE_CONNECTION_ID_LIMIT in tparams yet.
            None,
            Some(format!("{}", remote.get_integer(tparams::INITIAL_MAX_DATA))),
            Some(format!(
                "{}",
                remote.get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL)
            )),
            Some(format!(
                "{}",
                remote.get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
            )),
            Some(format!(
                "{}",
                remote.get_integer(tparams::INITIAL_MAX_STREAM_DATA_UNI)
            )),
            Some(format!(
                "{}",
                remote.get_integer(tparams::INITIAL_MAX_STREAMS_BIDI)
            )),
            Some(format!(
                "{}",
                remote.get_integer(tparams::INITIAL_MAX_STREAMS_UNI)
            )),
            // TODO(hawkinsw@obs.cr): We do not yet handle PREFERRED_ADDRESS in tparams yet.
            None,
        ))
    })
}

pub fn server_connection_started(qlog: &mut NeqoQlog, path: &Path) {
    connection_started(qlog, path)
}

pub fn client_connection_started(qlog: &mut NeqoQlog, path: &Path) {
    connection_started(qlog, path)
}

fn connection_started(qlog: &mut NeqoQlog, path: &Path) {
    qlog.add_event(|| {
        Some(Event::connection_started(
            if path.local_address().ip().is_ipv4() {
                "ipv4".into()
            } else {
                "ipv6".into()
            },
            format!("{}", path.local_address().ip()),
            format!("{}", path.remote_address().ip()),
            Some("QUIC".into()),
            path.local_address().port().into(),
            path.remote_address().port().into(),
            Some(format!("{:x}", QuicVersion::default().as_u32())),
            Some(format!("{}", path.local_cid())),
            Some(format!("{}", path.remote_cid())),
        ))
    })
}

pub fn packet_sent(qlog: &mut NeqoQlog, pt: PacketType, pn: PacketNumber, body: &[u8]) {
    qlog.add_event_with_stream(|stream| {
        let mut d = Decoder::from(body);

        stream.add_event(Event::packet_sent_min(
            to_qlog_pkt_type(pt),
            PacketHeader::new(pn, None, None, None, None, None),
            Some(Vec::new()),
        ))?;

        while d.remaining() > 0 {
            match Frame::decode(&mut d) {
                Ok(f) => {
                    stream.add_frame(frame_to_qlogframe(&f), false)?;
                }
                Err(_) => {
                    qinfo!("qlog: invalid frame");
                    break;
                }
            }
        }

        stream.finish_frames()
    })
}

pub fn packet_dropped(qlog: &mut NeqoQlog, payload: &PublicPacket) {
    qlog.add_event(|| {
        Some(Event::packet_dropped(
            Some(to_qlog_pkt_type(payload.packet_type())),
            Some(u64::try_from(payload.packet_len()).unwrap()),
            None,
        ))
    })
}

pub fn packets_lost(qlog: &mut NeqoQlog, pkts: &[SentPacket]) {
    qlog.add_event_with_stream(|stream| {
        for pkt in pkts {
            stream.add_event(Event::packet_lost_min(
                to_qlog_pkt_type(pkt.pt),
                pkt.pn.to_string(),
                Vec::new(),
            ))?;

            stream.finish_frames()?;
        }
        Ok(())
    })
}

pub fn packet_received(qlog: &mut NeqoQlog, payload: &DecryptedPacket) {
    qlog.add_event_with_stream(|stream| {
        let mut d = Decoder::from(&payload[..]);

        stream.add_event(Event::packet_received(
            to_qlog_pkt_type(payload.packet_type()),
            PacketHeader::new(payload.pn(), None, None, None, None, None),
            Some(Vec::new()),
            None,
            None,
            None,
        ))?;

        while d.remaining() > 0 {
            match Frame::decode(&mut d) {
                Ok(f) => stream.add_frame(frame_to_qlogframe(&f), false)?,
                Err(_) => {
                    qinfo!("qlog: invalid frame");
                    break;
                }
            }
        }

        stream.finish_frames()
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    ApplicationLimited,
    Recovery,
}

impl CongestionState {
    fn to_str(&self) -> &str {
        match self {
            Self::SlowStart => "slow_start",
            Self::CongestionAvoidance => "congestion_avoidance",
            Self::ApplicationLimited => "application_limited",
            Self::Recovery => "recovery",
        }
    }
}

pub fn congestion_state_updated(
    qlog: &mut NeqoQlog,
    curr_state: &mut CongestionState,
    new_state: CongestionState,
) {
    qlog.add_event(|| {
        if *curr_state != new_state {
            let evt = Event::congestion_state_updated(
                Some(curr_state.to_str().to_owned()),
                new_state.to_str().to_owned(),
            );
            *curr_state = new_state;
            Some(evt)
        } else {
            None
        }
    });
}

#[allow(dead_code)]
pub enum QlogMetric {
    MinRtt(Duration),
    SmoothedRtt(Duration),
    LatestRtt(Duration),
    RttVariance(u64),
    MaxAckDelay(u64),
    PtoCount(usize),
    CongestionWindow(usize),
    BytesInFlight(usize),
    SsThresh(usize),
    PacketsInFlight(u64),
    InRecovery(bool),
    PacingRate(u64),
}

pub fn metrics_updated(qlog: &mut NeqoQlog, updated_metrics: &[QlogMetric]) {
    debug_assert!(!updated_metrics.is_empty());

    qlog.add_event(|| {
        let mut min_rtt: Option<u64> = None;
        let mut smoothed_rtt: Option<u64> = None;
        let mut latest_rtt: Option<u64> = None;
        let mut rtt_variance: Option<u64> = None;
        let mut max_ack_delay: Option<u64> = None;
        let mut pto_count: Option<u64> = None;
        let mut congestion_window: Option<u64> = None;
        let mut bytes_in_flight: Option<u64> = None;
        let mut ssthresh: Option<u64> = None;
        let mut packets_in_flight: Option<u64> = None;
        let mut in_recovery: Option<bool> = None;
        let mut pacing_rate: Option<u64> = None;

        for metric in updated_metrics {
            match metric {
                QlogMetric::MinRtt(v) => min_rtt = Some(u64::try_from(v.as_millis()).unwrap()),
                QlogMetric::SmoothedRtt(v) => {
                    smoothed_rtt = Some(u64::try_from(v.as_millis()).unwrap())
                }
                QlogMetric::LatestRtt(v) => {
                    latest_rtt = Some(u64::try_from(v.as_millis()).unwrap())
                }
                QlogMetric::RttVariance(v) => rtt_variance = Some(*v),
                QlogMetric::MaxAckDelay(v) => max_ack_delay = Some(*v),
                QlogMetric::PtoCount(v) => pto_count = Some(u64::try_from(*v).unwrap()),
                QlogMetric::CongestionWindow(v) => {
                    congestion_window = Some(u64::try_from(*v).unwrap())
                }
                QlogMetric::BytesInFlight(v) => bytes_in_flight = Some(u64::try_from(*v).unwrap()),
                QlogMetric::SsThresh(v) => ssthresh = Some(u64::try_from(*v).unwrap()),
                QlogMetric::PacketsInFlight(v) => packets_in_flight = Some(*v),
                QlogMetric::InRecovery(v) => in_recovery = Some(*v),
                QlogMetric::PacingRate(v) => pacing_rate = Some(*v),
            }
        }

        Some(Event::metrics_updated(
            min_rtt,
            smoothed_rtt,
            latest_rtt,
            rtt_variance,
            max_ack_delay,
            pto_count,
            congestion_window,
            bytes_in_flight,
            ssthresh,
            packets_in_flight,
            in_recovery,
            pacing_rate,
        ))
    })
}

// Helper functions

fn frame_to_qlogframe(frame: &Frame) -> QuicFrame {
    match frame {
        Frame::Padding => QuicFrame::padding(),
        Frame::Ping => QuicFrame::ping(),
        Frame::Ack {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ack_ranges,
        } => {
            let ack_ranges =
                Frame::decode_ack_frame(*largest_acknowledged, *first_ack_range, ack_ranges).ok();

            QuicFrame::ack(Some(ack_delay.to_string()), ack_ranges, None, None, None)
        }
        Frame::ResetStream {
            stream_id,
            application_error_code,
            final_size,
        } => QuicFrame::reset_stream(
            stream_id.as_u64().to_string(),
            *application_error_code,
            final_size.to_string(),
        ),
        Frame::StopSending {
            stream_id,
            application_error_code,
        } => QuicFrame::stop_sending(stream_id.as_u64().to_string(), *application_error_code),
        Frame::Crypto { offset, data } => {
            QuicFrame::crypto(offset.to_string(), data.len().to_string())
        }
        Frame::NewToken { token } => QuicFrame::new_token(token.len().to_string(), hex(&token)),
        Frame::Stream {
            fin,
            stream_id,
            offset,
            data,
            ..
        } => QuicFrame::stream(
            stream_id.as_u64().to_string(),
            offset.to_string(),
            data.len().to_string(),
            *fin,
            None,
        ),
        Frame::MaxData { maximum_data } => QuicFrame::max_data(maximum_data.to_string()),
        Frame::MaxStreamData {
            stream_id,
            maximum_stream_data,
        } => QuicFrame::max_stream_data(
            stream_id.as_u64().to_string(),
            maximum_stream_data.to_string(),
        ),
        Frame::MaxStreams {
            stream_type,
            maximum_streams,
        } => QuicFrame::max_streams(
            match stream_type {
                frame::StreamType::BiDi => qlog::StreamType::Bidirectional,
                frame::StreamType::UniDi => qlog::StreamType::Unidirectional,
            },
            maximum_streams.as_u64().to_string(),
        ),
        Frame::DataBlocked { data_limit } => QuicFrame::data_blocked(data_limit.to_string()),
        Frame::StreamDataBlocked {
            stream_id,
            stream_data_limit,
        } => QuicFrame::stream_data_blocked(
            stream_id.as_u64().to_string(),
            stream_data_limit.to_string(),
        ),
        Frame::StreamsBlocked {
            stream_type,
            stream_limit,
        } => QuicFrame::streams_blocked(
            match stream_type {
                frame::StreamType::BiDi => qlog::StreamType::Bidirectional,
                frame::StreamType::UniDi => qlog::StreamType::Unidirectional,
            },
            stream_limit.as_u64().to_string(),
        ),
        Frame::NewConnectionId {
            sequence_number,
            retire_prior,
            connection_id,
            stateless_reset_token,
        } => QuicFrame::new_connection_id(
            sequence_number.to_string(),
            retire_prior.to_string(),
            connection_id.len() as u64,
            hex(&connection_id),
            hex(stateless_reset_token),
        ),
        Frame::RetireConnectionId { sequence_number } => {
            QuicFrame::retire_connection_id(sequence_number.to_string())
        }
        Frame::PathChallenge { data } => QuicFrame::path_challenge(Some(hex(data))),
        Frame::PathResponse { data } => QuicFrame::path_response(Some(hex(data))),
        Frame::ConnectionClose {
            error_code,
            frame_type,
            reason_phrase,
        } => QuicFrame::connection_close(
            match error_code {
                frame::CloseError::Transport(_) => qlog::ErrorSpace::TransportError,
                frame::CloseError::Application(_) => qlog::ErrorSpace::ApplicationError,
            },
            error_code.code(),
            0,
            String::from_utf8_lossy(&reason_phrase).to_string(),
            Some(frame_type.to_string()),
        ),
        Frame::HandshakeDone => QuicFrame::handshake_done(),
    }
}

fn to_qlog_pkt_type(ptype: PacketType) -> qlog::PacketType {
    match ptype {
        PacketType::Initial => qlog::PacketType::Initial,
        PacketType::Handshake => qlog::PacketType::Handshake,
        PacketType::ZeroRtt => qlog::PacketType::ZeroRtt,
        PacketType::Short => qlog::PacketType::OneRtt,
        PacketType::Retry => qlog::PacketType::Retry,
        PacketType::VersionNegotiation => qlog::PacketType::VersionNegotiation,
        PacketType::OtherVersion => qlog::PacketType::Unknown,
    }
}
