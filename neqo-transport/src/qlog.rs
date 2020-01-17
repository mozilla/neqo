// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::string::String;
use std::time::Instant;

use qlog::{
    self, ConnectivityEventType, EventData, PacketHeader, QuicFrame, QuicFrameTypeName,
    TransportEventType,
};

use neqo_common::{hex, qinfo, Decoder, NeqoQlogRef};

use crate::frame::{self, Frame};
use crate::packet::{DecryptedPacket, PacketNumber, PacketType};
use crate::path::Path;
use crate::QUIC_VERSION;

pub fn client_connection_started(qlog: &Option<NeqoQlogRef>, now: Instant, path: &Path) {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();
        let elapsed = now.duration_since(qlog.zero_time);

        qlog.trace.push_connectivity_event(
            format!("{}", elapsed.as_micros()),
            ConnectivityEventType::ConnectionStarted,
            EventData::ConnectionStarted {
                ip_version: if path.local_sock().ip().is_ipv4() {
                    "ipv4".into()
                } else {
                    "ipv6".into()
                },
                src_ip: format!("{}", path.local_sock().ip()),
                dst_ip: format!("{}", path.remote_sock().ip()),
                protocol: Some("QUIC".into()),
                src_port: path.local_sock().port().into(),
                dst_port: path.remote_sock().port().into(),
                quic_version: Some(format!("{:x}", QUIC_VERSION)),
                src_cid: Some(format!("{}", path.local_cid())),
                dst_cid: Some(format!("{}", path.remote_cid())),
            },
        )
    }
}

pub fn packet_sent(
    qlog: &Option<NeqoQlogRef>,
    now: Instant,
    pt: PacketType,
    pn: PacketNumber,
    body: &[u8],
) {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();
        let elapsed = now.duration_since(qlog.zero_time);

        let mut frames = Vec::new();
        let mut d = Decoder::from(body);

        while d.remaining() > 0 {
            match Frame::decode(&mut d) {
                Ok(f) => frames.push(frame_to_qlogframe(&f)),
                Err(_) => {
                    qinfo!("qlog: invalid frame");
                    break;
                }
            }
        }

        let packet_type = pkt_type_to_qlog_pkt_type(&pt);

        qlog.trace.push_transport_event(
            format!("{}", elapsed.as_micros()),
            TransportEventType::PacketSent,
            EventData::PacketSent {
                packet_type,
                header: PacketHeader {
                    packet_number: pn.to_string(),
                    packet_size: None,
                    payload_length: None,
                    version: None,
                    scil: None,
                    dcil: None,
                    scid: None,
                    dcid: None,
                },
                frames: Some(frames),
                is_coalesced: None,
                raw_encrypted: None,
                raw_decrypted: None,
            },
        )
    }
}

pub fn packet_received(qlog: &Option<NeqoQlogRef>, now: Instant, payload: &DecryptedPacket) {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();
        let elapsed = now.duration_since(qlog.zero_time);

        let mut frames = Vec::new();
        let mut d = Decoder::from(&payload[..]);

        while d.remaining() > 0 {
            match Frame::decode(&mut d) {
                Ok(f) => frames.push(frame_to_qlogframe(&f)),
                Err(_) => {
                    qinfo!("qlog: invalid frame");
                    break;
                }
            }
        }

        let packet_type = pkt_type_to_qlog_pkt_type(&payload.packet_type());

        qlog.trace.push_transport_event(
            format!("{}", elapsed.as_micros()),
            TransportEventType::PacketReceived,
            EventData::PacketReceived {
                packet_type,
                header: PacketHeader {
                    packet_number: payload.pn().to_string(),
                    packet_size: None,
                    payload_length: None,
                    version: None,
                    scil: None,
                    dcil: None,
                    scid: None,
                    dcid: None,
                },
                frames: Some(frames),
                is_coalesced: None,
                raw_encrypted: None,
                raw_decrypted: None,
            },
        )
    }
}

// Helper functions

fn frame_to_qlogframe(frame: &Frame) -> QuicFrame {
    match frame {
        Frame::Padding => QuicFrame::Padding {
            frame_type: QuicFrameTypeName::Padding,
        },
        Frame::Ping => QuicFrame::Ping {
            frame_type: QuicFrameTypeName::Ping,
        },
        Frame::Ack { ack_delay, .. } => QuicFrame::Ack {
            frame_type: QuicFrameTypeName::Ack,
            ack_delay: Some(ack_delay.to_string()),
            acked_ranges: None,
            ect1: None,
            ect0: None,
            ce: None,
        },
        Frame::ResetStream {
            stream_id,
            application_error_code,
            final_size,
        } => QuicFrame::ResetStream {
            frame_type: QuicFrameTypeName::ResetStream,
            stream_id: stream_id.as_u64().to_string(),
            error_code: *application_error_code,
            final_size: final_size.to_string(),
        },
        Frame::StopSending {
            stream_id,
            application_error_code,
        } => QuicFrame::StopSending {
            frame_type: QuicFrameTypeName::StopSending,
            stream_id: stream_id.as_u64().to_string(),
            error_code: *application_error_code,
        },
        Frame::Crypto { offset, data } => QuicFrame::Crypto {
            frame_type: QuicFrameTypeName::Crypto,
            offset: offset.to_string(),
            length: data.len().to_string(),
        },
        Frame::NewToken { token } => QuicFrame::NewToken {
            frame_type: QuicFrameTypeName::NewToken,
            length: token.len().to_string(),
            token: hex(&token),
        },
        Frame::Stream {
            fin,
            stream_id,
            offset,
            data,
            ..
        } => QuicFrame::Stream {
            frame_type: QuicFrameTypeName::Stream,
            stream_id: stream_id.as_u64().to_string(),
            offset: offset.to_string(),
            length: data.len().to_string(),
            fin: *fin,
            raw: None,
        },
        Frame::MaxData { maximum_data } => QuicFrame::MaxData {
            frame_type: QuicFrameTypeName::MaxData,
            maximum: maximum_data.to_string(),
        },
        Frame::MaxStreamData {
            stream_id,
            maximum_stream_data,
        } => QuicFrame::MaxStreamData {
            frame_type: QuicFrameTypeName::MaxStreamData,
            stream_id: stream_id.as_u64().to_string(),
            maximum: maximum_stream_data.to_string(),
        },
        Frame::MaxStreams {
            stream_type,
            maximum_streams,
        } => QuicFrame::MaxStreams {
            frame_type: QuicFrameTypeName::MaxData,
            stream_type: match stream_type {
                frame::StreamType::BiDi => qlog::StreamType::Bidirectional,
                frame::StreamType::UniDi => qlog::StreamType::Unidirectional,
            },
            maximum: maximum_streams.as_u64().to_string(),
        },
        Frame::DataBlocked { data_limit } => QuicFrame::DataBlocked {
            frame_type: QuicFrameTypeName::DataBlocked,
            limit: data_limit.to_string(),
        },
        Frame::StreamDataBlocked {
            stream_id,
            stream_data_limit,
        } => QuicFrame::StreamDataBlocked {
            frame_type: QuicFrameTypeName::StreamDataBlocked,
            stream_id: stream_id.as_u64().to_string(),
            limit: stream_data_limit.to_string(),
        },
        Frame::StreamsBlocked {
            stream_type,
            stream_limit,
        } => QuicFrame::StreamsBlocked {
            frame_type: QuicFrameTypeName::StreamsBlocked,
            stream_type: match stream_type {
                frame::StreamType::BiDi => qlog::StreamType::Bidirectional,
                frame::StreamType::UniDi => qlog::StreamType::Unidirectional,
            },
            limit: stream_limit.as_u64().to_string(),
        },
        Frame::NewConnectionId {
            sequence_number,
            retire_prior,
            connection_id,
            stateless_reset_token,
        } => QuicFrame::NewConnectionId {
            frame_type: QuicFrameTypeName::NewConnectionId,
            sequence_number: sequence_number.to_string(),
            retire_prior_to: retire_prior.to_string(),
            length: connection_id.len() as u64,
            connection_id: hex(&connection_id),
            reset_token: hex(stateless_reset_token),
        },
        Frame::RetireConnectionId { sequence_number } => QuicFrame::RetireConnectionId {
            frame_type: QuicFrameTypeName::RetireConnectionId,
            sequence_number: sequence_number.to_string(),
        },
        Frame::PathChallenge { data } => QuicFrame::PathChallenge {
            frame_type: QuicFrameTypeName::PathChallenge,
            data: Some(hex(data)),
        },
        Frame::PathResponse { data } => QuicFrame::PathResponse {
            frame_type: QuicFrameTypeName::PathResponse,
            data: Some(hex(data)),
        },
        Frame::ConnectionClose {
            error_code,
            frame_type,
            reason_phrase,
        } => QuicFrame::ConnectionClose {
            frame_type: QuicFrameTypeName::ConnectionClose,
            error_space: match error_code {
                frame::CloseError::Transport(_) => qlog::ErrorSpace::TransportError,
                frame::CloseError::Application(_) => qlog::ErrorSpace::ApplicationError,
            },
            error_code: error_code.code(),
            raw_error_code: 0,
            reason: String::from_utf8_lossy(&reason_phrase).to_string(),
            trigger_frame_type: Some(frame_type.to_string()),
        },
        Frame::HandshakeDone => QuicFrame::Unknown {
            frame_type: QuicFrameTypeName::Unknown,
            raw_frame_type: 0x1e,
        },
    }
}

fn pkt_type_to_qlog_pkt_type(ptype: &PacketType) -> qlog::PacketType {
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
