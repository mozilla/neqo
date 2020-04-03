// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::string::String;

use qlog::{self, event::Event, PacketHeader, QuicFrame};

use neqo_common::{hex, qinfo, Decoder, NeqoQlogRef};

use crate::frame::{self, Frame};
use crate::packet::{DecryptedPacket, PacketNumber, PacketType};
use crate::path::Path;
use crate::tparams::{self, TransportParametersHandler};
use crate::{Res, QUIC_VERSION};
use std::fmt::LowerHex;

// TODO(hawkinsw@obs.cr): This is copied verbatim from neqo-qpack/src/qlog.rs where
// it has appropriate tests. Refactor both uses into something in neqo-common.
fn slice_to_hex_string<T: LowerHex>(slice: &[T]) -> String {
    if slice.is_empty() {
        "0x0".to_string()
    } else {
        slice
            .iter()
            .fold("0x".to_string(), |acc, x| acc + &format!("{:x}", x))
    }
}

pub fn connection_tparams_set(
    qlog: &Option<NeqoQlogRef>,
    tph: &TransportParametersHandler,
) -> Res<()> {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();
        let remote = tph.remote();
        let event = Event::transport_parameters_set(
            None,
            None,
            None,
            None,
            None,
            None,
            if let Some(ocid) = remote.get_bytes(tparams::ORIGINAL_CONNECTION_ID) {
                // Cannot use packet::ConnectionId's Display trait implementation
                // because it does not include the 0x prefix.
                Some(slice_to_hex_string(&ocid))
            } else {
                None
            },
            if let Some(srt) = remote.get_bytes(tparams::STATELESS_RESET_TOKEN) {
                Some(slice_to_hex_string(&srt))
            } else {
                None
            },
            if remote.get_empty(tparams::DISABLE_MIGRATION).is_some() {
                Some(true)
            } else {
                None
            },
            Some(remote.get_integer(tparams::IDLE_TIMEOUT)),
            Some(remote.get_integer(tparams::MAX_PACKET_SIZE)),
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
        );

        qlog.streamer.add_event(event)?;
    }
    Ok(())
}

pub fn server_connection_started(qlog: &Option<NeqoQlogRef>, path: &Path) -> Res<()> {
    connection_started(qlog, path)
}

pub fn client_connection_started(qlog: &Option<NeqoQlogRef>, path: &Path) -> Res<()> {
    connection_started(qlog, path)
}

pub fn packet_sent(
    qlog: &Option<NeqoQlogRef>,
    pt: PacketType,
    pn: PacketNumber,
    body: &[u8],
) -> Res<()> {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();

        let mut d = Decoder::from(body);

        qlog.streamer.add_event(Event::packet_sent_min(
            pkt_type_to_qlog_pkt_type(pt),
            PacketHeader::new(pn, None, None, None, None, None),
            Some(Vec::new()),
        ))?;

        while d.remaining() > 0 {
            match Frame::decode(&mut d) {
                Ok(f) => qlog.streamer.add_frame(frame_to_qlogframe(&f), false)?,
                Err(_) => {
                    qinfo!("qlog: invalid frame");
                    break;
                }
            }
        }

        qlog.streamer.finish_frames()?;
    }
    Ok(())
}

pub fn packet_received(qlog: &Option<NeqoQlogRef>, payload: &DecryptedPacket) -> Res<()> {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();

        let mut d = Decoder::from(&payload[..]);

        qlog.streamer.add_event(Event::packet_received(
            pkt_type_to_qlog_pkt_type(payload.packet_type()),
            PacketHeader::new(payload.pn(), None, None, None, None, None),
            Some(Vec::new()),
            None,
            None,
            None,
        ))?;

        while d.remaining() > 0 {
            match Frame::decode(&mut d) {
                Ok(f) => qlog.streamer.add_frame(frame_to_qlogframe(&f), false)?,
                Err(_) => {
                    qinfo!("qlog: invalid frame");
                    break;
                }
            }
        }

        qlog.streamer.finish_frames()?;
    }
    Ok(())
}

// Helper functions

fn frame_to_qlogframe(frame: &Frame) -> QuicFrame {
    match frame {
        Frame::Padding => QuicFrame::padding(),
        Frame::Ping => QuicFrame::ping(),
        Frame::Ack { ack_delay, .. } => {
            QuicFrame::ack(Some(ack_delay.to_string()), None, None, None, None)
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
        Frame::HandshakeDone => QuicFrame::unknown(0x1e),
    }
}

fn pkt_type_to_qlog_pkt_type(ptype: PacketType) -> qlog::PacketType {
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

fn connection_started(qlog: &Option<NeqoQlogRef>, path: &Path) -> Res<()> {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();

        qlog.streamer.start_log()?;

        qlog.streamer.add_event(Event::connection_started(
            if path.local_sock().ip().is_ipv4() {
                "ipv4".into()
            } else {
                "ipv6".into()
            },
            format!("{}", path.local_sock().ip()),
            format!("{}", path.remote_sock().ip()),
            Some("QUIC".into()),
            path.local_sock().port().into(),
            path.remote_sock().port().into(),
            Some(format!("{:x}", QUIC_VERSION)),
            Some(format!("{}", path.local_cid())),
            Some(format!("{}", path.remote_cid())),
        ))?;
    }
    Ok(())
}
