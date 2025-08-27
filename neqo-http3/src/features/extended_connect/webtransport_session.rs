// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
    mem,
};

use neqo_common::{qtrace, Encoder, Role};
use neqo_transport::{Connection, StreamId};

use crate::{
    features::extended_connect::{
        ExtendedConnectEvents, ExtendedConnectType, Protocol, SessionCloseReason, SessionState,
    },
    frames::{FrameReader, StreamReaderRecvStreamWrapper, WebTransportFrame},
    Error, Http3StreamInfo, RecvStream, Res,
};

#[derive(Debug)]
pub(crate) struct Session {
    frame_reader: FrameReader,
    session_id: StreamId,
    send_streams: HashSet<StreamId>,
    recv_streams: HashSet<StreamId>,
    role: Role,
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "WebTransportSession")
    }
}

impl Session {
    #[must_use]
    pub(crate) fn new(session_id: StreamId, role: Role) -> Self {
        Self {
            session_id,
            frame_reader: FrameReader::new(),
            send_streams: HashSet::default(),
            recv_streams: HashSet::default(),
            role,
        }
    }
}

impl Protocol for Session {
    fn connect_type(&self) -> ExtendedConnectType {
        ExtendedConnectType::WebTransport
    }

    fn close_frame(&self, error: u32, message: &str) -> Option<Vec<u8>> {
        let close_frame = WebTransportFrame::CloseSession {
            error,
            message: message.to_string(),
        };
        let mut encoder = Encoder::default();
        close_frame.encode(&mut encoder);
        Some(encoder.into())
    }

    fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
    ) -> Res<Option<SessionState>> {
        let (f, fin) = self
            .frame_reader
            .receive::<WebTransportFrame>(&mut StreamReaderRecvStreamWrapper::new(
                conn,
                control_stream_recv,
            ))
            .map_err(|_| Error::HttpGeneralProtocolStream)?;
        qtrace!("[{self}] Received frame: {f:?} fin={fin}");
        if let Some(WebTransportFrame::CloseSession { error, message }) = f {
            events.session_end(
                ExtendedConnectType::WebTransport,
                self.session_id,
                SessionCloseReason::Clean { error, message },
                None,
            );
            if fin {
                Ok(Some(SessionState::Done))
            } else {
                Ok(Some(SessionState::FinPending))
            }
        } else if fin {
            events.session_end(
                ExtendedConnectType::WebTransport,
                self.session_id,
                SessionCloseReason::Clean {
                    error: 0,
                    message: String::new(),
                },
                None,
            );
            Ok(Some(SessionState::Done))
        } else {
            Ok(None)
        }
    }

    fn add_stream(
        &mut self,
        stream_id: StreamId,
        events: &mut Box<dyn ExtendedConnectEvents>,
    ) -> Res<()> {
        if stream_id.is_bidi() {
            self.send_streams.insert(stream_id);
            self.recv_streams.insert(stream_id);
        } else if stream_id.is_self_initiated(self.role) {
            self.send_streams.insert(stream_id);
        } else {
            self.recv_streams.insert(stream_id);
        }

        if !stream_id.is_self_initiated(self.role) {
            events.extended_connect_new_stream(Http3StreamInfo::new(
                stream_id,
                ExtendedConnectType::WebTransport.get_stream_type(self.session_id),
            ))?;
        }
        Ok(())
    }

    fn remove_recv_stream(&mut self, stream_id: StreamId) {
        self.recv_streams.remove(&stream_id);
    }

    fn remove_send_stream(&mut self, stream_id: StreamId) {
        self.send_streams.remove(&stream_id);
    }

    fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        (
            mem::take(&mut self.recv_streams),
            mem::take(&mut self.send_streams),
        )
    }

    fn write_datagram_prefix(&self, encoder: &mut Encoder) {
        // WebTransport does not add prefix (i.e. context ID).
    }

    fn read_datagram_prefix<'a>(&self, datagram: &'a [u8]) -> &'a [u8] {
        // WebTransport does not use a prefix (i.e. context ID).
        datagram
    }
}
