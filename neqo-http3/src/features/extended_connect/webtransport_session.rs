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
        session::{DgramContextIdError, Protocol, State},
        CloseReason, ExtendedConnectEvents, ExtendedConnectType,
    },
    frames::{FrameReader, StreamReaderRecvStreamWrapper, WebTransportFrame},
    Error, Http3StreamInfo, Http3StreamType, RecvStream, Res,
};

#[derive(Debug)]
pub struct Session {
    frame_reader: FrameReader,
    id: StreamId,
    send_streams: HashSet<StreamId>,
    recv_streams: HashSet<StreamId>,
    role: Role,
    /// Remote initiated streams received before session confirmation.
    ///
    /// [`HashSet`] size limited by QUIC connection stream limit.
    pending_streams: HashSet<StreamId>,
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
            id: session_id,
            frame_reader: FrameReader::new(),
            send_streams: HashSet::default(),
            recv_streams: HashSet::default(),
            role,
            pending_streams: HashSet::default(),
        }
    }
}

impl Protocol for Session {
    fn connect_type(&self) -> ExtendedConnectType {
        ExtendedConnectType::WebTransport
    }

    fn session_start(&mut self, events: &mut Box<dyn ExtendedConnectEvents>) -> Res<()> {
        // > WebTransport endpoints SHOULD buffer streams and
        // > datagrams until they can be associated with an
        // > established session.
        //
        // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#section-4.5>
        #[expect(clippy::iter_over_hash_type, reason = "no defined order necessary")]
        for stream_id in self.pending_streams.drain() {
            events.extended_connect_new_stream(
                Http3StreamInfo::new(stream_id, Http3StreamType::WebTransport(self.id)),
                // Explicitly emit a stream readable event. Such
                // event was previously suppressed as the
                // session was still negotiating.
                true,
            )?;
        }

        Ok(())
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
    ) -> Res<Option<State>> {
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
                self.id,
                CloseReason::Clean { error, message },
                None,
            );
            if fin {
                Ok(Some(State::Done))
            } else {
                Ok(Some(State::FinPending))
            }
        } else if fin {
            events.session_end(
                ExtendedConnectType::WebTransport,
                self.id,
                CloseReason::Clean {
                    error: 0,
                    message: String::new(),
                },
                None,
            );
            Ok(Some(State::Done))
        } else {
            Ok(None)
        }
    }

    fn add_stream(
        &mut self,
        stream_id: StreamId,
        events: &mut Box<dyn ExtendedConnectEvents>,
        state: State,
    ) -> Res<()> {
        match state {
            State::Negotiating | State::Active => {}
            State::FinPending | State::Done => return Ok(()),
        }

        if stream_id.is_bidi() {
            self.send_streams.insert(stream_id);
            self.recv_streams.insert(stream_id);
        } else if stream_id.is_self_initiated(self.role) {
            self.send_streams.insert(stream_id);
        } else {
            self.recv_streams.insert(stream_id);
        }

        match state {
            State::FinPending | State::Done => {
                unreachable!("see match above");
            }
            State::Negotiating => {
                // > a client may receive a server-initiated stream or a datagram
                // > before receiving the CONNECT response headers from the
                // > server.
                // >
                // > To handle this case, WebTransport endpoints SHOULD buffer
                // > streams and datagrams until they can be associated with an
                // > established session.
                //
                // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#section-4.5>
                self.pending_streams.insert(stream_id);
            }
            State::Active => {
                if !stream_id.is_self_initiated(self.role) {
                    events.extended_connect_new_stream(
                        Http3StreamInfo::new(stream_id, Http3StreamType::WebTransport(self.id)),
                        // Don't emit an additional stream readable event. Given
                        // that the session is already active, this event will
                        // be emitted through the WebTransport stream itself.
                        false,
                    )?;
                }
            }
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

    fn write_datagram_prefix(&self, _encoder: &mut Encoder) {
        // WebTransport does not add prefix (i.e. context ID).
    }

    fn dgram_context_id<'a>(&self, datagram: &'a [u8]) -> Result<&'a [u8], DgramContextIdError> {
        // WebTransport does not use a prefix (i.e. context ID).
        Ok(datagram)
    }
}
