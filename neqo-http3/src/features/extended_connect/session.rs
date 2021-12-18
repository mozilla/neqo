// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use super::{ExtendedConnectEvents, ExtendedConnectType, SessionCloseReason};
use crate::{
    frames::{FrameReader, StreamReaderRecvStreamWrapper, WebTransportFrame},
    CloseType, Http3StreamInfo, HttpRecvStreamEvents, RecvStream, RecvStreamEvents, Res,
    SendStream, SendStreamEvents,
};
use neqo_common::{qtrace, Encoder, Header, Role};
use neqo_transport::{Connection, StreamId};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::mem;
use std::rc::Rc;

#[derive(Debug, PartialEq)]
enum SessionState {
    Negotiating,
    Active,
    FinPending,
    Done,
}

impl SessionState {
    pub fn closing_state(&self) -> bool {
        matches!(self, Self::FinPending | Self::Done)
    }
}

#[derive(Debug)]
pub struct ExtendedConnectSession {
    connect_type: ExtendedConnectType,
    session_id: StreamId,
    state: SessionState,
    frame_reader: FrameReader,
    events: Box<dyn ExtendedConnectEvents>,
    send_streams: BTreeSet<StreamId>,
    recv_streams: BTreeSet<StreamId>,
    role: Role,
}

impl ::std::fmt::Display for ExtendedConnectSession {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "ExtendedConnectSesssion for {}",
            self.connect_type.string(),
        )
    }
}

impl ExtendedConnectSession {
    #[must_use]
    pub fn new(
        connect_type: ExtendedConnectType,
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
    ) -> Self {
        Self {
            connect_type,
            session_id,
            state: if role == Role::Client {
                SessionState::Negotiating
            } else {
                SessionState::Active
            },
            frame_reader: FrameReader::new(),
            events,
            send_streams: BTreeSet::new(),
            recv_streams: BTreeSet::new(),
            role,
        }
    }

    fn close(&mut self, stream_id: StreamId, close_type: CloseType) {
        if self.state.closing_state() {
            return;
        }
        qtrace!("ExtendedConnect close the session");
        self.state = SessionState::Done;
        if let CloseType::ResetApp(_) = close_type {
            return;
        }
        self.events.session_end(
            self.connect_type,
            stream_id,
            SessionCloseReason::from(close_type),
        );
    }

    /// # Panics
    /// This cannot panic because headers are checked before this function called.
    pub fn headers_ready(
        &mut self,
        stream_id: StreamId,
        headers: &[Header],
        interim: bool,
        fin: bool,
    ) {
        if self.state.closing_state() {
            return;
        }
        qtrace!(
            "ExtendedConnect response headers {:?}, fin={}",
            headers,
            fin
        );

        if interim {
            if fin {
                self.events.session_end(
                    self.connect_type,
                    stream_id,
                    SessionCloseReason::Clean {
                        error: 0,
                        message: "".to_string(),
                    },
                );
                self.state = SessionState::Done;
            }
        } else {
            let status = headers
                .iter()
                .find_map(|h| {
                    if h.name() == ":status" {
                        h.value().parse::<u16>().ok()
                    } else {
                        None
                    }
                })
                .unwrap();

            self.state = if (200..300).contains(&status) {
                if fin {
                    self.events.session_end(
                        self.connect_type,
                        stream_id,
                        SessionCloseReason::Clean {
                            error: 0,
                            message: "".to_string(),
                        },
                    );
                    SessionState::Done
                } else {
                    self.events
                        .session_start(self.connect_type, stream_id, status);
                    SessionState::Active
                }
            } else {
                self.events.session_end(
                    self.connect_type,
                    stream_id,
                    SessionCloseReason::Status(status),
                );
                SessionState::Done
            };
        }
    }

    pub fn add_stream(&mut self, stream_id: StreamId) {
        if let SessionState::Active = self.state {
            if stream_id.is_bidi() {
                self.send_streams.insert(stream_id);
                self.recv_streams.insert(stream_id);
            } else if stream_id.is_self_initiated(self.role) {
                self.send_streams.insert(stream_id);
            } else {
                self.recv_streams.insert(stream_id);
            }

            if !stream_id.is_self_initiated(self.role) {
                self.events
                    .extended_connect_new_stream(Http3StreamInfo::new(
                        stream_id,
                        self.connect_type.get_stream_type(self.session_id),
                    ));
            }
        }
    }

    pub fn remove_recv_stream(&mut self, stream_id: StreamId) {
        self.recv_streams.remove(&stream_id);
    }

    pub fn remove_send_stream(&mut self, stream_id: StreamId) {
        self.send_streams.remove(&stream_id);
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    pub fn take_sub_streams(&mut self) -> Option<(BTreeSet<StreamId>, BTreeSet<StreamId>)> {
        Some((
            mem::take(&mut self.recv_streams),
            mem::take(&mut self.send_streams),
        ))
    }

    /// # Errors
    /// It may return an error if the frame is not correctly decoded.
    pub fn read_control_stream(
        &mut self,
        recv_stream: &mut Box<dyn RecvStream>,
        conn: &mut Connection,
    ) -> Res<bool> {
        let (f, fin) = self.frame_reader.receive::<WebTransportFrame>(
            &mut StreamReaderRecvStreamWrapper::new(conn, recv_stream),
        )?;
        if let Some(WebTransportFrame::CloseSession { error, message }) = f {
            self.events.session_end(
                self.connect_type,
                self.session_id,
                SessionCloseReason::Clean { error, message },
            );
            self.state = if fin {
                SessionState::Done
            } else {
                SessionState::FinPending
            };
        } else if fin {
            self.events.session_end(
                self.connect_type,
                self.session_id,
                SessionCloseReason::Clean {
                    error: 0,
                    message: "".to_string(),
                },
            );
            self.state = SessionState::Done;
        }
        Ok(fin)
    }

    /// # Errors
    /// Return an error if the stream was closed on the transport layer, but that information is not yet
    /// consumed on the http/3 layer.
    pub fn close_session(
        &mut self,
        send_stream: &mut Box<dyn SendStream>,
        conn: &mut Connection,
        error: u32,
        message: &str,
    ) -> Res<()> {
self.state = SessionState::Done;
        let close_frame = WebTransportFrame::CloseSession {
            error,
            message: message.to_string(),
        };
        let mut encoder = Encoder::default();
        close_frame.encode(&mut encoder);
        send_stream.send_data(conn, &encoder)?;
        send_stream.close(conn)?;
        Ok(())
    }
}

impl RecvStreamEvents for Rc<RefCell<ExtendedConnectSession>> {
    fn data_readable(&self, _stream_info: Http3StreamInfo) {}

    fn recv_closed(&self, stream_info: Http3StreamInfo, close_type: CloseType) {
        if CloseType::Done != close_type {
            self.borrow_mut().close(stream_info.stream_id(), close_type);
        }
    }
}

impl HttpRecvStreamEvents for Rc<RefCell<ExtendedConnectSession>> {
    fn header_ready(
        &self,
        stream_info: Http3StreamInfo,
        headers: Vec<Header>,
        interim: bool,
        fin: bool,
    ) {
        self.borrow_mut()
            .headers_ready(stream_info.stream_id(), &headers, interim, fin);
    }
}

impl SendStreamEvents for Rc<RefCell<ExtendedConnectSession>> {
    fn data_writable(&self, _stream_info: Http3StreamInfo) {}

    /// Add a new `StopSending` event
    fn send_closed(&self, stream_info: Http3StreamInfo, close_type: CloseType) {
        if CloseType::Done != close_type {
            self.borrow_mut().close(stream_info.stream_id(), close_type);
        }
    }
}
