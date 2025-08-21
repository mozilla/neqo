// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    fmt::{self, Display, Formatter},
    mem,
    rc::Rc,
};

use neqo_common::{qtrace, Encoder, Header, MessageType, Role};
use neqo_qpack as qpack;
use neqo_transport::{Connection, DatagramTracking, StreamId};
use rustc_hash::FxHashSet as HashSet;

use super::{ExtendedConnectEvents, ExtendedConnectType, SessionCloseReason};
use crate::{
    frames::{FrameReader, StreamReaderRecvStreamWrapper, WebTransportFrame},
    recv_message::{RecvMessage, RecvMessageInfo},
    send_message::SendMessage,
    CloseType, Error, HFrame, Http3StreamInfo, Http3StreamType, HttpRecvStream,
    HttpRecvStreamEvents, Priority, PriorityHandler, ReceiveOutput, RecvStream, RecvStreamEvents,
    Res, SendStream, SendStreamEvents, Stream,
};

#[derive(Debug, PartialEq)]
enum SessionState {
    Negotiating {
        /// Remote initiated streams received before session confirmation.
        ///
        /// [`HashSet`] size limited by QUIC connection stream limit.
        pending_streams: HashSet<StreamId>,
    },
    Active,
    FinPending,
    Done,
}

impl SessionState {
    pub const fn closing_state(&self) -> bool {
        matches!(self, Self::FinPending | Self::Done)
    }
}

#[derive(Debug)]
pub struct WebTransportSession {
    control_stream_recv: Box<dyn RecvStream>,
    control_stream_send: Box<dyn SendStream>,
    stream_event_listener: Rc<RefCell<WebTransportSessionListener>>,
    session_id: StreamId,
    state: SessionState,
    frame_reader: FrameReader,
    events: Box<dyn ExtendedConnectEvents>,
    send_streams: HashSet<StreamId>,
    recv_streams: HashSet<StreamId>,
    role: Role,
}

impl Display for WebTransportSession {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "WebTransportSession session={}", self.session_id)
    }
}

impl WebTransportSession {
    #[must_use]
    pub fn new(
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
        qpack_encoder: Rc<RefCell<qpack::Encoder>>,
        qpack_decoder: Rc<RefCell<qpack::Decoder>>,
    ) -> Self {
        let stream_event_listener = Rc::new(RefCell::new(WebTransportSessionListener::default()));
        Self {
            control_stream_recv: Box::new(RecvMessage::new(
                &RecvMessageInfo {
                    message_type: MessageType::Response,
                    stream_type: Http3StreamType::ExtendedConnect,
                    stream_id: session_id,
                    first_frame_type: None,
                },
                qpack_decoder,
                Box::new(Rc::clone(&stream_event_listener)),
                None,
                PriorityHandler::new(false, Priority::default()),
            )),
            control_stream_send: Box::new(SendMessage::new(
                MessageType::Request,
                Http3StreamType::ExtendedConnect,
                session_id,
                qpack_encoder,
                Box::new(Rc::clone(&stream_event_listener)),
            )),
            stream_event_listener,
            session_id,
            state: SessionState::Negotiating {
                pending_streams: HashSet::default(),
            },
            frame_reader: FrameReader::new(),
            events,
            send_streams: HashSet::default(),
            recv_streams: HashSet::default(),
            role,
        }
    }

    /// # Panics
    ///
    /// This function is only called with `RecvStream` and `SendStream` that also implement
    /// the http specific functions and `http_stream()` will never return `None`.
    pub fn new_with_http_streams(
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
        mut control_stream_recv: Box<dyn RecvStream>,
        mut control_stream_send: Box<dyn SendStream>,
    ) -> Res<Self> {
        let stream_event_listener = Rc::new(RefCell::new(WebTransportSessionListener::default()));
        control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .set_new_listener(Box::new(Rc::clone(&stream_event_listener)));
        control_stream_send
            .http_stream()
            .ok_or(Error::Internal)?
            .set_new_listener(Box::new(Rc::clone(&stream_event_listener)));
        Ok(Self {
            control_stream_recv,
            control_stream_send,
            stream_event_listener,
            session_id,
            state: SessionState::Active,
            frame_reader: FrameReader::new(),
            events,
            send_streams: HashSet::default(),
            recv_streams: HashSet::default(),
            role,
        })
    }

    /// # Errors
    ///
    /// The function can only fail if supplied headers are not valid http headers.
    ///
    /// # Panics
    ///
    /// `control_stream_send` implements the  http specific functions and `http_stream()`
    /// will never return `None`.
    pub fn send_request(&mut self, headers: &[Header], conn: &mut Connection) -> Res<()> {
        self.control_stream_send
            .http_stream()
            .ok_or(Error::Internal)?
            .send_headers(headers, conn)
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<(ReceiveOutput, bool)> {
        qtrace!("[{self}] receive control data");
        let (out, _) = self.control_stream_recv.receive(conn)?;
        debug_assert!(out == ReceiveOutput::NoOutput);
        self.maybe_check_headers()?;
        self.read_control_stream(conn)?;
        Ok((ReceiveOutput::NoOutput, self.state == SessionState::Done))
    }

    fn header_unblocked(&mut self, conn: &mut Connection) -> Res<(ReceiveOutput, bool)> {
        let (out, _) = self
            .control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .header_unblocked(conn)?;
        debug_assert!(out == ReceiveOutput::NoOutput);
        self.maybe_check_headers()?;
        self.read_control_stream(conn)?;
        Ok((ReceiveOutput::NoOutput, self.state == SessionState::Done))
    }

    fn maybe_update_priority(&mut self, priority: Priority) -> Res<bool> {
        self.control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .maybe_update_priority(priority)
    }

    fn priority_update_frame(&mut self) -> Option<HFrame> {
        self.control_stream_recv
            .http_stream()?
            .priority_update_frame()
    }

    fn priority_update_sent(&mut self) -> Res<()> {
        self.control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .priority_update_sent()
    }

    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        self.control_stream_send.send(conn)?;
        if self.control_stream_send.done() {
            self.state = SessionState::Done;
        }
        Ok(())
    }

    fn has_data_to_send(&self) -> bool {
        self.control_stream_send.has_data_to_send()
    }

    fn done(&self) -> bool {
        self.state == SessionState::Done
    }

    fn close(&mut self, close_type: CloseType) {
        if self.state.closing_state() {
            return;
        }
        qtrace!("ExtendedConnect close the session");
        self.state = SessionState::Done;
        if !close_type.locally_initiated() {
            self.events.session_end(
                ExtendedConnectType::WebTransport,
                self.session_id,
                SessionCloseReason::from(close_type),
                None,
            );
        }
    }

    /// # Panics
    ///
    /// This cannot panic because headers are checked before this function called.
    pub fn maybe_check_headers(&mut self) -> Res<()> {
        let SessionState::Negotiating { pending_streams } = &mut self.state else {
            return Ok(());
        };

        if let Some((headers, interim, fin)) = self.stream_event_listener.borrow_mut().get_headers()
        {
            qtrace!("ExtendedConnect response headers {headers:?}, fin={fin}");

            if interim {
                if fin {
                    self.events.session_end(
                        ExtendedConnectType::WebTransport,
                        self.session_id,
                        SessionCloseReason::Clean {
                            error: 0,
                            message: String::new(),
                        },
                        Some(headers),
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
                    .ok_or(Error::Internal)?;

                self.state = if (200..300).contains(&status) {
                    if fin {
                        self.events.session_end(
                            ExtendedConnectType::WebTransport,
                            self.session_id,
                            SessionCloseReason::Clean {
                                error: 0,
                                message: String::new(),
                            },
                            Some(headers),
                        );
                        SessionState::Done
                    } else {
                        self.events.session_start(
                            ExtendedConnectType::WebTransport,
                            self.session_id,
                            status,
                            headers,
                        );
                        // > WebTransport endpoints SHOULD buffer streams and
                        // > datagrams until they can be associated with an
                        // > established session.
                        //
                        // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#section-4.5>
                        #[expect(
                            clippy::iter_over_hash_type,
                            reason = "no defined order necessary"
                        )]
                        for stream_id in pending_streams.drain() {
                            self.events.extended_connect_new_stream(
                                Http3StreamInfo::new(
                                    stream_id,
                                    ExtendedConnectType::WebTransport
                                        .get_stream_type(self.session_id),
                                ),
                                // Explicitly emit a stream readable event. Such
                                // event was previously suppressed as the
                                // session was still negotiating.
                                true,
                            )?;
                        }
                        SessionState::Active
                    }
                } else {
                    self.events.session_end(
                        ExtendedConnectType::WebTransport,
                        self.session_id,
                        SessionCloseReason::Status(status),
                        Some(headers),
                    );
                    SessionState::Done
                };
            }
        }
        Ok(())
    }

    pub fn add_stream(&mut self, stream_id: StreamId) -> Res<()> {
        match &self.state {
            SessionState::Negotiating { .. } | SessionState::Active => {}
            SessionState::FinPending | SessionState::Done => return Ok(()),
        }

        if stream_id.is_bidi() {
            self.send_streams.insert(stream_id);
            self.recv_streams.insert(stream_id);
        } else if stream_id.is_self_initiated(self.role) {
            self.send_streams.insert(stream_id);
        } else {
            self.recv_streams.insert(stream_id);
        }

        match &mut self.state {
            SessionState::FinPending | SessionState::Done => {
                unreachable!("see match above");
            }
            SessionState::Negotiating { pending_streams } => {
                // > a client may receive a server-initiated stream or a datagram
                // > before receiving the CONNECT response headers from the
                // > server.
                // >
                // > To handle this case, WebTransport endpoints SHOULD buffer
                // > streams and datagrams until they can be associated with an
                // > established session.
                //
                // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#section-4.5>
                pending_streams.insert(stream_id);
            }
            SessionState::Active => {
                if !stream_id.is_self_initiated(self.role) {
                    self.events.extended_connect_new_stream(
                        Http3StreamInfo::new(
                            stream_id,
                            ExtendedConnectType::WebTransport.get_stream_type(self.session_id),
                        ),
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

    pub fn remove_recv_stream(&mut self, stream_id: StreamId) {
        self.recv_streams.remove(&stream_id);
    }

    pub fn remove_send_stream(&mut self, stream_id: StreamId) {
        self.send_streams.remove(&stream_id);
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    pub fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        (
            mem::take(&mut self.recv_streams),
            mem::take(&mut self.send_streams),
        )
    }

    /// # Errors
    ///
    /// It may return an error if the frame is not correctly decoded.
    pub fn read_control_stream(&mut self, conn: &mut Connection) -> Res<()> {
        let (f, fin) = self
            .frame_reader
            .receive::<WebTransportFrame>(&mut StreamReaderRecvStreamWrapper::new(
                conn,
                &mut self.control_stream_recv,
            ))
            .map_err(|_| Error::HttpGeneralProtocolStream)?;
        qtrace!("[{self}] Received frame: {f:?} fin={fin}");
        if let Some(WebTransportFrame::CloseSession { error, message }) = f {
            self.events.session_end(
                ExtendedConnectType::WebTransport,
                self.session_id,
                SessionCloseReason::Clean { error, message },
                None,
            );
            self.state = if fin {
                SessionState::Done
            } else {
                SessionState::FinPending
            };
        } else if fin {
            self.events.session_end(
                ExtendedConnectType::WebTransport,
                self.session_id,
                SessionCloseReason::Clean {
                    error: 0,
                    message: String::new(),
                },
                None,
            );
            self.state = SessionState::Done;
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Return an error if the stream was closed on the transport layer, but that information is not
    /// yet consumed on the http/3 layer.
    pub fn close_session(&mut self, conn: &mut Connection, error: u32, message: &str) -> Res<()> {
        self.state = SessionState::Done;
        let close_frame = WebTransportFrame::CloseSession {
            error,
            message: message.to_string(),
        };
        let mut encoder = Encoder::default();
        close_frame.encode(&mut encoder);
        self.control_stream_send
            .send_data_atomic(conn, encoder.as_ref())?;
        self.control_stream_send.close(conn)?;
        self.state = if self.control_stream_send.done() {
            SessionState::Done
        } else {
            SessionState::FinPending
        };
        Ok(())
    }

    fn send_data(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        self.control_stream_send.send_data(conn, buf)
    }

    /// # Errors
    ///
    /// Returns an error if the datagram exceeds the remote datagram size limit.
    pub fn send_datagram<I: Into<DatagramTracking>>(
        &self,
        conn: &mut Connection,
        buf: &[u8],
        id: I,
    ) -> Res<()> {
        qtrace!("[{self}] send_datagram state={:?}", self.state);
        if self.state == SessionState::Active {
            let mut dgram_data = Encoder::default();
            dgram_data.encode_varint(self.session_id.as_u64() / 4);
            dgram_data.encode(buf);
            conn.send_datagram(dgram_data.into(), id)?;
        } else {
            debug_assert!(false);
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub fn datagram(&self, datagram: Vec<u8>) {
        if self.state == SessionState::Active {
            self.events.new_datagram(self.session_id, datagram);
        }
    }
}

impl Stream for Rc<RefCell<WebTransportSession>> {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::ExtendedConnect
    }
}

impl RecvStream for Rc<RefCell<WebTransportSession>> {
    fn receive(&mut self, conn: &mut Connection) -> Res<(ReceiveOutput, bool)> {
        self.borrow_mut().receive(conn)
    }

    fn reset(&mut self, close_type: CloseType) -> Res<()> {
        self.borrow_mut().close(close_type);
        Ok(())
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        Some(self)
    }

    fn webtransport(&self) -> Option<Rc<RefCell<WebTransportSession>>> {
        Some(Self::clone(self))
    }
}

impl HttpRecvStream for Rc<RefCell<WebTransportSession>> {
    fn header_unblocked(&mut self, conn: &mut Connection) -> Res<(ReceiveOutput, bool)> {
        self.borrow_mut().header_unblocked(conn)
    }

    fn maybe_update_priority(&mut self, priority: Priority) -> Res<bool> {
        self.borrow_mut().maybe_update_priority(priority)
    }

    fn priority_update_frame(&mut self) -> Option<HFrame> {
        self.borrow_mut().priority_update_frame()
    }

    fn priority_update_sent(&mut self) -> Res<()> {
        self.borrow_mut().priority_update_sent()
    }
}

impl SendStream for Rc<RefCell<WebTransportSession>> {
    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        self.borrow_mut().send(conn)
    }

    fn send_data(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        self.borrow_mut().send_data(conn, buf)
    }

    fn has_data_to_send(&self) -> bool {
        self.borrow_mut().has_data_to_send()
    }

    fn stream_writable(&self) {}

    fn done(&self) -> bool {
        self.borrow_mut().done()
    }

    fn close(&mut self, conn: &mut Connection) -> Res<()> {
        self.borrow_mut().close_session(conn, 0, "")
    }

    fn close_with_message(&mut self, conn: &mut Connection, error: u32, message: &str) -> Res<()> {
        self.borrow_mut().close_session(conn, error, message)
    }

    fn handle_stop_sending(&mut self, close_type: CloseType) {
        self.borrow_mut().close(close_type);
    }
}

#[derive(Debug, Default)]
struct WebTransportSessionListener {
    headers: Option<(Vec<Header>, bool, bool)>,
}

impl WebTransportSessionListener {
    fn set_headers(&mut self, headers: Vec<Header>, interim: bool, fin: bool) {
        self.headers = Some((headers, interim, fin));
    }

    pub fn get_headers(&mut self) -> Option<(Vec<Header>, bool, bool)> {
        mem::take(&mut self.headers)
    }
}

impl RecvStreamEvents for Rc<RefCell<WebTransportSessionListener>> {}

impl HttpRecvStreamEvents for Rc<RefCell<WebTransportSessionListener>> {
    fn header_ready(
        &self,
        _stream_info: &Http3StreamInfo,
        headers: Vec<Header>,
        interim: bool,
        fin: bool,
    ) {
        if !interim || fin {
            self.borrow_mut().set_headers(headers, interim, fin);
        }
    }
}

impl SendStreamEvents for Rc<RefCell<WebTransportSessionListener>> {}
