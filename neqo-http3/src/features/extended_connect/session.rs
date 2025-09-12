// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    collections::HashSet,
    fmt::{self, Debug, Display, Formatter},
    rc::Rc,
};

use neqo_common::{qdebug, qtrace, Encoder, Header, MessageType, Role};
use neqo_transport::{AppError, Connection, DatagramTracking, StreamId};

use crate::{
    features::extended_connect::{ExtendedConnectEvents, ExtendedConnectType, Listener},
    frames::HFrame,
    priority::PriorityHandler,
    recv_message::{RecvMessage, RecvMessageInfo},
    send_message::SendMessage,
    CloseType, Error, Http3StreamType, HttpRecvStream, Priority, ReceiveOutput, RecvStream, Res,
    SendStream, Stream,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CloseReason {
    Error(AppError),
    Status(u16),
    Clean { error: u32, message: String },
}

impl From<CloseType> for CloseReason {
    fn from(close_type: CloseType) -> Self {
        match close_type {
            CloseType::ResetApp(e) | CloseType::ResetRemote(e) | CloseType::LocalError(e) => {
                Self::Error(e)
            }
            CloseType::Done => Self::Clean {
                error: 0,
                message: String::new(),
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct Session {
    control_stream_recv: Box<dyn RecvStream>,
    control_stream_send: Box<dyn SendStream>,
    stream_event_listener: Rc<RefCell<Listener>>,
    id: StreamId,
    state: State,
    events: Box<dyn ExtendedConnectEvents>,
    /// Corresponds to the `:protocol` pseudo-header in the HTTP EXTENDED
    /// CONNECT request.
    protocol: Box<dyn Protocol>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum State {
    Negotiating,
    Active,
    FinPending,
    Done,
}

impl State {
    pub(crate) const fn closing_state(self) -> bool {
        matches!(self, Self::FinPending | Self::Done)
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}-session={}", self.protocol.connect_type(), self.id)
    }
}

impl Session {
    #[must_use]
    pub(crate) fn new(
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
        qpack_encoder: Rc<RefCell<neqo_qpack::Encoder>>,
        qpack_decoder: Rc<RefCell<neqo_qpack::Decoder>>,
        connect_type: ExtendedConnectType,
    ) -> Self {
        let stream_event_listener = Rc::new(RefCell::new(Listener::default()));
        let protocol = connect_type.new_protocol(session_id, role);
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
            id: session_id,
            state: State::Negotiating,
            events,
            protocol,
        }
    }

    pub(crate) fn new_with_http_streams(
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
        mut control_stream_recv: Box<dyn RecvStream>,
        mut control_stream_send: Box<dyn SendStream>,
        connect_type: ExtendedConnectType,
    ) -> Res<Self> {
        let stream_event_listener = Rc::new(RefCell::new(Listener::default()));
        let protocol = connect_type.new_protocol(session_id, role);
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
            id: session_id,
            state: State::Active,
            events,
            protocol,
        })
    }

    /// # Errors
    ///
    /// The function can only fail if supplied headers are not valid http headers.
    pub(crate) fn send_request(&mut self, headers: &[Header], conn: &mut Connection) -> Res<()> {
        qdebug!("[{self}]: send_request {headers:?}");
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
        Ok((ReceiveOutput::NoOutput, self.state == State::Done))
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
        Ok((ReceiveOutput::NoOutput, self.state == State::Done))
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
            self.state = State::Done;
        }
        Ok(())
    }

    fn close(&mut self, close_type: CloseType) {
        if self.state.closing_state() {
            return;
        }
        qdebug!("[{self}]: close session type={close_type:?}");
        self.state = State::Done;
        if !close_type.locally_initiated() {
            self.events.session_end(
                self.protocol.connect_type(),
                self.id,
                CloseReason::from(close_type),
                None,
            );
        }
    }

    pub(crate) fn maybe_check_headers(&mut self) -> Res<()> {
        if self.state != State::Negotiating {
            return Ok(());
        }

        if let Some((headers, interim, fin)) = self.stream_event_listener.borrow_mut().get_headers()
        {
            qtrace!("ExtendedConnect response headers {headers:?}, fin={fin}");

            if interim {
                if fin {
                    self.events.session_end(
                        self.protocol.connect_type(),
                        self.id,
                        CloseReason::Clean {
                            error: 0,
                            message: String::new(),
                        },
                        Some(headers),
                    );
                    self.state = State::Done;
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
                            self.protocol.connect_type(),
                            self.id,
                            CloseReason::Clean {
                                error: 0,
                                message: String::new(),
                            },
                            Some(headers),
                        );
                        State::Done
                    } else {
                        self.events.session_start(
                            self.protocol.connect_type(),
                            self.id,
                            status,
                            headers,
                        );
                        self.protocol.session_start(&mut self.events)?;
                        State::Active
                    }
                } else {
                    self.events.session_end(
                        self.protocol.connect_type(),
                        self.id,
                        CloseReason::Status(status),
                        Some(headers),
                    );
                    State::Done
                };
            }
        }
        Ok(())
    }

    pub(crate) fn add_stream(&mut self, stream_id: StreamId) -> Res<()> {
        self.protocol
            .add_stream(stream_id, &mut self.events, self.state)
    }

    pub(crate) fn remove_recv_stream(&mut self, stream_id: StreamId) {
        self.protocol.remove_recv_stream(stream_id);
    }

    pub(crate) fn remove_send_stream(&mut self, stream_id: StreamId) {
        self.protocol.remove_send_stream(stream_id);
    }

    #[must_use]
    pub(crate) const fn is_active(&self) -> bool {
        matches!(self.state, State::Active)
    }

    pub(crate) fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        self.protocol.take_sub_streams()
    }

    /// # Errors
    ///
    /// It may return an error if the frame is not correctly decoded.
    pub(crate) fn read_control_stream(&mut self, conn: &mut Connection) -> Res<()> {
        qdebug!("[{self}]: read_control_stream");
        if let Some(new_state) = self.protocol.read_control_stream(
            conn,
            &mut self.events,
            &mut self.control_stream_recv,
        )? {
            self.state = new_state;
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Return an error if the stream was closed on the transport layer, but that information is not
    /// yet consumed on the http/3 layer.
    pub(crate) fn close_session(
        &mut self,
        conn: &mut Connection,
        error: u32,
        message: &str,
    ) -> Res<()> {
        qdebug!("[{self}]: close_session");
        self.state = State::Done;

        if let Some(close_frame) = self.protocol.close_frame(error, message) {
            self.control_stream_send
                .send_data_atomic(conn, close_frame.as_ref())?;
        }

        self.control_stream_send.close(conn)?;
        self.state = if self.control_stream_send.done() {
            State::Done
        } else {
            State::FinPending
        };
        Ok(())
    }

    fn send_data(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        self.control_stream_send.send_data(conn, buf)
    }

    /// # Errors
    ///
    /// Returns an error if the datagram exceeds the remote datagram size limit.
    pub(crate) fn send_datagram<I: Into<DatagramTracking>>(
        &self,
        conn: &mut Connection,
        buf: &[u8],
        id: I,
    ) -> Res<()> {
        qtrace!("[{self}] send_datagram state={:?}", self.state);
        if self.state == State::Active {
            let mut dgram_data = Encoder::default();
            dgram_data.encode_varint(self.id.as_u64() / 4);
            self.protocol.write_datagram_prefix(&mut dgram_data);
            dgram_data.encode(buf);
            conn.send_datagram(dgram_data.into(), id)?;
        } else {
            qdebug!("[{self}]: cannot send datagram in {:?} state.", self.state);
            debug_assert!(false);
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn datagram(&self, datagram: &[u8]) {
        if self.state != State::Active {
            qdebug!("[{self}]: received datagram on {:?} session.", self.state);
            return;
        }
        let datagram = match self.protocol.dgram_context_id(datagram) {
            Ok(datagram) => datagram,
            Err(e) => {
                qdebug!("[{self}]: received datagram with invalid context identifier: {e}");
                return;
            }
        };
        self.events
            .new_datagram(self.id, datagram.to_vec(), self.protocol.connect_type());
    }

    fn has_data_to_send(&self) -> bool {
        self.control_stream_send.has_data_to_send()
    }

    fn done(&self) -> bool {
        self.state == State::Done
    }
}

impl Stream for Rc<RefCell<Session>> {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::ExtendedConnect
    }
}

impl RecvStream for Rc<RefCell<Session>> {
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

    fn extended_connect_session(&self) -> Option<Rc<RefCell<Session>>> {
        Some(Self::clone(self))
    }
}

impl HttpRecvStream for Rc<RefCell<Session>> {
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

impl SendStream for Rc<RefCell<Session>> {
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

/// An extended connect protocol.
///
/// "Protocol" here corresponds to the `:protocol` pseudo header in the HTTP
/// Extended CONNECT method.
pub(crate) trait Protocol: Debug + Display {
    fn connect_type(&self) -> ExtendedConnectType;

    fn session_start(&mut self, _events: &mut Box<dyn ExtendedConnectEvents>) -> Res<()> {
        Ok(())
    }

    fn close_frame(&self, _error: u32, _message: &str) -> Option<Vec<u8>> {
        None
    }

    fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
    ) -> Res<Option<State>>;

    fn add_stream(
        &mut self,
        _stream_id: StreamId,
        _events: &mut Box<dyn ExtendedConnectEvents>,
        _state: State,
    ) -> Res<()> {
        let msg = "Protocol does not support adding streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
        Ok(())
    }

    fn remove_recv_stream(&mut self, _stream_id: StreamId) {
        let msg = "Protocol does not support removing recv streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
    }

    fn remove_send_stream(&mut self, _stream_id: StreamId) {
        let msg = "Protocol does not support removing send streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
    }

    fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        (HashSet::default(), HashSet::default())
    }

    fn write_datagram_prefix(&self, encoder: &mut Encoder);

    fn dgram_context_id<'a>(&self, datagram: &'a [u8]) -> Result<&'a [u8], DgramContextIdError>;
}

#[derive(Debug, Error)]
pub(crate) enum DgramContextIdError {
    #[error("Missing context identifier")]
    MissingIdentifier,
    #[error("Unknown context identifier: {0}")]
    UnknownIdentifier(u8),
}
