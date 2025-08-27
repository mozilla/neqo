// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub(crate) mod connect_udp_session;
pub(crate) mod webtransport_session;
pub(crate) mod webtransport_streams;

use std::{
    cell::RefCell,
    collections::HashSet,
    fmt::{self, Debug, Display, Formatter},
    mem,
    rc::Rc,
};

use neqo_common::{qdebug, qtrace, Encoder, Header, MessageType, Role};
use neqo_transport::{AppError, Connection, DatagramTracking, StreamId};
pub(crate) use webtransport_session::WebTransportSession;

use crate::{
    client_events::Http3ClientEvents,
    features::{extended_connect::connect_udp_session::ConnectUdpSession, NegotiationState},
    frames::HFrame,
    priority::PriorityHandler,
    recv_message::{RecvMessage, RecvMessageInfo},
    send_message::SendMessage,
    settings::{HSettingType, HSettings},
    CloseType, Error, Http3StreamInfo, Http3StreamType, HttpRecvStream, HttpRecvStreamEvents,
    Priority, ReceiveOutput, RecvStream, RecvStreamEvents, Res, SendStream, SendStreamEvents,
    Stream,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SessionCloseReason {
    Error(AppError),
    Status(u16),
    Clean { error: u32, message: String },
}

impl From<CloseType> for SessionCloseReason {
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

pub(crate) trait ExtendedConnectEvents: Debug {
    fn session_start(
        &self,
        connect_type: ExtendedConnectType,
        stream_id: StreamId,
        status: u16,
        headers: Vec<Header>,
    );
    fn session_end(
        &self,
        connect_type: ExtendedConnectType,
        stream_id: StreamId,
        reason: SessionCloseReason,
        headers: Option<Vec<Header>>,
    );
    fn extended_connect_new_stream(&self, stream_info: Http3StreamInfo) -> Res<()>;
    fn new_datagram(
        &self,
        session_id: StreamId,
        datagram: Vec<u8>,
        connect_type: ExtendedConnectType,
    );
}

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
pub(crate) enum ExtendedConnectType {
    WebTransport,
    ConnectUdp,
}

impl ExtendedConnectType {
    #[must_use]
    pub const fn string(self) -> &'static str {
        match self {
            Self::WebTransport => "webtransport",
            Self::ConnectUdp => "connect-udp",
        }
    }

    #[must_use]
    pub const fn get_stream_type(self, session_id: StreamId) -> Http3StreamType {
        match self {
            Self::WebTransport => Http3StreamType::WebTransport(session_id),
            Self::ConnectUdp => Http3StreamType::ConnectUdp(session_id),
        }
    }

    pub(crate) fn new_protocol(&self, session_id: StreamId, role: Role) -> Box<dyn Protocol> {
        match self {
            Self::WebTransport => Box::new(WebTransportSession::new(session_id, role)),
            Self::ConnectUdp => Box::new(ConnectUdpSession::new(session_id)),
        }
    }
}

impl From<ExtendedConnectType> for HSettingType {
    fn from(from: ExtendedConnectType) -> Self {
        match from {
            ExtendedConnectType::WebTransport => Self::EnableWebTransport,
            ExtendedConnectType::ConnectUdp => Self::EnableConnect,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExtendedConnectFeature {
    feature_negotiation: NegotiationState,
}

impl ExtendedConnectFeature {
    #[must_use]
    pub fn new(connect_type: ExtendedConnectType, enable: bool) -> Self {
        Self {
            feature_negotiation: NegotiationState::new(enable, HSettingType::from(connect_type)),
        }
    }

    pub fn set_listener(&mut self, new_listener: Http3ClientEvents) {
        self.feature_negotiation.set_listener(new_listener);
    }

    pub fn handle_settings(&mut self, settings: &HSettings) {
        self.feature_negotiation.handle_settings(settings);
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.feature_negotiation.enabled()
    }
}

// TODO: Should this move to its own file?
#[derive(Debug)]
pub(crate) struct Session {
    control_stream_recv: Box<dyn RecvStream>,
    control_stream_send: Box<dyn SendStream>,
    stream_event_listener: Rc<RefCell<Listener>>,
    session_id: StreamId,
    state: SessionState,
    events: Box<dyn ExtendedConnectEvents>,
    // TODO: Is `protocol` the right term?
    protocol: Box<dyn Protocol>,
}

// TODO: Move
#[derive(Debug, PartialEq)]
pub(crate) enum SessionState {
    Negotiating,
    Active,
    FinPending,
    Done,
}

impl SessionState {
    pub(crate) const fn closing_state(&self) -> bool {
        matches!(self, Self::FinPending | Self::Done)
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO: update
        write!(f, "session={}", self.session_id)
    }
}

impl Session {
    #[must_use]
    pub fn new(
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
            session_id,
            state: SessionState::Negotiating,
            events,
            protocol,
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
            session_id,
            state: SessionState::Active,
            events,
            protocol,
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

    // TODO: Move to webtransport?
    fn maybe_update_priority(&mut self, priority: Priority) -> Res<bool> {
        self.control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .maybe_update_priority(priority)
    }

    // TODO: Move to webtransport?
    fn priority_update_frame(&mut self) -> Option<HFrame> {
        self.control_stream_recv
            .http_stream()?
            .priority_update_frame()
    }

    // TODO: Move to webtransport?
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

    fn close(&mut self, close_type: CloseType) {
        if self.state.closing_state() {
            return;
        }
        // TODO: update now that there are multiple extended connect types.
        qtrace!("ExtendedConnect close the session");
        self.state = SessionState::Done;
        if !close_type.locally_initiated() {
            self.events.session_end(
                self.protocol.connect_type(),
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
        if SessionState::Negotiating != self.state {
            return Ok(());
        }

        if let Some((headers, interim, fin)) = self.stream_event_listener.borrow_mut().get_headers()
        {
            qtrace!("ExtendedConnect response headers {headers:?}, fin={fin}");

            if interim {
                if fin {
                    self.events.session_end(
                        self.protocol.connect_type(),
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
                            self.protocol.connect_type(),
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
                            self.protocol.connect_type(),
                            self.session_id,
                            status,
                            headers,
                        );
                        SessionState::Active
                    }
                } else {
                    self.events.session_end(
                        self.protocol.connect_type(),
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
        if self.state == SessionState::Active {
            self.protocol.add_stream(stream_id, &mut self.events)?;
        }
        Ok(())
    }

    pub fn remove_recv_stream(&mut self, stream_id: StreamId) {
        self.protocol.remove_recv_stream(stream_id);
    }

    pub fn remove_send_stream(&mut self, stream_id: StreamId) {
        self.protocol.remove_send_stream(stream_id);
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    pub fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        self.protocol.take_sub_streams()
    }

    /// # Errors
    ///
    /// It may return an error if the frame is not correctly decoded.
    pub fn read_control_stream(&mut self, conn: &mut Connection) -> Res<()> {
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
    pub fn close_session(&mut self, conn: &mut Connection, error: u32, message: &str) -> Res<()> {
        qdebug!("[{self}]: close_session");
        self.state = SessionState::Done;

        if let Some(close_frame) = self.protocol.close_frame(error, message) {
            self.control_stream_send
                .send_data_atomic(conn, close_frame.as_ref())?;
        }

        self.control_stream_send.close(conn)?;
        self.state = if self.control_stream_send.done() {
            // TODO: In this case, don't we have to call
            // self.events.session_end? Or does the caller of close_session not
            // expect an event, as they already know it is now closed?
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
            self.protocol.write_datagram_prefix(&mut dgram_data);
            dgram_data.encode(buf);
            conn.send_datagram(dgram_data.into(), id)?;
        } else {
            debug_assert!(false);
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub fn datagram(&self, datagram: &[u8]) {
        if self.state == SessionState::Active {
            let datagram = self.protocol.read_datagram_prefix(datagram);
            self.events.new_datagram(
                self.session_id,
                datagram.to_vec(),
                self.protocol.connect_type(),
            );
        }
    }

    fn has_data_to_send(&self) -> bool {
        self.control_stream_send.has_data_to_send()
    }

    fn done(&self) -> bool {
        self.state == SessionState::Done
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

#[derive(Debug, Default)]
struct Listener {
    headers: Option<(Vec<Header>, bool, bool)>,
}

impl Listener {
    fn set_headers(&mut self, headers: Vec<Header>, interim: bool, fin: bool) {
        self.headers = Some((headers, interim, fin));
    }

    pub fn get_headers(&mut self) -> Option<(Vec<Header>, bool, bool)> {
        mem::take(&mut self.headers)
    }
}

impl RecvStreamEvents for Rc<RefCell<Listener>> {}

impl HttpRecvStreamEvents for Rc<RefCell<Listener>> {
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

impl SendStreamEvents for Rc<RefCell<Listener>> {}

trait Protocol: Debug + Display {
    fn connect_type(&self) -> ExtendedConnectType;

    fn close_frame(&self, error: u32, message: &str) -> Option<Vec<u8>>;

    fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
    ) -> Res<Option<SessionState>>;

    fn add_stream(
        &mut self,
        stream_id: StreamId,
        events: &mut Box<dyn ExtendedConnectEvents>,
    ) -> Res<()>;

    fn remove_recv_stream(&mut self, stream_id: StreamId);

    fn remove_send_stream(&mut self, stream_id: StreamId);

    fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>);

    fn write_datagram_prefix(&self, encoder: &mut Encoder);

    fn read_datagram_prefix<'a>(&self, datagram: &'a [u8]) -> &'a [u8];
}

#[cfg(test)]
mod tests;
