// TODO: Rename to connect_udp_session.rs to be consistent with webtransport_session.rs?
use std::{
    cell::RefCell,
    fmt::{self, Display, Formatter},
    mem,
    rc::Rc,
};

use neqo_common::{qdebug, Encoder, Header, MessageType, Role};
use neqo_qpack as qpack;
use neqo_transport::{Connection, DatagramTracking, StreamId};

use crate::{
    features::extended_connect::{ExtendedConnectEvents, ExtendedConnectType, SessionCloseReason},
    priority::PriorityHandler,
    recv_message::{RecvMessage, RecvMessageInfo},
    send_message::SendMessage,
    CloseType, Error, Http3StreamInfo, Http3StreamType, HttpRecvStream, HttpRecvStreamEvents,
    Priority, ReceiveOutput, RecvStream, RecvStreamEvents, Res, SendStream, SendStreamEvents,
    Stream,
};

// TODO: De-duplicate with webtransport_session.rs?
#[derive(Debug, PartialEq)]
enum SessionState {
    Negotiating,
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
pub struct ConnectUdpSession {
    control_stream_recv: Box<dyn RecvStream>,
    control_stream_send: Box<dyn SendStream>,
    stream_event_listener: Rc<RefCell<ConnectUdpSessionListener>>,
    session_id: StreamId,
    state: SessionState,
    events: Box<dyn ExtendedConnectEvents>,
    role: Role,
}

impl Display for ConnectUdpSession {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "ConnectUdpSession={},role={}",
            self.session_id, self.role
        )
    }
}

impl ConnectUdpSession {
    #[must_use]
    pub fn new(
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
        qpack_encoder: Rc<RefCell<qpack::Encoder>>,
        qpack_decoder: Rc<RefCell<qpack::Decoder>>,
    ) -> Self {
        let stream_event_listener = Rc::new(RefCell::new(ConnectUdpSessionListener::default()));
        let session = Self {
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
            role,
        };
        qdebug!("[{session}]: new");
        session
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
        let stream_event_listener = Rc::new(RefCell::new(ConnectUdpSessionListener::default()));
        control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .set_new_listener(Box::new(Rc::clone(&stream_event_listener)));
        control_stream_send
            .http_stream()
            .ok_or(Error::Internal)?
            .set_new_listener(Box::new(Rc::clone(&stream_event_listener)));
        let session = Self {
            control_stream_recv,
            control_stream_send,
            stream_event_listener,
            session_id,
            state: SessionState::Active,
            events,
            role,
        };
        qdebug!("[{session}]: new with http stream");
        Ok(session)
    }

    /// # Errors
    ///
    /// Return an error if the stream was closed on the transport layer, but that information is not
    /// yet consumed on the http/3 layer.
    pub fn close_session(&mut self, conn: &mut Connection, error: u32, message: &str) -> Res<()> {
        qdebug!("[{self}]: close_session");
        // TODO: WebTransport sends a message. needed here as well?
        self.control_stream_send.close(conn)?;
        self.state = if self.control_stream_send.done() {
            SessionState::Done
        } else {
            SessionState::FinPending
        };

        // TODO: WebTransport only does this on fin.
        self.events.session_end(
            ExtendedConnectType::ConnectUdp,
            self.session_id,
            SessionCloseReason::Clean {
                error,
                message: message.to_string(),
            },
            None,
        );

        Ok(())
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
        qdebug!("[{self}]: send_datagram len={}", buf.len());
        if self.state == SessionState::Active {
            let mut dgram_data = Encoder::default();
            dgram_data.encode_varint(self.session_id.as_u64() / 4);
            dgram_data.encode_varint(0u64);
            dgram_data.encode(buf);
            conn.send_datagram(dgram_data.into(), id)?;
        } else {
            debug_assert!(false);
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    // TODO: De-duplicate with webtransport_session.rs?
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
        qdebug!("[{self}]: receive");
        let (out, _) = self.control_stream_recv.receive(conn)?;
        debug_assert!(out == ReceiveOutput::NoOutput);
        self.maybe_check_headers()?;
        self.read_control_stream(conn)?;
        Ok((ReceiveOutput::NoOutput, self.state == SessionState::Done))
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
            qdebug!("[{self}]: ExtendedConnect response headers {headers:?}, fin={fin}");

            if interim {
                if fin {
                    self.events.session_end(
                        ExtendedConnectType::ConnectUdp,
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
                            ExtendedConnectType::ConnectUdp,
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
                            ExtendedConnectType::ConnectUdp,
                            self.session_id,
                            status,
                            headers,
                        );
                        SessionState::Active
                    }
                } else {
                    self.events.session_end(
                        ExtendedConnectType::ConnectUdp,
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

    fn has_data_to_send(&self) -> bool {
        self.control_stream_send.has_data_to_send()
    }

    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        self.control_stream_send.send(conn)?;
        if self.control_stream_send.done() {
            self.state = SessionState::Done;
        }
        Ok(())
    }

    fn done(&self) -> bool {
        self.state == SessionState::Done
    }

    fn close(&mut self, close_type: CloseType) {
        if self.state.closing_state() {
            return;
        }
        // TODO: update now that there are multiple extended connect types.
        qdebug!("[{self}]: close");
        self.state = SessionState::Done;
        if !close_type.locally_initiated() {
            self.events.session_end(
                ExtendedConnectType::ConnectUdp,
                self.session_id,
                SessionCloseReason::from(close_type),
                None,
            );
        }
    }

    pub fn datagram(&self, datagram: Vec<u8>) {
        qdebug!("[{self}]: new datagram");
        if self.state == SessionState::Active {
            self.events
                .new_datagram(self.session_id, datagram, ExtendedConnectType::ConnectUdp);
        } else {
            panic!();
        }
    }

    /// # Errors
    ///
    /// It may return an error if the frame is not correctly decoded.
    pub fn read_control_stream(&mut self, conn: &mut Connection) -> Res<()> {
        qdebug!("[{self}]: read_control_stream");
        // TODO
        let mut buf = [0; 1500];
        let (_, fin) = self.control_stream_recv.read_data(conn, buf.as_mut())?;
        if fin {
            self.events.session_end(
                ExtendedConnectType::ConnectUdp,
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
}

impl Stream for Rc<RefCell<ConnectUdpSession>> {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::ExtendedConnect
    }
}

impl RecvStream for Rc<RefCell<ConnectUdpSession>> {
    fn receive(&mut self, conn: &mut Connection) -> Res<(ReceiveOutput, bool)> {
        self.borrow_mut().receive(conn)
    }

    fn reset(&mut self, _close_type: CloseType) -> Res<()> {
        todo!()
    }

    fn connect_udp(&self) -> Option<Rc<RefCell<ConnectUdpSession>>> {
        Some(Self::clone(self))
    }
}

impl HttpRecvStream for Rc<RefCell<ConnectUdpSession>> {
    fn header_unblocked(&mut self, _conn: &mut Connection) -> Res<(ReceiveOutput, bool)> {
        todo!()
    }

    fn maybe_update_priority(&mut self, _priority: Priority) -> Res<bool> {
        todo!()
    }

    fn priority_update_frame(&mut self) -> Option<crate::frames::HFrame> {
        todo!()
    }

    fn priority_update_sent(&mut self) -> Res<()> {
        todo!()
    }
}

impl SendStream for Rc<RefCell<ConnectUdpSession>> {
    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        self.borrow_mut().send(conn)
    }

    fn has_data_to_send(&self) -> bool {
        self.borrow_mut().has_data_to_send()
    }

    fn stream_writable(&self) {}

    fn done(&self) -> bool {
        self.borrow_mut().done()
    }

    fn send_data(&mut self, _conn: &mut Connection, _buf: &[u8]) -> Res<usize> {
        todo!()
    }

    fn close(&mut self, _conn: &mut Connection) -> Res<()> {
        todo!()
    }

    fn handle_stop_sending(&mut self, close_type: CloseType) {
        self.borrow_mut().close(close_type);
    }

    fn close_with_message(&mut self, conn: &mut Connection, error: u32, message: &str) -> Res<()> {
        self.borrow_mut().close_session(conn, error, message)
    }
}

#[derive(Debug, Default)]
struct ConnectUdpSessionListener {
    headers: Option<(Vec<Header>, bool, bool)>,
}

impl ConnectUdpSessionListener {
    fn set_headers(&mut self, headers: Vec<Header>, interim: bool, fin: bool) {
        self.headers = Some((headers, interim, fin));
    }

    pub fn get_headers(&mut self) -> Option<(Vec<Header>, bool, bool)> {
        mem::take(&mut self.headers)
    }
}

impl RecvStreamEvents for Rc<RefCell<ConnectUdpSessionListener>> {}

impl HttpRecvStreamEvents for Rc<RefCell<ConnectUdpSessionListener>> {
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

impl SendStreamEvents for Rc<RefCell<ConnectUdpSessionListener>> {}
