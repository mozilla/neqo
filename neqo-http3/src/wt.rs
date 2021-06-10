// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::Http3Connection;
use crate::priority::PriorityHandler;
use crate::recv_message::{MessageType, RecvMessage};
use crate::send_message::{SendMessage, SendMessageEvents};
use crate::wt_stream::{WebTransportRecvStream, WebTransportSendStream};
use crate::{
    AppError, Error, Header, Http3StreamType, HttpRecvStream, HttpSendStream, Priority,
    ReceiveOutput, RecvMessageEvents, RecvStream, Res, ResetType, SendStream, WtEvents,
    WtRecvStream, WtSendStream,
};
use neqo_common::qtrace;
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::{Connection, StreamId, StreamType};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

#[derive(Debug, Clone, Copy, PartialEq)]
enum WebTransportControllerState {
    Negotiating,
    Negotiated,
    NegotiationFailed,
    Disabled,
}

#[derive(Debug)]
pub struct WebTransportController {
    state: WebTransportControllerState,
}

impl ::std::fmt::Display for WebTransportController {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "WebTransport")
    }
}

impl WebTransportController {
    pub fn new(enable: bool) -> Self {
        if enable {
            Self {
                state: WebTransportControllerState::Negotiating,
            }
        } else {
            Self {
                state: WebTransportControllerState::Disabled,
            }
        }
    }

    pub fn set_negotiated(&mut self, negotiated: bool) {
        qtrace!([self], "set_negotiated {}", negotiated);
        if !self.locally_enabled() {
            return;
        }
        self.state = if negotiated {
            WebTransportControllerState::Negotiated
        } else {
            WebTransportControllerState::NegotiationFailed
        };
    }

    pub fn enabled(&self) -> bool {
        self.state == WebTransportControllerState::Negotiated
    }

    pub fn locally_enabled(&self) -> bool {
        self.state != WebTransportControllerState::Disabled
    }

    pub fn accept_stream(&self, stream_type: StreamType) -> Res<bool> {
        match (self.state, stream_type) {
            (WebTransportControllerState::Negotiating, _)
            | (WebTransportControllerState::NegotiationFailed, StreamType::UniDi)
            | (WebTransportControllerState::Disabled, StreamType::UniDi) => Ok(false),
            (WebTransportControllerState::Negotiated, _) => Ok(true),
            (WebTransportControllerState::NegotiationFailed, StreamType::BiDi)
            | (WebTransportControllerState::Disabled, StreamType::BiDi) => {
                Err(Error::HttpGeneralProtocol)
            }
        }
    }
}

#[derive(Debug)]
enum WebTransportHttpEventsListenerResult {
    Negotiating,
    Success,
    Error,
}

impl WebTransportHttpEventsListenerResult {
    fn success(&mut self) {
        *self = WebTransportHttpEventsListenerResult::Success;
    }

    fn error(&mut self) {
        *self = WebTransportHttpEventsListenerResult::Error;
    }

    fn result(&self) -> Option<bool> {
        match self {
            WebTransportHttpEventsListenerResult::Negotiating => None,
            WebTransportHttpEventsListenerResult::Success => Some(true),
            WebTransportHttpEventsListenerResult::Error => Some(false),
        }
    }
}

#[derive(Debug)]
struct WebTransportHttpEventsListener {
    state: Rc<RefCell<WebTransportHttpEventsListenerResult>>,
}

impl WebTransportHttpEventsListener {
    fn new(state: Rc<RefCell<WebTransportHttpEventsListenerResult>>) -> Self {
        Self { state }
    }
}

impl RecvMessageEvents for WebTransportHttpEventsListener {
    /// Add a new `HeaderReady` event.
    fn header_ready(&self, _stream_id: u64, headers: Vec<Header>, _interim: bool, _fin: bool) {
        qtrace!("WebTransport Headers {:?}", headers);
        if headers
            .iter()
            .find_map(|h| {
                if h.name() == ":status" && h.value() == "200" {
                    Some(())
                } else {
                    None
                }
            })
            .is_some()
        {
            self.state.borrow_mut().success();
        } else {
            self.state.borrow_mut().error();
        }
    }

    fn data_readable(&self, _stream_id: u64) {
        self.state.borrow_mut().error();
    }

    fn reset(&self, _stream_id: u64, _error: AppError, _local: bool) {
        self.state.borrow_mut().error();
    }

    fn web_transport_new_session(&self, _stream_id: u64, _headers: Vec<Header>) {}
}

impl SendMessageEvents for WebTransportHttpEventsListener {
    /// Add a new `DataWritable` event.
    fn data_writable(&self, _stream_id: u64) {}

    fn remove_send_side_event(&self, _stream_id: u64) {}

    /// Add a new `StopSending` event
    fn stop_sending(&self, _stream_id: u64, _error: AppError) {
        self.state.borrow_mut().error();
    }
}

#[derive(Debug)]
enum WebTransportSessionState {
    Negotiating {
        send_stream: SendMessage,
        recv_stream: RecvMessage,
        listener: Rc<RefCell<WebTransportHttpEventsListenerResult>>,
    },
    // Server only
    SendingResponse {
        send_stream: Box<dyn SendStream>,
    },
    Active,
    Done,
}

#[derive(Debug)]
pub struct WebTransportSession {
    state: WebTransportSessionState,
    stream_id: u64,
    active_streams: BTreeSet<u64>,
    events: Box<dyn WtEvents>,
}

impl ::std::fmt::Display for WebTransportSession {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "WebTransportSesssion id={}", self.stream_id)
    }
}

impl WebTransportSession {
    pub fn new(
        stream_id: u64,
        headers: Vec<Header>,
        qpack_encoder: Rc<RefCell<QPackEncoder>>,
        qpack_decoder: Rc<RefCell<QPackDecoder>>,
        events: Box<dyn WtEvents>,
    ) -> Self {
        let listener = Rc::new(RefCell::new(
            WebTransportHttpEventsListenerResult::Negotiating,
        ));
        Self {
            state: WebTransportSessionState::Negotiating {
                send_stream: SendMessage::new_with_headers(
                    stream_id,
                    headers,
                    qpack_encoder,
                    Box::new(WebTransportHttpEventsListener::new(listener.clone())),
                ),
                recv_stream: RecvMessage::new(
                    MessageType::Response,
                    stream_id,
                    qpack_decoder,
                    Box::new(WebTransportHttpEventsListener::new(listener.clone())),
                    None,
                    PriorityHandler::new(true, Priority::default()),
                    false,
                ),
                listener,
            },
            stream_id,
            active_streams: BTreeSet::new(),
            events,
        }
    }

    pub fn new_server_side(
        stream_id: u64,
        send_stream: Box<dyn SendStream>,
        events: Box<dyn WtEvents>,
    ) -> Self {
        Self {
            state: WebTransportSessionState::SendingResponse { send_stream },
            stream_id,
            active_streams: BTreeSet::new(),
            events,
        }
    }

    pub(crate) fn create_session(
        host: &str,
        path: &str,
        origin: &str,
        conn: &mut Connection,
        handler: &mut Http3Connection,
        events: Box<dyn WtEvents>,
    ) -> Res<u64> {
        let id = conn
            .stream_create(StreamType::BiDi)
            .map_err(|e| Error::map_stream_create_errors(&e))?;

        // Transform pseudo-header fields
        let final_headers = vec![
            Header::new(":method", "CONNECT"),
            Header::new(":scheme", "https"),
            Header::new(":authority", host),
            Header::new(":path", path),
            Header::new(":protocol", "webtransport"),
            Header::new("origin", origin),
        ];

        let session = Rc::new(RefCell::new(WebTransportSession::new(
            id,
            final_headers,
            handler.qpack_encoder.clone(),
            handler.qpack_decoder.clone(),
            events,
        )));

        qtrace!("Created: {:?}", session.borrow());

        handler.add_streams(
            id,
            Box::new(WebTransportSessionSender::new(session.clone())),
            Box::new(WebTransportSessionReceiver::new(session)),
        );
        Ok(id)
    }

    pub(crate) fn create_session_server(
        stream_id: u64,
        send_stream: Box<dyn SendStream>,
        events: Box<dyn WtEvents>,
        handler: &mut Http3Connection,
    ) {
        let session = Rc::new(RefCell::new(WebTransportSession::new_server_side(
            stream_id,
            send_stream,
            events,
        )));
        handler.add_streams(
            stream_id,
            Box::new(WebTransportSessionSender::new(session.clone())),
            Box::new(WebTransportSessionReceiver::new(session)),
        );
    }

    pub fn create_new_stream_local(
        session: Rc<RefCell<WebTransportSession>>,
        stream_type: StreamType,
        conn: &mut Connection,
    ) -> Res<(u64, Box<dyn SendStream>, Option<Box<dyn RecvStream>>)> {
        let stream_id = conn
            .stream_create(stream_type)
            .map_err(|e| Error::map_stream_create_errors(&e))?;
        session.borrow_mut().add_stream(stream_id);
        Ok((
            stream_id,
            Box::new(WebTransportSendStream::new(
                stream_id,
                session.clone(),
                session.borrow().events(),
                true,
            )),
            if StreamId::new(stream_id).is_bidi() {
                Some(Box::new(WebTransportRecvStream::new(
                    stream_id,
                    session.clone(),
                    session.borrow().events(),
                )))
            } else {
                None
            },
        ))
    }

    pub fn create_new_stream_remote(
        session: Rc<RefCell<WebTransportSession>>,
        stream_id: u64,
    ) -> (Box<dyn RecvStream>, Option<Box<dyn SendStream>>) {
        session
            .borrow_mut()
            .events
            .web_transport_new_stream(stream_id);
        session
            .borrow_mut()
            .events
            .web_transport_data_readable(stream_id);
        session.borrow_mut().add_stream(stream_id);
        (
            Box::new(WebTransportRecvStream::new(
                stream_id,
                session.clone(),
                session.borrow().events(),
            )),
            if StreamId::new(stream_id).is_bidi() {
                Some(Box::new(WebTransportSendStream::new(
                    stream_id,
                    session.clone(),
                    session.borrow().events(),
                    false,
                )))
            } else {
                None
            },
        )
    }

    fn events(&self) -> Box<dyn WtEvents> {
        self.events.clone_box()
    }

    pub fn add_stream(&mut self, stream_id: u64) {
        self.active_streams.insert(stream_id);
    }

    pub fn remove_stream(&mut self, stream_id: u64) {
        self.active_streams.remove(&stream_id);
    }

    fn stream_reset(&mut self) -> Res<()> {
        // Close all streams
        Ok(())
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<()> {
        match &mut self.state {
            WebTransportSessionState::Negotiating {
                recv_stream,
                listener,
                ..
            } => {
                recv_stream.receive(conn)?;
                let result = listener.borrow().result();
                if let Some(r) = result {
                    self.events
                        .web_transport_session_negotiated(self.stream_id, r);
                    self.state = if r {
                        WebTransportSessionState::Active
                    } else {
                        WebTransportSessionState::Done
                    };
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn done(&self) -> bool {
        matches!(self.state, WebTransportSessionState::Done)
    }

    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        match &mut self.state {
            WebTransportSessionState::Negotiating { send_stream, .. } => send_stream.send(conn),
            WebTransportSessionState::SendingResponse { send_stream } => {
                send_stream.send(conn)?;
                if !send_stream.has_data_to_send() {
                    self.state = WebTransportSessionState::Active;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn has_data_to_send(&self) -> bool {
        match &self.state {
            WebTransportSessionState::Negotiating { send_stream, .. } => {
                send_stream.has_data_to_send()
            }
            WebTransportSessionState::SendingResponse { send_stream } => {
                send_stream.has_data_to_send()
            }
            _ => false,
        }
    }

    fn close(&self) {}

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

#[derive(Debug)]
struct WebTransportSessionReceiver {
    session: Rc<RefCell<WebTransportSession>>,
    priority_handler: PriorityHandler,
}

impl WebTransportSessionReceiver {
    fn new(session: Rc<RefCell<WebTransportSession>>) -> Self {
        Self {
            session,
            priority_handler: PriorityHandler::new(false, Priority::default()),
        }
    }
}

impl RecvStream for WebTransportSessionReceiver {
    fn stream_reset(&mut self, _error: AppError, _reset_type: ResetType) -> Res<()> {
        self.session.borrow_mut().stream_reset()
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<ReceiveOutput> {
        self.session.borrow_mut().receive(conn)?;
        Ok(ReceiveOutput::NoOutput)
    }

    fn done(&self) -> bool {
        self.session.borrow_mut().done()
    }

    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::WebTransportSession
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        Some(self)
    }

    fn wt_stream(&mut self) -> Option<&mut dyn WtRecvStream> {
        None
    }
}

impl HttpRecvStream for WebTransportSessionReceiver {
    fn read_data(&mut self, _conn: &mut Connection, _buf: &mut [u8]) -> Res<(usize, bool)> {
        Err(Error::HttpInternal(10))
    }

    fn header_unblocked(&mut self, conn: &mut Connection) -> Res<()> {
        self.session.borrow_mut().receive(conn)
    }

    fn priority_handler_mut(&mut self) -> &mut PriorityHandler {
        &mut self.priority_handler
    }
}

#[derive(Debug)]
struct WebTransportSessionSender {
    session: Rc<RefCell<WebTransportSession>>,
}

impl WebTransportSessionSender {
    fn new(session: Rc<RefCell<WebTransportSession>>) -> Self {
        Self { session }
    }
}

impl SendStream for WebTransportSessionSender {
    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        self.session.borrow_mut().send(conn)
    }

    fn has_data_to_send(&self) -> bool {
        self.session.borrow_mut().has_data_to_send()
    }

    fn stream_writable(&self) {}

    fn done(&self) -> bool {
        self.session.borrow_mut().done()
    }

    fn stop_sending(&mut self, _error: AppError) {
        let _ = self.session.borrow_mut().stream_reset();
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpSendStream> {
        Some(self)
    }

    fn get_wt_session(&self) -> Option<Rc<RefCell<WebTransportSession>>> {
        Some(self.session.clone())
    }

    fn wt_stream(&mut self) -> Option<&mut dyn WtSendStream> {
        None
    }
}

impl HttpSendStream for WebTransportSessionSender {
    fn close(&mut self, _conn: &mut Connection) -> Res<()> {
        self.session.borrow_mut().close();
        Ok(())
    }

    fn set_message(&mut self, _headers: &[Header], _data: Option<&[u8]>) -> Res<()> {
        Err(Error::HttpInternal(12))
    }

    fn send_body(&mut self, _conn: &mut Connection, _buf: &[u8]) -> Res<usize> {
        Err(Error::HttpInternal(13))
    }
}
