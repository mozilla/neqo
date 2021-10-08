// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use crate::connection::Http3State;
use crate::connection_server::Http3ServerHandler;
use crate::{Headers, Priority, Res};
use neqo_common::{qdebug, qinfo, Header};
use neqo_transport::server::ActiveConnectionRef;
use neqo_transport::{AppError, Connection, StreamId};

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct StreamHandler {
    conn: ActiveConnectionRef,
    handler: Rc<RefCell<Http3ServerHandler>>,
    stream_id: StreamId,
}

impl ::std::fmt::Display for StreamHandler {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        let conn: &Connection = &self.conn.borrow();
        write!(f, "conn={} stream_id={}", conn, self.stream_id)
    }
}

impl std::hash::Hash for StreamHandler {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.conn.hash(state);
        state.write_u64(self.stream_id.as_u64());
        state.finish();
    }
}

impl PartialEq for StreamHandler {
    fn eq(&self, other: &Self) -> bool {
        self.conn == other.conn && self.stream_id == other.stream_id
    }
}

impl Eq for StreamHandler {}

impl StreamHandler {
    /// Supply a response header to a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn send_headers(&mut self, headers: &[Header]) -> Res<()> {
        self.handler
            .borrow_mut()
            .send_headers(self.stream_id, headers, &mut self.conn.borrow_mut())
    }

    /// Supply response data to a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn send_data(&mut self, data: &[u8]) -> Res<()> {
        qinfo!([self], "Set new response.");
        self.handler
            .borrow_mut()
            .send_data(self.stream_id, data, &mut self.conn.borrow_mut())
    }

    /// Close sending side.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_close_send(&mut self) -> Res<()> {
        qinfo!([self], "Set new response.");
        self.handler
            .borrow_mut()
            .stream_close_send(self.stream_id, &mut self.conn.borrow_mut())
    }

    /// Request a peer to stop sending a stream.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_stop_sending(&mut self, app_error: AppError) -> Res<()> {
        qdebug!(
            [self],
            "stop sending stream_id:{} error:{}.",
            self.stream_id,
            app_error
        );
        self.handler.borrow_mut().stream_stop_sending(
            self.stream_id,
            app_error,
            &mut self.conn.borrow_mut(),
        )
    }

    /// Reset sending side of a stream.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_reset_send(&mut self, app_error: AppError) -> Res<()> {
        qdebug!(
            [self],
            "reset send stream_id:{} error:{}.",
            self.stream_id,
            app_error
        );
        self.handler.borrow_mut().stream_reset_send(
            self.stream_id,
            app_error,
            &mut self.conn.borrow_mut(),
        )
    }

    /// Reset a stream/request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore
    pub fn cancel_fetch(&mut self, app_error: AppError) -> Res<()> {
        qdebug!([self], "reset error:{}.", app_error);
        self.handler.borrow_mut().cancel_fetch(
            self.stream_id,
            app_error,
            &mut self.conn.borrow_mut(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct ClientRequestStream {
    stream_handler: StreamHandler,
}

impl ::std::fmt::Display for ClientRequestStream {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http3 server {:?}", self.stream_handler)
    }
}

impl ClientRequestStream {
    pub(crate) fn new(
        conn: ActiveConnectionRef,
        handler: Rc<RefCell<Http3ServerHandler>>,
        stream_id: StreamId,
    ) -> Self {
        Self {
            stream_handler: StreamHandler {
                conn,
                handler,
                stream_id,
            },
        }
    }

    /// Supply a response header to a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn send_headers(&mut self, headers: &[Header]) -> Res<()> {
        self.stream_handler.send_headers(headers)
    }

    /// Supply response data to a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn send_data(&mut self, data: &[u8]) -> Res<()> {
        qinfo!([self], "Set new response.");
        self.stream_handler.send_data(data)
    }

    /// Close sending side.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_close_send(&mut self) -> Res<()> {
        qinfo!([self], "Set new response.");
        self.stream_handler.stream_close_send()
    }

    /// Request a peer to stop sending a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_stop_sending(&mut self, app_error: AppError) -> Res<()> {
        self.stream_handler.stream_stop_sending(app_error)
    }

    /// Reset a stream/request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore
    pub fn cancel_fetch(&mut self, app_error: AppError) -> Res<()> {
        self.stream_handler.cancel_fetch(app_error)
    }
}

impl std::hash::Hash for ClientRequestStream {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stream_handler.hash(state);
        state.finish();
    }
}

impl PartialEq for ClientRequestStream {
    fn eq(&self, other: &Self) -> bool {
        self.stream_handler == other.stream_handler
    }
}

impl Eq for ClientRequestStream {}

#[derive(Debug, Clone)]
pub struct WebTransportRequest {
    stream_handler: StreamHandler,
}

impl ::std::fmt::Display for WebTransportRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "WebTransport session {}", self.stream_handler)
    }
}

impl WebTransportRequest {
    pub(crate) fn new(
        conn: ActiveConnectionRef,
        handler: Rc<RefCell<Http3ServerHandler>>,
        stream_id: StreamId,
    ) -> Self {
        Self {
            stream_handler: StreamHandler {
                conn,
                handler,
                stream_id,
            },
        }
    }

    /// Respond to a webTransport session request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn response(&mut self, accept: bool) -> Res<()> {
        qinfo!([self], "Set a respons for a WebTransport session.");
        self.stream_handler
            .handler
            .borrow_mut()
            .webtransport_session_response(
                &mut self.stream_handler.conn.borrow_mut(),
                self.stream_handler.stream_id,
                accept,
            )
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_handler.stream_id
    }

    /// Close sending side.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_close_send(&mut self) -> Res<()> {
        self.stream_handler.stream_close_send()
    }

    /// Request a peer to stop sending a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_stop_sending(&mut self, app_error: AppError) -> Res<()> {
        self.stream_handler.stream_stop_sending(app_error)
    }

    /// Reset sending side of a stream.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_reset_send(&mut self, app_error: AppError) -> Res<()> {
        self.stream_handler.stream_reset_send(app_error)
    }

    /// Reset a stream/request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore
    pub fn cancel_fetch(&mut self, app_error: AppError) -> Res<()> {
        self.stream_handler.cancel_fetch(app_error)
    }
}

impl std::hash::Hash for WebTransportRequest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stream_handler.hash(state);
        state.finish();
    }
}

impl PartialEq for WebTransportRequest {
    fn eq(&self, other: &Self) -> bool {
        self.stream_handler == other.stream_handler
    }
}

impl Eq for WebTransportRequest {}

#[derive(Debug, Clone)]
pub enum WebTransportServerEvent {
    WebTransportNewSession {
        session: WebTransportRequest,
        headers: Headers,
    },
    WebTransportSessionClosed {
        session: WebTransportRequest,
        error: Option<AppError>,
    },
}

#[derive(Debug, Clone)]
pub enum Http3ServerEvent {
    /// Headers are ready.
    Headers {
        request: ClientRequestStream,
        headers: Headers,
        fin: bool,
    },
    /// Request data is ready.
    Data {
        request: ClientRequestStream,
        data: Vec<u8>,
        fin: bool,
    },
    /// When individual connection change state. It is only used for tests.
    StateChange {
        conn: ActiveConnectionRef,
        state: Http3State,
    },
    PriorityUpdate {
        stream_id: StreamId,
        priority: Priority,
    },
    WebTransport(WebTransportServerEvent),
}

#[derive(Debug, Default, Clone)]
pub struct Http3ServerEvents {
    events: Rc<RefCell<VecDeque<Http3ServerEvent>>>,
}

impl Http3ServerEvents {
    fn insert(&self, event: Http3ServerEvent) {
        self.events.borrow_mut().push_back(event);
    }

    /// Take all events
    pub fn events(&self) -> impl Iterator<Item = Http3ServerEvent> {
        self.events.replace(VecDeque::new()).into_iter()
    }

    /// Whether there is request pending.
    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }

    /// Take the next event if present.
    pub fn next_event(&self) -> Option<Http3ServerEvent> {
        self.events.borrow_mut().pop_front()
    }

    /// Insert a `Headers` event.
    pub(crate) fn headers(&self, request: ClientRequestStream, headers: Headers, fin: bool) {
        self.insert(Http3ServerEvent::Headers {
            request,
            headers,
            fin,
        });
    }

    /// Insert a `StateChange` event.
    pub(crate) fn connection_state_change(&self, conn: ActiveConnectionRef, state: Http3State) {
        self.insert(Http3ServerEvent::StateChange { conn, state });
    }

    /// Insert a `Data` event.
    pub(crate) fn data(&self, request: ClientRequestStream, data: Vec<u8>, fin: bool) {
        self.insert(Http3ServerEvent::Data { request, data, fin });
    }

    pub(crate) fn priority_update(&self, stream_id: StreamId, priority: Priority) {
        self.insert(Http3ServerEvent::PriorityUpdate {
            stream_id,
            priority,
        });
    }

    pub(crate) fn webtransport_new_session(&self, session: WebTransportRequest, headers: Headers) {
        self.insert(Http3ServerEvent::WebTransport(
            WebTransportServerEvent::WebTransportNewSession { session, headers },
        ));
    }

    pub(crate) fn webtransport_session_closed(
        &self,
        session: WebTransportRequest,
        error: Option<AppError>,
    ) {
        self.insert(Http3ServerEvent::WebTransport(
            WebTransportServerEvent::WebTransportSessionClosed { session, error },
        ));
    }
}
