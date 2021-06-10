// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use crate::connection::Http3State;
use crate::connection_server::Http3ServerHandler;
use crate::{Header, Priority, Res};
use neqo_common::{qdebug, qinfo};
use neqo_transport::server::ActiveConnectionRef;
use neqo_transport::{AppError, Connection, StreamType};

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct StreamHandler {
    pub conn: ActiveConnectionRef,
    pub handler: Rc<RefCell<Http3ServerHandler>>,
    pub stream_id: u64,
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
        state.write_u64(self.stream_id);
        state.finish();
    }
}

impl PartialEq for StreamHandler {
    fn eq(&self, other: &Self) -> bool {
        self.conn == other.conn && self.stream_id == other.stream_id
    }
}

impl Eq for StreamHandler {}

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
        stream_id: u64,
    ) -> Self {
        Self {
            stream_handler: StreamHandler {
                conn,
                handler,
                stream_id,
            },
        }
    }

    /// Supply a response to a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn set_response(&mut self, headers: &[Header], data: &[u8]) -> Res<()> {
        qinfo!([self], "Set new response.");
        self.stream_handler.handler.borrow_mut().set_response(
            self.stream_handler.stream_id,
            headers,
            data,
        )
    }

    /// Request a peer to stop sending a request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_stop_sending(&mut self, app_error: AppError) -> Res<()> {
        qdebug!([self], "stop sending error={}.", app_error);
        self.stream_handler
            .conn
            .borrow_mut()
            .stream_stop_sending(self.stream_handler.stream_id, app_error)?;
        Ok(())
    }

    /// Reset a stream/request.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore
    pub fn stream_reset(&mut self, app_error: AppError) -> Res<()> {
        qdebug!([self], "reset error:{}.", app_error);
        self.stream_handler.handler.borrow_mut().stream_reset(
            &mut self.stream_handler.conn.borrow_mut(),
            self.stream_handler.stream_id,
            app_error,
        )
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
pub struct WtRequestStream {
    stream_handler: StreamHandler,
}

impl ::std::fmt::Display for WtRequestStream {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "WebTransport session {}", self.stream_handler)
    }
}

impl WtRequestStream {
    pub(crate) fn new(
        conn: ActiveConnectionRef,
        handler: Rc<RefCell<Http3ServerHandler>>,
        stream_id: u64,
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
            .wt_session_response(
                &mut self.stream_handler.conn.borrow_mut(),
                self.stream_handler.stream_id,
                accept,
            )
    }

    /// Create a WebTraansport stream.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn create_stream(&mut self, stream_type: StreamType) -> Res<WtStream> {
        qinfo!(
            [self],
            "WebTransport create a new stream type={:?}",
            stream_type
        );
        Ok(WtStream::new(
            self.stream_handler.conn.clone(),
            self.stream_handler.handler.clone(),
            self.stream_handler.handler.borrow_mut().wt_create_stream(
                &mut self.stream_handler.conn.borrow_mut(),
                self.stream_handler.stream_id,
                stream_type,
            )?,
        ))
    }
}

impl std::hash::Hash for WtRequestStream {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stream_handler.hash(state);
        state.finish();
    }
}

impl PartialEq for WtRequestStream {
    fn eq(&self, other: &Self) -> bool {
        self.stream_handler == other.stream_handler
    }
}

impl Eq for WtRequestStream {}

#[derive(Debug, Clone)]
pub struct WtStream {
    stream_handler: StreamHandler,
}

impl ::std::fmt::Display for WtStream {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "WebTransport stream {}", self.stream_handler)
    }
}

impl WtStream {
    pub(crate) fn new(
        conn: ActiveConnectionRef,
        handler: Rc<RefCell<Http3ServerHandler>>,
        stream_id: u64,
    ) -> Self {
        Self {
            stream_handler: StreamHandler {
                conn,
                handler,
                stream_id,
            },
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_handler.stream_id
    }

    /// Send data ona WebTransport Stream.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore or if
    /// the stream is only a receiver stream.
    pub fn send_data(&mut self, data: &[u8]) -> Res<usize> {
        qinfo!([self], "Send data.");
        self.stream_handler
            .handler
            .borrow_mut()
            .wt_stream_send_data(
                &mut self.stream_handler.conn.borrow_mut(),
                self.stream_handler.stream_id,
                data,
            )
    }

    /// Close the steam.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn close(&mut self) -> Res<()> {
        qdebug!([self], "close stream.");
        self.stream_handler
            .conn
            .borrow_mut()
            .stream_close_send(self.stream_handler.stream_id)?;
        Ok(())
    }

    /// Request a peer to stop sending data.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn stream_stop_sending(&mut self, app_error: AppError) -> Res<()> {
        qdebug!([self], "stop sending error:{}.", app_error);
        self.stream_handler
            .conn
            .borrow_mut()
            .stream_stop_sending(self.stream_handler.stream_id, app_error)?;
        Ok(())
    }

    /// Reset a stream.
    /// # Errors
    /// It may return `InvalidStreamId` if a stream does not exist anymore
    pub fn stream_reset(&mut self, app_error: AppError) -> Res<()> {
        qdebug!([self], "reset error:{}.", app_error);
        self.stream_handler.handler.borrow_mut().stream_reset(
            &mut self.stream_handler.conn.borrow_mut(),
            self.stream_handler.stream_id,
            app_error,
        )
    }
}

impl std::hash::Hash for WtStream {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stream_handler.hash(state);
        state.finish();
    }
}

impl PartialEq for WtStream {
    fn eq(&self, other: &Self) -> bool {
        self.stream_handler == other.stream_handler
    }
}

#[derive(Debug, Clone)]
pub enum Http3ServerEvent {
    /// Headers are ready.
    Headers {
        request: ClientRequestStream,
        headers: Vec<Header>,
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
        stream_id: u64,
        priority: Priority,
    },
    WebTransportNewSession {
        request: WtRequestStream,
        headers: Vec<Header>,
    },
    WebTransportNewStream {
        request: WtStream,
    },
    WebTransportStreamData {
        request: WtStream,
        data: Vec<u8>,
        fin: bool,
    },
    WebTransportStreamReset {
        request: WtStream,
        error: AppError,
    },
    WebTransportDataWritable {
        request: WtStream,
    },
    WebTransportStreamStopSending {
        request: WtStream,
        error: AppError,
    },
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
    pub(crate) fn headers(&self, request: ClientRequestStream, headers: Vec<Header>, fin: bool) {
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

    pub(crate) fn priority_update(&self, stream_id: u64, priority: Priority) {
        self.insert(Http3ServerEvent::PriorityUpdate {
            stream_id,
            priority,
        })
    }

    pub(crate) fn web_transport_new_session(&self, request: WtRequestStream, headers: Vec<Header>) {
        self.insert(Http3ServerEvent::WebTransportNewSession { request, headers });
    }

    pub(crate) fn web_transport_new_stream(&self, request: WtStream) {
        self.insert(Http3ServerEvent::WebTransportNewStream { request });
    }

    pub(crate) fn web_transport_stream_data(&self, request: WtStream, data: Vec<u8>, fin: bool) {
        self.insert(Http3ServerEvent::WebTransportStreamData { request, data, fin });
    }

    pub(crate) fn web_transport_stream_reset(&self, request: WtStream, error: AppError) {
        self.insert(Http3ServerEvent::WebTransportStreamReset { request, error });
    }

    pub(crate) fn web_transport_data_writable(&self, request: WtStream) {
        self.insert(Http3ServerEvent::WebTransportDataWritable { request });
    }

    pub(crate) fn web_transport_stream_stop_sending(&self, request: WtStream, error: AppError) {
        self.insert(Http3ServerEvent::WebTransportStreamStopSending { request, error });
    }
}
