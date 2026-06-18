// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    fmt::{self, Display, Formatter},
    rc::Rc,
    time::Instant,
};

use neqo_common::{Bytes, Header, qdebug};
use neqo_transport::{DatagramTracking, StreamId, server::ConnectionRef};

use crate::{
    Http3ServerEvent, Http3State, Http3StreamInfo, Http3StreamType, Res, SessionAcceptAction,
    connection_server::Http3ServerHandler,
    features::extended_connect,
    server_events::{Http3ServerEvents, StreamHandler},
};

#[derive(Debug, Clone)]
pub struct ServerSession {
    stream_handler: StreamHandler,
}

impl Display for ServerSession {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConnectUdp session {}", self.stream_handler)
    }
}

impl ServerSession {
    pub(crate) const fn new(
        conn: ConnectionRef,
        handler: Rc<RefCell<Http3ServerHandler>>,
        stream_id: StreamId,
    ) -> Self {
        Self {
            stream_handler: StreamHandler {
                conn,
                handler,
                stream_info: Http3StreamInfo::new(stream_id, Http3StreamType::Http),
            },
        }
    }

    #[must_use]
    pub fn state(&self) -> Http3State {
        self.stream_handler.handler.borrow().state()
    }

    /// Respond to a `ConnectUdp` session request.
    ///
    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn response(&self, accept: &SessionAcceptAction, now: Instant) -> Res<()> {
        qdebug!("[{self}] Set a response for a ConnectUdp session");
        self.stream_handler
            .handler
            .borrow_mut()
            .connect_udp_session_accept(
                &mut self.stream_handler.conn.borrow_mut(),
                self.stream_handler.stream_info.stream_id(),
                accept,
                now,
            )
    }

    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    /// Also return an error if the stream was closed on the transport layer,
    /// but that information is not yet consumed on the  http/3 layer.
    pub fn close_session(&self, error: u32, message: &str, now: Instant) -> Res<()> {
        self.stream_handler
            .handler
            .borrow_mut()
            .connect_udp_close_session(
                &mut self.stream_handler.conn.borrow_mut(),
                self.stream_handler.stream_info.stream_id(),
                error,
                message,
                now,
            )
    }

    #[must_use]
    pub const fn stream_id(&self) -> StreamId {
        self.stream_handler.stream_id()
    }

    /// Send connect-udp datagram.
    ///
    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    /// The function returns `TooMuchData` if the supply buffer is bigger than
    /// the allowed remote datagram size.
    pub fn send_datagram<I: Into<DatagramTracking>>(
        &self,
        buf: &[u8],
        id: I,
        now: Instant,
    ) -> Res<()> {
        let session_id = self.stream_handler.stream_id();
        self.stream_handler
            .handler
            .borrow_mut()
            .connect_udp_send_datagram(
                &mut self.stream_handler.conn.borrow_mut(),
                session_id,
                buf,
                id,
                now,
            )
    }

    #[must_use]
    pub fn remote_datagram_size(&self) -> u64 {
        self.stream_handler.conn.borrow().remote_datagram_size()
    }

    /// Used for testing only.
    ///
    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn reset_send(&self) -> Res<()> {
        self.stream_handler.handler.borrow_mut().stream_reset_send(
            self.stream_id(),
            0,
            &mut self.stream_handler.conn.borrow_mut(),
        )
    }
}

#[derive(Debug, Clone)]
pub enum ServerEvent {
    NewSession {
        session: ServerSession,
        headers: Vec<Header>,
    },
    SessionClosed {
        session: ServerSession,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    },
    Datagram {
        session: ServerSession,
        datagram: Bytes,
    },
}

pub trait ServerEvents {
    fn connect_udp_new_session(&self, session: ServerSession, headers: Vec<Header>);
    fn connect_udp_session_closed(
        &self,
        session: ServerSession,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    );
    fn connect_udp_datagram(&self, session: ServerSession, datagram: Bytes);
}

impl ServerEvents for Http3ServerEvents {
    fn connect_udp_new_session(&self, session: ServerSession, headers: Vec<Header>) {
        self.insert(Http3ServerEvent::ConnectUdp(ServerEvent::NewSession {
            session,
            headers,
        }));
    }

    fn connect_udp_session_closed(
        &self,
        session: ServerSession,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    ) {
        self.insert(Http3ServerEvent::ConnectUdp(ServerEvent::SessionClosed {
            session,
            reason,
            headers,
        }));
    }

    fn connect_udp_datagram(&self, session: ServerSession, datagram: Bytes) {
        self.insert(Http3ServerEvent::ConnectUdp(ServerEvent::Datagram {
            session,
            datagram,
        }));
    }
}
