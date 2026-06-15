// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    fmt::{self, Display, Formatter},
    ops::Deref,
    rc::Rc,
    time::Instant,
};

use neqo_common::{Bytes, Encoder, Header, qdebug};
use neqo_transport::{
    Connection, DatagramTracking, Error as TransportError, StreamId, StreamType, recv_stream,
    send_stream, server::ConnectionRef, streams::SendOrder,
};

use crate::{
    Error, Http3Client, Http3OrWebTransportStream, Http3ServerEvent, Http3State, Http3StreamInfo,
    Http3StreamType, Res, SessionAcceptAction,
    connection::Http3Connection,
    connection_server::Http3ServerHandler,
    features::extended_connect,
    server_events::{Http3ServerEvents, StreamHandler},
};

pub trait WebTransport {
    /// Returns the current max size of a datagram that can fit into a packet.
    /// The value will change over time depending on the encoded size of the
    /// packet number, ack frames, etc.
    ///
    /// # Errors
    ///
    /// The function returns `NotAvailable` if datagrams are not enabled.
    ///
    /// # Panics
    ///
    /// This cannot panic. The max varint length is 8.
    fn webtransport_max_datagram_size(&self, session_id: StreamId) -> Res<u64>;

    /// Sets the `SendOrder` for a given stream
    ///
    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    fn webtransport_set_sendorder(
        &mut self,
        stream_id: StreamId,
        sendorder: Option<SendOrder>,
    ) -> Res<()>;

    /// Sets the `Fairness` for a given stream
    ///
    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    //
    // TODO: Currently not called in neqo or gecko. It should likely be called at least from gecko.
    fn webtransport_set_fairness(&mut self, stream_id: StreamId, fairness: bool) -> Res<()>;

    /// Returns the current `send_stream::Stats` of a `WebTransportSendStream`.
    ///
    /// # Errors
    ///
    /// `InvalidStreamId` if the stream does not exist.
    fn webtransport_send_stream_stats(&mut self, stream_id: StreamId) -> Res<send_stream::Stats>;

    /// Returns the current `recv_stream::Stats` of a `WebTransportRecvStream`.
    ///
    /// # Errors
    ///
    /// `InvalidStreamId` if the stream does not exist.
    fn webtransport_recv_stream_stats(&mut self, stream_id: StreamId) -> Res<recv_stream::Stats>;

    /// Export WebTransport keying material per
    /// [draft-ietf-webtrans-http3 §4.8](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-15.html#section-4.8).
    ///
    /// Derives keying material scoped to a specific WebTransport session
    /// by calling the TLS exporter with label `"EXPORTER-WebTransport"`
    /// and a context struct that binds the session ID, application label,
    /// and application context together.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidStreamId` if `session_id` does not
    /// correspond to an active WebTransport session,
    /// `Error::InvalidInput` if `out` is empty or `label`/`context`
    /// exceed 255 bytes, or `Error::Transport` on TLS export failure.
    fn webtransport_export_keying_material(
        &self,
        session_id: StreamId,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Res<()>;
}

impl WebTransport for Http3Client {
    fn webtransport_max_datagram_size(&self, session_id: StreamId) -> Res<u64> {
        let qsid_len = Encoder::varint_len(session_id.as_u64() >> 2);
        Ok(self
            .connection()
            .max_datagram_size()?
            .saturating_sub(u64::try_from(qsid_len).map_err(|_| Error::Internal)?))
    }

    fn webtransport_set_sendorder(
        &mut self,
        stream_id: StreamId,
        sendorder: Option<SendOrder>,
    ) -> Res<()> {
        Http3Connection::stream_set_sendorder(self.connection_mut(), stream_id, sendorder)
    }

    fn webtransport_set_fairness(&mut self, stream_id: StreamId, fairness: bool) -> Res<()> {
        Http3Connection::stream_set_fairness(self.connection_mut(), stream_id, fairness)
    }

    fn webtransport_send_stream_stats(&mut self, stream_id: StreamId) -> Res<send_stream::Stats> {
        let (conn, handler) = self.connection_and_handler();
        handler
            .send_streams_mut()
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?
            .stats(conn)
    }

    fn webtransport_recv_stream_stats(&mut self, stream_id: StreamId) -> Res<recv_stream::Stats> {
        let (conn, handler) = self.connection_and_handler();
        handler
            .recv_streams_mut()
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?
            .stats(conn)
    }

    fn webtransport_export_keying_material(
        &self,
        session_id: StreamId,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Res<()> {
        self.handler()
            .validate_extended_connect_session(session_id)?;
        self.connection()
            .webtransport_export_keying_material(session_id, label, context, out)
    }
}

pub trait WebTransportExportKeyingMaterial {
    /// Export keying material for WebTransport.
    ///
    /// # Errors
    /// When the input is invalid or the underlying connection fails to export.
    fn webtransport_export_keying_material(
        &self,
        session_id: StreamId,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Res<()>;
}

impl WebTransportExportKeyingMaterial for Connection {
    fn webtransport_export_keying_material(
        &self,
        session_id: StreamId,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Res<()> {
        // encode_vec(1, …) uses a 1-byte length prefix, so max 255 bytes.
        if out.is_empty() || label.len() > 255 || context.len() > 255 {
            return Err(Error::InvalidInput);
        }

        let mut wt_context = Encoder::with_capacity(
            Encoder::varint_len(session_id.as_u64()) + 1 + label.len() + 1 + context.len(),
        );
        wt_context.encode_varint(session_id.as_u64());
        wt_context.encode_vec(1, label);
        wt_context.encode_vec(1, context);

        self.export_keying_material("EXPORTER-WebTransport", wt_context.as_ref(), out)
            .map_err(|e| match e {
                TransportError::InvalidInput => Error::InvalidInput,
                other => Error::Transport(other),
            })
    }
}

#[derive(Debug, Clone)]
pub struct WebTransportRequest {
    stream_handler: StreamHandler,
}

impl Display for WebTransportRequest {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "WebTransport session {}", self.stream_handler)
    }
}

impl WebTransportRequest {
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

    /// Respond to a `WebTransport` session request.
    ///
    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn response(&self, accept: &SessionAcceptAction, now: Instant) -> Res<()> {
        qdebug!("[{self}] Set a response for a WebTransport session");
        self.stream_handler
            .handler
            .borrow_mut()
            .webtransport_session_accept(
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
            .webtransport_close_session(
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

    /// Create `WebTransport` stream.
    ///
    /// # Errors
    ///
    /// It may return `InvalidStreamId` if a stream does not exist anymore.
    pub fn create_stream(&self, stream_type: StreamType) -> Res<Http3OrWebTransportStream> {
        let session_id = self.stream_handler.stream_id();
        let id = self
            .stream_handler
            .handler
            .borrow_mut()
            .webtransport_create_stream(
                &mut self.stream_handler.conn.borrow_mut(),
                session_id,
                stream_type,
            )?;

        Ok(Http3OrWebTransportStream::new(
            self.stream_handler.conn.clone(),
            Rc::clone(&self.stream_handler.handler),
            Http3StreamInfo::new(id, Http3StreamType::WebTransport(session_id)),
        ))
    }

    /// Send `WebTransport` datagram.
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
            .webtransport_send_datagram(
                &mut self.stream_handler.conn.borrow_mut(),
                session_id,
                buf,
                id,
                now,
            )
    }

    // TODO: Currently not called in neqo or gecko. It should likely be called at least from gecko.
    #[must_use]
    pub fn remote_datagram_size(&self) -> u64 {
        self.stream_handler.conn.borrow().remote_datagram_size()
    }

    /// Returns the current max size of a datagram that can fit into a packet.
    /// The value will change over time depending on the encoded size of the
    /// packet number, ack frames, etc.
    ///
    /// # Errors
    ///
    /// The function returns `NotAvailable` if datagrams are not enabled.
    ///
    /// # Panics
    ///
    /// This cannot panic. The max varint length is 8.
    pub fn max_datagram_size(&self) -> Res<u64> {
        let qsid_len = Encoder::varint_len(self.stream_handler.stream_id().as_u64() >> 2);
        Ok(self
            .stream_handler
            .conn
            .borrow()
            .max_datagram_size()?
            .saturating_sub(u64::try_from(qsid_len).map_err(|_| Error::Internal)?))
    }

    /// Export keying material for this WebTransport session
    /// (draft-ietf-webtrans-http3 §4.8).
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidStreamId` if the session is no longer active,
    /// `Error::InvalidInput` if `out` is empty or `label`/`context`
    /// exceed 255 bytes, or `Error::Transport` if the connection is not ready
    /// or the TLS export fails.
    pub fn export_keying_material(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Res<()> {
        let session_id = self.stream_handler.stream_id();
        self.stream_handler
            .handler
            .borrow()
            .validate_extended_connect_session(session_id)?;
        self.stream_handler
            .conn
            .borrow()
            .webtransport_export_keying_material(session_id, label, context, out)
    }
}

impl Deref for WebTransportRequest {
    type Target = StreamHandler;
    fn deref(&self) -> &Self::Target {
        &self.stream_handler
    }
}

#[derive(Debug, Clone)]
pub enum WebTransportServerEvent {
    NewSession {
        session: WebTransportRequest,
        headers: Vec<Header>,
    },
    SessionClosed {
        session: WebTransportRequest,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    },
    NewStream(Http3OrWebTransportStream),
    Datagram {
        session: WebTransportRequest,
        datagram: Bytes,
    },
}

pub trait WebTransportServerEvents {
    fn webtransport_new_session(&self, session: WebTransportRequest, headers: Vec<Header>);
    fn webtransport_session_closed(
        &self,
        session: WebTransportRequest,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    );
    fn webtransport_new_stream(&self, stream: Http3OrWebTransportStream);
    fn webtransport_datagram(&self, session: WebTransportRequest, datagram: Bytes);
}

impl WebTransportServerEvents for Http3ServerEvents {
    fn webtransport_new_session(&self, session: WebTransportRequest, headers: Vec<Header>) {
        self.insert(Http3ServerEvent::WebTransport(
            WebTransportServerEvent::NewSession { session, headers },
        ));
    }

    fn webtransport_session_closed(
        &self,
        session: WebTransportRequest,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    ) {
        self.insert(Http3ServerEvent::WebTransport(
            WebTransportServerEvent::SessionClosed {
                session,
                reason,
                headers,
            },
        ));
    }

    fn webtransport_new_stream(&self, stream: Http3OrWebTransportStream) {
        self.insert(Http3ServerEvent::WebTransport(
            WebTransportServerEvent::NewStream(stream),
        ));
    }

    fn webtransport_datagram(&self, session: WebTransportRequest, datagram: Bytes) {
        self.insert(Http3ServerEvent::WebTransport(
            WebTransportServerEvent::Datagram { session, datagram },
        ));
    }
}
