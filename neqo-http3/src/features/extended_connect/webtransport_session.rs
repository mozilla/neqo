// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    mem,
    time::Instant,
};

use neqo_common::{Bytes, Encoder, Role, qtrace};
use neqo_transport::{Connection, StreamId};

use crate::{
    Error, Http3StreamInfo, Http3StreamType, RecvStream, Res,
    features::extended_connect::{
        datagram_queue::{DatagramOutcome, WebTransportDatagramQueue},
        send_group::{SendGroup, SendGroupId},
        stats::WebTransportSessionStats,
        CloseReason, ExtendedConnectEvents, ExtendedConnectType,
        session::{DgramContextIdError, Protocol, State},
    },
    frames::{FrameReader, StreamReaderRecvStreamWrapper, WebTransportFrame},
};

#[derive(Debug)]
pub struct Session {
    frame_reader: FrameReader,
    id: StreamId,
    send_streams: HashSet<StreamId>,
    recv_streams: HashSet<StreamId>,
    role: Role,
    /// Remote initiated streams received before session confirmation.
    ///
    /// [`HashSet`] size limited by QUIC connection stream limit.
    pending_streams: HashSet<StreamId>,
    /// Whether the session is draining (no new streams should be created).
    draining: bool,
    /// The negotiated protocol from server response headers.
    negotiated_protocol: Option<String>,
    /// The list of protocols offered by the client in the request.
    offered_protocols: Vec<String>,
    /// Send groups for this session.
    send_groups: HashMap<SendGroupId, SendGroup>,
    /// Session-level statistics.
    stats: WebTransportSessionStats,
    /// Datagram queue for managing outgoing datagrams.
    datagram_queue: WebTransportDatagramQueue,
    /// Anticipated concurrent incoming unidirectional streams.
    anticipated_incoming_uni: Option<u16>,
    /// Anticipated concurrent incoming bidirectional streams.
    anticipated_incoming_bidi: Option<u16>,
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "WebTransportSession")
    }
}

impl Session {
    #[must_use]
    pub(crate) fn new(session_id: StreamId, role: Role) -> Self {
        Self {
            id: session_id,
            frame_reader: FrameReader::new(),
            send_streams: HashSet::default(),
            recv_streams: HashSet::default(),
            role,
            pending_streams: HashSet::default(),
            draining: false,
            negotiated_protocol: None,
            offered_protocols: Vec::new(),
            send_groups: HashMap::default(),
            stats: WebTransportSessionStats::new(),
            datagram_queue: WebTransportDatagramQueue::new(),
            anticipated_incoming_uni: None,
            anticipated_incoming_bidi: None,
        }
    }

    /// Mark session as draining.
    pub(crate) fn set_draining(&mut self) {
        self.draining = true;
    }

    /// Check if session is draining.
    pub(crate) fn is_draining(&self) -> bool {
        self.draining
    }

    /// Set the offered protocols list from the client request.
    pub(crate) fn set_offered_protocols(&mut self, protocols: Vec<String>) {
        self.offered_protocols = protocols;
    }

    /// Set the negotiated protocol from server response headers.
    pub(crate) fn set_protocol(&mut self, protocol: Option<String>) {
        self.negotiated_protocol = protocol;
    }

    /// Get the negotiated protocol.
    pub(crate) fn protocol(&self) -> Option<&str> {
        self.negotiated_protocol.as_deref()
    }

    /// Set the anticipated concurrent incoming unidirectional streams.
    pub(crate) fn set_anticipated_incoming_uni(&mut self, value: u16) {
        self.anticipated_incoming_uni = Some(value);
    }

    /// Set the anticipated concurrent incoming bidirectional streams.
    pub(crate) fn set_anticipated_incoming_bidi(&mut self, value: u16) {
        self.anticipated_incoming_bidi = Some(value);
    }

    /// Create a new send group for this session.
    pub(crate) fn create_send_group(&mut self) -> SendGroupId {
        let id = SendGroupId::new();
        let group = SendGroup::new(id, self.id);
        self.send_groups.insert(id, group);
        id
    }

    /// Validate that a send group belongs to this session.
    pub(crate) fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        self.send_groups.contains_key(&group_id)
    }

    /// Get the session ID for a send group.
    pub(crate) fn send_group_session(&self, group_id: SendGroupId) -> Option<StreamId> {
        self.send_groups.get(&group_id).map(|g| g.session_id())
    }

    pub(crate) fn record_bytes_sent(&mut self, bytes: u64) {
        self.stats.bytes_sent += bytes;
    }

    pub(crate) fn record_bytes_received(&mut self, bytes: u64) {
        self.stats.bytes_received += bytes;
    }

    pub(crate) fn record_datagram_sent(&mut self) {
        self.stats.datagrams_sent += 1;
    }

    pub(crate) fn record_datagram_received(&mut self) {
        self.stats.datagrams_received += 1;
    }

    pub(crate) fn record_stream_opened(&mut self, local: bool) {
        if local {
            self.stats.streams_opened_local += 1;
        } else {
            self.stats.streams_opened_remote += 1;
        }
    }

    #[must_use]
    pub(crate) fn stats(&self) -> WebTransportSessionStats {
        let mut stats = self.stats.clone();
        stats.timestamp = Some(Instant::now());
        stats
    }

    pub(crate) fn set_datagram_high_water_mark(&mut self, mark: f64) {
        self.datagram_queue.set_high_water_mark(mark);
    }

    pub(crate) fn set_datagram_max_age(&mut self, age_ms: f64) {
        self.datagram_queue.set_max_age(age_ms);
    }

    pub(crate) fn enqueue_datagram(
        &mut self,
        data: Bytes,
        id: u64,
    ) -> (bool, Option<(u64, DatagramOutcome)>) {
        self.datagram_queue.enqueue(data, id)
    }

    pub(crate) fn process_datagram_queue(
        &mut self,
        send_fn: &mut dyn FnMut(&[u8], u64) -> Result<(), ()>,
    ) -> Vec<(u64, DatagramOutcome)> {
        self.datagram_queue.process_queue(send_fn)
    }
}

impl Protocol for Session {
    fn connect_type(&self) -> ExtendedConnectType {
        ExtendedConnectType::WebTransport
    }

    fn session_start(&mut self, events: &mut Box<dyn ExtendedConnectEvents>) -> Res<()> {
        // > WebTransport endpoints SHOULD buffer streams and
        // > datagrams until they can be associated with an
        // > established session.
        //
        // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#section-4.5>
        #[expect(clippy::iter_over_hash_type, reason = "no defined order necessary")]
        for stream_id in self.pending_streams.drain() {
            events.extended_connect_new_stream(
                Http3StreamInfo::new(stream_id, Http3StreamType::WebTransport(self.id)),
                // Explicitly emit a stream readable event. Such
                // event was previously suppressed as the
                // session was still negotiating.
                true,
            )?;
        }

        Ok(())
    }

    fn close_frame(&self, error: u32, message: &str) -> Option<Vec<u8>> {
        let close_frame = WebTransportFrame::CloseSession {
            error,
            message: message.to_string(),
        };
        let mut encoder = Encoder::default();
        close_frame.encode(&mut encoder);
        Some(encoder.into())
    }

    fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
        now: Instant,
    ) -> Res<Option<State>> {
        let (f, fin) = self
            .frame_reader
            .receive::<WebTransportFrame>(
                &mut StreamReaderRecvStreamWrapper::new(conn, control_stream_recv),
                now,
            )
            .map_err(|_| Error::HttpGeneralProtocolStream)?;
        qtrace!("[{self}] Received frame: {f:?} fin={fin}");
        if let Some(WebTransportFrame::CloseSession { error, message }) = f {
            events.session_end(
                ExtendedConnectType::WebTransport,
                self.id,
                CloseReason::Clean { error, message },
                None,
            );
            if fin {
                Ok(Some(State::Done))
            } else {
                Ok(Some(State::FinPending))
            }
        } else if fin {
            events.session_end(
                ExtendedConnectType::WebTransport,
                self.id,
                CloseReason::Clean {
                    error: 0,
                    message: String::new(),
                },
                None,
            );
            Ok(Some(State::Done))
        } else {
            Ok(None)
        }
    }

    fn add_stream(
        &mut self,
        stream_id: StreamId,
        events: &mut Box<dyn ExtendedConnectEvents>,
        state: State,
    ) -> Res<()> {
        match state {
            State::Negotiating | State::Active => {}
            State::FinPending | State::Done => return Ok(()),
        }

        if stream_id.is_bidi() {
            self.send_streams.insert(stream_id);
            self.recv_streams.insert(stream_id);
        } else if stream_id.is_self_initiated(self.role) {
            self.send_streams.insert(stream_id);
        } else {
            self.recv_streams.insert(stream_id);
        }

        match state {
            State::FinPending | State::Done => {
                unreachable!("see match above");
            }
            State::Negotiating => {
                // > a client may receive a server-initiated stream or a datagram
                // > before receiving the CONNECT response headers from the
                // > server.
                // >
                // > To handle this case, WebTransport endpoints SHOULD buffer
                // > streams and datagrams until they can be associated with an
                // > established session.
                //
                // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#section-4.5>
                self.pending_streams.insert(stream_id);
            }
            State::Active => {
                if !stream_id.is_self_initiated(self.role) {
                    events.extended_connect_new_stream(
                        Http3StreamInfo::new(stream_id, Http3StreamType::WebTransport(self.id)),
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

    fn remove_recv_stream(&mut self, stream_id: StreamId) {
        self.recv_streams.remove(&stream_id);
    }

    fn remove_send_stream(&mut self, stream_id: StreamId) {
        self.send_streams.remove(&stream_id);
    }

    fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        (
            mem::take(&mut self.recv_streams),
            mem::take(&mut self.send_streams),
        )
    }

    fn set_offered_protocols(&mut self, protocols: Vec<String>) {
        self.set_offered_protocols(protocols);
    }

    fn set_protocol(&mut self, protocol: Option<String>) {
        self.set_protocol(protocol);
    }

    fn protocol(&self) -> Option<&str> {
        self.protocol()
    }

    fn create_send_group(&mut self) -> Option<SendGroupId> {
        Some(self.create_send_group())
    }

    fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        self.validate_send_group(group_id)
    }

    fn record_bytes_sent(&mut self, bytes: u64) {
        self.record_bytes_sent(bytes);
    }

    fn record_bytes_received(&mut self, bytes: u64) {
        self.record_bytes_received(bytes);
    }

    fn record_datagram_sent(&mut self) {
        self.record_datagram_sent();
    }

    fn record_datagram_received(&mut self) {
        self.record_datagram_received();
    }

    fn record_stream_opened(&mut self, local: bool) {
        self.record_stream_opened(local);
    }

    fn stats(&self) -> Option<WebTransportSessionStats> {
        Some(self.stats())
    }

    fn write_datagram_prefix(&self, _encoder: &mut Encoder) {
        // WebTransport does not add prefix (i.e. context ID).
    }

    fn dgram_context_id(&self, datagram: Bytes) -> Result<Bytes, DgramContextIdError> {
        // WebTransport does not use a prefix (i.e. context ID).
        Ok(datagram)
    }

    fn set_datagram_high_water_mark(&mut self, mark: f64) {
        self.set_datagram_high_water_mark(mark);
    }

    fn set_datagram_max_age(&mut self, age_ms: f64) {
        self.set_datagram_max_age(age_ms);
    }

    fn enqueue_datagram(&mut self, data: Bytes, id: u64) -> (bool, Option<(u64, DatagramOutcome)>) {
        self.enqueue_datagram(data, id)
    }

    fn process_datagram_queue(
        &mut self,
        send_fn: &mut dyn FnMut(&[u8], u64) -> Result<(), ()>,
    ) -> Vec<(u64, DatagramOutcome)> {
        self.process_datagram_queue(send_fn)
    }
}
