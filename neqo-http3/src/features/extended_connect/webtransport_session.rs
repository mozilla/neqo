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
    Error, Http3StreamInfo, Http3StreamType, RecvStream, Res, SendStream,
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
    /// Whether the session is draining (the remote signalled graceful shutdown).
    ///
    /// Set when a `WT_DRAIN_SESSION` capsule is received; for GOAWAY-triggered
    /// draining the application is notified via [`WebTransportEvent::Draining`]
    /// instead. Will also be set for GOAWAY once `WT_DRAIN_SESSION` handling is
    /// wired into the GOAWAY path.
    // TODO: wire into GOAWAY path and WT_DRAIN_SESSION handling.
    draining: bool,
    /// The negotiated protocol from server response headers.
    negotiated_protocol: Option<String>,
    /// Send groups for this session.
    send_groups: HashMap<SendGroupId, SendGroup>,
    /// Session-level statistics.
    stats: WebTransportSessionStats,
    /// Datagram queue for managing outgoing datagrams.
    datagram_queue: WebTransportDatagramQueue,
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
            send_groups: HashMap::default(),
            stats: WebTransportSessionStats::new(),
            datagram_queue: WebTransportDatagramQueue::new(),
        }
    }

    /// Mark session as draining (called when a `WT_DRAIN_SESSION` capsule is received).
    // TODO: call from WT_DRAIN_SESSION capsule handler and from GOAWAY path.
    #[expect(dead_code, reason = "pending WT_DRAIN_SESSION capsule implementation")]
    pub(crate) fn set_draining(&mut self) {
        self.draining = true;
    }

    /// Returns `true` if the session has been marked as draining.
    #[expect(dead_code, reason = "pending WT_DRAIN_SESSION capsule implementation")]
    pub(crate) fn is_draining(&self) -> bool {
        self.draining
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

    pub(crate) fn record_datagram_expired_outgoing(&mut self) {
        self.stats.expired_outgoing += 1;
    }

    pub(crate) fn record_datagram_lost_outgoing(&mut self) {
        self.stats.lost_outgoing += 1;
    }

    pub(crate) fn record_datagram_dropped_incoming(&mut self) {
        self.stats.dropped_incoming += 1;
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
 
     pub(crate) fn set_datagram_max_age(&mut self, age_ms: f64, now: Instant) -> Vec<(Option<u64>, DatagramOutcome)> {
         self.datagram_queue.set_max_age(age_ms, now)
     }

     pub(crate) fn enqueue_datagram(&mut self, data: Bytes, id: Option<u64>, payload_len: usize, now: Instant) -> (bool, Option<(Option<u64>, DatagramOutcome)>) {
         self.datagram_queue.enqueue(data, id, payload_len, now)
     }

     pub(crate) fn process_datagram_queue(&mut self, now: Instant, send_fn: &mut dyn FnMut(&[u8], Option<u64>) -> Result<(), ()>) -> (Vec<(Option<u64>, DatagramOutcome)>, u64, u64) {
         self.datagram_queue.process_queue(now, send_fn)
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

    fn set_protocol(&mut self, protocol: Option<String>) {
        self.negotiated_protocol = protocol;
    }

    fn protocol(&self) -> Option<&str> {
        self.negotiated_protocol.as_deref()
    }

    fn new_send_group(&mut self) -> Option<SendGroupId> {
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

    fn datagram_capsule_support(&self) -> bool {
        // HTTP/3 WebTransport requires QUIC datagram support. In other words,
        // HTTP/3 WebTransport never falls back to HTTP datagram capsules.
        //
        // > WebTransport over HTTP/3 also requires support for QUIC datagrams.
        // > To indicate support, both the client and the server send a
        // > max_datagram_frame_size transport parameter with a value greater than
        // > 0 (see Section 3 of [QUIC-DATAGRAM]).
        //
        // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-3.1>
        false
    }

    fn write_datagram_capsule(
        &self,
        _control_stream_send: &mut Box<dyn SendStream>,
        _conn: &mut Connection,
        _buf: &[u8],
        _now: Instant,
    ) -> Res<()> {
        debug_assert!(
            false,
            "[{self}] WebTransport does not support datagram capsules."
        );
        Ok(())
    }

    fn set_datagram_high_water_mark(&mut self, mark: f64) {
        self.set_datagram_high_water_mark(mark);
    }

    fn set_datagram_max_age(
        &mut self,
        age_ms: f64,
        now: Instant,
    ) -> Vec<(Option<u64>, DatagramOutcome)> {
        self.set_datagram_max_age(age_ms, now)
    }

    fn enqueue_datagram(
        &mut self,
        data: Bytes,
        id: Option<u64>,
        payload_len: usize,
        now: Instant,
    ) -> (bool, Option<(Option<u64>, DatagramOutcome)>) {
        self.enqueue_datagram(data, id, payload_len, now)
    }

    fn process_datagram_queue(
        &mut self,
        now: Instant,
        send_fn: &mut dyn FnMut(&[u8], Option<u64>) -> Result<(), ()>,
    ) -> (Vec<(Option<u64>, DatagramOutcome)>, u64, u64) {
        self.process_datagram_queue(now, send_fn)
    }
}
