// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    mem,
    time::Instant,
};

use neqo_common::{Bytes, Encoder, Header, Role, qtrace};
use neqo_transport::{Connection, StreamId, StreamType, streams::SendGroupId};
use rustc_hash::FxHashSet as HashSet;
use sfv::{BareItem, Item, Parser};

use crate::{
    Error, Http3StreamInfo, Http3StreamType, RecvStream, Res, SendStream,
    features::extended_connect::{
        CloseReason, ExtendedConnectEvents, ExtendedConnectType,
        session::{DgramContextIdError, Protocol, State},
        stats::SessionStats,
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
    /// The negotiated protocol from server response headers.
    negotiated_protocol: Option<String>,
    /// Send groups registered for this session.
    send_groups: HashSet<SendGroupId>,
    /// Cumulative count of locally-initiated uni streams over the session
    /// lifetime. The per-session stream limit is cumulative (like QUIC's
    /// `MAX_STREAMS`), so this never decreases when a stream closes.
    cumulative_uni_count: u64,
    /// Cumulative count of locally-initiated bidi streams over the session
    /// lifetime.
    cumulative_bidi_count: u64,
    /// Session-level statistics.
    stats: SessionStats,
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
            negotiated_protocol: None,
            send_groups: HashSet::default(),
            cumulative_uni_count: 0,
            cumulative_bidi_count: 0,
            stats: SessionStats::new(),
        }
    }
    /// Register a send group with a caller-provided ID for this session.
    ///
    /// Returns an error if the ID is already in use.
    pub(crate) fn register_send_group(&mut self, id: SendGroupId) -> Res<()> {
        self.send_groups
            .insert(id)
            .then_some(())
            .ok_or(Error::InvalidState)
    }

    /// Validate that a send group belongs to this session.
    pub(crate) fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        self.send_groups.contains(&group_id)
    }

    #[must_use]
    pub(crate) const fn local_stream_count(&self, stream_type: StreamType) -> u64 {
        match stream_type {
            StreamType::UniDi => self.cumulative_uni_count,
            StreamType::BiDi => self.cumulative_bidi_count,
        }
    }
    pub(crate) const fn record_bytes_sent(&mut self, bytes: u64) {
        self.stats.bytes_sent += bytes;
    }

    pub(crate) const fn record_bytes_received(&mut self, bytes: u64) {
        self.stats.bytes_received += bytes;
    }

    pub(crate) const fn record_datagram_sent(&mut self) {
        self.stats.datagrams_sent += 1;
    }

    pub(crate) const fn record_datagram_received(&mut self) {
        self.stats.datagrams_received += 1;
    }

    pub(crate) const fn record_stream_opened(&mut self, local: bool) {
        if local {
            self.stats.streams_opened_local += 1;
        } else {
            self.stats.streams_opened_remote += 1;
        }
    }

    #[expect(dead_code, reason = "pending datagram stats update")]
    pub(crate) const fn record_datagram_expired_outgoing(&mut self) {
        self.stats.expired_outgoing += 1;
    }

    #[expect(dead_code, reason = "pending datagram stats update")]
    pub(crate) const fn record_datagram_lost_outgoing(&mut self) {
        self.stats.lost_outgoing += 1;
    }

    #[expect(dead_code, reason = "pending datagram stats update")]
    pub(crate) const fn record_datagram_dropped_incoming(&mut self) {
        self.stats.dropped_incoming += 1;
    }

    #[must_use]
    #[expect(
        clippy::disallowed_methods,
        reason = "stats snapshot needs wall-clock time"
    )]
    pub(crate) fn stats(&self) -> SessionStats {
        let mut stats = self.stats.clone();
        stats.timestamp = Some(Instant::now());
        stats
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
            if stream_id.is_self_initiated(self.role) {
                self.cumulative_bidi_count += 1;
            }
        } else if stream_id.is_self_initiated(self.role) {
            self.send_streams.insert(stream_id);
            self.cumulative_uni_count += 1;
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

    fn process_response_headers(&mut self, headers: &[Header]) {
        self.negotiated_protocol = headers
            .iter()
            .find(|h| h.name().eq_ignore_ascii_case("wt-protocol"))
            .and_then(|h| Parser::new(h.value()).parse::<Item>().ok())
            .and_then(|item| {
                if let BareItem::String(s) = item.bare_item {
                    Some(s.into())
                } else {
                    None
                }
            });
    }

    fn protocol(&self) -> Option<&str> {
        self.negotiated_protocol.as_deref()
    }

    fn register_send_group(&mut self, id: SendGroupId) -> Res<()> {
        Self::register_send_group(self, id)
    }

    fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        Self::validate_send_group(self, group_id)
    }

    fn local_stream_count(&self, stream_type: StreamType) -> u64 {
        self.local_stream_count(stream_type)
    }

    fn record_bytes_sent(&mut self, bytes: u64) {
        Self::record_bytes_sent(self, bytes);
    }

    fn record_bytes_received(&mut self, bytes: u64) {
        Self::record_bytes_received(self, bytes);
    }

    fn record_datagram_sent(&mut self) {
        Self::record_datagram_sent(self);
    }

    fn record_datagram_received(&mut self) {
        Self::record_datagram_received(self);
    }

    fn record_stream_opened(&mut self, local: bool) {
        Self::record_stream_opened(self, local);
    }

    fn stats(&self) -> Option<SessionStats> {
        Some(Self::stats(self))
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
}
