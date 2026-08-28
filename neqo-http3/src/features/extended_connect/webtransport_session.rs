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

/// `WT_FLOW_CONTROL_ERROR` HTTP/3 error code (draft-15 §9.5), used to close a
/// session whose peer violates the per-session stream limit.
pub const WT_FLOW_CONTROL_ERROR: u64 = 0x045d_4487;

/// Maximum permitted `WT_MAX_STREAMS` value (draft-15 §5.6.2): a larger value
/// cannot be encoded as a stream ID and must be treated as `H3_DATAGRAM_ERROR`.
const WT_MAX_STREAMS_LIMIT: u64 = 1 << 60;

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
    stats: SessionStats,
    draining: bool,
    /// Cumulative count of locally-initiated uni streams over the session
    /// lifetime. The per-session stream limit is cumulative (like QUIC's
    /// `MAX_STREAMS`), so this never decreases when a stream closes.
    cumulative_uni_count: u64,
    /// Cumulative count of locally-initiated bidi streams over the session
    /// lifetime.
    cumulative_bidi_count: u64,
    /// Cumulative count of remote-initiated uni streams, used to enforce the
    /// limit we advertised to the peer (draft-15 §5.6.2). Like the local
    /// counts, this never decreases.
    remote_uni_count: u64,
    /// Cumulative count of remote-initiated bidi streams.
    remote_bidi_count: u64,
    /// Highest `WT_MAX_STREAMS` value the peer has granted us per type, if
    /// any. Raises the send limit above the peer's initial
    /// `SETTINGS_WT_INITIAL_MAX_STREAMS_*`.
    granted_max_streams_uni: Option<u64>,
    granted_max_streams_bidi: Option<u64>,
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
            stats: SessionStats::default(),
            draining: false,
            cumulative_uni_count: 0,
            cumulative_bidi_count: 0,
            remote_uni_count: 0,
            remote_bidi_count: 0,
            granted_max_streams_uni: None,
            granted_max_streams_bidi: None,
        }
    }

    /// Mark session as draining. Returns `true` if this was the first call
    /// (i.e. the session was not already draining).
    pub(crate) const fn set_draining(&mut self) -> bool {
        !mem::replace(&mut self.draining, true)
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

    #[must_use]
    pub(crate) const fn remote_stream_count(&self, stream_type: StreamType) -> u64 {
        match stream_type {
            StreamType::UniDi => self.remote_uni_count,
            StreamType::BiDi => self.remote_bidi_count,
        }
    }

    #[must_use]
    pub(crate) const fn granted_max_streams(&self, stream_type: StreamType) -> Option<u64> {
        match stream_type {
            StreamType::UniDi => self.granted_max_streams_uni,
            StreamType::BiDi => self.granted_max_streams_bidi,
        }
    }

    /// Record a `WT_MAX_STREAMS` value that passed validation, raising our send limit.
    const fn set_granted_max_streams(&mut self, stream_type: StreamType, maximum: u64) {
        match stream_type {
            StreamType::UniDi => self.granted_max_streams_uni = Some(maximum),
            StreamType::BiDi => self.granted_max_streams_bidi = Some(maximum),
        }
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
        // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.5>
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
        match f {
            Some(WebTransportFrame::CloseSession { error, message }) => {
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
            }
            Some(WebTransportFrame::DrainSession) => {
                if self.set_draining() {
                    events.session_draining(ExtendedConnectType::WebTransport, self.id);
                }
                if fin {
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
            Some(WebTransportFrame::MaxStreams {
                stream_type,
                maximum,
            }) => {
                // TODO(draft-15 §5.1-7): if flow control was not negotiated
                // as enabled by both endpoints, this capsule should be
                // ignored rather than processed. Not yet plumbed through to
                // this session; harmless today since we do not send this
                // capsule in production yet (test-only).
                // draft-15 §5.6.2: raise our send limit. A value that cannot be
                // encoded as a stream ID is an H3_DATAGRAM_ERROR connection error.
                if maximum > WT_MAX_STREAMS_LIMIT {
                    return Err(Error::HttpDatagram);
                }
                // A value below a previously received one is a flow-control
                // violation; close the session. We compare only against prior
                // WT_MAX_STREAMS capsules, not the peer's initial
                // SETTINGS_WT_INITIAL_MAX_STREAMS_* value, which the session
                // does not retain.
                let previous = self.granted_max_streams(stream_type);
                if matches!(previous, Some(prev) if maximum < prev) {
                    drop(conn.stream_stop_sending(self.id, WT_FLOW_CONTROL_ERROR));
                    drop(conn.stream_reset_send(self.id, WT_FLOW_CONTROL_ERROR));
                    events.session_end(
                        ExtendedConnectType::WebTransport,
                        self.id,
                        CloseReason::Error(WT_FLOW_CONTROL_ERROR),
                        None,
                    );
                    Ok(Some(State::Done))
                } else {
                    self.set_granted_max_streams(stream_type, maximum);
                    // Wake anything blocked on the session's stream limit (the signal
                    // `waitUntilAvailable` listens for). Only on an actual increase:
                    // a repeated capsule grants no new credit.
                    if previous.is_none_or(|prev| maximum > prev) {
                        events.session_stream_creatable(stream_type);
                    }
                    Ok(None)
                }
            }
            None if fin => {
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
            }
            None => Ok(None),
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
            } else {
                self.remote_bidi_count += 1;
            }
        } else if stream_id.is_self_initiated(self.role) {
            self.send_streams.insert(stream_id);
            self.cumulative_uni_count += 1;
        } else {
            self.recv_streams.insert(stream_id);
            self.remote_uni_count += 1;
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
                // <https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.5>
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

    fn stats(&self) -> Option<&SessionStats> {
        Some(&self.stats)
    }

    fn stats_mut(&mut self) -> Option<&mut SessionStats> {
        Some(&mut self.stats)
    }

    fn register_send_group(&mut self, id: SendGroupId) -> Res<()> {
        Self::register_send_group(self, id)
    }

    fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        Self::validate_send_group(self, group_id)
    }

    fn local_stream_count(&self, stream_type: StreamType) -> u64 {
        Self::local_stream_count(self, stream_type)
    }

    fn remote_stream_count(&self, stream_type: StreamType) -> u64 {
        Self::remote_stream_count(self, stream_type)
    }

    fn granted_max_streams(&self, stream_type: StreamType) -> Option<u64> {
        Self::granted_max_streams(self, stream_type)
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

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, cmp::min, rc::Rc, time::Instant};

    use neqo_common::{Bytes, Encoder, Header, Role};
    use neqo_transport::{Connection, StreamId, StreamType};
    use test_fixture::{default_client, now};

    use super::{Protocol as _, Session, State, WT_FLOW_CONTROL_ERROR, WT_MAX_STREAMS_LIMIT};
    use crate::{
        CloseType, Error, Http3StreamInfo, Http3StreamType, ReceiveOutput, RecvStream, Res, Stream,
        features::extended_connect::{
            CloseReason, ExtendedConnectEvents, ExtendedConnectType,
            datagram_queue::DatagramOutcome,
        },
        frames::WebTransportFrame,
    };

    /// Records the session events emitted while a control-stream frame is processed.
    #[derive(Debug, Default, Clone)]
    struct RecordingEvents {
        draining: Rc<RefCell<Vec<StreamId>>>,
        ended: Rc<RefCell<Vec<(StreamId, CloseReason)>>>,
    }

    impl ExtendedConnectEvents for RecordingEvents {
        fn session_start(&self, _: ExtendedConnectType, _: StreamId, _: u16, _: Vec<Header>) {}
        fn session_end(
            &self,
            _: ExtendedConnectType,
            stream_id: StreamId,
            reason: CloseReason,
            _: Option<Vec<Header>>,
        ) {
            self.ended.borrow_mut().push((stream_id, reason));
        }
        fn session_draining(&self, _: ExtendedConnectType, stream_id: StreamId) {
            self.draining.borrow_mut().push(stream_id);
        }
        fn session_stream_creatable(&self, _: StreamType) {}
        fn extended_connect_new_stream(&self, _: Http3StreamInfo, _: bool) -> Res<()> {
            Ok(())
        }
        fn new_datagram(&self, _: StreamId, _: Bytes, _: ExtendedConnectType) {}
        fn datagram_outcome(&self, _: StreamId, _: DatagramOutcome, _: ExtendedConnectType) {}
    }

    /// A [`RecvStream`] that serves `data` and reports the stream FIN together with its final
    /// bytes, so `FrameReader` yields the frame with `fin = true`. This is the one case the
    /// integration harness can't produce, because neqo sends a capsule and its FIN as separate
    /// stream frames.
    #[derive(Debug)]
    struct FinWithFrameStream {
        data: Vec<u8>,
        offset: usize,
    }

    impl Stream for FinWithFrameStream {
        fn stream_type(&self) -> Http3StreamType {
            Http3StreamType::ExtendedConnect
        }
    }

    impl RecvStream for FinWithFrameStream {
        fn receive(&mut self, _conn: &mut Connection, _now: Instant) -> Res<(ReceiveOutput, bool)> {
            unreachable!()
        }
        fn reset(&mut self, _close_type: CloseType) -> Res<()> {
            unreachable!()
        }
        fn read_data(
            &mut self,
            _conn: &mut Connection,
            buf: &mut [u8],
            _now: Instant,
        ) -> Res<(usize, bool)> {
            let n = min(buf.len(), self.data.len() - self.offset);
            buf[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
            self.offset += n;
            Ok((n, self.offset == self.data.len()))
        }
    }

    /// draft-ietf-webtrans-http3-14 §4.7: a `WT_DRAIN_SESSION` capsule read together with the
    /// stream FIN drains and cleanly closes the session, returning `State::Done` and emitting a
    /// `Draining` event followed by a clean `SessionClosed` (error 0).
    #[test]
    fn drain_session_with_fin_ends_session() {
        let session_id = StreamId::new(0);
        let mut session = Session::new(session_id, Role::Client);

        let mut enc = Encoder::default();
        WebTransportFrame::DrainSession.encode(&mut enc);
        let mut recv: Box<dyn RecvStream> = Box::new(FinWithFrameStream {
            data: enc.into(),
            offset: 0,
        });

        let recorder = RecordingEvents::default();
        let mut events: Box<dyn ExtendedConnectEvents> = Box::new(recorder.clone());
        let mut conn = default_client();

        let state = session
            .read_control_stream(&mut conn, &mut events, &mut recv, now())
            .unwrap();

        assert_eq!(
            state,
            Some(State::Done),
            "capsule with FIN should transition the session to Done"
        );
        assert_eq!(
            *recorder.draining.borrow(),
            vec![session_id],
            "expected a single Draining event"
        );
        assert_eq!(
            *recorder.ended.borrow(),
            vec![(
                session_id,
                CloseReason::Clean {
                    error: 0,
                    message: String::new(),
                }
            )],
            "expected a clean SessionClosed with error 0"
        );
    }

    fn deliver_max_streams(
        session: &mut Session,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        stream_type: StreamType,
        maximum: u64,
    ) -> Res<Option<State>> {
        let mut enc = Encoder::default();
        WebTransportFrame::MaxStreams {
            stream_type,
            maximum,
        }
        .encode(&mut enc);
        let mut recv: Box<dyn RecvStream> = Box::new(FinWithFrameStream {
            data: enc.into(),
            offset: 0,
        });
        session.read_control_stream(conn, events, &mut recv, now())
    }

    /// draft-ietf-webtrans-http3-15 §5.6.2: a `WT_MAX_STREAMS` capsule with a value below one
    /// previously granted is a flow-control violation and must close the session with
    /// `WT_FLOW_CONTROL_ERROR`, even though the raising capsule that granted it did not itself
    /// carry a FIN.
    #[test]
    fn max_streams_capsule_decreasing_closes_session() {
        let session_id = StreamId::new(0);
        let mut session = Session::new(session_id, Role::Client);
        let recorder = RecordingEvents::default();
        let mut events: Box<dyn ExtendedConnectEvents> = Box::new(recorder.clone());
        let mut conn = default_client();

        let state = deliver_max_streams(&mut session, &mut conn, &mut events, StreamType::UniDi, 5)
            .unwrap();
        assert_eq!(state, None, "raising the limit must not end the session");

        let state = deliver_max_streams(&mut session, &mut conn, &mut events, StreamType::UniDi, 3)
            .unwrap();
        assert_eq!(
            state,
            Some(State::Done),
            "a decreasing MAX_STREAMS value must end the session"
        );
        assert_eq!(
            *recorder.ended.borrow(),
            vec![(session_id, CloseReason::Error(WT_FLOW_CONTROL_ERROR))],
            "expected SessionClosed with WT_FLOW_CONTROL_ERROR"
        );
    }

    /// draft-ietf-webtrans-http3-15 §5.6.2: a `WT_MAX_STREAMS` value that cannot be encoded as a
    /// stream ID (i.e. exceeds `1 << 60`) must be rejected as `H3_DATAGRAM_ERROR`, a connection
    /// error, not merely a session-level close.
    #[test]
    fn max_streams_capsule_exceeding_limit_is_datagram_error() {
        let session_id = StreamId::new(0);
        let mut session = Session::new(session_id, Role::Client);
        let recorder = RecordingEvents::default();
        let mut events: Box<dyn ExtendedConnectEvents> = Box::new(recorder.clone());
        let mut conn = default_client();

        let result = deliver_max_streams(
            &mut session,
            &mut conn,
            &mut events,
            StreamType::UniDi,
            WT_MAX_STREAMS_LIMIT + 1,
        );

        assert!(
            matches!(result, Err(Error::HttpDatagram)),
            "expected H3_DATAGRAM_ERROR for an unencodable MAX_STREAMS value, got {result:?}"
        );
        assert!(
            recorder.ended.borrow().is_empty(),
            "the session itself should not report a clean/graceful end for a connection error"
        );
    }
}
