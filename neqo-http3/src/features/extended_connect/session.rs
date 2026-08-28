// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    fmt::{self, Debug, Display, Formatter},
    rc::Rc,
    str::from_utf8,
    time::{Duration, Instant},
};

use neqo_common::{Bytes, Encoder, Header, MessageType, Role, qdebug, qtrace, to_u64};
use neqo_transport::{
    AppError, Connection, DatagramTracking, StreamId, StreamType, streams::SendGroupId,
};
use rustc_hash::FxHashSet as HashSet;

use crate::{
    CloseType, Error, Http3StreamType, HttpRecvStream, Priority, ReceiveOutput, RecvStream, Res,
    SendStream, Stream,
    features::extended_connect::{
        ExtendedConnectEvents, ExtendedConnectType, HeaderListener, Headers,
        datagram_queue::{
            DatagramId, DatagramOutcome, DatagramQueue, DatagramQueueCapacity,
            DatagramQueueOutcome, default_max_age,
        },
        stats::SessionStats,
    },
    frames::HFrame,
    priority::PriorityHandler,
    recv_message::{RecvMessage, RecvMessageInfo},
    send_message::SendMessage,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CloseReason {
    Error(AppError),
    Status(u16),
    Clean { error: u32, message: String },
}

impl From<CloseType> for CloseReason {
    fn from(close_type: CloseType) -> Self {
        match close_type {
            CloseType::ResetApp(e) | CloseType::ResetRemote(e) | CloseType::LocalError(e) => {
                Self::Error(e)
            }
            CloseType::Done => Self::Clean {
                error: 0,
                message: String::new(),
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct Session {
    control_stream_recv: Box<dyn RecvStream>,
    control_stream_send: Box<dyn SendStream>,
    stream_event_listener: Rc<RefCell<HeaderListener>>,
    id: StreamId,
    state: State,
    events: Box<dyn ExtendedConnectEvents>,
    /// Corresponds to the `:protocol` pseudo-header in the HTTP EXTENDED
    /// CONNECT request.
    protocol: Box<dyn Protocol>,
    draining: bool,
    /// Outgoing datagrams awaiting handover to the QUIC layer. Shared by every
    /// extended-CONNECT protocol; the queue itself is protocol-agnostic.
    datagram_queue: DatagramQueue,
    anticipated_incoming_uni: u16,
    anticipated_incoming_bidi: u16,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum State {
    Negotiating,
    Active,
    FinPending,
    Done,
}

impl State {
    pub(crate) const fn closing_state(self) -> bool {
        matches!(self, Self::FinPending | Self::Done)
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}-session={}", self.protocol.connect_type(), self.id)
    }
}

impl Session {
    #[must_use]
    pub(crate) fn new(
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
        qpack_encoder: Rc<RefCell<neqo_qpack::Encoder>>,
        qpack_decoder: Rc<RefCell<neqo_qpack::Decoder>>,
        connect_type: ExtendedConnectType,
    ) -> Self {
        let stream_event_listener = Rc::new(RefCell::new(HeaderListener::default()));
        let protocol = connect_type.new_protocol(session_id, role);
        Self {
            control_stream_recv: Box::new(RecvMessage::new(
                &RecvMessageInfo {
                    message_type: MessageType::Response,
                    stream_type: Http3StreamType::ExtendedConnect,
                    stream_id: session_id,
                    first_frame_type: None,
                },
                qpack_decoder,
                Box::new(Rc::clone(&stream_event_listener)),
                PriorityHandler::new(Priority::default()),
            )),
            control_stream_send: Box::new(SendMessage::new(
                MessageType::Request,
                Http3StreamType::ExtendedConnect,
                session_id,
                qpack_encoder,
                Box::new(Rc::clone(&stream_event_listener)),
            )),
            stream_event_listener,
            id: session_id,
            state: State::Negotiating,
            events,
            protocol,
            draining: false,
            datagram_queue: DatagramQueue::new(),
            anticipated_incoming_uni: 0,
            anticipated_incoming_bidi: 0,
        }
    }

    pub(crate) fn new_with_http_streams(
        session_id: StreamId,
        events: Box<dyn ExtendedConnectEvents>,
        role: Role,
        mut control_stream_recv: Box<dyn RecvStream>,
        mut control_stream_send: Box<dyn SendStream>,
        connect_type: ExtendedConnectType,
    ) -> Res<Self> {
        let stream_event_listener = Rc::new(RefCell::new(HeaderListener::default()));
        let protocol = connect_type.new_protocol(session_id, role);
        control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .set_new_listener(Box::new(Rc::clone(&stream_event_listener)));
        control_stream_send
            .http_stream()
            .ok_or(Error::Internal)?
            .set_new_listener(Box::new(Rc::clone(&stream_event_listener)));
        Ok(Self {
            control_stream_recv,
            control_stream_send,
            stream_event_listener,
            id: session_id,
            state: State::Active,
            events,
            protocol,
            draining: false,
            datagram_queue: DatagramQueue::new(),
            anticipated_incoming_uni: 0,
            anticipated_incoming_bidi: 0,
        })
    }

    /// Returns the type of this extended CONNECT session.
    pub(crate) fn connect_type(&self) -> ExtendedConnectType {
        self.protocol.connect_type()
    }

    /// Mark session as draining. Returns `true` if this was the first call
    /// (i.e. the session was not already draining).
    pub(crate) const fn set_draining(&mut self) -> bool {
        !std::mem::replace(&mut self.draining, true)
    }

    /// # Errors
    ///
    /// The function can only fail if supplied headers are not valid http headers.
    pub(crate) fn send_request(&mut self, headers: &[Header], conn: &mut Connection) -> Res<()> {
        qdebug!("[{self}]: send_request {headers:?}");
        self.control_stream_send
            .http_stream()
            .ok_or(Error::Internal)?
            .send_headers(headers, conn)
    }

    fn receive(&mut self, conn: &mut Connection, now: Instant) -> Res<(ReceiveOutput, bool)> {
        qtrace!("[{self}] receive control data");
        let (out, _) = self.control_stream_recv.receive(conn, now)?;
        debug_assert_eq!(out, ReceiveOutput::NoOutput);
        self.maybe_check_headers()?;
        self.read_control_stream(conn, now)?;
        Ok((ReceiveOutput::NoOutput, self.state == State::Done))
    }

    fn header_unblocked(
        &mut self,
        conn: &mut Connection,
        now: Instant,
    ) -> Res<(ReceiveOutput, bool)> {
        let (out, _) = self
            .control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .header_unblocked(conn, now)?;
        debug_assert_eq!(out, ReceiveOutput::NoOutput);
        self.maybe_check_headers()?;
        self.read_control_stream(conn, now)?;
        Ok((ReceiveOutput::NoOutput, self.state == State::Done))
    }

    fn maybe_update_priority(&mut self, priority: Priority) -> Res<bool> {
        self.control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .maybe_update_priority(priority)
    }

    fn priority_update_frame(&mut self) -> Option<HFrame> {
        self.control_stream_recv
            .http_stream()?
            .priority_update_frame()
    }

    fn priority_update_sent(&mut self) -> Res<()> {
        self.control_stream_recv
            .http_stream()
            .ok_or(Error::Internal)?
            .priority_update_sent()
    }

    fn send(&mut self, conn: &mut Connection, now: Instant) -> Res<()> {
        self.control_stream_send.send(conn, now)?;
        if self.control_stream_send.done() {
            self.state = State::Done;
        }
        Ok(())
    }

    fn close(&mut self, close_type: CloseType) {
        if self.state.closing_state() {
            return;
        }
        qdebug!("[{self}]: close session type={close_type:?}");
        self.state = State::Done;
        self.drop_queued_datagrams();
        if !close_type.locally_initiated() {
            self.events.session_end(
                self.protocol.connect_type(),
                self.id,
                CloseReason::from(close_type),
                None,
            );
        }
    }

    pub(crate) fn maybe_check_headers(&mut self) -> Res<()> {
        if self.state != State::Negotiating {
            return Ok(());
        }

        if let Some(Headers {
            headers,
            interim,
            fin,
        }) = self.stream_event_listener.borrow_mut().get_headers()
        {
            qtrace!("ExtendedConnect response headers {headers:?}, fin={fin}");

            if interim {
                if fin {
                    self.events.session_end(
                        self.protocol.connect_type(),
                        self.id,
                        CloseReason::Clean {
                            error: 0,
                            message: String::new(),
                        },
                        Some(headers),
                    );
                    self.state = State::Done;
                }
            } else {
                let status = headers
                    .iter()
                    .find_map(|h| {
                        if h.name() == ":status" {
                            from_utf8(h.value()).ok()?.parse::<u16>().ok()
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::Internal)?;

                self.state = if (200..300).contains(&status) {
                    if fin {
                        self.events.session_end(
                            self.protocol.connect_type(),
                            self.id,
                            CloseReason::Clean {
                                error: 0,
                                message: String::new(),
                            },
                            Some(headers),
                        );
                        State::Done
                    } else {
                        self.protocol.process_response_headers(&headers);

                        self.events.session_start(
                            self.protocol.connect_type(),
                            self.id,
                            status,
                            headers,
                        );
                        self.protocol.session_start(&mut self.events)?;
                        State::Active
                    }
                } else {
                    self.events.session_end(
                        self.protocol.connect_type(),
                        self.id,
                        CloseReason::Status(status),
                        Some(headers),
                    );
                    State::Done
                };
            }
        }
        Ok(())
    }

    pub(crate) fn add_stream(&mut self, stream_id: StreamId) -> Res<()> {
        self.protocol
            .add_stream(stream_id, &mut self.events, self.state)
    }

    pub(crate) fn remove_recv_stream(&mut self, stream_id: StreamId) {
        self.protocol.remove_recv_stream(stream_id);
    }

    pub(crate) fn remove_send_stream(&mut self, stream_id: StreamId) {
        self.protocol.remove_send_stream(stream_id);
    }

    #[must_use]
    pub(crate) const fn is_active(&self) -> bool {
        matches!(self.state, State::Active)
    }

    #[must_use]
    pub(crate) const fn is_closing(&self) -> bool {
        self.state.closing_state()
    }

    pub(crate) fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        self.protocol.take_sub_streams()
    }

    /// # Errors
    ///
    /// It may return an error if the frame is not correctly decoded.
    pub(crate) fn read_control_stream(&mut self, conn: &mut Connection, now: Instant) -> Res<()> {
        qdebug!("[{self}]: read_control_stream");
        if let Some(new_state) = self.protocol.read_control_stream(
            conn,
            &mut self.events,
            &mut self.control_stream_recv,
            now,
        )? {
            if new_state.closing_state() {
                self.drop_queued_datagrams();
            }
            self.state = new_state;
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Return an error if the stream was closed on the transport layer, but that information is not
    /// yet consumed on the http/3 layer.
    pub(crate) fn close_session(
        &mut self,
        conn: &mut Connection,
        error: u32,
        message: &str,
        now: Instant,
    ) -> Res<()> {
        qdebug!("[{self}]: close_session");
        self.state = State::Done;
        self.drop_queued_datagrams();

        if let Some(close_frame) = self.protocol.close_frame(error, message) {
            self.control_stream_send
                .send_data_atomic(conn, close_frame.as_ref(), now)?;
        }

        self.control_stream_send.close(conn, now)?;
        self.state = if self.control_stream_send.done() {
            State::Done
        } else {
            State::FinPending
        };
        Ok(())
    }

    fn send_data(&mut self, conn: &mut Connection, buf: &[u8], now: Instant) -> Res<usize> {
        self.control_stream_send.send_data(conn, buf, now)
    }

    /// Enqueue a datagram for sending.
    ///
    /// The datagram is placed into the per-session datagram queue and will be
    /// moved to the QUIC send queue when `process_datagram_queue()` is called
    /// (which happens during `process_http3()` as part of `process_output()`).
    /// The caller must ensure `process_output()` is called afterward to
    /// actually transmit the datagram.
    ///
    /// Returns the state of the queue after the datagram was accepted, so the
    /// caller can apply backpressure (see `DatagramQueueOutcome`).
    ///
    /// When the peer only supports the HTTP DATAGRAM Capsule fallback (no
    /// QUIC DATAGRAM support), the capsule is written straight to the
    /// control stream instead of going through the queue: the returned
    /// `DatagramQueueOutcome` is always `Ok` on that path and carries no
    /// backpressure signal, and a resulting `DatagramOutcome::Sent` means
    /// only "written to the control stream", not "accepted by
    /// `Connection::send_datagram`" as it does on the queued path.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The encoded datagram exceeds the peer's `max_datagram_frame_size`
    ///   (`Error::Transport(neqo_transport::Error::TooMuchData)`).
    /// - The session is not in Active state (`Error::Unavailable`).
    /// - The peer supports neither QUIC DATAGRAM nor the HTTP DATAGRAM Capsule
    ///   (`Error::Transport(neqo_transport::Error::NotAvailable)`).
    /// - HTTP DATAGRAM Capsule sending fails.
    pub(crate) fn send_datagram<I: Into<DatagramTracking>>(
        &mut self,
        conn: &mut Connection,
        buf: &[u8],
        id: I,
        now: Instant,
        send_group_id: u64,
        send_order: i64,
    ) -> Res<DatagramQueueOutcome> {
        qtrace!("[{self}] send_datagram state={:?}", self.state);
        if self.state != State::Active {
            qdebug!("[{self}]: cannot send datagram in {:?} state.", self.state);
            return Err(Error::Unavailable);
        }
        let remote_datagram_size = conn.remote_datagram_size();
        if remote_datagram_size == 0 {
            if self.protocol.datagram_capsule_support() {
                qtrace!("[{self}] remote_datagram_size is 0, trying HTTP DATAGRAM Capsule");
                self.protocol.write_datagram_capsule(
                    &mut self.control_stream_send,
                    conn,
                    buf,
                    now,
                )?;
                if let DatagramTracking::Id(id) = id.into() {
                    self.report_datagram_outcome(DatagramOutcome::Sent(id));
                }
                return Ok(DatagramQueueOutcome::Ok);
            }
            qdebug!("[{self}] peer does not support QUIC DATAGRAM");
            return Err(Error::Transport(neqo_transport::Error::NotAvailable));
        }

        let mut dgram_data = Encoder::default();
        dgram_data.encode_varint(self.id.as_u64() / 4);
        self.protocol.write_datagram_prefix(&mut dgram_data);
        dgram_data.encode(buf);

        if to_u64(dgram_data.len()) > remote_datagram_size {
            return Err(Error::Transport(neqo_transport::Error::TooMuchData));
        }

        let id_opt = match id.into() {
            DatagramTracking::Id(id_val) => Some(id_val),
            DatagramTracking::None => None,
        };

        // Expire before enqueueing: otherwise a queue full of stale datagrams
        // evicts one on `enqueue` below and reports `Overflowed`/`Dropped`
        // for it, when it should have been reported `Expired`.
        let expired = self
            .datagram_queue
            .expire(now, default_max_age(conn.stats().min_rtt));
        for outcome in self.record_expired(expired) {
            self.report_datagram_outcome(outcome);
        }

        let outcome = self.datagram_queue.enqueue(
            Vec::<u8>::from(dgram_data),
            id_opt,
            now,
            send_group_id,
            send_order,
        );
        if let DatagramQueueOutcome::Overflowed { dropped } = &outcome {
            self.count_dropped_outgoing(to_u64(dropped.len()));
            for id in dropped.iter().flatten() {
                self.report_datagram_outcome(DatagramOutcome::Dropped(*id));
            }
        }
        qtrace!("[{self}] enqueued datagram for sending via QUIC datagram");
        Ok(outcome)
    }

    /// Count every expired datagram and report an outcome for the tracked ones.
    ///
    /// Untracked datagrams (`None`) get no outcome, but must still be counted:
    /// the stat is the number of datagrams that expired, not the number the
    /// application asked to be notified about.
    fn record_expired(&mut self, expired: Vec<Option<DatagramId>>) -> Vec<DatagramOutcome> {
        if let Some(stats) = self.protocol.stats_mut() {
            stats.datagrams_expired_outgoing += to_u64(expired.len());
        }
        expired
            .into_iter()
            .flatten()
            .map(DatagramOutcome::Expired)
            .collect()
    }

    /// Report an outcome through this session's own `events`/`connect_type`,
    /// rather than returning it to the caller: keeps a connect-udp session's
    /// outcomes from being mis-tagged as `WebTransport` by a caller that
    /// only knows about `WebTransport`.
    fn report_datagram_outcome(&self, outcome: DatagramOutcome) {
        self.events
            .datagram_outcome(self.id, outcome, self.protocol.connect_type());
    }

    /// Count every datagram discarded without being sent and without
    /// expiring, tracked or not: [`Self::report_datagram_outcome`] only
    /// fires for tracked ones, but the stat must reflect all of them.
    fn count_dropped_outgoing(&mut self, n: u64) {
        if let Some(stats) = self.protocol.stats_mut() {
            stats.datagrams_dropped_outgoing += n;
        }
    }

    /// Drain the per-session datagram queue and hand datagrams to the QUIC layer.
    ///
    /// `budget` bounds how many datagrams are handed over this call; the rest
    /// stay queued for a later call, so that a burst is paced against what
    /// the connection can send instead of overflowing the QUIC layer's
    /// fixed-size queue. See [`DatagramQueue::drain`]. The caller - which may
    /// be sharing the connection's transport-level capacity fairly across
    /// several sessions - is responsible for choosing `budget`; this does
    /// not clamp it against
    /// [`Connection::remaining_datagram_queue_capacity`][neqo_transport::Connection::remaining_datagram_queue_capacity]
    /// itself.
    ///
    /// A no-op once the session is no longer `Active`: nothing enqueues new
    /// datagrams past that point, and any already queued are dropped and
    /// reported by [`Self::close`]/[`Self::close_session`], not handed to a
    /// `conn.send_datagram()` the peer has already been told is closed.
    ///
    /// Outcomes are reported directly through this session's own `events` and
    /// `connect_type`, rather than returned to the caller, so a connect-udp
    /// session's outcomes can't be mis-tagged as `WebTransport` by a caller
    /// that only knows about `WebTransport`.
    pub(crate) fn process_datagram_queue(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        budget: usize,
    ) {
        if self.state != State::Active {
            return;
        }

        let (expired, to_send) =
            self.datagram_queue
                .drain(now, budget, default_max_age(conn.stats().min_rtt));
        for outcome in self.record_expired(expired) {
            self.report_datagram_outcome(outcome);
        }

        for dgram in to_send {
            let tracking = dgram
                .id
                .map_or(DatagramTracking::None, DatagramTracking::Id);
            // A datagram the QUIC layer refuses is gone: `drain` already removed it
            // from the queue. Report it so the application isn't left waiting, and
            // keep going, since a later datagram may still be small enough to fit.
            let outcome = match conn.send_datagram(dgram.data, tracking) {
                Ok(()) => DatagramOutcome::Sent,
                Err(e) => {
                    qdebug!("[{self}] QUIC layer refused datagram {:?}: {e}", dgram.id);
                    self.count_dropped_outgoing(1);
                    DatagramOutcome::Dropped
                }
            };
            if let Some(id) = dgram.id {
                self.report_datagram_outcome(outcome(id));
            }
        }
    }

    /// Drop every datagram still queued when the session closes, reporting
    /// each tracked one so the application isn't left waiting for an outcome
    /// that will never come once nothing will call
    /// [`Self::process_datagram_queue`] again.
    fn drop_queued_datagrams(&mut self) {
        let dropped = self.datagram_queue.take_all();
        self.count_dropped_outgoing(to_u64(dropped.len()));
        for id in dropped.into_iter().filter_map(|d| d.id) {
            self.report_datagram_outcome(DatagramOutcome::Dropped(id));
        }
    }

    /// The instant at which this session's datagram queue next needs
    /// [`Self::process_datagram_queue`] called to expire a stale datagram.
    /// See [`DatagramQueue::next_expiry`].
    pub(crate) fn next_datagram_expiry(&self, conn: &Connection) -> Option<Instant> {
        self.datagram_queue
            .next_expiry(default_max_age(conn.stats().min_rtt))
    }

    pub(crate) fn set_datagram_high_water_mark(&mut self, mark: Option<usize>) {
        self.datagram_queue.set_high_water_mark(mark);
    }

    pub(crate) const fn datagram_queue_capacity(&self) -> DatagramQueueCapacity {
        self.datagram_queue.capacity()
    }

    pub(crate) fn set_datagram_max_age(
        &mut self,
        max_age: Option<Duration>,
        now: Instant,
        default_max_age: Duration,
    ) {
        let expired = self
            .datagram_queue
            .set_max_age(max_age, now, default_max_age);
        for outcome in self.record_expired(expired) {
            self.report_datagram_outcome(outcome);
        }
    }

    pub(crate) const fn set_anticipated_incoming(&mut self, stream_type: StreamType, value: u16) {
        match stream_type {
            StreamType::UniDi => self.anticipated_incoming_uni = value,
            StreamType::BiDi => self.anticipated_incoming_bidi = value,
        }
    }

    pub(crate) const fn anticipated_incoming(&self, stream_type: StreamType) -> u16 {
        match stream_type {
            StreamType::UniDi => self.anticipated_incoming_uni,
            StreamType::BiDi => self.anticipated_incoming_bidi,
        }
    }

    pub(crate) fn datagram(&self, datagram: Bytes) {
        if self.state != State::Active {
            qdebug!("[{self}]: received datagram on {:?} session.", self.state);
            return;
        }

        // dgram_context_id returns the payload after stripping any context ID
        match self.protocol.dgram_context_id(datagram) {
            Ok(slice) => {
                self.events
                    .new_datagram(self.id, slice, self.protocol.connect_type());
            }
            Err(e) => {
                qdebug!("[{self}]: received datagram with invalid context identifier: {e}");
            }
        }
    }

    pub(crate) fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        self.protocol.validate_send_group(group_id)
    }

    pub(crate) fn local_stream_count(&self, stream_type: StreamType) -> u64 {
        self.protocol.local_stream_count(stream_type)
    }

    pub(crate) fn remote_stream_count(&self, stream_type: StreamType) -> u64 {
        self.protocol.remote_stream_count(stream_type)
    }

    pub(crate) fn granted_max_streams(&self, stream_type: StreamType) -> Option<u64> {
        self.protocol.granted_max_streams(stream_type)
    }

    /// Session statistics, for protocols that track them (only `WebTransport`).
    #[must_use]
    pub(crate) fn stats(&self) -> Option<SessionStats> {
        self.protocol.stats().copied()
    }

    fn has_data_to_send(&self) -> bool {
        self.control_stream_send.has_data_to_send()
    }

    fn done(&self) -> bool {
        self.state == State::Done
    }
}

impl Stream for Rc<RefCell<Session>> {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::ExtendedConnect
    }

    fn session_protocol(&self) -> Option<String> {
        self.borrow().protocol.protocol().map(ToString::to_string)
    }

    fn register_send_group(&mut self, id: SendGroupId) -> Res<()> {
        self.borrow_mut().protocol.register_send_group(id)
    }

    fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        self.borrow().protocol.validate_send_group(group_id)
    }
}

impl RecvStream for Rc<RefCell<Session>> {
    fn receive(&mut self, conn: &mut Connection, now: Instant) -> Res<(ReceiveOutput, bool)> {
        self.borrow_mut().receive(conn, now)
    }

    fn reset(&mut self, close_type: CloseType) -> Res<()> {
        self.borrow_mut().close(close_type);
        Ok(())
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        Some(self)
    }

    fn extended_connect_session(&self) -> Option<Rc<RefCell<Session>>> {
        Some(Self::clone(self))
    }
}

impl HttpRecvStream for Rc<RefCell<Session>> {
    fn header_unblocked(
        &mut self,
        conn: &mut Connection,
        now: Instant,
    ) -> Res<(ReceiveOutput, bool)> {
        self.borrow_mut().header_unblocked(conn, now)
    }

    fn maybe_update_priority(&mut self, priority: Priority) -> Res<bool> {
        self.borrow_mut().maybe_update_priority(priority)
    }

    fn priority_update_frame(&mut self) -> Option<HFrame> {
        self.borrow_mut().priority_update_frame()
    }

    fn priority_update_sent(&mut self) -> Res<()> {
        self.borrow_mut().priority_update_sent()
    }
}

impl SendStream for Rc<RefCell<Session>> {
    fn send(&mut self, conn: &mut Connection, now: Instant) -> Res<()> {
        self.borrow_mut().send(conn, now)
    }

    fn send_data(&mut self, conn: &mut Connection, buf: &[u8], now: Instant) -> Res<usize> {
        self.borrow_mut().send_data(conn, buf, now)
    }

    fn has_data_to_send(&self) -> bool {
        self.borrow_mut().has_data_to_send()
    }

    fn stream_writable(&self) {}

    fn done(&self) -> bool {
        self.borrow_mut().done()
    }

    fn close(&mut self, conn: &mut Connection, now: Instant) -> Res<()> {
        self.borrow_mut().close_session(conn, 0, "", now)
    }

    fn close_with_message(
        &mut self,
        conn: &mut Connection,
        error: u32,
        message: &str,
        now: Instant,
    ) -> Res<()> {
        self.borrow_mut().close_session(conn, error, message, now)
    }

    fn handle_stop_sending(&mut self, close_type: CloseType) {
        self.borrow_mut().close(close_type);
    }
}

/// An extended connect protocol.
///
/// "Protocol" here corresponds to the `:protocol` pseudo header in the HTTP
/// Extended CONNECT method.
pub(crate) trait Protocol: Debug + Display {
    fn connect_type(&self) -> ExtendedConnectType;

    fn session_start(&mut self, _events: &mut Box<dyn ExtendedConnectEvents>) -> Res<()> {
        Ok(())
    }

    fn close_frame(&self, _error: u32, _message: &str) -> Option<Vec<u8>> {
        None
    }

    fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
        now: Instant,
    ) -> Res<Option<State>>;

    fn add_stream(
        &mut self,
        _stream_id: StreamId,
        _events: &mut Box<dyn ExtendedConnectEvents>,
        _state: State,
    ) -> Res<()> {
        let msg = "Protocol does not support adding streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
        Ok(())
    }

    fn remove_recv_stream(&mut self, _stream_id: StreamId) {
        let msg = "Protocol does not support removing recv streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
    }

    fn remove_send_stream(&mut self, _stream_id: StreamId) {
        let msg = "Protocol does not support removing send streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
    }

    fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        (HashSet::default(), HashSet::default())
    }

    fn process_response_headers(&mut self, _headers: &[Header]) {}

    /// Per-session statistics, for protocols that expose them.
    ///
    /// Only `WebTransport` surfaces session statistics to the API consumer, so
    /// every other protocol leaves this at `None` and the counters above are
    /// simply not recorded.
    /// Callers reach this only after checking the session is `WebTransport`, so
    /// a protocol without stats never gets here.
    fn stats(&self) -> Option<&SessionStats> {
        debug_assert!(
            false,
            "stats called for extended connect protocol not tracking stats"
        );
        None
    }

    fn stats_mut(&mut self) -> Option<&mut SessionStats> {
        None
    }

    fn protocol(&self) -> Option<&str> {
        None
    }

    fn register_send_group(&mut self, _id: SendGroupId) -> Res<()> {
        Err(Error::InvalidStreamId)
    }

    fn validate_send_group(&self, _group_id: SendGroupId) -> bool {
        false
    }

    fn local_stream_count(&self, _stream_type: StreamType) -> u64 {
        0
    }

    fn remote_stream_count(&self, _stream_type: StreamType) -> u64 {
        0
    }

    fn granted_max_streams(&self, _stream_type: StreamType) -> Option<u64> {
        None
    }

    fn write_datagram_prefix(&self, encoder: &mut Encoder);

    fn dgram_context_id(&self, datagram: Bytes) -> Result<Bytes, DgramContextIdError>;

    /// Whether the extended CONNECT protocol supports sending datagrams as HTTP
    /// DATAGRAM Capsules when QUIC datagrams are unavailable.
    fn datagram_capsule_support(&self) -> bool;

    /// Write a datagram as an HTTP DATAGRAM Capsule to the control stream.
    fn write_datagram_capsule(
        &self,
        _control_stream_send: &mut Box<dyn SendStream>,
        _conn: &mut Connection,
        _buf: &[u8],
        _now: Instant,
    ) -> Res<()>;
}

#[derive(Debug, Error)]
pub(crate) enum DgramContextIdError {
    #[error("Missing context identifier")]
    MissingIdentifier,
    #[error("Unknown context identifier: {0}")]
    UnknownIdentifier(u64),
}
