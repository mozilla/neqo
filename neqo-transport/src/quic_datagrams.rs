// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Outbound QUIC datagram queueing and backpressure:
//!
//! [`QuicDatagrams::add_datagram`] queues the datagram (unless it exceeds the
//! peer's datagram-size limit) and reports whether the queue still had room:
//! `Ok(true)` if so, or `Ok(false)` once a send has filled it. `Ok(false)` is a
//! high-watermark signal to stop, not a rejection: the datagram is still queued
//! and nothing already queued is dropped. A single [`OutgoingDatagramSpaceAvailable`]
//! event fires once the queue drops back below capacity, whether a slot was freed
//! by sending a datagram or by dropping one too big for any packet.
//!
//! [`OutgoingDatagramSpaceAvailable`]: crate::ConnectionEvent::OutgoingDatagramSpaceAvailable

// https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram

use std::{
    cmp::min,
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use neqo_common::{Buffer, Encoder, qdebug, qtrace, to_u64};

use crate::{
    ConnectionEvents, Error, Res, Stats,
    datagram_queue::{
        DatagramId, DatagramQueue, DatagramQueueCapacity, DatagramQueueOutcome, QueuedDatagram,
    },
    events::OutgoingDatagramOutcome,
    frame::{FrameEncoder as _, FrameType},
    packet, recovery,
    stream_id::StreamId,
    streams::{SendGroupId, SendOrder},
};

/// Length of a [`FrameType::Datagram`] or [`FrameType::DatagramWithLen`] in
/// QUIC varint encoding.
pub const DATAGRAM_FRAME_TYPE_VARINT_LEN: usize = 1;
static_assertions::const_assert_eq!(
    Encoder::varint_len(FrameType::Datagram as u64),
    DATAGRAM_FRAME_TYPE_VARINT_LEN
);
static_assertions::const_assert_eq!(
    Encoder::varint_len(FrameType::DatagramWithLen as u64),
    DATAGRAM_FRAME_TYPE_VARINT_LEN
);

#[derive(Debug, Clone, Copy)]
pub enum DatagramTracking {
    None,
    Id(u64),
}

impl From<Option<u64>> for DatagramTracking {
    fn from(v: Option<u64>) -> Self {
        v.map_or(Self::None, Self::Id)
    }
}

pub struct QuicDatagram {
    data: Vec<u8>,
    tracking: DatagramTracking,
}

impl QuicDatagram {
    pub const MAX_SIZE: u64 = 65535;

    const fn tracking(&self) -> &DatagramTracking {
        &self.tracking
    }
}

impl AsRef<[u8]> for QuicDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}

pub struct QuicDatagrams {
    /// The max size of a datagram that would be acceptable.
    local_datagram_size: u64,
    /// The max size of a datagram that would be acceptable by the peer.
    remote_datagram_size: u64,
    max_queued_outgoing_datagrams: usize,
    /// Set once a send fills the queue; cleared when a freed slot emits the
    /// resume event. See the [module documentation](self).
    blocked: bool,
    /// Datagram queued for sending via [`Self::add_datagram`]: a plain,
    /// count-bounded FIFO with no per-session tracking, priority, or age
    /// policy, for callers that don't need any of that.
    datagrams: VecDeque<QuicDatagram>,
    /// Per-session outgoing-datagram queues (byte budget, high-water-mark,
    /// send-group/send-order priority, max-age), keyed by an opaque `u64`
    /// handle. In practice this is the session's control-stream `StreamId`,
    /// but `QuicDatagrams` treats it as an opaque tag — this does not give
    /// transport a "session" concept, any more than [`crate::send_stream::
    /// SendStreams`] keying per-stream priority state by `StreamId` does.
    ///
    /// An entry is created lazily on first use and only removed by
    /// [`Self::drop_session_datagrams`] (session teardown) — *not* whenever
    /// it happens to drain empty, since a temporarily empty queue can still
    /// carry an application-set high-water-mark/max-age that must survive
    /// until the session closes.
    queues: BTreeMap<StreamId, DatagramQueue>,
    /// Session at which the next cross-session round-robin round starts.
    /// See [`Self::next_active_session_from`].
    queue_rr_next: StreamId,
    conn_events: ConnectionEvents,
}

impl QuicDatagrams {
    pub fn new(
        local_datagram_size: u64,
        max_queued_outgoing_datagrams: usize,
        conn_events: ConnectionEvents,
    ) -> Self {
        Self {
            local_datagram_size,
            remote_datagram_size: 0,
            max_queued_outgoing_datagrams,
            blocked: false,
            datagrams: VecDeque::with_capacity(max_queued_outgoing_datagrams),
            queues: BTreeMap::new(),
            queue_rr_next: StreamId::new(0),
            conn_events,
        }
    }

    pub const fn remote_datagram_size(&self) -> u64 {
        self.remote_datagram_size
    }

    pub fn set_remote_datagram_size(&mut self, v: u64) {
        self.remote_datagram_size = min(v, QuicDatagram::MAX_SIZE);
    }

    /// Encode a single datagram payload that is already known to fit
    /// (`len + DATAGRAM_FRAME_TYPE_VARINT_LEN <= builder.remaining()`).
    fn encode_datagram<B: Buffer>(
        data: &[u8],
        tracking: DatagramTracking,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
    ) {
        let len = data.len();
        let length_len = Encoder::varint_len(to_u64(len));
        // Include a length if there is space for another frame after this one.
        if builder.remaining()
            >= DATAGRAM_FRAME_TYPE_VARINT_LEN
                + length_len
                + len
                + packet::Builder::MINIMUM_FRAME_SIZE
        {
            builder.encode_frame(FrameType::DatagramWithLen, |b| {
                b.encode_vvec(data);
            });
        } else {
            builder.encode_frame(FrameType::Datagram, |b| {
                b.encode(data);
            });
            builder.mark_full();
        }
        debug_assert!(builder.len() <= builder.limit());
        stats.frame_tx.datagram += 1;
        tokens.push(recovery::Token::Datagram(tracking));
    }

    /// This function tries to write a datagram frame into a packet. If the
    /// frame does not fit into the packet, the datagram will be dropped and a
    /// [`OutgoingDatagramOutcome::DroppedTooBig`] event will be posted.
    ///
    /// Drains `datagrams` first (see its doc), then round-robins across the
    /// per-session [`DatagramQueue`]s in `queues`, one datagram at a time,
    /// expiry-and-priority-ordered within each. Both loops stop, without
    /// consuming anything further, the moment something does not fit into
    /// an otherwise non-empty packet — that datagram stays queued for the
    /// next `process_output` call rather than being round-tripped out and
    /// back in.
    pub fn write_frames<B: Buffer>(
        &mut self,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
    ) {
        while let Some(dgram) = self.datagrams.pop_front() {
            let len = dgram.as_ref().len();
            if len + DATAGRAM_FRAME_TYPE_VARINT_LEN <= builder.remaining() {
                Self::encode_datagram(dgram.as_ref(), *dgram.tracking(), builder, tokens, stats);
                qtrace!(
                    "Sent QUIC datagram, {} remaining in queue.",
                    self.datagrams.len()
                );
            } else if tokens.is_empty() {
                // If the packet is empty, except packet headers, and the
                // datagram cannot fit, drop it.
                // Also continue trying to write the next QuicDatagram.
                qdebug!(
                    "QUIC datagram ({}) does not fit MTU, dropping it, {} remaining in queue.",
                    dgram.data.len(),
                    self.datagrams.len()
                );
                self.conn_events
                    .datagram_outcome(dgram.tracking(), OutgoingDatagramOutcome::DroppedTooBig);
                stats.datagram_tx.dropped_too_big += 1;
            } else {
                self.datagrams.push_front(dgram);
                // The datagram did not fit and no slot was freed, so leave the
                // queue as is and try later on an emptier packet.
                break;
            }
        }
        // A send or drop above may have freed a slot and brought the queue below
        // capacity; resume a blocked application if so. See the module docs.
        if self.blocked && self.datagrams.len() < self.max_queued_outgoing_datagrams {
            self.blocked = false;
            self.conn_events.datagram_space_available();
        }

        loop {
            let Some(session) = self.next_active_session_from(self.queue_rr_next) else {
                return;
            };
            let queue = self
                .queues
                .get(&session)
                .expect("next_active_session_from only returns known sessions");
            let Some(len) = queue.peek_next_len() else {
                unreachable!("next_active_session_from only returns non-empty sessions")
            };
            if len + DATAGRAM_FRAME_TYPE_VARINT_LEN <= builder.remaining() {
                let dgram = self.take_from_session_queue(session);
                Self::encode_datagram(&dgram.data, dgram.id.into(), builder, tokens, stats);
            } else if tokens.is_empty() {
                let dgram = self.take_from_session_queue(session);
                qdebug!("QUIC datagram ({}) does not fit MTU.", dgram.data.len());
                self.conn_events
                    .datagram_outcome(&dgram.id.into(), OutgoingDatagramOutcome::DroppedTooBig);
                stats.datagram_tx.dropped_too_big += 1;
            } else {
                // Leave it queued; try again on a later, emptier packet.
                return;
            }
        }
    }

    /// Starting at `start` and wrapping around, the first session with a
    /// non-empty queue. Unlike the inner per-session `DatagramQueue`'s own
    /// group map, `queues` keeps empty entries around (see its doc comment),
    /// so this filters emptiness explicitly rather than relying on every
    /// entry present being non-empty.
    fn next_active_session_from(&self, start: StreamId) -> Option<StreamId> {
        self.queues
            .range(start..)
            .chain(self.queues.range(..start))
            .find(|(_, q)| !q.is_empty())
            .map(|(id, _)| *id)
    }

    /// Take the next datagram off `session`'s queue, resuming a blocked
    /// sender and advancing the round-robin cursor past it. Must only be
    /// called immediately after a [`DatagramQueue::peek_next_len`] on the
    /// same session that returned `Some`, with no other mutation in between.
    fn take_from_session_queue(&mut self, session: StreamId) -> QueuedDatagram {
        let queue = self
            .queues
            .get_mut(&session)
            .expect("next_active_session_from only returns known sessions");
        let dgram = queue
            .take_next()
            .expect("just peeked Some above, with no intervening mutation");
        if queue.resume_if_unblocked() {
            self.conn_events.datagram_space_available();
        }
        self.queue_rr_next = StreamId::new(session.as_u64().wrapping_add(1));
        dgram
    }

    /// Get or lazily create `session`'s queue.
    fn queue_mut(&mut self, session: StreamId) -> &mut DatagramQueue {
        self.queues.entry(session).or_default()
    }

    /// Enqueue a datagram on `session`'s outgoing queue. See
    /// [`DatagramQueue::enqueue`].
    pub fn enqueue_datagram(
        &mut self,
        session: StreamId,
        data: Vec<u8>,
        id: Option<DatagramId>,
        now: Instant,
        send_group_id: SendGroupId,
        send_order: SendOrder,
    ) -> DatagramQueueOutcome {
        self.queue_mut(session)
            .enqueue(data, id, now, send_group_id, send_order)
    }

    /// See [`DatagramQueue::set_high_water_mark`].
    pub fn set_datagram_high_water_mark(&mut self, session: StreamId, mark: Option<usize>) {
        self.queue_mut(session).set_high_water_mark(mark);
    }

    /// See [`DatagramQueue::set_max_queued_bytes`].
    pub fn set_datagram_max_queued_bytes(&mut self, session: StreamId, bytes: usize) {
        self.queue_mut(session).set_max_queued_bytes(bytes);
    }

    /// See [`DatagramQueue::set_max_age`].
    pub fn set_datagram_max_age(
        &mut self,
        session: StreamId,
        max_age: Option<Duration>,
        now: Instant,
        default_max_age: Duration,
    ) -> Vec<Option<DatagramId>> {
        let queue = self.queue_mut(session);
        let expired = queue.set_max_age(max_age, now, default_max_age);
        // Shrinking the limit can expire enough to put a blocked queue back
        // under its high water mark, and nothing else will revisit it.
        if queue.resume_if_unblocked() {
            self.conn_events.datagram_space_available();
        }
        expired
    }

    /// See [`DatagramQueue::capacity`].
    #[must_use]
    pub fn datagram_queue_capacity(&self, session: StreamId) -> DatagramQueueCapacity {
        self.queues.get(&session).map_or_else(
            || DatagramQueue::default().capacity(),
            DatagramQueue::capacity,
        )
    }

    /// Remove every datagram queued on `session`'s behalf, e.g. because the
    /// session is closing. Returns one entry per removed datagram, `Some(id)`
    /// for tracked ones, for the caller to report a `Dropped` outcome for.
    pub fn drop_session_datagrams(&mut self, session: StreamId) -> Vec<Option<DatagramId>> {
        self.queues.remove(&session).map_or_else(Vec::new, |mut q| {
            q.take_all().into_iter().map(|d| d.id).collect()
        })
    }

    /// The instant at which the oldest datagram queued on any session
    /// crosses its effective max-age, if any session has one queued.
    #[must_use]
    pub fn next_datagram_expiry(&self, default_max_age: Duration) -> Option<Instant> {
        self.queues
            .values()
            .filter_map(|q| q.next_expiry(default_max_age))
            .min()
    }

    /// Expire stale datagrams on every session's queue, returning one entry
    /// per expired datagram across all sessions (`Some(id)` for tracked
    /// ones). Not gated on there being anything else to do: expiry is not a
    /// send, so it must happen even when nothing else is scheduled (see
    /// [`DatagramQueue::expire`]'s doc comment).
    ///
    /// Nothing currently reads the returned IDs outside tests, but a
    /// caller that wants to report per-datagram outcomes can use them.
    ///
    /// Expiry is the *expected* way one of these queues sheds load, so this
    /// is also where a blocked sender is usually resumed: a queue whose
    /// datagrams all expire while the application waits is never revisited
    /// by a send, and the wait would never end.
    pub fn expire_datagrams(
        &mut self,
        now: Instant,
        default_max_age: Duration,
    ) -> Vec<Option<DatagramId>> {
        let mut expired = Vec::new();
        let mut resume = false;
        for queue in self.queues.values_mut() {
            expired.extend(queue.expire(now, default_max_age));
            resume |= queue.resume_if_unblocked();
        }
        if resume {
            self.conn_events.datagram_space_available();
        }
        expired
    }

    /// Queue a datagram for sending. See the [module documentation](self) for
    /// the backpressure contract.
    ///
    /// Returns `Ok(true)` if the queue still has room afterwards, or `Ok(false)`
    /// if this datagram filled it. The datagram is queued in either case.
    ///
    /// # Error
    ///
    /// Returns `TooMuchData` if the supply buffer is bigger than the allowed
    /// remote datagram size. Whether the datagram fits into a packet (the MTU
    /// limit) is only checked at send time, where it is dropped if it does not.
    pub fn add_datagram(&mut self, data: Vec<u8>, tracking: DatagramTracking) -> Res<bool> {
        if to_u64(data.len()) > self.remote_datagram_size {
            qdebug!(
                "QUIC datagram exceeds remote limit, dropping it, datagram size {}, remote datagram size limit {}.",
                data.len(),
                self.remote_datagram_size
            );
            return Err(Error::TooMuchData);
        }
        self.datagrams.push_back(QuicDatagram { data, tracking });
        if self.datagrams.len() < self.max_queued_outgoing_datagrams {
            return Ok(true);
        }
        qdebug!(
            "QUIC datagram queue full (len {} / max {}), applying backpressure.",
            self.datagrams.len(),
            self.max_queued_outgoing_datagrams
        );
        self.blocked = true;
        Ok(false)
    }

    pub fn handle_datagram(&self, data: &[u8]) -> Res<()> {
        // A `local_datagram_size` of 0 means we advertised a
        // max_datagram_frame_size of 0, i.e. no DATAGRAM frame support
        // (RFC 9221, Section 3).
        if self.local_datagram_size == 0 || self.local_datagram_size < to_u64(data.len()) {
            return Err(Error::ProtocolViolation);
        }
        self.conn_events.add_datagram(data);
        Ok(())
    }
}
