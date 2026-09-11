// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Outbound QUIC datagram queueing and backpressure: see
//! [`crate::datagram_queue`] for the per-session queue's own byte-budget and
//! high-water-mark contract. [`QuicDatagrams`] holds one such queue per
//! session and round-robins between them at packet-build time.

// https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram

use std::{
    cmp::min,
    collections::BTreeMap,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use neqo_common::{Buffer, Encoder, qdebug, to_u64};

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

/// The protocol maximum size of a QUIC datagram (RFC 9221).
pub const MAX_DATAGRAM_SIZE: u64 = 65535;

pub struct QuicDatagrams {
    /// The max size of a datagram that would be acceptable.
    local_datagram_size: u64,
    /// The max size of a datagram that would be acceptable by the peer.
    remote_datagram_size: u64,
    /// Per-session outgoing-datagram queues (byte budget, high-water-mark,
    /// send-group/send-order priority, max-age), keyed by the session's control stream ID.
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
    pub const fn new(local_datagram_size: u64, conn_events: ConnectionEvents) -> Self {
        Self {
            local_datagram_size,
            remote_datagram_size: 0,
            queues: BTreeMap::new(),
            queue_rr_next: StreamId::new(0),
            conn_events,
        }
    }

    pub const fn remote_datagram_size(&self) -> u64 {
        self.remote_datagram_size
    }

    pub fn set_remote_datagram_size(&mut self, v: u64) {
        self.remote_datagram_size = min(v, MAX_DATAGRAM_SIZE);
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
    /// Round-robins across the per-session [`DatagramQueue`]s in `queues`,
    /// one datagram at a time, expiry-and-priority-ordered within each,
    /// stopping without consuming anything further the moment something
    /// does not fit into an otherwise non-empty packet — that datagram
    /// stays queued for the next `process_output` call rather than being
    /// round-tripped out and back in.
    pub fn write_frames<B: Buffer>(
        &mut self,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
    ) {
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
                let dgram = self.take_from_session_queue(session, true);
                Self::encode_datagram(&dgram.data, dgram.id.into(), builder, tokens, stats);
            } else if tokens.is_empty() {
                let dgram = self.take_from_session_queue(session, false);
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
    /// sender and advancing the round-robin cursor past it. `sent` records
    /// whether the datagram is actually being handed to the packet builder,
    /// as opposed to being dropped for not fitting the MTU. Must only be
    /// called immediately after a [`DatagramQueue::peek_next_len`] on the
    /// same session that returned `Some`, with no other mutation in between.
    fn take_from_session_queue(&mut self, session: StreamId, sent: bool) -> QueuedDatagram {
        let queue = self
            .queues
            .get_mut(&session)
            .expect("next_active_session_from only returns known sessions");
        let dgram = queue
            .take_next()
            .expect("just peeked Some above, with no intervening mutation");
        if sent {
            queue.record_sent();
        }
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
    pub fn set_datagram_high_water_mark(&mut self, session: StreamId, mark: Option<NonZeroUsize>) {
        let queue = self.queue_mut(session);
        queue.set_high_water_mark(mark);
        if queue.resume_if_unblocked() {
            self.conn_events.datagram_space_available();
        }
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

    /// See [`DatagramQueue::take_sent_count`].
    pub fn take_session_sent_count(&mut self, session: StreamId) -> u64 {
        self.queues
            .get_mut(&session)
            .map_or(0, DatagramQueue::take_sent_count)
    }

    /// Whether any session has a sent count waiting to be picked up. See
    /// [`DatagramQueue::has_sent`].
    #[must_use]
    pub fn has_pending_sent(&self) -> bool {
        self.queues.values().any(DatagramQueue::has_sent)
    }

    /// Remove every datagram queued on `session`'s behalf, e.g. because the
    /// session is closing. Returns one entry per removed datagram, `Some(id)`
    /// for tracked ones, for the caller to report a `Dropped` outcome for.
    pub fn drop_session_datagrams(&mut self, session: StreamId) -> Vec<Option<DatagramId>> {
        self.queues
            .remove(&session)
            .map_or_else(Vec::new, |mut q| q.take_all().map(|d| d.id).collect())
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
    /// [`DatagramQueue::expire`]'s doc comment). Called by
    /// `Connection::process_timer` on its own schedule, and also by
    /// `Connection::expire_datagrams` for a caller that wants the expired
    /// IDs, e.g. to report an outcome tagged by application protocol.
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
        let Self {
            queues,
            conn_events,
            ..
        } = self;
        queues
            .values_mut()
            .flat_map(|queue| Self::expire_queue(queue, conn_events, now, default_max_age))
            .collect()
    }

    /// [`Self::expire_datagrams`] for a single session, so a caller that
    /// reports outcomes per session does not pick up another session's
    /// datagrams. Callers that own every session (and so cannot
    /// misattribute) can use the connection-wide sweep instead.
    pub fn expire_session_datagrams(
        &mut self,
        session: StreamId,
        now: Instant,
        default_max_age: Duration,
    ) -> Vec<Option<DatagramId>> {
        let Some(queue) = self.queues.get_mut(&session) else {
            return Vec::new();
        };
        Self::expire_queue(queue, &self.conn_events, now, default_max_age)
    }

    /// Expire `queue`'s stale entries and, if that unblocks it, fire the
    /// resume event. Shared by [`Self::expire_datagrams`] (every session)
    /// and [`Self::expire_session_datagrams`] (a single one).
    fn expire_queue(
        queue: &mut DatagramQueue,
        conn_events: &ConnectionEvents,
        now: Instant,
        default_max_age: Duration,
    ) -> Vec<Option<DatagramId>> {
        let expired = queue.expire(now, default_max_age);
        if queue.resume_if_unblocked() {
            conn_events.datagram_space_available();
        }
        expired
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
