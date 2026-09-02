// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram

use std::{cmp::min, collections::VecDeque, fmt::Debug, time::Instant};

use neqo_common::{Buffer, Encoder, qdebug, to_u64};

use crate::{
    ConnectionEvents, Error, Res, Stats,
    events::OutgoingDatagramOutcome,
    frame::{FrameEncoder as _, FrameType},
    packet, recovery,
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

/// A source of outgoing datagrams, pulled from at packet-build time rather
/// than pre-queued inside transport.
///
/// [`QuicDatagrams::write_frames`] calls [`Self::next_datagram_len`] to see
/// whether there is a datagram ready and how big it is, then, once it knows
/// the datagram fits (or must be dropped for being oversized), calls
/// [`Self::take_next_datagram`] to remove exactly what was just peeked. The
/// two must be called as a strict pair with no other mutation of the source
/// in between: an implementation that orders multiple queues (e.g. round-
/// robin across sessions) advances that ordering on `take_next_datagram`,
/// keyed off what `next_datagram_len` most recently looked at.
pub trait OutgoingDatagramSource: Debug {
    /// The length of the next datagram ready to send as of `now`, if any.
    /// Implementations should expire or otherwise discard anything no
    /// longer worth sending before answering.
    fn next_datagram_len(&mut self, now: Instant) -> Option<usize>;

    /// Remove and return what the most recent call to
    /// [`Self::next_datagram_len`] described.
    fn take_next_datagram(&mut self, now: Instant) -> Option<(Vec<u8>, DatagramTracking)>;
}

#[derive(Debug)]
pub struct QuicDatagram {
    data: Vec<u8>,
    tracking: DatagramTracking,
}

impl QuicDatagram {
    pub const MAX_SIZE: u64 = 65535;
}

impl AsRef<[u8]> for QuicDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}

/// The default [`OutgoingDatagramSource`].
///
/// A small FIFO with head-drop eviction once `max_queued` datagrams are
/// pending. This is what [`QuicDatagrams::add_datagram`] enqueues into when
/// no external source has been registered.
#[derive(Debug)]
pub struct BufferedDatagramSource {
    max_queued: usize,
    datagrams: VecDeque<QuicDatagram>,
}

impl BufferedDatagramSource {
    #[must_use]
    pub fn new(max_queued: usize) -> Self {
        Self {
            max_queued,
            datagrams: VecDeque::with_capacity(max_queued),
        }
    }

    /// How many more datagrams can be queued before [`Self::push`] starts
    /// evicting datagrams that are already queued.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.max_queued.saturating_sub(self.datagrams.len())
    }

    /// Queue a datagram, head-dropping the oldest queued datagram first if
    /// the queue is already at `max_queued`.
    ///
    /// # Errors
    ///
    /// Never fails in practice; the only error path is an internal
    /// invariant (the queue reporting itself full but yielding nothing to
    /// drop) that cannot occur.
    pub fn push(
        &mut self,
        data: Vec<u8>,
        tracking: DatagramTracking,
        stats: &mut Stats,
        conn_events: &ConnectionEvents,
    ) -> Res<()> {
        if self.datagrams.len() == self.max_queued {
            qdebug!("QUIC datagram queue full, dropping first datagram in queue (head-drop).");
            let dropped = self.datagrams.pop_front().ok_or(Error::Internal)?;
            conn_events
                .datagram_outcome(&dropped.tracking, OutgoingDatagramOutcome::DroppedQueueFull);
            stats.datagram_tx.dropped_queue_full += 1;
        }
        self.datagrams.push_back(QuicDatagram { data, tracking });
        Ok(())
    }
}

impl OutgoingDatagramSource for BufferedDatagramSource {
    fn next_datagram_len(&mut self, _now: Instant) -> Option<usize> {
        self.datagrams.front().map(|d| d.as_ref().len())
    }

    fn take_next_datagram(&mut self, _now: Instant) -> Option<(Vec<u8>, DatagramTracking)> {
        self.datagrams.pop_front().map(|d| (d.data, d.tracking))
    }
}

pub struct QuicDatagrams {
    /// The max size of a datagram that would be acceptable.
    local_datagram_size: u64,
    /// The max size of a datagram that would be acceptable by the peer.
    remote_datagram_size: u64,
    /// Where datagrams passed to [`Self::add_datagram`] end up, and what
    /// [`Self::write_frames`] pulls from when no external source is passed
    /// in.
    default_source: BufferedDatagramSource,
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
            default_source: BufferedDatagramSource::new(max_queued_outgoing_datagrams),
            conn_events,
        }
    }

    pub const fn remote_datagram_size(&self) -> u64 {
        self.remote_datagram_size
    }

    pub fn set_remote_datagram_size(&mut self, v: u64) {
        self.remote_datagram_size = min(v, QuicDatagram::MAX_SIZE);
    }

    /// How many more datagrams can be queued before [`Self::add_datagram`]
    /// starts evicting datagrams that are already queued.
    pub fn remaining_capacity(&self) -> usize {
        self.default_source.remaining_capacity()
    }

    /// Pull datagrams from `external` (or, if `None`, from the default
    /// buffered source) and write them into the packet being built. If a
    /// datagram does not fit and the packet is otherwise empty, the
    /// datagram is dropped and a [`OutgoingDatagramOutcome::DroppedTooBig`]
    /// event is posted.
    pub fn write_frames<B: Buffer>(
        &mut self,
        external: Option<&mut dyn OutgoingDatagramSource>,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
        now: Instant,
    ) {
        match external {
            Some(source) => {
                Self::pull_frames(source, builder, tokens, stats, &self.conn_events, now);
            }
            None => {
                Self::pull_frames(
                    &mut self.default_source,
                    builder,
                    tokens,
                    stats,
                    &self.conn_events,
                    now,
                );
            }
        }
    }

    fn pull_frames<B: Buffer>(
        source: &mut dyn OutgoingDatagramSource,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
        conn_events: &ConnectionEvents,
        now: Instant,
    ) {
        while let Some(len) = source.next_datagram_len(now) {
            if len + DATAGRAM_FRAME_TYPE_VARINT_LEN <= builder.remaining() {
                // The datagram fits into the packet.
                let Some((data, tracking)) = source.take_next_datagram(now) else {
                    debug_assert!(
                        false,
                        "OutgoingDatagramSource::take_next_datagram returned None right after \
                         next_datagram_len returned Some"
                    );
                    return;
                };
                let length_len = Encoder::varint_len(to_u64(data.len()));
                // Include a length if there is space for another frame after this one.
                if builder.remaining()
                    >= DATAGRAM_FRAME_TYPE_VARINT_LEN
                        + length_len
                        + data.len()
                        + packet::Builder::MINIMUM_FRAME_SIZE
                {
                    builder.encode_frame(FrameType::DatagramWithLen, |b| {
                        b.encode_vvec(&data);
                    });
                } else {
                    builder.encode_frame(FrameType::Datagram, |b| {
                        b.encode(&data);
                    });
                    builder.mark_full();
                }
                debug_assert!(builder.len() <= builder.limit());
                stats.frame_tx.datagram += 1;
                tokens.push(recovery::Token::Datagram(tracking));
            } else if tokens.is_empty() {
                // If the packet is empty, except packet headers, and the
                // datagram cannot fit, drop it.
                // Also continue trying to write the next datagram.
                let Some((data, tracking)) = source.take_next_datagram(now) else {
                    debug_assert!(
                        false,
                        "OutgoingDatagramSource::take_next_datagram returned None right after \
                         next_datagram_len returned Some"
                    );
                    return;
                };
                qdebug!("QUIC datagram ({}) does not fit MTU.", data.len());
                conn_events.datagram_outcome(&tracking, OutgoingDatagramOutcome::DroppedTooBig);
                stats.datagram_tx.dropped_too_big += 1;
            } else {
                // Try later on an empty packet. Nothing was taken, so the
                // datagram stays queued in `source`.
                return;
            }
        }
    }

    /// Add a datagram to the default send queue.
    ///
    /// # Error
    ///
    /// The function returns `TooMuchData` if the supply buffer is bigger than
    /// the allowed remote datagram size. The function does not check if the
    /// datagram can fit into a packet (i.e. MTU limit). This is checked during
    /// creation of an actual packet and the datagram will be dropped if it does
    /// not fit into the packet.
    pub fn add_datagram(
        &mut self,
        data: Vec<u8>,
        tracking: DatagramTracking,
        stats: &mut Stats,
    ) -> Res<()> {
        if to_u64(data.len()) > self.remote_datagram_size {
            qdebug!(
                "QUIC datagram exceeds remote limit, dropping it, datagram size {}, remote datagram size limit {}.",
                data.len(),
                self.remote_datagram_size
            );
            return Err(Error::TooMuchData);
        }
        self.default_source.push(data, tracking, stats, &self.conn_events)
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
