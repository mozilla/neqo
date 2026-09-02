// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram

use std::{cmp::min, collections::VecDeque, fmt::Debug, time::Instant};

use neqo_common::{Buffer, Encoder, qdebug, qwarn, to_u64};

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

/// A simple [`OutgoingDatagramSource`]: a FIFO with head-drop eviction once
/// `max_queued` datagrams are pending.
///
/// Not used by [`QuicDatagrams`] itself - there is no default source, so a
/// connection with none registered simply has nothing to pull. This exists
/// as an off-the-shelf option for a caller (e.g. a test, or a consumer with
/// no priority/age policy of its own) that wants *some* queue without
/// writing one, via [`crate::Connection::set_outgoing_datagram_source`].
/// Eviction reports nothing on its own: it hands the evicted datagram back
/// to [`Self::push`]'s caller, which decides what, if anything, to do with
/// it.
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

    /// Queue a datagram, head-dropping and returning the oldest queued
    /// datagram first if the queue is already at `max_queued`.
    pub fn push(
        &mut self,
        data: Vec<u8>,
        tracking: DatagramTracking,
    ) -> Option<(Vec<u8>, DatagramTracking)> {
        let evicted = if self.datagrams.len() == self.max_queued {
            qdebug!("QUIC datagram queue full, dropping first datagram in queue (head-drop).");
            self.datagrams.pop_front().map(|d| (d.data, d.tracking))
        } else {
            None
        };
        self.datagrams.push_back(QuicDatagram { data, tracking });
        evicted
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
    conn_events: ConnectionEvents,
}

impl QuicDatagrams {
    pub const fn new(local_datagram_size: u64, conn_events: ConnectionEvents) -> Self {
        Self {
            local_datagram_size,
            remote_datagram_size: 0,
            conn_events,
        }
    }

    pub const fn remote_datagram_size(&self) -> u64 {
        self.remote_datagram_size
    }

    pub fn set_remote_datagram_size(&mut self, v: u64) {
        self.remote_datagram_size = min(v, QuicDatagram::MAX_SIZE);
    }

    /// Pull datagrams from `source` and write them into the packet being
    /// built. If a datagram does not fit and the packet is otherwise empty,
    /// the datagram is dropped and a
    /// [`OutgoingDatagramOutcome::DroppedTooBig`] event is posted.
    pub fn write_frames<B: Buffer>(
        &self,
        source: &mut dyn OutgoingDatagramSource,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
        now: Instant,
    ) {
        while let Some(len) = source.next_datagram_len(now) {
            if len + DATAGRAM_FRAME_TYPE_VARINT_LEN <= builder.remaining() {
                // The datagram fits into the packet.
                let Some((data, tracking)) = source.take_next_datagram(now) else {
                    // A misbehaving source: it said it had one, then didn't.
                    // Nothing was written, so just stop for this packet
                    // rather than risk looping on a source that keeps
                    // claiming to have data it can't actually hand over.
                    qwarn!(
                        "OutgoingDatagramSource::take_next_datagram returned None right after \
                         next_datagram_len returned Some"
                    );
                    return;
                };
                debug_assert_eq!(
                    data.len(),
                    len,
                    "OutgoingDatagramSource::take_next_datagram's length did not match next_datagram_len's"
                );
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
                    qwarn!(
                        "OutgoingDatagramSource::take_next_datagram returned None right after \
                         next_datagram_len returned Some"
                    );
                    return;
                };
                qdebug!("QUIC datagram ({}) does not fit MTU.", data.len());
                self.conn_events
                    .datagram_outcome(&tracking, OutgoingDatagramOutcome::DroppedTooBig);
                stats.datagram_tx.dropped_too_big += 1;
            } else {
                // Try later on an empty packet. Nothing was taken, so the
                // datagram stays queued in `source`.
                return;
            }
        }
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

#[cfg(test)]
mod tests {
    use test_fixture::now;

    use super::{BufferedDatagramSource, DatagramTracking, OutgoingDatagramSource as _};

    #[test]
    fn empty_source_returns_none() {
        let mut source = BufferedDatagramSource::new(2);
        assert!(source.next_datagram_len(now()).is_none());
        assert!(source.take_next_datagram(now()).is_none());
    }

    #[test]
    fn peek_len_matches_take_next_datagram() {
        let mut source = BufferedDatagramSource::new(2);
        assert!(
            source
                .push(vec![1, 2, 3], DatagramTracking::Id(1))
                .is_none()
        );

        let peeked = source
            .next_datagram_len(now())
            .expect("something is queued");
        let (data, tracking) = source
            .take_next_datagram(now())
            .expect("something is queued");
        assert_eq!(peeked, data.len());
        assert!(matches!(tracking, DatagramTracking::Id(1)));
    }

    #[test]
    fn push_then_take_is_fifo() {
        let mut source = BufferedDatagramSource::new(3);
        source.push(vec![1], DatagramTracking::Id(1));
        source.push(vec![2], DatagramTracking::Id(2));
        source.push(vec![3], DatagramTracking::Id(3));

        let mut ids = Vec::new();
        while let Some((_, DatagramTracking::Id(id))) = source.take_next_datagram(now()) {
            ids.push(id);
        }
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn push_evicts_oldest_when_full() {
        let mut source = BufferedDatagramSource::new(2);
        assert!(source.push(vec![1], DatagramTracking::Id(1)).is_none());
        assert!(source.push(vec![2], DatagramTracking::Id(2)).is_none());

        let evicted = source
            .push(vec![3], DatagramTracking::Id(3))
            .expect("queue is full, so this must evict");
        assert!(matches!(evicted.1, DatagramTracking::Id(1)));

        let mut ids = Vec::new();
        while let Some((_, DatagramTracking::Id(id))) = source.take_next_datagram(now()) {
            ids.push(id);
        }
        assert_eq!(
            ids,
            vec![2, 3],
            "the evicted datagram must not still be queued"
        );
    }
}
