// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram

use std::{cmp::min, collections::VecDeque};

use neqo_common::{Buffer, Encoder, qdebug, qtrace, to_u64};

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
    /// Set when a send filled the outgoing QUIC datagram queue, i.e.
    /// [`add_datagram`](Self::add_datagram) returned `false`. Used to emit a
    /// single [`OutgoingDatagramSpaceAvailable`] event once space frees.
    ///
    /// [`OutgoingDatagramSpaceAvailable`]: crate::ConnectionEvent::OutgoingDatagramSpaceAvailable
    blocked: bool,
    /// Datagram queued for sending.
    datagrams: VecDeque<QuicDatagram>,
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
            conn_events,
        }
    }

    pub const fn remote_datagram_size(&self) -> u64 {
        self.remote_datagram_size
    }

    pub fn set_remote_datagram_size(&mut self, v: u64) {
        self.remote_datagram_size = min(v, QuicDatagram::MAX_SIZE);
    }

    /// This function tries to write a datagram frame into a packet. If the
    /// frame does not fit into the packet, the datagram will be dropped and a
    /// [`OutgoingDatagramOutcome::DroppedTooBig`] event will be posted.
    pub fn write_frames<B: Buffer>(
        &mut self,
        builder: &mut packet::Builder<B>,
        tokens: &mut recovery::Tokens,
        stats: &mut Stats,
    ) {
        while let Some(dgram) = self.datagrams.pop_front() {
            let len = dgram.as_ref().len();
            if len + DATAGRAM_FRAME_TYPE_VARINT_LEN <= builder.remaining() {
                // The datagram fits into the packet.
                let length_len = Encoder::varint_len(to_u64(len));
                // Include a length if there is space for another frame after this one.
                if builder.remaining()
                    >= DATAGRAM_FRAME_TYPE_VARINT_LEN
                        + length_len
                        + len
                        + packet::Builder::MINIMUM_FRAME_SIZE
                {
                    builder.encode_frame(FrameType::DatagramWithLen, |b| {
                        b.encode_vvec(dgram.as_ref());
                    });
                } else {
                    builder.encode_frame(FrameType::Datagram, |b| {
                        b.encode(dgram.as_ref());
                    });
                    builder.mark_full();
                }
                debug_assert!(builder.len() <= builder.limit());
                stats.frame_tx.datagram += 1;
                tokens.push(recovery::Token::Datagram(*dgram.tracking()));
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
        // Sending or dropping datagrams above may have freed slots. Resume the
        // application if it was blocked and the queue is now below capacity.
        // Covering the drop path is what stops a queue emptied entirely by
        // `DroppedTooBig` from stalling. The length guard matters because the
        // queue can sit one over capacity (a full queue still accepts one more,
        // returning `false`), so one freed slot may not suffice.
        if self.blocked && self.datagrams.len() < self.max_queued_outgoing_datagrams {
            self.blocked = false;
            self.conn_events.datagram_space_available();
        }
    }

    /// Add a datagram to the send queue.
    ///
    /// Unless it returns an error (see below), the QUIC datagram is queued. The
    /// returned bool reports whether the outgoing QUIC datagram queue still had
    /// room afterwards:
    ///
    /// - `Ok(true)`: queued, and space remains for more.
    /// - `Ok(false)`: queued, but the queue is now full. The application should stop producing QUIC
    ///   datagrams until it receives an [`OutgoingDatagramSpaceAvailable`] event, which is emitted
    ///   once a queue slot frees up. Nothing already queued is dropped.
    ///
    /// The datagram is accepted even when the queue is already at capacity. The
    /// application has already produced it, so neqo holds it here, ready to
    /// send, rather than leaving it in a queue upstream that neqo cannot reach
    /// once space frees. `false` is a high-watermark signal to stop, not a
    /// rejection.
    ///
    /// # Error
    ///
    /// The function returns `TooMuchData` if the supply buffer is bigger than
    /// the allowed remote datagram size. The function does not check if the
    /// datagram can fit into a packet (i.e. MTU limit). This is checked during
    /// creation of an actual packet and the datagram will be dropped if it does
    /// not fit into the packet.
    ///
    /// [`OutgoingDatagramSpaceAvailable`]: crate::ConnectionEvent::OutgoingDatagramSpaceAvailable
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
