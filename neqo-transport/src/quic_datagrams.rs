// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram

use crate::frame::{FRAME_TYPE_DATAGRAM, FRAME_TYPE_DATAGRAM_WITH_LEN};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::stats::FrameStats;
use crate::{ConnectionEvents, Error, Res};
use neqo_common::Encoder;
use std::cmp::min;
use std::convert::TryFrom;

pub const MAX_QUIC_DATAGRAM: u64 = 65535;

pub struct QuicDatagrams {
    /// The max size of a datagram that would be acceptable.
    local_datagram_size: u64,
    /// The max size of a datagram that would be acceptable by the peer.
    remote_datagram_size: u64,
    /// The max number of datagrams that will be queued in connection events.
    /// If the number is exceeded, the oldest datagram will be dropped.
    max_queued_datagrams: usize,
    /// Datagram queued for sending.
    datagram: Option<Vec<u8>>,
    conn_events: ConnectionEvents,
}

impl QuicDatagrams {
    pub fn new(
        local_datagram_size: u64,
        max_queued_datagrams: usize,
        conn_events: ConnectionEvents,
    ) -> Self {
        Self {
            local_datagram_size,
            remote_datagram_size: 0,
            max_queued_datagrams,
            datagram: None,
            conn_events,
        }
    }

    pub fn remote_datagram_size(&self) -> u64 {
        self.remote_datagram_size
    }

    pub fn set_remote_datagram_size(&mut self, v: u64) {
        self.remote_datagram_size = min(v, MAX_QUIC_DATAGRAM);
    }

    /// This function tries to write a datagram frame into a packet.
    /// If the frame does not fit into the packet, the datagram will
    /// be dropped and a DatagramLost event will be posted.
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        if let Some(data) = &self.datagram.take() {
            let len = data.len();
            if builder.remaining() >= len + 1 {
                // + 1 for Frame type
                let length_len = Encoder::varint_len(u64::try_from(len).unwrap());
                if builder.remaining() > 1 + length_len + len {
                    builder.encode_varint(FRAME_TYPE_DATAGRAM_WITH_LEN);
                    builder.encode_vvec(&data);
                } else {
                    builder.encode_varint(FRAME_TYPE_DATAGRAM);
                    builder.encode(&data);
                }
                debug_assert!(builder.len() <= builder.limit());
                self.datagram = None;
                stats.datagram += 1;
                tokens.push(RecoveryToken::Datagram);
            } else {
                // TODO try writing in a completely empty packet,
                // before dropping a datagram.
                self.conn_events.datagram_lost();
            }
        }
    }

    /// Returns true if there was an unsent datagram that has been dismissed.
    /// # Error
    /// The function returns `TooMuchData` if the supply buffer is bigger than
    /// the allowed remote datagram size. The funcion does not check if the
    /// datagram can fit into a packet (i.e. MTU limit). This is checked during
    /// creation of an actual packet and the datagram will be dropped if it does
    /// not fit into the packet.
    pub fn add_datagram(&mut self, buf: &[u8]) -> Res<bool> {
        if u64::try_from(buf.len()).unwrap() > self.remote_datagram_size {
            return Err(Error::TooMuchData);
        }
        Ok(self.datagram.replace(buf.to_vec()).is_some())
    }

    pub fn handle_datagram(&self, data: &[u8]) -> Res<()> {
        if self.local_datagram_size < u64::try_from(data.len()).unwrap() {
            return Err(Error::ProtocolViolation);
        }
        self.conn_events
            .add_datagram(self.max_queued_datagrams, data);
        Ok(())
    }
}
