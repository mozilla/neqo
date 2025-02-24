// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Enable just this file for logging to just see packets.
// e.g. "RUST_LOG=neqo_transport::dump neqo-client ..."

use std::fmt::Display;

use neqo_common::IpTos;
use qlog::events::quic::PacketHeader;

use super::DecryptedPacket;
use crate::{
    packet::{PacketNumber, PacketType},
    path::PathRef,
};

#[derive(Clone, Copy)]
pub enum Direction {
    Tx,
    Rx,
}

impl Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tx => write!(f, "TX ->"),
            Self::Rx => write!(f, "-> RX"),
        }
    }
}

pub struct MetaData<'a> {
    path: &'a PathRef,
    direction: Direction,
    packet_type: PacketType,
    packet_number: PacketNumber,
    tos: IpTos,
    len: usize,
    payload: &'a [u8],
}

impl MetaData<'_> {
    #[allow(clippy::missing_const_for_fn)] // TODO: False positive on nightly. Check periodically if this can be removed.
    pub fn new_in<'a>(
        path: &'a PathRef,
        tos: IpTos,
        len: usize,
        decrypted: &'a DecryptedPacket,
    ) -> MetaData<'a> {
        MetaData {
            path,
            direction: Direction::Rx,
            packet_type: decrypted.packet_type(),
            packet_number: decrypted.pn(),
            tos,
            len,
            payload: decrypted,
        }
    }

    pub fn new_out<'a>(
        path: &'a PathRef,
        packet_type: PacketType,
        packet_number: PacketNumber,
        length: usize,
        payload: &'a [u8],
    ) -> MetaData<'a> {
        MetaData {
            path,
            direction: Direction::Tx,
            packet_type,
            packet_number,
            tos: path.borrow().tos(),
            len: length,
            payload,
        }
    }

    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    #[must_use]
    pub const fn length(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }
}

impl From<MetaData<'_>> for PacketHeader {
    fn from(val: MetaData<'_>) -> Self {
        Self::with_type(
            val.packet_type.into(),
            Some(val.packet_number),
            None,
            None,
            None,
        )
    }
}

impl Display for MetaData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pn={} type={:?} {} {:?} len {}",
            self.packet_number,
            self.packet_type,
            self.path.borrow(),
            self.tos,
            self.len,
        )
    }
}
