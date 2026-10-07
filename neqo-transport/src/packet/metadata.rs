// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Enable just this file for logging to just see packets.
// e.g. "RUST_LOG=neqo_transport::dump neqo-client ..."

use std::fmt::{self, Display, Formatter};

use neqo_common::Tos;
use qlog::events::quic::PacketHeader;
use strum::Display;

use crate::{packet, path::PathRef, version::Version};

#[derive(Clone, Copy, Display)]
pub enum Direction {
    #[strum(to_string = "TX ->")]
    Tx,
    #[strum(to_string = "-> RX")]
    Rx,
}

/// `(scid, dcid)`, as in [`PacketHeader`].
type Cids<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

pub struct MetaData<'a> {
    path: &'a PathRef,
    packet_type: packet::Type,
    packet_number: packet::Number,
    version: Version,
    tos: Tos,
    len: usize,
    payload: &'a [u8],
    /// The CIDs of a received packet, as these can differ from the path's.
    rx_cids: Option<Cids<'a>>,
}

impl MetaData<'_> {
    pub fn new_in<'a>(
        path: &'a PathRef,
        tos: Tos,
        len: usize,
        decrypted: &'a packet::Decrypted,
        version: Version,
    ) -> MetaData<'a> {
        MetaData {
            path,
            packet_type: decrypted.packet_type(),
            packet_number: decrypted.pn(),
            version,
            tos,
            len,
            payload: decrypted,
            rx_cids: Some((decrypted.scid.as_deref(), Some(&decrypted.dcid))),
        }
    }

    pub const fn new_out<'a>(
        path: &'a PathRef,
        packet_type: packet::Type,
        packet_number: packet::Number,
        length: usize,
        payload: &'a [u8],
        tos: Tos,
        version: Version,
    ) -> MetaData<'a> {
        MetaData {
            path,
            packet_type,
            packet_number,
            version,
            tos,
            len: length,
            payload,
            rx_cids: None,
        }
    }

    #[must_use]
    pub const fn direction(&self) -> Direction {
        if self.rx_cids.is_some() {
            Direction::Rx
        } else {
            Direction::Tx
        }
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
        let path = val.path.borrow();
        // On TX, the path's CIDs are the ones written into the packet.
        let (scid, dcid) = val.rx_cids.unwrap_or_else(|| {
            (
                path.local_cid().map(AsRef::as_ref),
                path.remote_cid().map(AsRef::as_ref),
            )
        });
        Self::with_type(
            val.packet_type.into(),
            Some(val.packet_number),
            Some(val.version.wire_version()),
            scid,
            dcid,
        )
    }
}

impl Display for MetaData<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
