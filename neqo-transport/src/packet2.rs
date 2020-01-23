// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Encoding and decoding packets off the wire.
#![allow(dead_code)] // TODO(mt) remove

use crate::cid::ConnectionId;
use crate::crypto::CryptoDxState;
use crate::{Res, QUIC_VERSION};

use neqo_common::{hex, qdebug, qtrace, Encoder};

use std::iter::ExactSizeIterator;
use std::ops::{Deref, DerefMut, Range};

const PACKET_TYPE_INITIAL: u8 = 0x0;
const PACKET_TYPE_0RTT: u8 = 0x01;
const PACKET_TYPE_HANDSHAKE: u8 = 0x2;
const PACKET_TYPE_RETRY: u8 = 0x03;

const PACKET_BIT_LONG: u8 = 0x80;
const PACKET_BIT_SHORT: u8 = 0x00;
const PACKET_BIT_FIXED_QUIC: u8 = 0x40;

const SAMPLE_SIZE: usize = 16;

pub type PacketNumber = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    VersionNegotiation,
    Initial,
    Handshake,
    ZeroRtt,
    Retry,
    Short,
}

impl PacketType {
    #[must_use]
    fn code(&self) -> u8 {
        match self {
            Self::Initial => PACKET_TYPE_INITIAL,
            Self::ZeroRtt => PACKET_TYPE_0RTT,
            Self::Handshake => PACKET_TYPE_HANDSHAKE,
            Self::Retry { .. } => PACKET_TYPE_RETRY,
            _ => panic!("shouldn't be here"),
        }
    }
}

struct PacketBuilderoffsets {
    /// The bits of the first octet that need masking.
    first_byte_mask: u8,
    /// The offset of the length field.
    len: usize,
    /// The location of the packet number field.
    pn: Range<usize>,
}

/// A packet builder that can be used to produce short packets and long packets.
/// This does not produce Retry or Version Negotiation.
pub struct PacketBuilder {
    encoder: Encoder,
    pn: PacketNumber,
    header: Range<usize>,
    offsets: PacketBuilderoffsets,
}

impl PacketBuilder {
    /// Start building a long header packet.
    pub fn short(mut encoder: Encoder, key_phase: bool, dcid: &ConnectionId) -> Self {
        let header_start = encoder.len();
        encoder.encode_byte(PACKET_BIT_SHORT | PACKET_BIT_FIXED_QUIC | (u8::from(key_phase) << 2));
        encoder.encode(&dcid);
        Self {
            encoder,
            pn: u64::max_value(),
            header: header_start..header_start,
            offsets: PacketBuilderoffsets {
                first_byte_mask: 0x1f,
                pn: 0..0,
                len: 0,
            },
        }
    }

    /// Start building a long header packet.
    /// For an Initial packet you will need to call initial_token(),
    /// even if the token is empty.
    pub fn long(
        mut encoder: Encoder,
        pt: PacketType,
        dcid: &ConnectionId,
        scid: &ConnectionId,
    ) -> Self {
        let header_start = encoder.len();
        encoder.encode_byte(PACKET_BIT_LONG | PACKET_BIT_FIXED_QUIC | pt.code() << 4);
        encoder.encode_uint(4, QUIC_VERSION);
        encoder.encode_vec(1, dcid);
        encoder.encode_vec(1, scid);
        Self {
            encoder,
            pn: u64::max_value(),
            header: header_start..header_start,
            offsets: PacketBuilderoffsets {
                first_byte_mask: 0x0f,
                pn: 0..0,
                len: 0,
            },
        }
    }

    /// For an Initial packet, encode the token.
    /// If you fail to do this, then you will not get a valid packet.
    pub fn initial_token(&mut self, token: &[u8]) {
        debug_assert_eq!(
            self.encoder[self.header.start] & 0xb0,
            PACKET_BIT_LONG | PACKET_TYPE_INITIAL << 4
        );
        self.encoder.encode_vvec(token);
    }

    /// Add a packet number of the given size.
    /// For a long header packet, this also inserts a dummy length.
    /// The length is filled in after calling `build`.
    pub fn pn(&mut self, pn: PacketNumber, pn_len: usize) {
        // Reserve space for a length in long headers.
        if (self.encoder[self.header.start] & 0x80) == PACKET_BIT_LONG {
            self.offsets.len = self.encoder.len();
            self.encoder.encode(&[0; 2]);
        }
        // Encode the packet number and save its offset.
        debug_assert!(pn_len <= 4 && pn_len > 0);
        let pn_offset = self.encoder.len();
        self.encoder.encode_uint(pn_len, pn);
        self.offsets.pn = pn_offset..self.encoder.len();

        // Now encode the packet number length and save the header length.
        self.encoder[self.header.start] |= (pn_len - 1) as u8;
        self.header.end = self.encoder.len();
        self.pn = pn;
    }

    fn write_len(&mut self, expansion: usize) {
        let len = self.encoder.len() - (self.offsets.len + 2) + expansion;
        self.encoder[self.offsets.len] = 0x40 | ((len >> 8) & 0x3f) as u8;
        self.encoder[self.offsets.len + 1] = (len & 0xff) as u8;
    }

    /// Build the packet and return the encoder.
    #[must_use]
    pub fn build(mut self, crypto: &mut CryptoDxState) -> Res<Encoder> {
        if self.offsets.len > 0 {
            self.write_len(crypto.expansion());
        }
        let hdr = &self.encoder[self.header.clone()];
        let body = &self.encoder[self.header.end..];
        qdebug!("Build pn={} hdr={} body={}", self.pn, hex(hdr), hex(body));
        let ciphertext = crypto.encrypt(self.pn, hdr, body)?;

        // Calculate the mask.
        let offset = 4 - self.offsets.pn.len();
        let sample = &ciphertext[offset..offset + SAMPLE_SIZE];
        let mask = crypto.compute_mask(sample)?;
        qtrace!("mask={}", hex(&mask));

        // Apply the mask.
        self.encoder[self.header.start] ^= mask[0] & self.offsets.first_byte_mask;
        for (i, j) in (1..self.offsets.pn.len() + 1).zip(self.offsets.pn) {
            self.encoder[j] ^= mask[i];
        }

        // Finally, cut off the plaintext and add back the ciphertext.
        self.encoder.truncate(self.header.end);
        self.encoder.encode(&ciphertext);
        qdebug!("Built {}", hex(&self.encoder));
        Ok(self.encoder)
    }

    /// Abort writing of this packet and return the encoder.
    #[must_use]
    pub fn abort(mut self) -> Encoder {
        self.encoder.truncate(self.header.start);
        self.encoder
    }

    /// Work out if nothing was added after the header.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.encoder.len() == self.header.end
    }
}

impl Deref for PacketBuilder {
    type Target = Encoder;

    fn deref(&self) -> &Self::Target {
        &self.encoder
    }
}

impl DerefMut for PacketBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.encoder
    }
}

impl Into<Encoder> for PacketBuilder {
    fn into(self) -> Encoder {
        self.encoder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoDxDirection, CryptoDxState};
    use neqo_common::Encoder;
    use test_fixture::fixture_init;

    #[test]
    fn build_sample() {
        const CLIENT_CID: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        const SERVER_CID: &[u8] = &[0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
        const SAMPLE_PAYLOAD: &[u8] = &[
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x18, 0x41, 0x0a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03,
            0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78, 0x25,
            0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43, 0x0b,
            0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24,
            0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0, 0x8a,
            0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83, 0x4d,
            0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ];
        const EXPECTED: &[u8] = &[
            0xc9, 0xff, 0x00, 0x00, 0x18, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x74, 0x16, 0x8b, 0xf2, 0x2b, 0x70, 0x02, 0x59, 0x6f, 0x99, 0xae,
            0x67, 0xab, 0xf6, 0x5a, 0x58, 0x52, 0xf5, 0x4f, 0x58, 0xc3, 0x7c, 0x80, 0x86, 0x82,
            0xe2, 0xe4, 0x04, 0x92, 0xd8, 0xa3, 0x89, 0x9f, 0xb0, 0x4f, 0xc0, 0xaf, 0xe9, 0xaa,
            0xbc, 0x87, 0x67, 0xb1, 0x8a, 0x0a, 0xa4, 0x93, 0x53, 0x74, 0x26, 0x37, 0x3b, 0x48,
            0xd5, 0x02, 0x21, 0x4d, 0xd8, 0x56, 0xd6, 0x3b, 0x78, 0xce, 0xe3, 0x7b, 0xc6, 0x64,
            0xb3, 0xfe, 0x86, 0xd4, 0x87, 0xac, 0x7a, 0x77, 0xc5, 0x30, 0x38, 0xa3, 0xcd, 0x32,
            0xf0, 0xb5, 0x00, 0x4d, 0x9f, 0x57, 0x54, 0xc4, 0xf7, 0xf2, 0xd1, 0xf3, 0x5c, 0xf3,
            // -- For draft-25, change the 0x18 above and use these lines:
            // 0xf7, 0x11, 0x63, 0x51, 0xc9, 0x2b, 0x99, 0xc8, 0xae, 0x58, 0x33, 0x22, 0x5c, 0xb5,
            // 0x18, 0x55, 0x20, 0xd6, 0x1e, 0x68, 0xcf, 0x5f,
            // -- These are draft-24 values:
            0xf7, 0x11, 0x63, 0x51, 0xc9, 0x2b, 0x58, 0x4d, 0x2d, 0xdd, 0x6c, 0x26, 0xc7, 0x8a,
            0x84, 0x07, 0xf0, 0x9e, 0xfd, 0xa4, 0xa3, 0x08,
        ];

        fixture_init();
        let mut prot =
            CryptoDxState::new_initial(CryptoDxDirection::Write, "server in", CLIENT_CID);

        // The spec uses PN=1, but our crypto refuses to skip packet numbers.
        // So burn an encryption:
        let burn = prot.encrypt(0, &[], &[]).expect("burn OK");
        assert_eq!(burn.len(), prot.expansion());

        let mut builder = PacketBuilder::long(
            Encoder::new(),
            PacketType::Initial,
            &ConnectionId::from(&[][..]),
            &ConnectionId::from(SERVER_CID),
        );
        builder.initial_token(&[]);
        builder.pn(1, 2);
        builder.encode(&SAMPLE_PAYLOAD);
        let packet = builder.build(&mut prot).expect("build");
        assert_eq!(&packet[..], EXPECTED);
    }
}
