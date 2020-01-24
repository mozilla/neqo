// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Encoding and decoding packets off the wire.

// A lot of methods and types contain the word Packet
#![allow(clippy::module_name_repetitions)]

use neqo_common::{hex, matches, qtrace, Decoder, Encoder};
use neqo_crypto::random;

use std::convert::{TryFrom, TryInto};

use crate::tracking::PNSpace;
use crate::{Error, Res};

const PACKET_TYPE_INITIAL: u8 = 0x0;
const PACKET_TYPE_0RTT: u8 = 0x01;
const PACKET_TYPE_HANDSHAKE: u8 = 0x2;
const PACKET_TYPE_RETRY: u8 = 0x03;

const PACKET_BIT_LONG: u8 = 0x80;
const PACKET_BIT_SHORT: u8 = 0x00;
const PACKET_BIT_FIXED_QUIC: u8 = 0x40;

const SAMPLE_SIZE: usize = 16;

const AUTH_TAG_LEN: usize = 16;

#[derive(Debug, PartialEq)]
pub enum PacketType {
    Short(bool), // Includes whether the key phase is set
    ZeroRTT,
    Handshake,
    VN(Vec<Version>), // List of versions
    Initial(Vec<u8>), // Token
    Retry { odcid: ConnectionId, token: Vec<u8> },
}

impl PacketType {
    #[must_use]
    fn code(&self) -> u8 {
        match self {
            Self::Initial(..) => PACKET_TYPE_INITIAL,
            Self::ZeroRTT => PACKET_TYPE_0RTT,
            Self::Handshake => PACKET_TYPE_HANDSHAKE,
            Self::Retry { .. } => PACKET_TYPE_RETRY,
            _ => panic!("shouldn't be here"),
        }
    }

    #[must_use]
    pub fn space(&self) -> PNSpace {
        match self {
            Self::Short(_) | Self::ZeroRTT => PNSpace::ApplicationData,
            Self::Handshake => PNSpace::Handshake,
            Self::Initial(_) => PNSpace::Initial,
            _ => panic!("don't ask for the space when there isn't one"),
        }
    }

    #[must_use]
    pub fn key_phase(&self) -> bool {
        matches!(self, Self::Short(true))
    }
}

impl Default for PacketType {
    fn default() -> Self {
        Self::Short(false)
    }
}

pub type Version = u32;
pub type PacketNumber = u64;

#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct ConnectionId(pub Vec<u8>);

impl std::ops::Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConnectionId {
    pub fn generate(len: usize) -> Self {
        assert!(matches!(len, 0..=20));
        Self(random(len))
    }

    // Apply a wee bit of greasing here in picking a length between 8 and 20 bytes long.
    pub fn generate_initial() -> Self {
        let v = random(1);
        // Bias selection toward picking 8 (>50% of the time).
        let len: usize = ::std::cmp::max(8, 5 + (v[0] & (v[0] >> 4))).into();
        Self::generate(len)
    }
}

impl ::std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "CID {}", hex(&self.0))
    }
}

impl ::std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

impl From<&[u8]> for ConnectionId {
    fn from(buf: &[u8]) -> Self {
        Self(Vec::from(buf))
    }
}

pub trait ConnectionIdDecoder {
    fn decode_cid(&self, dec: &mut Decoder) -> Option<ConnectionId>;
}

#[derive(Default, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct PacketHdr {
    pub tbyte: u8,
    pub tipe: PacketType,
    pub version: Option<Version>,
    pub dcid: ConnectionId,
    pub scid: Option<ConnectionId>,
    pub pn: PacketNumber,
    pub hdr_len: usize,
    body_len: usize,
}

impl PacketHdr {
    // Similar names are allowed here because
    // dcid and scid are defined and commonly used in the spec.
    #[allow(clippy::similar_names)]
    pub fn new(
        tbyte: u8,
        tipe: PacketType,
        version: Option<Version>,
        dcid: ConnectionId,
        scid: Option<ConnectionId>,
        pn: PacketNumber,
    ) -> Self {
        Self {
            tbyte,
            tipe,
            version,
            dcid,
            scid,
            pn,
            hdr_len: 0,
            body_len: 0,
        }
    }

    pub fn body_len(&self) -> usize {
        self.body_len
    }

    // header length plus auth tag
    pub fn overhead(&self, aead_expansion: usize, pmtu: usize) -> usize {
        match &self.tipe {
            PacketType::Short(_) => {
                // Leading byte.
                let mut len = 1;
                len += self.dcid.0.len();
                len += pn_length(self.pn);
                len + aead_expansion
            }
            PacketType::VN(_) => unimplemented!("Can't get overhead for VN"),
            PacketType::Retry { .. } => unimplemented!("Can't get overhead for Retry"),
            PacketType::Initial(..) | PacketType::ZeroRTT | PacketType::Handshake => {
                let pnl = pn_length(self.pn);

                // Leading byte.
                let mut len = 1;
                len += 4; // Version
                len += 1; // DCID length
                len += self.dcid.len();
                len += 1; // SCID length
                len += self.scid.as_ref().unwrap().len();

                if let PacketType::Initial(token) = &self.tipe {
                    len += Encoder::varint_len(token.len().try_into().unwrap());
                    len += token.len();
                }

                len += Encoder::varint_len((pnl + pmtu + aead_expansion) as u64);
                len += pnl;
                len + aead_expansion
            }
        }
    }
}

pub trait HeaderProtectionMask {
    fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>>;
    #[must_use]
    fn next_pn(&self) -> PacketNumber;
}

pub trait Protector: HeaderProtectionMask {
    fn encrypt(&mut self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>>;
}

pub trait Unprotector: HeaderProtectionMask {
    fn decrypt(&mut self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>>;
}

// TODO(mt) test this.  It's a strict implementation of the spec,
// but that doesn't mean we shouldn't test it.
fn decode_pn(expected: PacketNumber, pn: u64, w: usize) -> PacketNumber {
    let window = 1_u64 << (w * 8);
    let candidate = (expected & !(window - 1)) | pn;
    if candidate + (window / 2) <= expected {
        candidate + window
    } else if candidate > expected + (window / 2) {
        match candidate.checked_sub(window) {
            Some(pn_sub) => pn_sub,
            None => candidate,
        }
    } else {
        candidate
    }
}

fn encode_pnl(l: usize) -> u8 {
    assert!(l <= 4);
    (l - 1) as u8
}

fn decode_pnl(u: u8) -> usize {
    assert!(u < 4); // This came from 2 bits
    (u + 1) as usize
}

/*
  Short Header

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+
  |0|1|S|R|R|K|P P|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                Destination Connection ID (0..144)           ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Packet Number (8/16/24/32)              ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Protected Payload (*)                   ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  Long Header

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+
  |1|1|T T|X X X X|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Version (32)                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | DCID Len (8)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Destination Connection ID (0..160)            ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | SCID Len (8)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Source Connection ID (0..160)               ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Handshake
  +-+-+-+-+-+-+-+-+
  |1|1| 2 |R R|P P|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Version (32)                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | DCID Len (8)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Destination Connection ID (0..160)            ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | SCID Len (8)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Source Connection ID (0..160)               ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Length (i)                        ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Packet Number (8/16/24/32)               ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          Payload (*)                        ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Retry
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+
  |1|1| 3 | Unused|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Version (32)                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | DCID Len (8)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Destination Connection ID (0..160)            ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | SCID Len (8)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Source Connection ID (0..160)               ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | ODCID Len (8) |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Original Destination Connection ID (0..160)        ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Retry Token (*)                      ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

pub fn decode_packet_hdr(cid_parser: &dyn ConnectionIdDecoder, pd: &[u8]) -> Res<PacketHdr> {
    macro_rules! d {
        ($d:expr) => {
            match $d {
                Some(v) => v,
                _ => return Err(Error::NoMoreData),
            }
        };
    }

    let mut p = PacketHdr::default();
    let mut d = Decoder::from(pd);

    // Get the type byte
    p.tbyte = d!(d.decode_byte());
    if (p.tbyte & 0x80) == 0 {
        if p.tbyte & 0x40 == 0 {
            return Err(Error::InvalidPacket);
        }

        // Short Header.
        p.tipe = PacketType::Short((p.tbyte & 4) != 0);
        let cid = d!(cid_parser.decode_cid(&mut d));
        p.dcid = ConnectionId(cid.to_vec()); // TODO(mt) unnecessary copy
        p.hdr_len = pd.len() - d.remaining();
        p.body_len = d.remaining();
        return Ok(p);
    }

    let version = d!(d.decode_uint(4)) as u32;
    p.version = Some(version);
    p.dcid = ConnectionId(d!(d.decode_vec(1)).to_vec());
    p.scid = Some(ConnectionId(d!(d.decode_vec(1)).to_vec()));

    if version == 0 {
        let mut vns = vec![];
        while d.remaining() > 0 {
            vns.push(d!(d.decode_uint(4)) as u32);
        }
        p.tipe = PacketType::VN(vns);
        // No need to set hdr_length and body_length
        // because we won't need them.
        return Ok(p);
    } else {
        if p.tbyte & 0x40 == 0 {
            return Err(Error::InvalidPacket);
        }

        p.tipe = match (p.tbyte >> 4) & 0x3 {
            // TODO(ekr@rtfm.com): Check the 0 bits.
            PACKET_TYPE_INITIAL => {
                PacketType::Initial(d!(d.decode_vvec()).to_vec()) // TODO(mt) unnecessary copy
            }
            PACKET_TYPE_0RTT => PacketType::ZeroRTT,
            PACKET_TYPE_HANDSHAKE => PacketType::Handshake,
            PACKET_TYPE_RETRY => {
                let odcid = ConnectionId(d!(d.decode_vec(1)).to_vec()); // TODO(mt) unnecessary copy
                let token = d.decode_remainder().to_vec(); // TODO(mt) unnecessary copy
                p.tipe = PacketType::Retry { odcid, token };
                return Ok(p);
            }
            _ => unreachable!(),
        };
    }

    p.body_len = usize::try_from(d!(d.decode_varint()))?;
    if p.body_len > d.remaining() {
        return Err(Error::InvalidPacket);
    }
    p.hdr_len = pd.len() - d.remaining();

    Ok(p)
}

pub fn decrypt_packet_hdr<'p>(
    crypto: &mut dyn HeaderProtectionMask,
    hdr: &mut PacketHdr,
    pkt: &'p [u8],
) -> Res<(Vec<u8>, &'p [u8])> {
    assert!(!matches!(
        hdr.tipe,
        PacketType::Retry{..} | PacketType::VN(_)
    ));

    qtrace!("unmask hdr={}", hex(&pkt[..hdr.hdr_len + 4]));

    let sample_offset = hdr.hdr_len + 4;
    let mask = if let Some(sample) = pkt.get(sample_offset..(sample_offset + SAMPLE_SIZE)) {
        crypto.compute_mask(sample)
    } else {
        Err(Error::NoMoreData)
    }?;

    // Un-mask the leading byte.
    debug_assert_eq!(hdr.tbyte, pkt[0]);
    hdr.tbyte ^= mask[0]
        & match hdr.tipe {
            PacketType::Short(key_phase) => {
                let flip = (mask[0] & 4) != 0;
                hdr.tipe = PacketType::Short(key_phase ^ flip);
                0x1f
            }
            _ => 0x0f,
        };
    let pn_len = decode_pnl(hdr.tbyte & 0x3);

    // Make a copy of the header to work on.
    let mut hdrbytes = pkt[0..(hdr.hdr_len + pn_len)].to_vec();
    hdrbytes[0] = hdr.tbyte;

    // Unmask the PN.
    let mut pn_encoded: u64 = 0;
    for i in 0..pn_len {
        hdrbytes[hdr.hdr_len + i] ^= mask[1 + i];
        pn_encoded <<= 8;
        pn_encoded += u64::from(hdrbytes[hdr.hdr_len + i]);
    }

    qtrace!("unmasked hdr={}", hex(&hdrbytes));
    hdr.hdr_len += pn_len;
    hdr.body_len -= pn_len;

    hdr.pn = decode_pn(crypto.next_pn(), pn_encoded, pn_len);
    Ok((hdrbytes, &pkt[hdr.hdr_len..hdr.hdr_len + hdr.body_len]))
}

pub fn decrypt_packet_body(
    crypto: &mut dyn Unprotector,
    pn: PacketNumber,
    hdrbytes: &[u8],
    body: &[u8],
) -> Res<Vec<u8>> {
    Ok(crypto.decrypt(pn, hdrbytes, body)?)
}

fn encode_packet_short(
    crypto: &mut dyn Protector,
    hdr: &PacketHdr,
    key_phase: bool,
    body: &[u8],
) -> Vec<u8> {
    let mut enc = Encoder::default();
    // Leading byte.
    let pnl = pn_length(hdr.pn);
    enc.encode_byte(
        PACKET_BIT_SHORT | PACKET_BIT_FIXED_QUIC | (u8::from(key_phase) << 2) | encode_pnl(pnl),
    );
    enc.encode(&hdr.dcid.0);
    enc.encode_uint(pnl, hdr.pn);

    encrypt_packet(crypto, hdr, enc, body)
}

pub fn encode_packet_vn(hdr: &PacketHdr) -> Vec<u8> {
    let mut d = Encoder::default();
    let rand_byte = random(1)[0];
    d.encode_byte(PACKET_BIT_LONG | rand_byte);
    d.encode_uint(4, 0_u64); // version
    d.encode_vec(1, &hdr.dcid);
    d.encode_vec(1, hdr.scid.as_ref().unwrap());
    if let PacketType::VN(vers) = &hdr.tipe {
        for ver in vers {
            d.encode_uint(4, *ver);
        }
    } else {
        panic!("wrong packet type");
    }
    d.into()
}

/* Handle Initial, 0-RTT, Handshake. */
fn encode_packet_long(crypto: &mut dyn Protector, hdr: &PacketHdr, body: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::default();

    let pnl = pn_length(hdr.pn);
    enc.encode_byte(
        PACKET_BIT_LONG | PACKET_BIT_FIXED_QUIC | hdr.tipe.code() << 4 | encode_pnl(pnl),
    );
    enc.encode_uint(4, hdr.version.unwrap());
    enc.encode_vec(1, &*hdr.dcid);
    enc.encode_vec(1, &*hdr.scid.as_ref().unwrap());

    if let PacketType::Initial(token) = &hdr.tipe {
        enc.encode_vvec(&token);
    }
    enc.encode_varint((pnl + body.len() + AUTH_TAG_LEN) as u64);
    enc.encode_uint(pnl, hdr.pn);

    encrypt_packet(crypto, hdr, enc, body)
}

fn encrypt_packet(
    crypto: &mut dyn Protector,
    hdr: &PacketHdr,
    mut enc: Encoder,
    body: &[u8],
) -> Vec<u8> {
    let hdr_len = enc.len();
    // Encrypt the packet. This has too many copies.
    let ct = crypto.encrypt(hdr.pn, &enc, body).unwrap();
    enc.encode(&ct);
    qtrace!("mask hdr={}", hex(&enc[0..hdr_len]));
    let pn_start = hdr_len - pn_length(hdr.pn);
    let mask = crypto
        .compute_mask(&enc[pn_start + 4..pn_start + SAMPLE_SIZE + 4])
        .unwrap();
    enc[0] ^= mask[0]
        & match hdr.tipe {
            PacketType::Short(_) => 0x1f,
            _ => 0x0f,
        };
    for i in 0..pn_length(hdr.pn) {
        enc[pn_start + i] ^= mask[i + 1];
    }
    qtrace!("masked hdr={}", hex(&enc[0..hdr_len]));
    enc.into()
}

// TODO(ekr@rtfm.com): Minimal packet number lengths.
fn pn_length(_pn: PacketNumber) -> usize {
    3
}

pub fn encode_retry(hdr: &PacketHdr) -> Vec<u8> {
    let rand_byte = random(1)[0];
    if let PacketType::Retry { odcid, token } = &hdr.tipe {
        let mut enc = Encoder::default();
        let b0 =
            PACKET_BIT_LONG | PACKET_BIT_FIXED_QUIC | (PACKET_TYPE_RETRY << 4) | (rand_byte & 0xf);
        enc.encode_byte(b0);
        enc.encode_uint(4, hdr.version.unwrap());
        enc.encode_vec(1, &hdr.dcid);
        enc.encode_vec(1, &hdr.scid.as_ref().unwrap());
        enc.encode_vec(1, odcid);
        enc.encode(token);
        enc.into()
    } else {
        unreachable!()
    }
}

pub fn encode_packet(crypto: &mut dyn Protector, hdr: &PacketHdr, body: &[u8]) -> Vec<u8> {
    match &hdr.tipe {
        PacketType::Short(key_phase) => encode_packet_short(crypto, hdr, *key_phase, body),
        PacketType::VN(_) => encode_packet_vn(hdr),
        PacketType::Retry { .. } => encode_retry(hdr),
        PacketType::Initial(..) | PacketType::ZeroRTT | PacketType::Handshake => {
            encode_packet_long(crypto, hdr, body)
        }
    }
}

#[cfg(test)]
#[allow(unused_variables)]
mod tests {
    use super::*;
    use neqo_common::matches;
    use test_fixture::fixture_init;

    const TEST_BODY: [u8; 6] = [0x01, 0x23, 0x45, 0x67, 0x89, 0x10];

    struct TestFixture {}

    const AEAD_MASK: u8 = 0;

    impl TestFixture {
        fn auth_tag(hdr: &[u8], body: &[u8]) -> [u8; AUTH_TAG_LEN] {
            [0; AUTH_TAG_LEN]
        }
    }

    impl HeaderProtectionMask for TestFixture {
        fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>> {
            Ok(vec![0xa5; 5])
        }

        #[must_use]
        fn next_pn(&self) -> PacketNumber {
            0
        }
    }

    impl Unprotector for TestFixture {
        fn decrypt(&mut self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
            let mut pt = body.to_vec();

            for i in &mut pt {
                *i ^= AEAD_MASK;
            }
            let pt_len = pt.len() - AUTH_TAG_LEN;
            let at = Self::auth_tag(hdr, &pt[0..pt_len]);
            for i in 0..16 {
                if at[i] != pt[pt_len + i] {
                    return Err(Error::DecryptError);
                }
            }
            Ok(pt[0..pt_len].to_vec())
        }
    }

    impl Protector for TestFixture {
        fn encrypt(&mut self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
            let tag = Self::auth_tag(hdr, body);
            let mut enc = Encoder::with_capacity(body.len() + tag.len());
            enc.encode(body);
            enc.encode(&tag);
            for i in 0..enc.len() {
                enc[i] ^= AEAD_MASK;
            }

            Ok(enc.into())
        }
    }

    impl ConnectionIdDecoder for TestFixture {
        fn decode_cid(&self, dec: &mut Decoder) -> Option<ConnectionId> {
            dec.decode(5).map(ConnectionId::from)
        }
    }

    fn default_hdr() -> PacketHdr {
        PacketHdr {
            tbyte: 0,
            tipe: PacketType::Short(false),
            version: Some(31),
            dcid: ConnectionId(vec![1, 2, 3, 4, 5]),
            scid: None,
            pn: 0x0505,
            hdr_len: 0,
            body_len: 0,
        }
    }

    fn assert_headers_equal(left: &PacketHdr, right: &PacketHdr) {
        assert_eq!(left.tipe, right.tipe);
        assert_eq!(left.dcid, right.dcid);
        assert_eq!(left.scid, right.scid);
        assert_eq!(left.pn, right.pn);
    }

    fn test_decrypt_packet(f: &mut TestFixture, packet: Vec<u8>) -> Res<(PacketHdr, Vec<u8>)> {
        let mut phdr = decode_packet_hdr(f, &packet)?;
        let (hdr, body) = decrypt_packet_hdr(f, &mut phdr, &packet)?;
        let payload = decrypt_packet_body(f, phdr.pn, &hdr, body)?;
        Ok((phdr, payload))
    }

    fn test_encrypt_decrypt(f: &mut TestFixture, hdr: &mut PacketHdr, body: &[u8]) -> PacketHdr {
        let packet = encode_packet(f, hdr, &TEST_BODY);
        let (dec_hdr, dec_body) = test_decrypt_packet(f, packet).unwrap();
        assert_headers_equal(&hdr, &dec_hdr);
        assert_eq!(body.to_vec(), dec_body);
        dec_hdr
    }

    #[test]
    fn test_short_packet() {
        let mut f = TestFixture {};
        let mut hdr = default_hdr();
        test_encrypt_decrypt(&mut f, &mut hdr, &TEST_BODY);
    }

    #[test]
    fn test_short_packet_damaged() {
        let mut f = TestFixture {};
        let hdr = default_hdr();
        let mut packet = encode_packet(&mut f, &hdr, &TEST_BODY);
        let plen = packet.len();
        packet[plen - 1] ^= 0x7;
        assert!(test_decrypt_packet(&mut f, packet).is_err());
    }

    #[test]
    fn test_handshake_packet() {
        let mut f = TestFixture {};
        let mut hdr = default_hdr();
        hdr.tipe = PacketType::Handshake;
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        test_encrypt_decrypt(&mut f, &mut hdr, &TEST_BODY);
    }

    #[test]
    fn test_handshake_packet_damaged() {
        let mut f = TestFixture {};
        let mut hdr = default_hdr();
        hdr.tipe = PacketType::Handshake;
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        let mut packet = encode_packet(&mut f, &hdr, &TEST_BODY);
        let plen = packet.len();
        packet[plen - 1] ^= 0x7;
        assert!(test_decrypt_packet(&mut f, packet).is_err());
    }

    #[test]
    fn test_initial_packet() {
        let mut f = TestFixture {};
        let mut hdr = default_hdr();
        let tipe = PacketType::Initial(vec![0x0, 0x0, 0x0, 0x0]);
        hdr.tipe = tipe;
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        test_encrypt_decrypt(&mut f, &mut hdr, &TEST_BODY);
    }

    #[test]
    fn test_initial_packet_damaged() {
        let mut f = TestFixture {};
        let mut hdr = default_hdr();
        hdr.tipe = PacketType::Initial(vec![0x0, 0x0, 0x0, 0x0]);
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        let mut packet = encode_packet(&mut f, &hdr, &TEST_BODY);
        let plen = packet.len();
        packet[plen - 1] ^= 0x7;
        assert!(test_decrypt_packet(&mut f, packet).is_err());
    }

    #[test]
    fn test_retry() {
        fixture_init();
        let mut hdr = default_hdr();
        hdr.tipe = PacketType::Retry {
            odcid: ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]),
            token: vec![99, 88, 77, 66, 55, 44, 33],
        };
        hdr.scid = Some(ConnectionId(vec![1, 2, 3, 4, 5]));
        let packet = encode_retry(&hdr);
        let f = TestFixture {};
        let decoded = decode_packet_hdr(&f, &packet).expect("should decode");
        assert_eq!(decoded.tipe, hdr.tipe);
        assert_eq!(decoded.version, hdr.version);
        assert_eq!(decoded.dcid, hdr.dcid);
        assert_eq!(decoded.scid, hdr.scid);
    }

    #[test]
    fn generate_initial_cid() {
        fixture_init();
        for i in 0..100 {
            let cid = ConnectionId::generate_initial();
            if !matches!(cid.len(), 8..=20) {
                panic!("connection ID {:?}", cid);
            }
        }
    }
}
