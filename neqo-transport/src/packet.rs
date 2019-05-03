// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use derive_more::Deref;

use neqo_common::data::{Data, DataBuf};
use neqo_common::hex;
use neqo_common::{matches, qtrace};

use crate::nss_stub::Epoch;
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
    Short,
    ZeroRTT,
    Handshake,
    VN(Vec<u32>),     // List of versions
    Initial(Vec<u8>), // Token
    Retry(Vec<u8>),   // Token
}

impl Default for PacketType {
    fn default() -> PacketType {
        PacketType::Short
    }
}

impl PacketType {
    fn code(&self) -> u8 {
        match self {
            PacketType::Initial(..) => PACKET_TYPE_INITIAL,
            PacketType::ZeroRTT => PACKET_TYPE_0RTT,
            PacketType::Handshake => PACKET_TYPE_HANDSHAKE,
            PacketType::Retry(..) => PACKET_TYPE_RETRY,
            _ => unimplemented!(),
        }
    }
}

pub type Version = u32;
pub type PacketNumber = u64;

#[derive(Default, Deref, Debug, PartialEq)]
pub struct ConnectionId(pub Vec<u8>);

#[derive(Default, Debug)]
pub struct PacketHdr {
    pub tbyte: u8,
    pub tipe: PacketType,
    pub version: Option<Version>,
    pub dcid: ConnectionId,
    pub scid: Option<ConnectionId>,
    pub pn: PacketNumber,
    pub epoch: Epoch,
    pub hdr_len: usize,
    body_len: usize,
}

impl PacketHdr {
    pub fn new(
        tbyte: u8,
        tipe: PacketType,
        version: Option<Version>,
        dcid: ConnectionId,
        scid: Option<ConnectionId>,
        pn: PacketNumber,
        epoch: Epoch,
        hdr_len: usize,
    ) -> PacketHdr {
        PacketHdr {
            tbyte,
            tipe,
            version,
            dcid,
            scid,
            pn,
            epoch,
            hdr_len,
            body_len: 0,
        }
    }

    pub fn body_len(&self) -> usize {
        self.body_len
    }
}

pub trait PacketDecoder {
    fn get_cid_len(&self) -> usize;
}

pub trait CryptoCtx {
    fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>>;
    fn aead_decrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>>;
    fn aead_encrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>>;
}

pub struct PacketNumberDecoder {
    expected: u64
}
impl PacketNumberDecoder {
    pub fn new(largest_acknowledged: u64) -> PacketNumberDecoder {
        PacketNumberDecoder { expected: largest_acknowledged + 1 }
    }

    fn decode_pn(&self, pn: u64, w: usize) -> PacketNumber {
        let window = 1u64 << (w * 8);
        let candidate = (self.expected & !(window - 1)) | pn;
        if candidate + (window/2) <= self.expected {
            candidate + window
        } else if candidate > self.expected + (window/2) {
            match candidate.checked_sub(window) {
                Some(pn_sub) => pn_sub,
                None => candidate,
            }
        } else {
            candidate
        }
    }
}

fn encode_cidl_half(l: usize) -> u8 {
    match l {
        0 => 0,
        4...18 => (l - 3) as u8,
        _ => panic!("Illegal CID length"),
    }
}
fn encode_cidl(d: usize, s: usize) -> u8 {
    (encode_cidl_half(d) << 4) | encode_cidl_half(s)
}

fn decode_cidl_half(l: u8) -> u8 {
    match l {
        0 => 0,
        _ => l + 3,
    }
}

fn decode_cidl(l: u8) -> (u8, u8) {
    (decode_cidl_half(l >> 4), decode_cidl_half(l & 0xf))
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
  |DCIL(4)|SCIL(4)|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Destination Connection ID (0/32..144)         ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Source Connection ID (0/32..144)            ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Handshake
  +-+-+-+-+-+-+-+-+
  |1|1| 0 |R R|P P|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Version (32)                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |DCIL(4)|SCIL(4)|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Destination Connection ID (0/32..144)         ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Source Connection ID (0/32..144)            ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Token Length (i)                    ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                            Token (*)                        ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Length (i)                        ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Packet Number (8/16/24/32)               ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          Payload (*)                        ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

pub fn decode_packet_hdr(dec: &PacketDecoder, pd: &[u8]) -> Res<PacketHdr> {
    let mut p = PacketHdr::default();

    let mut d = Data::from_slice(pd);

    // Get the type byte
    p.tbyte = d.decode_byte()?;
    if p.tbyte & 0x40 == 0 {
        return Err(Error::InvalidPacket);
    }

    if (p.tbyte & 0x80) == 0 {
        // Short Header.
        p.tipe = PacketType::Short;
        p.dcid = ConnectionId(d.decode_data(dec.get_cid_len())?);
        p.hdr_len = d.offset();
        p.body_len = d.remaining();
        p.epoch = 3; // TODO(ekr@rtfm.com): Decode key phase bits.
        return Ok(p);
    }

    let version = d.decode_uint(4)? as u32;
    let (dest_len, src_len) = decode_cidl(d.decode_byte()?);

    p.dcid = ConnectionId(d.decode_data(dest_len.into())?);
    p.scid = Some(ConnectionId(d.decode_data(src_len.into())?));
    if version == 0 {
        let mut vns = vec![];

        while d.remaining() > 0 {
            let vn = d.decode_uint(4)? as u32;
            vns.push(vn);
        }
        p.tipe = PacketType::VN(vns);
        // No need to set hdr_length and body_length
        // because we won't need them.
        return Ok(p);
    } else {
        p.tipe = match (p.tbyte >> 4) & 0x3 {
            // TODO(ekr@rtfm.com): Check the 0 bits.
            PACKET_TYPE_INITIAL => {
                p.epoch = 0;
                PacketType::Initial(d.decode_data_and_len()?)
            }
            PACKET_TYPE_0RTT => {
                p.epoch = 1;
                PacketType::ZeroRTT
            }
            PACKET_TYPE_HANDSHAKE => {
                p.epoch = 2;
                PacketType::Handshake
            }
            // TODO(ekr@rtfm.com): Read ODCIL.
            PACKET_TYPE_RETRY => PacketType::Retry(d.decode_remainder()?),
            _ => unreachable!(),
        };

        if matches!(p.tipe, PacketType::Retry(..)) {
            return Ok(p);
        }
    }

    p.body_len = d.decode_varint()? as usize;
    p.hdr_len = d.offset();

    Ok(p)
}

pub fn decrypt_packet(
    crypto: &CryptoCtx,
    pn: PacketNumberDecoder,
    hdr: &mut PacketHdr,
    pkt: &[u8],
) -> Res<Vec<u8>> {
    assert!(!matches!(
        hdr.tipe,
        PacketType::Retry(..) | PacketType::VN(..)
    ));

    // First remove the header protection.
    let payload = &pkt[hdr.hdr_len..];

    if payload.len() < (4 + SAMPLE_SIZE) {
        return Err(Error::NoMoreData);
    }
    let mask = crypto.compute_mask(&payload[4..(SAMPLE_SIZE + 4)])?;

    // Now put together a raw header to work on.
    let pn_len = decode_pnl((hdr.tbyte ^ mask[0]) & 0x3);
    let mut hdrbytes = pkt[0..(hdr.hdr_len + pn_len)].to_vec();

    qtrace!("unmask hdr={}", hex(&hdrbytes));
    // Un-mask the leading byte.
    hdrbytes[0] ^= mask[0]
        & match hdr.tipe {
            PacketType::Short => 0x1f,
            _ => 0x0f,
        };

    // Now unmask the PN.
    let mut pn_encoded: u64 = 0;
    for i in 0..pn_len {
        hdrbytes[hdr.hdr_len + i] ^= mask[1 + i];
        pn_encoded <<= 8;
        pn_encoded += hdrbytes[hdr.hdr_len + i] as u64;
    }
    qtrace!("unmasked hdr={}", hex(&hdrbytes));
    hdr.hdr_len += pn_len;
    hdr.body_len -= pn_len;

    // Now call out to expand the PN.
    hdr.pn = pn.decode_pn(pn_encoded, pn_len);

    // Finally, decrypt.
    Ok(crypto.aead_decrypt(
        hdr.pn,
        &hdrbytes,
        &pkt[hdr.hdr_len..hdr.hdr_len + hdr.body_len()],
    )?)
}

fn encode_packet_short(crypto: &CryptoCtx, hdr: &PacketHdr, body: &[u8]) -> Vec<u8> {
    let mut d = Data::default();
    // Leading byte.
    let pnl = pn_length(hdr.pn);
    d.encode_byte(PACKET_BIT_SHORT | PACKET_BIT_FIXED_QUIC | encode_pnl(pnl));
    d.encode_vec(&hdr.dcid.0);
    d.encode_uint(hdr.pn, pnl);

    encrypt_packet(crypto, hdr, d, body)
}

/* Hanlde Initial, 0-RTT, Handshake. */
fn encode_packet_long(crypto: &CryptoCtx, hdr: &PacketHdr, body: &[u8]) -> Vec<u8> {
    let mut d = Data::default();

    let pnl = pn_length(hdr.pn);
    d.encode_byte(PACKET_BIT_LONG | PACKET_BIT_FIXED_QUIC | hdr.tipe.code() << 4 | encode_pnl(pnl));
    d.encode_uint(hdr.version.unwrap(), 4);
    d.encode_byte(encode_cidl(
        hdr.dcid.len(),
        hdr.scid.as_ref().unwrap().len(),
    ));
    d.encode_vec(&*hdr.dcid);
    d.encode_vec(&*hdr.scid.as_ref().unwrap());

    if let PacketType::Initial(token) = &hdr.tipe {
        d.encode_vec_and_len(&token);
    }
    d.encode_varint((pnl + body.len() + AUTH_TAG_LEN) as u64);
    d.encode_uint(hdr.pn, pnl);

    encrypt_packet(crypto, hdr, d, body)
}

fn encrypt_packet(crypto: &CryptoCtx, hdr: &PacketHdr, mut d: Data, body: &[u8]) -> Vec<u8> {
    let hdr_len = d.remaining();
    // Encrypt the packet. This has too many copies.
    let ct = crypto.aead_encrypt(hdr.pn, d.as_mut_vec(), body).unwrap();
    d.encode_vec(&ct);
    let ret = d.as_mut_vec();
    qtrace!("mask hdr={}", hex(&ret[0..hdr_len]));
    let pn_start = hdr_len - pn_length(hdr.pn);
    let mask = crypto
        .compute_mask(&ret[pn_start + 4..pn_start + SAMPLE_SIZE + 4])
        .unwrap();
    ret[0] ^= mask[0]
        & match hdr.tipe {
            PacketType::Short => 0x1f,
            _ => 0x0f,
        };
    for i in 0..pn_length(hdr.pn) {
        ret[pn_start + i] ^= mask[i + 1];
    }
    qtrace!("masked hdr={}", hex(&ret[0..hdr_len]));
    ret.to_vec()
}

// TODO(ekr@rtfm.com): Minimal packet number lengths.
fn pn_length(_pn: PacketNumber) -> usize {
    return 3;
}

pub fn encode_packet(crypto: &CryptoCtx, hdr: &PacketHdr, body: &[u8]) -> Vec<u8> {
    match hdr.tipe {
        PacketType::Short => encode_packet_short(crypto, hdr, body),
        /*
        PacketType::VN(..) => encode_packet_vn(ctx, &d, hdr, body),
        PacketType::Retry(..) => encode_retry(ctx, &d, hdr, body), */
        PacketType::Initial(..) | PacketType::Handshake | PacketType::Retry(..) => {
            encode_packet_long(crypto, hdr, body)
        }
        _ => unimplemented!(),
    }
}

#[cfg(test)]
#[allow(unused_variables)]
mod tests {
    use super::*;

    const TEST_BODY: [u8; 6] = [0x01, 0x23, 0x45, 0x67, 0x89, 0x10];

    struct TestFixture {}

    const AEAD_MASK: u8 = 0;

    impl TestFixture {
        fn auth_tag(hdr: &[u8], body: &[u8]) -> [u8; AUTH_TAG_LEN] {
            [0; AUTH_TAG_LEN]
        }
    }

    impl CryptoCtx for TestFixture {
        fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>> {
            Ok(vec![0xa5, 0xa5, 0xa5, 0xa5, 0xa5])
        }

        fn aead_decrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
            let mut pt = body.to_vec();

            for i in 0..pt.len() {
                pt[i] ^= AEAD_MASK;
            }
            let pt_len = pt.len() - AUTH_TAG_LEN;
            let at = TestFixture::auth_tag(hdr, &pt[0..pt_len]);
            for i in 0..16 {
                if at[i] != pt[pt_len + i] {
                    return Err(Error::DecryptError);
                }
            }
            Ok(pt[0..pt_len].to_vec())
        }

        fn aead_encrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
            let mut d = Data::from_slice(body);
            d.encode_vec(&TestFixture::auth_tag(hdr, body));
            let v = d.as_mut_vec();
            for i in 0..v.len() {
                v[i] ^= AEAD_MASK;
            }

            Ok(v.to_vec())
        }
    }

    impl PacketDecoder for TestFixture {
        fn get_cid_len(&self) -> usize {
            5
        }
    }

    fn default_hdr() -> PacketHdr {
        PacketHdr {
            tbyte: 0,
            tipe: PacketType::Short,
            version: Some(31),
            dcid: ConnectionId(vec![1, 2, 3, 4, 5]),
            scid: None,
            pn: 0x0505,
            epoch: 0,
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

    fn test_decrypt_packet(f: &TestFixture, packet: Vec<u8>) -> Res<(PacketHdr, Vec<u8>)> {
        let mut phdr = decode_packet_hdr(f, &packet)?;
        let body = decrypt_packet(f, PacketNumberDecoder::new(0), &mut phdr, &packet)?;
        Ok((phdr, body))
    }

    fn test_encrypt_decrypt(f: &TestFixture, hdr: &mut PacketHdr, body: &[u8]) -> PacketHdr {
        let packet = encode_packet(f, hdr, &TEST_BODY);
        let res = test_decrypt_packet(&f, packet).unwrap();
        assert_headers_equal(&hdr, &res.0);
        assert_eq!(body.to_vec(), res.1);
        res.0
    }

    #[test]
    fn test_short_packet() {
        let f = TestFixture {};
        let mut hdr = default_hdr();
        test_encrypt_decrypt(&f, &mut hdr, &TEST_BODY);
    }

    #[test]
    fn test_short_packet_damaged() {
        let f = TestFixture {};
        let mut hdr = default_hdr();
        let mut packet = encode_packet(&f, &mut hdr, &TEST_BODY);
        let plen = packet.len();
        packet[plen - 1] ^= 0x7;
        assert!(test_decrypt_packet(&f, packet).is_err());
    }

    #[test]
    fn test_handshake_packet() {
        let f = TestFixture {};
        let mut hdr = default_hdr();
        hdr.tipe = PacketType::Handshake;
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        test_encrypt_decrypt(&f, &mut hdr, &TEST_BODY);
    }

    #[test]
    fn test_handshake_packet_damaged() {
        let f = TestFixture {};
        let mut hdr = default_hdr();
        hdr.tipe = PacketType::Handshake;
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        let mut packet = encode_packet(&f, &mut hdr, &TEST_BODY);
        let plen = packet.len();
        packet[plen - 1] ^= 0x7;
        assert!(test_decrypt_packet(&f, packet).is_err());
    }

    #[test]
    fn test_initial_packet() {
        let f = TestFixture {};
        let mut hdr = default_hdr();
        let tipe = PacketType::Initial(vec![0x0, 0x0, 0x0, 0x0]);
        hdr.tipe = tipe;
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        test_encrypt_decrypt(&f, &mut hdr, &TEST_BODY);
    }

    #[test]
    fn test_initial_packet_damaged() {
        let f = TestFixture {};
        let mut hdr = default_hdr();
        hdr.tipe = PacketType::Initial(vec![0x0, 0x0, 0x0, 0x0]);
        hdr.scid = Some(ConnectionId(vec![9, 8, 7, 6, 5, 4, 3, 2]));
        let mut packet = encode_packet(&f, &mut hdr, &TEST_BODY);
        let plen = packet.len();
        packet[plen - 1] ^= 0x7;
        assert!(test_decrypt_packet(&f, packet).is_err());
    }
}

/*
if matches!(hdr.tipe, PacketType::Short) {
    return
}


    t = 0x12;
    // TODO(ekr@rtfm.com): Key phase.
    t |= 0x3; // 32-bit packet number.
} else {
    // Look up the type bits.
    let tf = match hdr.tipe {
        PacketType::ZeroRTT => PACKET_TYPE_0RTT,
        PacketType::Handshake => PACKET_TYPE_HANDSHAKE,
        PacketType::Initial(..) => PACKET_TYPE_INITIAL,
        PacketType::Retry(..) => PACKET_TYPE_RETRY,
        // TODO(ekr@rtfm.com): Randomize VN.
        _ => unimplemented!()
    };

    // This is the top-half of the header byte.
    t = 0x40 | tf << 4;

    // Now the type-specific low-order bits.
    t |= match hdr.tipe {
        // Always use the 32-bit packet # size.
        PacketType::ZeroRTT | PacketType::Handshake | PacketType::Initial(..) => 0x3,
        PacketType::Retry(..) => unimplemented!(), // ODCIL.
        _ => unimplemented!()
    };
}

// Finally, encode the byte.
d.encode_byte(t);


Err(Error::Internal)*/
