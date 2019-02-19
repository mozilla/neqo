// TODO(ekr@rtfm.com): Remove this once I've implemented everything.
#![allow(unused_variables, dead_code)]
use super::data::*;
use super::*;

const PACKET_TYPE_INITIAL: u8 = 0x0;
const PACKET_TYPE_0RTT: u8 = 0x01;
const PACKET_TYPE_HANDSHAKE: u8 = 0x2;
const PACKET_TYPE_RETRY: u8 = 0x03;

const SAMPLE_SIZE: usize = 16;

enum PacketType {
    Short,
    ZeroRTT,
    Handshake,
    VN(Vec<u32>),
    Initial(Vec<u8>),
    Retry(Vec<u8>),
}

impl Default for PacketType {
    fn default() -> PacketType {
        PacketType::Short
    }
}

#[derive(Default)]
struct Version(u32);
#[derive(Default)]
struct PacketNumber(u64);
#[derive(Default)]
struct ConnectionId(Vec<u8>);

#[derive(Default)]
struct PacketHdr {
    tbyte: u8,
    tipe: PacketType,
    version: Option<Version>,
    dcid: ConnectionId,
    scid: Option<ConnectionId>,
    pn: PacketNumber,
    hdr_len: usize,
    body_len: usize,
}

trait PacketDecoder {
    fn get_cid_len(&self) -> usize;
}

trait PacketConn {
    fn compute_mask(&self, sample: &[u8]) -> Res<[u8; 5]>;
    fn decode_pn(&self, pn: u64) -> Res<PacketNumber>;
    fn aead_decrypt(&self, p: &PacketHdr) -> Res<Vec<u8>>;
    fn aead_encrypt(&self, p: &PacketHdr) -> Res<Vec<u8>>;
}

fn decode_packet(dec: &PacketDecoder, pd: &[u8]) -> Res<PacketHdr> {
    let mut p = PacketHdr::default();

    let mut d = Data::from_slice(pd);

    // Get the type byte
    p.tbyte = d.decode_byte()?;
    if (p.tbyte & 0x80) == 0 {
        // Short Header.
        p.tipe = PacketType::Short;
        p.dcid = ConnectionId(d.decode_data(dec.get_cid_len())?);
        p.hdr_len = d.offset();
        p.body_len = d.remaining();
        return Ok(p);
    }

    // Long header.
    if p.tbyte & 0x40 != 0 {
        return Err(Error::ErrInvalidPacket);
    }

    let v = d.decode_uint(4)? as u32;
    let idl = d.decode_byte()?;
    p.dcid = ConnectionId(d.decode_data((idl >> 4) as usize)?);
    p.scid = Some(ConnectionId(d.decode_data((idl & 0xf) as usize)?));
    if v == 0 {
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
            PACKET_TYPE_INITIAL => PacketType::Initial(d.decode_data_and_len()?),
            PACKET_TYPE_0RTT => PacketType::ZeroRTT,
            PACKET_TYPE_HANDSHAKE => PacketType::Handshake,
            // TODO(ekr@rtfm.com): Read ODCIL.
            PACKET_TYPE_RETRY => PacketType::Retry(d.decode_remainder()?),
            _ => unreachable!(),
        };

        if matches!(p.tipe, PacketType::Retry(..)) {
            return Ok(p);
        }
    }

    p.hdr_len = d.offset();
    p.body_len = d.remaining();

    Ok(p)
}

fn decrypt_packet(ctx: &PacketConn, hdr: &mut PacketHdr, pkt: &[u8]) -> Res<()> {
    assert!(!matches!(
        hdr.tipe,
        PacketType::Retry(..) | PacketType::VN(..)
    ));

    // First remove the header protection.
    let payload = &pkt[hdr.hdr_len..];

    if payload.len() < (4 + SAMPLE_SIZE) {
        return Err(Error::ErrNoMoreData);
    }
    let mask = ctx.compute_mask(&payload[4..(SAMPLE_SIZE + 4)])?;

    // Now put together a raw header to work on.
    let pn_len = (1 + ((hdr.tbyte ^ mask[0]) & 0x3)) as usize;

    let mut hdrbytes = pkt[0..(hdr.hdr_len + pn_len)].to_vec();

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

    hdr.hdr_len += pn_len;
    hdr.body_len -= pn_len;

    // Now call out to expand the PN.
    hdr.pn = ctx.decode_pn(pn_encoded)?;

    // Finally, decrypt.

    Ok(())
}
