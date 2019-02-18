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
struct Packet {
    tipe: PacketType,
    version: Option<Version>,
    dcid: ConnectionId,
    scid: Option<ConnectionId>,
    pn: PacketNumber,
    payload: Option<Vec<u8>>,
}

trait PacketDecoder {
    fn get_cid_len(&self) -> usize;
}

trait PacketConn {
    fn compute_mask(&self, sample: &[u8]) -> Res<[u8; 5]>;
    fn decode_pn(&self, pn: u64) -> Res<u64>;
    fn aead_decrypt(&self, p: &Packet) -> Res<Vec<u8>>;
    fn aead_encrypt(&self, p: &Packet) -> Res<Vec<u8>>;
}

fn decode_packet(dec: &PacketDecoder, d: &mut Data) -> Res<Packet> {
    let mut p = Packet::default();

    // Get the type byte
    let length: usize;
    let t = d.decode_byte()?;
    if (t & 0x80) == 0 {
        // Short Header.
        p.tipe = PacketType::Short;
        p.dcid = ConnectionId(d.decode_data(dec.get_cid_len())?);
        p.payload = Some(d.decode_remainder()?);
        return Ok(p);
    }

    // Long header.
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
        return Ok(p);
    } else {
        p.tipe = match (t >> 4) & 0x3 {
            PACKET_TYPE_INITIAL => PacketType::Initial(d.decode_data_and_len()?),
            PACKET_TYPE_0RTT => PacketType::ZeroRTT,
            PACKET_TYPE_HANDSHAKE => PacketType::Handshake,
            PACKET_TYPE_RETRY => PacketType::Retry(d.decode_remainder()?),
            _ => unreachable!(),
        };

        if matches!(p.tipe, PacketType::Retry(..)) {
            return Ok(p);
        }
    }

    p.payload = Some(d.decode_data_and_len()?);
    Ok(p)
}

impl Packet {
    fn decrypt(&self, ctx: &PacketConn) -> Res<()> {
        // First remove the header protection.
        let payload = self.payload.as_ref().unwrap();

        if payload.len() < (4 + SAMPLE_SIZE) {
            return Err(Error::ErrNoMoreData);
        }

        let mask = ctx.compute_mask(&payload[4..(SAMPLE_SIZE + 4)])?;

        Ok(())
    }
}
