// TODO(ekr@rtfm.com): Remove this once I've implemented everything.
#![allow(unused_variables, dead_code)]
use super::data::*;
use super::*;

const PACKET_TYPE_INITIAL: u8 = 0x0;
const PACKET_TYPE_0RTT: u8 = 0x01;
const PACKET_TYPE_HANDSHAKE: u8 = 0x2;
const PACKET_TYPE_RETRY: u8 = 0x03;

const PACKET_BIT_SHORT: u8 = 0x80;
const PACKET_BIT_FIXED_QUIC: u8 = 0x40;
const PACKET_BIT_PN_LENGTH: u8 = 0x03;

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
type PacketNumber = u64;
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
    epoch: u64,
    hdr_len: usize,
    body_len: usize,
}

trait PacketDecoder {
    fn get_cid_len(&self) -> usize;
}

trait PacketCtx {
    fn compute_mask(&self, sample: &[u8]) -> Res<[u8; 5]>;
    fn decode_pn(&self, pn: u64) -> Res<PacketNumber>;
    fn aead_decrypt(&self, pn: PacketNumber, epoch: u64, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>>;
    fn aead_encrypt(&self, pn: PacketNumber, epoch: u64, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>>;
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
*/
fn decode_packet(dec: &PacketDecoder, pd: &[u8]) -> Res<PacketHdr> {
    let mut p = PacketHdr::default();

    let mut d = Data::from_slice(pd);

    // Get the type byte
    p.tbyte = d.decode_byte()?;
    if p.tbyte & 0x40 == 0{
        return Err(Error::ErrInvalidPacket);
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

    // Long header.
    if p.tbyte & 0x40 != 0 {
        return Err(Error::ErrInvalidPacket);
    }

    let v = d.decode_uint(4)? as u32;
    let idl = d.decode_byte()?;
    // TODO(ekr@rtfm.com): Do the right decoder. for CIDL
    unimplemented!();
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
            PACKET_TYPE_INITIAL => {
                p.epoch = 0;
                PacketType::Initial(d.decode_data_and_len()?)
            },
            PACKET_TYPE_0RTT => {
                p.epoch = 1;
                PacketType::ZeroRTT
            },
            PACKET_TYPE_HANDSHAKE => {
                p.epoch = 2;
                PacketType::Handshake
            },
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

fn decrypt_packet(ctx: &PacketCtx, hdr: &mut PacketHdr, pkt: &[u8]) -> Res<Vec<u8>> {
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
    Ok(ctx.aead_decrypt(hdr.pn, hdr.epoch, &hdrbytes, &pkt[hdr.hdr_len..])?)
}


fn encode_packet_short(ctx: &PacketCtx, d: &mut Data, hdr: &mut PacketHdr, body: &[u8]) -> Res<Vec<u8>> {
    // Leading byte.
    d.encode_byte(PACKET_BIT_SHORT |
                  PACKET_BIT_FIXED_QUIC |
                  PACKET_BIT_PN_LENGTH);
    d.encode_vec(&hdr.dcid.0);
    d.encode_uint(hdr.pn, 4);

    encrypt_packet(ctx, hdr, d, body)
}

fn encrypt_packet(ctx: &PacketCtx, hdr: &mut PacketHdr, d: &mut Data, body: &[u8]) -> Res<Vec<u8>> {
    let hdr_len = d.remaining();
    // Encrypt the packet. This has too many copies.
    let ct = ctx.aead_encrypt(hdr.pn, hdr.epoch, d.as_mut_vec(), body).unwrap();
    d.encode_vec(&ct);
    let mask = ctx.compute_mask(&ct[0..SAMPLE_SIZE]).unwrap();
    let ret = d.as_mut_vec();
    ret[0] ^= mask[0] & 0x1f;
    for i in hdr_len-4..hdr_len {
        ret[i] ^= mask[1 + 1];
    }
    Ok(ret.to_vec())
}

fn encode_packet(ctx: &PacketCtx, hdr: &mut PacketHdr, body: &[u8]) -> Res<Vec<u8>> {
    let mut d = Data::default();

    match hdr.tipe {
        PacketType::Short => encode_packet_short(ctx, &mut d, hdr, body),
        /*
        PacketType::VN(..) => encode_packet_vn(ctx, &d, hdr, body),
        PacketType::Retry(..) => encode_retry(ctx, &d, hdr, body),
        _ => encode_packet_long(ctx, hdr, body)*/
        _ => unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFixture {}

    impl TestFixture {
        fn auth_tag(hdr: &[u8], body: &[u8]) -> [u8; 16] {
            [0; 16]
        }
    }
    
    impl PacketCtx for TestFixture {
        fn compute_mask(&self, sample: &[u8]) -> Res<[u8; 5]> {
            Ok([0xa5,0xa5,0xa5,0xa5,0xa5])
        }

        fn decode_pn(&self, pn: u64) -> Res<PacketNumber> {
            Ok(pn)
        }

        fn aead_decrypt(&self, pn: PacketNumber, epoch: u64, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
            unimplemented!()
        }
        fn aead_encrypt(&self, pn: PacketNumber, epoch: u64, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>>
        {
            let mut d = Data::from_slice(body);
            d.encode_vec(&TestFixture::auth_tag(hdr, body));
            let v = d.as_mut_vec();
            for i in 0..v.len() {
                v[i] ^= 0x7;
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
            version: Some(Version(31)),
            dcid: ConnectionId(vec![1,2,3,4,5]),
            scid: None,
            pn: 12345,
            epoch: 0,
            hdr_len: 0,
            body_len: 0
        }
    }
    
    #[test]
    fn test_short_packet() {
        let f = TestFixture{};
        let mut hdr = default_hdr();
        let body = [0x01, 0x23, 0x45, 0x67, 0x89, 0x10];
        let packet = encode_packet(&f, &mut hdr, &body).unwrap();
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

    
    Err(Error::ErrInternal)*/

