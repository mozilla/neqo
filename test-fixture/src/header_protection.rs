// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(
    clippy::allow_attributes,
    clippy::missing_panics_doc,
    clippy::unwrap_in_result,
    reason = "This is test code."
)]

use std::ops::Range;

use neqo_common::{hex_with_len, qtrace, Datagram, Decoder, Role};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3},
    hkdf, hp, Aead, AeadTrait as _,
};

pub use crate::{default_client, now, CountingConnectionIdGenerator};

// Decode the header of a client Initial packet, returning three values:
// * the entire header short of the packet number,
// * just the DCID,
// * just the SCID, and
// * the protected payload including the packet number.
// Any token is thrown away.
#[must_use]
#[expect(clippy::type_complexity, reason = "OK in test.")]
pub fn decode_initial_header(dgram: &Datagram, role: Role) -> Option<(&[u8], &[u8], &[u8], &[u8])> {
    let mut dec = Decoder::new(&dgram[..]);
    let type_and_ver = dec.decode(5).unwrap().to_vec();
    // The client sets the QUIC bit, the server might not.
    match role {
        Role::Client => {
            if type_and_ver[0] & 0xf0 != 0xc0 {
                return None;
            }
        }
        Role::Server => {
            if type_and_ver[0] & 0xb0 != 0x80 {
                return None;
            }
        }
    }
    let dest_cid = dec.decode_vec(1).unwrap();
    let src_cid = dec.decode_vec(1).unwrap();
    dec.skip_vvec(); // Ignore any the token.

    // Need to read of the length separately so that we can find the packet number.
    let payload_len = usize::try_from(dec.decode_varint().unwrap()).unwrap();
    let pn_offset = dgram.len() - dec.remaining();
    Some((
        &dgram[..pn_offset],
        dest_cid,
        src_cid,
        dec.decode(payload_len).unwrap(),
    ))
}

/// Generate an AEAD and header protection object for a client Initial.
/// Note that this works for QUIC version 1 only.
#[must_use]
pub fn initial_aead_and_hp(dcid: &[u8], role: Role) -> (Aead, hp::Key) {
    const INITIAL_SALT: &[u8] = &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let initial_secret = hkdf::extract(
        TLS_VERSION_1_3,
        TLS_AES_128_GCM_SHA256,
        Some(
            hkdf::import_key(TLS_VERSION_1_3, INITIAL_SALT)
                .as_ref()
                .unwrap(),
        ),
        hkdf::import_key(TLS_VERSION_1_3, dcid).as_ref().unwrap(),
    )
    .unwrap();

    let secret = hkdf::expand_label(
        TLS_VERSION_1_3,
        TLS_AES_128_GCM_SHA256,
        &initial_secret,
        &[],
        match role {
            Role::Client => "client in",
            Role::Server => "server in",
        },
    )
    .unwrap();
    (
        Aead::new(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256, &secret, "quic ").unwrap(),
        hp::Key::extract(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256, &secret, "quic hp").unwrap(),
    )
}

// Remove header protection, returning the unmasked header and the packet number.
#[must_use]
pub fn remove(hp: &hp::Key, header: &[u8], payload: &[u8]) -> (Vec<u8>, u64) {
    // Make a copy of the header that can be modified.
    let mut fixed_header = header.to_vec();
    let pn_offset = header.len();
    // Save 4 extra in case the packet number is that long.
    assert!(payload.len() > 19);
    fixed_header.extend_from_slice(&payload[..4]);

    // Sample for masking and apply the mask.
    let mask = hp.mask(payload[4..20].try_into().unwrap()).unwrap();
    fixed_header[0] ^= mask[0] & 0xf;
    let pn_len = 1 + usize::from(fixed_header[0] & 0x3);
    for i in 0..pn_len {
        fixed_header[pn_offset + i] ^= mask[1 + i];
    }
    // Trim down to size.
    fixed_header.truncate(pn_offset + pn_len);
    // The packet number should be 1.
    // This doesn't use a `Decoder` because the public API can't handle a three byte packet number.
    let mut pn = [0; 8];
    pn[8 - pn_len..].copy_from_slice(&fixed_header[pn_offset..pn_offset + pn_len]);
    (fixed_header, u64::from_be_bytes(pn))
}

pub fn apply(hp: &hp::Key, packet: &mut [u8], pn_bytes: Range<usize>) {
    let sample_start = pn_bytes.start + 4;
    let sample_end = sample_start + 16;
    let mask = hp
        .mask(packet[sample_start..sample_end].try_into().unwrap())
        .unwrap();
    qtrace!(
        "sample={} mask={}",
        hex_with_len(&packet[sample_start..sample_end]),
        hex_with_len(mask)
    );
    packet[0] ^= mask[0] & 0xf;
    for i in 0..(pn_bytes.end - pn_bytes.start) {
        packet[pn_bytes.start + i] ^= mask[1 + i];
    }
}
