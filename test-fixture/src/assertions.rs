// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{addr, addr_v4};
use neqo_common::{Datagram, Decoder};
use neqo_transport::version::WireVersion;
use neqo_transport::Version;
use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;

const PACKET_TYPE_MASK: u8 = 0b1011_0000;

fn assert_default_version(dec: &mut Decoder) -> Version {
    let version =
        Version::try_from(WireVersion::try_from(dec.decode_uint(4).unwrap()).unwrap()).unwrap();
    assert!(version == Version::Version1 || version == Version::Version2);
    version
}

fn assert_long_packet_type(b: u8, v1_expected: u8, version: Version) {
    assert_eq!(0, v1_expected & !PACKET_TYPE_MASK);
    let expected = if version == Version::Version2 {
        // Add one to the packet type and then clear the 0b0100_0000 bit if it overflows.
        (v1_expected + 0b0001_0000) & PACKET_TYPE_MASK
    } else {
        v1_expected
    };
    assert_eq!(b & PACKET_TYPE_MASK, expected);
}

/// Simple checks for the version being correct.
/// # Panics
/// If this is not a long header packet with the given version.
pub fn assert_version(payload: &[u8], v: u32) {
    let mut dec = Decoder::from(payload);
    assert_eq!(dec.decode_byte().unwrap() & 0x80, 0x80, "is long header");
    assert_eq!(dec.decode_uint(4).unwrap(), u64::from(v));
}

/// Simple checks for a Version Negotiation packet.
/// # Panics
/// If this is clearly not a Version Negotiation packet.
pub fn assert_vn(payload: &[u8]) {
    let mut dec = Decoder::from(payload);
    assert_eq!(dec.decode_byte().unwrap() & 0x80, 0x80, "is long header");
    assert_eq!(dec.decode_uint(4).unwrap(), 0);
    dec.skip_vec(1); // DCID
    dec.skip_vec(1); // SCID
    assert_eq!(dec.remaining() % 4, 0);
}

/// Do a simple decode of the datagram to verify that it is coalesced.
/// # Panics
/// If the tests fail.
pub fn assert_coalesced_0rtt(payload: &[u8]) {
    assert!(payload.len() >= 1200);
    let mut dec = Decoder::from(payload);
    let initial_type = dec.decode_byte().unwrap(); // Initial
    let version = assert_default_version(&mut dec);
    assert_long_packet_type(initial_type, 0b1000_0000, version);
    dec.skip_vec(1); // DCID
    dec.skip_vec(1); // SCID
    dec.skip_vvec();
    let initial_len = dec.decode_varint().unwrap();
    dec.skip(initial_len.try_into().unwrap());
    let zrtt_type = dec.decode_byte().unwrap();
    assert_long_packet_type(zrtt_type, 0b1001_0000, version);
}

/// # Panics
/// If the tests fail.
pub fn assert_retry(payload: &[u8]) {
    let mut dec = Decoder::from(payload);
    let t = dec.decode_byte().unwrap();
    let version = assert_default_version(&mut dec);
    assert_long_packet_type(t, 0b1011_0000, version);
}

/// Assert that this is an Initial packet with (or without) a token.
/// # Panics
/// If the tests fail.
pub fn assert_initial(payload: &[u8], expect_token: bool) {
    let mut dec = Decoder::from(payload);
    let t = dec.decode_byte().unwrap();
    let version = assert_default_version(&mut dec);
    assert_long_packet_type(t, 0b1000_0000, version);
    dec.skip_vec(1); // Destination Connection ID.
    dec.skip_vec(1); // Source Connection ID.
    let token = dec.decode_vvec().unwrap();
    assert_eq!(expect_token, !token.is_empty());
}

/// # Panics
/// If the tests fail.
pub fn assert_no_1rtt(payload: &[u8]) {
    let mut dec = Decoder::from(payload);
    while let Some(b1) = dec.decode_byte() {
        // If this is just padding, that's OK.  Check.
        if payload.iter().skip(dec.offset()).all(|b| *b == 0) {
            return;
        }
        assert_eq!(b1 & 0x80, 0x80); // This has to be a long header.
        let version = assert_default_version(&mut dec);
        let retry_type = if version == Version::Version2 {
            0b1000_0000
        } else {
            0b1011_0000
        };
        assert_ne!(b1 & PACKET_TYPE_MASK, retry_type); // This can't be Retry.
        dec.skip_vec(1); // DCID
        dec.skip_vec(1); // SCID
        let initial_type = if version == Version::Version2 {
            0b1001_0000
        } else {
            0b1000_0000
        };
        if (b1 & PACKET_TYPE_MASK) == initial_type {
            dec.skip_vvec(); // Initial token.
        }
        dec.skip_vvec(); // Skip the payload.
    }
}

/// # Panics
/// When the path doesn't use the given socket address at both ends.
pub fn assert_path(dgram: &Datagram, path_addr: SocketAddr) {
    assert_eq!(dgram.source(), path_addr);
    assert_eq!(dgram.destination(), path_addr);
}

/// # Panics
/// When the path doesn't use the default v4 socket address at both ends.
pub fn assert_v4_path(dgram: &Datagram, padded: bool) {
    assert_path(dgram, addr_v4());
    if padded {
        assert_eq!(dgram.len(), 1357 /* PATH_MTU_V4 */);
    }
}

/// # Panics
/// When the path doesn't use the default v6 socket address at both ends.
pub fn assert_v6_path(dgram: &Datagram, padded: bool) {
    assert_path(dgram, addr());
    if padded {
        assert_eq!(dgram.len(), 1337 /* PATH_MTU_V6 */);
    }
}
