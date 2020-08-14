// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryFrom;
use std::convert::TryInto;

use neqo_common::Decoder;
use neqo_transport::QuicVersion;

fn assert_default_version(dec: &mut Decoder) {
    let version: QuicVersion = u32::try_from(dec.decode_uint(4).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(version, QuicVersion::default());
}

// Do a simple decode of the datagram to verify that it is coalesced.
pub fn assert_coalesced_0rtt(payload: &[u8]) {
    assert!(payload.len() >= 1200);
    let mut dec = Decoder::from(payload);
    let initial_type = dec.decode_byte().unwrap(); // Initial
    assert_eq!(initial_type & 0b1011_0000, 0b1000_0000);
    assert_default_version(&mut dec);
    dec.skip_vec(1); // DCID
    dec.skip_vec(1); // SCID
    dec.skip_vvec();
    let initial_len = dec.decode_varint().unwrap();
    dec.skip(initial_len.try_into().unwrap());
    let zrtt_type = dec.decode_byte().unwrap();
    assert_eq!(zrtt_type & 0b1011_0000, 0b1001_0000);
}

pub fn assert_retry(payload: &[u8]) {
    assert_eq!(payload[0] & 0b1011_0000, 0b1011_0000);
}

pub fn assert_no_1rtt(payload: &[u8]) {
    let mut dec = Decoder::from(payload);
    while let Some(b1) = dec.decode_byte() {
        assert_eq!(b1 & 0x80, 0x80); // This has to be a long header.
        assert_ne!(b1 & 0b0011_0000, 0b0011_0000); // This can't be Retry.
        assert_default_version(&mut dec);
        dec.skip_vec(1); // DCID
        dec.skip_vec(1); // SCID
        if (b1 & 0b0011_0000) == 0b0000_0000 {
            dec.skip_vvec(); // Initial token.
        }
        dec.skip_vvec(); // Skip the payload.
    }
}
