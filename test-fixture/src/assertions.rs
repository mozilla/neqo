// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::convert::TryInto;

use neqo_common::Decoder;
use neqo_transport::QUIC_VERSION;

// Do a simple decode of the datagram to verify that it is coalesced.
pub fn assert_coalesced_0rtt(payload: &[u8]) {
    assert!(payload.len() >= 1200);
    let mut dec = Decoder::from(payload);
    let initial_type = dec.decode_byte().unwrap(); // Initial
    assert_eq!(initial_type & 0b1111_0000, 0b1100_0000);
    let version = dec.decode_uint(4).unwrap();
    assert_eq!(version, QUIC_VERSION.into());
    dec.skip_vec(1); // DCID
    dec.skip_vec(1); // SCID
    dec.skip_vvec();
    let initial_len = dec.decode_varint().unwrap();
    dec.skip(initial_len.try_into().unwrap());
    let zrtt_type = dec.decode_byte().unwrap();
    assert_eq!(zrtt_type & 0b1111_0000, 0b1101_0000);
}

pub fn assert_retry(payload: &[u8]) {
    assert_eq!(payload[0] & 0b1111_0000, 0b1111_0000);
}
