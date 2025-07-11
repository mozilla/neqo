// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::Deref;

use neqo_common::Encoder;

use crate::{huffman, prefix::Prefix};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Data {
    buf: Vec<u8>,
}

impl Data {
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub fn encode_varint(&mut self, i: u64) {
        Encoder::new_borrowed_vec(&mut self.buf).encode_varint(i);
    }

    pub(crate) fn encode_prefixed_encoded_int(&mut self, prefix: Prefix, mut val: u64) -> usize {
        let first_byte_max: u8 = if prefix.len() == 0 {
            0xff
        } else {
            (1 << (8 - prefix.len())) - 1
        };

        if val < u64::from(first_byte_max) {
            let v = u8::try_from(val).expect("first_byte_max is a u8 and val is smaller");
            self.write_byte((prefix.prefix() & !first_byte_max) | v);
            return 1;
        }

        self.write_byte(prefix.prefix() | first_byte_max);
        val -= u64::from(first_byte_max);

        let mut written = 1;
        let mut done = false;
        while !done {
            let mut b = (val & 0x7f) as u8; // Safe because of the mask.
            val >>= 7;
            if val > 0 {
                b |= 0x80;
            } else {
                done = true;
            }

            self.write_byte(b);
            written += 1;
        }
        written
    }

    pub fn encode_literal(&mut self, use_huffman: bool, prefix: Prefix, value: &[u8]) {
        let real_prefix = Prefix::new(
            if use_huffman {
                prefix.prefix() | (0x80 >> prefix.len())
            } else {
                prefix.prefix()
            },
            prefix.len() + 1,
        );

        if use_huffman {
            let encoded = huffman::encode(value);
            self.encode_prefixed_encoded_int(
                real_prefix,
                u64::try_from(encoded.len()).expect("usize fits in u64"),
            );
            self.write_bytes(&encoded);
        } else {
            self.encode_prefixed_encoded_int(
                real_prefix,
                u64::try_from(value.len()).expect("usize fits in u64"),
            );
            self.write_bytes(value);
        }
    }

    pub fn write_bytes(&mut self, buf: &[u8]) {
        self.buf.extend_from_slice(buf);
    }

    pub fn read(&mut self, r: usize) {
        assert!(
            r <= self.buf.len(),
            "want to set more bytes read than remain in the buffer"
        );
        self.buf = self.buf.split_off(r);
    }
}

impl Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::{Data, Prefix};

    #[test]
    fn encode_prefixed_encoded_int_1() {
        let mut d = Data::default();
        d.encode_prefixed_encoded_int(Prefix::new(0xC0, 2), 5);
        assert_eq!(d[..], [0xc5]);
    }

    #[test]
    fn encode_prefixed_encoded_int_2() {
        let mut d = Data::default();
        d.encode_prefixed_encoded_int(Prefix::new(0xC0, 2), 65);
        assert_eq!(d[..], [0xff, 0x02]);
    }

    #[test]
    fn encode_prefixed_encoded_int_3() {
        let mut d = Data::default();
        d.encode_prefixed_encoded_int(Prefix::new(0xC0, 2), 100_000);
        assert_eq!(d[..], [0xff, 0xe1, 0x8c, 0x06]);
    }

    #[test]
    fn max_int() {
        let mut d = Data::default();
        d.encode_prefixed_encoded_int(Prefix::new(0x80, 1), u64::MAX);
        assert_eq!(
            d[..],
            [0xff, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    const VALUE: &[u8] = b"custom-key";

    const LITERAL: &[u8] = &[
        0xca, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
    ];
    const LITERAL_HUFFMAN: &[u8] = &[0xe8, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];

    #[test]
    fn encode_literal() {
        let mut d = Data::default();
        d.encode_literal(false, Prefix::new(0xC0, 2), VALUE);
        assert_eq!(&&d[..], &LITERAL);
    }

    #[test]
    fn encode_literal_huffman() {
        let mut d = Data::default();
        d.encode_literal(true, Prefix::new(0xC0, 2), VALUE);
        assert_eq!(&&d[..], &LITERAL_HUFFMAN);
    }
}
