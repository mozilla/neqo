// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_variables, dead_code)]

use crate::huffman::encode_huffman;
use crate::Prefix;
use std::convert::TryInto;
use std::ops::Deref;

#[derive(Default, Debug, PartialEq)]
pub(crate) struct QPData {
    buf: Vec<u8>,
}

impl QPData {
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub(crate) fn encode_prefixed_encoded_int(&mut self, prefix: Prefix, mut val: u64) {
        if prefix.len > 7 {
            panic!("invalid QPACK integer prefix")
        }

        let first_byte_max: u8 = if prefix.len == 0 {
            0xff
        } else {
            (1 << (8 - prefix.len)) - 1
        };

        if val < u64::from(first_byte_max) {
            self.write_byte((prefix.prefix & !first_byte_max) | (val as u8));
            return;
        }
        self.write_byte(prefix.prefix | first_byte_max);
        val -= u64::from(first_byte_max);

        let mut done = false;
        while !done {
            let mut b = (val as u8) & 0x7f;
            val >>= 7;
            if val > 0 {
                b |= 0x80;
            } else {
                done = true;
            }
            self.write_byte(b);
        }
    }

    pub fn encode_prefixed_encoded_int_fix(
        &mut self,
        offset: usize,
        prefix: Prefix,
        mut val: u64,
    ) -> usize {
        if prefix.len > 7 {
            panic!("invalid HPACK integer prefix")
        }

        let first_byte_max: u8 = if prefix.len == 0 {
            0xff
        } else {
            (1 << (8 - prefix.len)) - 1
        };

        if val < u64::from(first_byte_max) {
            self.buf[offset] = (prefix.prefix & !first_byte_max) | (val as u8);
            return 1;
        }
        self.write_byte(prefix.prefix | first_byte_max);
        val -= u64::from(first_byte_max);

        let mut written = 1;
        let mut done = false;
        while !done {
            let mut b = (val as u8) & 0x7f;
            val >>= 7;
            if val > 0 {
                b |= 0x80;
            } else {
                done = true;
            }
            self.buf[offset + written] = b;
            written += 1;
        }
        written
    }

    pub fn encode_literal(&mut self, use_huffman: bool, prefix: Prefix, value: &[u8]) {
        let real_prefix = Prefix {
            prefix: if use_huffman {
                prefix.prefix | (0x80 >> prefix.len)
            } else {
                prefix.prefix
            },
            len: prefix.len + 1,
        };

        if use_huffman {
            let encoded = encode_huffman(value);
            self.encode_prefixed_encoded_int(real_prefix, encoded.len().try_into().unwrap());
            self.write_bytes(&encoded);
        } else {
            self.encode_prefixed_encoded_int(real_prefix, value.len().try_into().unwrap());
            self.write_bytes(&value);
        }
    }

    pub fn write_bytes(&mut self, buf: &[u8]) {
        self.buf.extend_from_slice(buf);
    }

    pub fn read(&mut self, r: usize) {
        if r > self.buf.len() {
            panic!("want to set more byte read than remaing in the buffer.");
        }

        self.buf = self.buf.split_off(r);
    }
}

impl Deref for QPData {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.buf.deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_prefixed_encoded_int_1() {
        let mut d = QPData::default();
        d.encode_prefixed_encoded_int(
            Prefix {
                prefix: 0xff,
                len: 2,
            },
            5,
        );
        assert_eq!(d[..], [0xc5]);
    }

    #[test]
    fn test_encode_prefixed_encoded_int_2() {
        let mut d = QPData::default();
        d.encode_prefixed_encoded_int(
            Prefix {
                prefix: 0xff,
                len: 2,
            },
            65,
        );
        assert_eq!(d[..], [0xff, 0x02]);
    }

    #[test]
    fn test_encode_prefixed_encoded_int_3() {
        let mut d = QPData::default();
        d.encode_prefixed_encoded_int(
            Prefix {
                prefix: 0xff,
                len: 2,
            },
            100_000,
        );
        assert_eq!(d[..], [0xff, 0xe1, 0x8c, 0x06]);
    }

    const VALUE: &[u8] = &[0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79];

    const LITERAL: &[u8] = &[
        0xea, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
    ];
    const LITERAL_HUFFMAN: &[u8] = &[0xe8, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];

    #[test]
    fn test_encode_literal() {
        let mut d = QPData::default();
        d.encode_literal(
            false,
            Prefix {
                prefix: 0xff,
                len: 2,
            },
            VALUE,
        );
        assert_eq!(&&d[..], &LITERAL);
    }

    #[test]
    fn test_encode_literal_huffman() {
        let mut d = QPData::default();
        d.encode_literal(
            true,
            Prefix {
                prefix: 0xff,
                len: 2,
            },
            VALUE,
        );
        assert_eq!(&&d[..], &LITERAL_HUFFMAN);
    }
}
