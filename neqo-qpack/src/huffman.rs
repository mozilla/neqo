// TOTO(dragana) remove this
#![allow(unused_variables, dead_code)]

use crate::huffman_decode_helper::{HuffmanDecodeTable, HUFFMAN_DECODE_ROOT};
use crate::huffman_table::HUFFMAN_TABLE;
use neqo_http3::hframe::ReadBuf;
use neqo_transport::HError;

pub fn encode_header_block(input: &[u8], output: &mut Vec<u8>) {
    let mut left: u8 = 8;
    let mut saved: u8 = 0;
    for c in input {
        let mut e = HUFFMAN_TABLE[*c as usize];

        // Fill the privious byte
        if e.len < left {
            saved = saved | ((e.val as u8) << left - e.len);
            left -= e.len;
            e.len = 0;
        } else {
            let v: u8 = (e.val >> (e.len - left)) as u8;
            saved = saved | v;
            output.push(saved);
            e.len -= left;
            left = 8;
            saved = 0;
        }

        while e.len >= 8 {
            let v: u8 = (e.val >> (e.len - 8)) as u8;
            output.push(v);
            e.len -= 8;
        }

        if e.len > 0 {
            saved = ((e.val & ((1 << e.len) - 1)) as u8) << (8 - e.len);
            left = 8 - e.len;
        }
    }

    if left < 8 {
        let v: u8 = (1 << left) - 1;
        saved = saved | v;
        output.push(saved);
    }
}

pub fn decode_header_block(input: &mut ReadBuf, output: &mut Vec<u8>) -> Result<(), HError> {
    let mut byte: u8 = 0;
    let mut bits_left: u8 = 0;
    while input.remaining() > 0 {
        if let Some(c) =
            decode_huffman_character(HUFFMAN_DECODE_ROOT, input, &mut byte, &mut bits_left)?
        {
            output.push(c);
        }
    }

    if bits_left > 7 {
        return Err(HError::ErrHttpUnexpected);
    }
    if bits_left > 0 {
        let mask: u8 = ((1 << bits_left) - 1) << (8 - bits_left);
        let bits: u8 = byte & mask;
        if bits != mask {
            return Err(HError::ErrHttpUnexpected);
        }
    }
    Ok(())
}

fn extract_byte(input: &mut ReadBuf, byte: &mut u8, bits_left: &mut u8) -> Result<(), HError> {
    if *bits_left != 0 {
        let (c, left) = input.read_bits(8 - *bits_left);
        *byte = *byte | (c << ((8 - *bits_left) - left));
        *bits_left += left;
        Ok(())
    } else {
        let (c, left) = input.read_bits(8);
        *byte = c << (8 - left);
        *bits_left = left;
        Ok(())
    }
}

fn decode_huffman_character(
    table: &HuffmanDecodeTable,
    input: &mut ReadBuf,
    byte: &mut u8,
    bits_left: &mut u8,
) -> Result<Option<u8>, HError> {
    extract_byte(input, byte, bits_left)?;

    if table.index_has_a_next_table(*byte) {
        if input.remaining() == 0 {
            // This is the last bit and it is padding.
            return Ok(None);
        }

        *bits_left = 0;
        return decode_huffman_character(table.next_table(*byte), input, byte, &mut *bits_left);
    }

    let entry = table.entry(*byte);
    if entry.val == 256 {
        return Err(HError::ErrHttpUnexpected);
    }

    if entry.prefix_len > *bits_left as u16 {
        assert!(input.remaining() == 0);
        // This is the last bit and it is padding.
        return Ok(None);
    }
    let c = entry.val as u8;

    *bits_left -= entry.prefix_len as u8;
    if *bits_left != 0 {
        // move bits to the beginning of the byte.
        *byte <<= entry.prefix_len;
    }
    Ok(Some(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestElement {
        pub val: &'static [u8],
        pub res: &'static [u8],
    }
    const TEST_CASES: &'static [TestElement] = &[
        TestElement {
            val: b"www.example.com",
            res: &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ],
        },
        TestElement {
            val: b"no-cache",
            res: &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf],
        },
        TestElement {
            val: b"custom-key",
            res: &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
        },
        TestElement {
            val: b"custom-value",
            res: &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
        },
        TestElement {
            val: b"private",
            res: &[0xae, 0xc3, 0x77, 0x1a, 0x4b],
        },
        TestElement {
            val: b"Mon, 21 Oct 2013 20:13:21 GMT",
            res: &[
                0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b,
                0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff,
            ],
        },
        TestElement {
            val: b"https://www.example.com",
            res: &[
                0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82,
                0xae, 0x43, 0xd3,
            ],
        },
        TestElement {
            val: b"Mon, 21 Oct 2013 20:13:22 GMT",
            res: &[
                0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b,
                0x81, 0x66, 0xe0, 0x84, 0xa6, 0x2d, 0x1b, 0xff,
            ],
        },
        TestElement {
            val: b"gzip",
            res: &[0x9b, 0xd9, 0xab],
        },
        TestElement {
            val: b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            res: &[
                0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2, 0xe6, 0xc7, 0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b,
                0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36, 0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5,
                0x29, 0x1f, 0x95, 0x87, 0x31, 0x60, 0x65, 0xc0, 0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06,
                0x3d, 0x50, 0x07,
            ],
        },
        TestElement {
            val: b"<?\\ >",
            res: &[0xff, 0xf9, 0xfe, 0x7f, 0xff, 0x05, 0x3f, 0xef],
        },
    ];

    #[test]
    fn test_encoder() {
        for e in TEST_CASES {
            let mut out: Vec<u8> = Vec::new();
            encode_header_block(e.val, &mut out);

            assert_eq!(out[..], *e.res);
        }
    }

    #[test]
    fn test_decoder() {
        for e in TEST_CASES {
            let mut out: Vec<u8> = Vec::new();
            assert_eq!(
                Ok(()),
                decode_header_block(&mut ReadBuf::from(e.res), &mut out)
            );

            assert_eq!(out[..], *e.val);
        }
    }
}
