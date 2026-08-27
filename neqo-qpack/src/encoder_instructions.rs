// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    mem,
};

use neqo_common::{qdebug, qtrace};

use crate::{
    Res,
    prefix::{
        ENCODER_CAPACITY, ENCODER_DUPLICATE, ENCODER_INSERT_WITH_NAME_LITERAL,
        ENCODER_INSERT_WITH_NAME_REF_DYNAMIC, ENCODER_INSERT_WITH_NAME_REF_STATIC, NO_PREFIX,
    },
    qpack_send_buf::Encoder,
    reader::{IntReader, LiteralReader, ReadByte, Reader},
};

// The encoder only uses InsertWithNameLiteral.
// All instructions are used for testing, therefore they are guarded with `#[cfg(test)]`.
#[derive(Debug, PartialEq, Eq)]
pub enum EncoderInstruction<'a> {
    Capacity {
        value: u64,
    },
    #[cfg(test)]
    InsertWithNameRefStatic {
        index: u64,
        value: &'a [u8],
    },
    #[cfg(test)]
    InsertWithNameRefDynamic {
        index: u64,
        value: &'a [u8],
    },
    InsertWithNameLiteral {
        name: &'a [u8],
        value: &'a [u8],
    },
    #[cfg(test)]
    Duplicate {
        index: u64,
    },
    #[cfg(test)]
    #[expect(dead_code, reason = "Only used in tests.")]
    NoInstruction,
}

impl EncoderInstruction<'_> {
    pub(crate) fn marshal<T: Encoder>(&self, enc: &mut T, use_huffman: bool) {
        match self {
            Self::Capacity { value } => {
                enc.encode_prefixed_encoded_int(ENCODER_CAPACITY, *value);
            }
            #[cfg(test)]
            Self::InsertWithNameRefStatic { index, value } => {
                enc.encode_prefixed_encoded_int(ENCODER_INSERT_WITH_NAME_REF_STATIC, *index);
                enc.encode_literal(use_huffman, NO_PREFIX, value);
            }
            #[cfg(test)]
            Self::InsertWithNameRefDynamic { index, value } => {
                enc.encode_prefixed_encoded_int(ENCODER_INSERT_WITH_NAME_REF_DYNAMIC, *index);
                enc.encode_literal(use_huffman, NO_PREFIX, value);
            }
            Self::InsertWithNameLiteral { name, value } => {
                enc.encode_literal(use_huffman, ENCODER_INSERT_WITH_NAME_LITERAL, name);
                enc.encode_literal(use_huffman, NO_PREFIX, value);
            }
            #[cfg(test)]
            Self::Duplicate { index } => {
                enc.encode_prefixed_encoded_int(ENCODER_DUPLICATE, *index);
            }
            #[cfg(test)]
            Self::NoInstruction => {}
        }
    }
}

#[derive(Debug, Default)]
enum EncoderInstructionReaderState {
    #[default]
    ReadInstruction,
    ReadFirstInt {
        reader: IntReader,
    },
    ReadFirstLiteral {
        reader: LiteralReader,
    },
    ReadSecondLiteral {
        reader: LiteralReader,
    },
    Done,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub enum DecodedEncoderInstruction {
    Capacity {
        value: u64,
    },
    InsertWithNameRefStatic {
        index: u64,
        value: Vec<u8>,
    },
    InsertWithNameRefDynamic {
        index: u64,
        value: Vec<u8>,
    },
    InsertWithNameLiteral {
        name: Vec<u8>,
        value: Vec<u8>,
    },
    Duplicate {
        index: u64,
    },
    #[default]
    NoInstruction,
}

impl<'a> From<&'a EncoderInstruction<'a>> for DecodedEncoderInstruction {
    fn from(inst: &'a EncoderInstruction) -> Self {
        match inst {
            EncoderInstruction::Capacity { value } => Self::Capacity { value: *value },
            #[cfg(test)]
            EncoderInstruction::InsertWithNameRefStatic { index, value } => {
                Self::InsertWithNameRefStatic {
                    index: *index,
                    value: value.to_vec(),
                }
            }
            #[cfg(test)]
            EncoderInstruction::InsertWithNameRefDynamic { index, value } => {
                Self::InsertWithNameRefDynamic {
                    index: *index,
                    value: value.to_vec(),
                }
            }
            EncoderInstruction::InsertWithNameLiteral { name, value } => {
                Self::InsertWithNameLiteral {
                    name: name.to_vec(),
                    value: value.to_vec(),
                }
            }
            #[cfg(test)]
            EncoderInstruction::Duplicate { index } => Self::Duplicate { index: *index },
            #[cfg(test)]
            EncoderInstruction::NoInstruction => Self::NoInstruction,
        }
    }
}

#[derive(Debug, Default)]
pub struct EncoderInstructionReader {
    state: EncoderInstructionReaderState,
    instruction: DecodedEncoderInstruction,
}

impl Display for EncoderInstructionReader {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "EncoderInstructionReader state={:?} instruction: {:?}",
            self.state, self.instruction
        )
    }
}

impl EncoderInstructionReader {
    fn decode_instruction_from_byte(&mut self, b: u8) {
        self.instruction = if ENCODER_INSERT_WITH_NAME_REF_STATIC.cmp_prefix(b) {
            DecodedEncoderInstruction::InsertWithNameRefStatic {
                index: 0,
                value: Vec::new(),
            }
        } else if ENCODER_INSERT_WITH_NAME_REF_DYNAMIC.cmp_prefix(b) {
            DecodedEncoderInstruction::InsertWithNameRefDynamic {
                index: 0,
                value: Vec::new(),
            }
        } else if ENCODER_INSERT_WITH_NAME_LITERAL.cmp_prefix(b) {
            DecodedEncoderInstruction::InsertWithNameLiteral {
                name: Vec::new(),
                value: Vec::new(),
            }
        } else if ENCODER_CAPACITY.cmp_prefix(b) {
            DecodedEncoderInstruction::Capacity { value: 0 }
        } else if ENCODER_DUPLICATE.cmp_prefix(b) {
            DecodedEncoderInstruction::Duplicate { index: 0 }
        } else {
            unreachable!("The above patterns match everything");
        };
        qdebug!("[{self}] instruction decoded");
    }

    fn decode_instruction_type<T: ReadByte + Reader>(&mut self, recv: &mut T) -> Res<()> {
        let b = recv.read_byte()?;

        self.decode_instruction_from_byte(b);
        match self.instruction {
            DecodedEncoderInstruction::Capacity { .. }
            | DecodedEncoderInstruction::Duplicate { .. } => {
                self.state = EncoderInstructionReaderState::ReadFirstInt {
                    reader: IntReader::new(b, ENCODER_CAPACITY.len()),
                }
            }
            DecodedEncoderInstruction::InsertWithNameRefStatic { .. }
            | DecodedEncoderInstruction::InsertWithNameRefDynamic { .. } => {
                self.state = EncoderInstructionReaderState::ReadFirstInt {
                    reader: IntReader::new(b, ENCODER_INSERT_WITH_NAME_REF_STATIC.len()),
                }
            }
            DecodedEncoderInstruction::InsertWithNameLiteral { .. } => {
                self.state = EncoderInstructionReaderState::ReadFirstLiteral {
                    reader: LiteralReader::new_with_first_byte(
                        b,
                        ENCODER_INSERT_WITH_NAME_LITERAL.len(),
                    ),
                }
            }
            DecodedEncoderInstruction::NoInstruction => {
                unreachable!("We must have instruction at this point");
            }
        }
        Ok(())
    }

    /// # Errors
    ///
    /// 1) `NeedMoreData` if the reader needs more data
    /// 2) `ClosedCriticalStream`
    /// 3) other errors will be translated to `EncoderStream` by the caller of this function.
    pub fn read_instructions<T: ReadByte + Reader>(
        &mut self,
        recv: &mut T,
    ) -> Res<DecodedEncoderInstruction> {
        qdebug!("[{self}] reading instructions");
        loop {
            match &mut self.state {
                EncoderInstructionReaderState::ReadInstruction => {
                    self.decode_instruction_type(recv)?;
                }
                EncoderInstructionReaderState::ReadFirstInt { reader } => {
                    let val = reader.read(recv)?;

                    qtrace!("[{self}] First varint read {val}");
                    match &mut self.instruction {
                        DecodedEncoderInstruction::Capacity { value: v, .. }
                        | DecodedEncoderInstruction::Duplicate { index: v } => {
                            *v = val;
                            self.state = EncoderInstructionReaderState::Done;
                        }
                        DecodedEncoderInstruction::InsertWithNameRefStatic { index, .. }
                        | DecodedEncoderInstruction::InsertWithNameRefDynamic { index, .. } => {
                            *index = val;
                            self.state = EncoderInstructionReaderState::ReadFirstLiteral {
                                reader: LiteralReader::default(),
                            };
                        }
                        _ => unreachable!("This instruction cannot be in this state"),
                    }
                }
                EncoderInstructionReaderState::ReadFirstLiteral { reader } => {
                    let val = reader.read(recv)?;

                    qtrace!("[{self}] first literal read {val:?}");
                    match &mut self.instruction {
                        DecodedEncoderInstruction::InsertWithNameRefStatic { value, .. }
                        | DecodedEncoderInstruction::InsertWithNameRefDynamic { value, .. } => {
                            *value = val;
                            self.state = EncoderInstructionReaderState::Done;
                        }
                        DecodedEncoderInstruction::InsertWithNameLiteral { name, .. } => {
                            *name = val;
                            self.state = EncoderInstructionReaderState::ReadSecondLiteral {
                                reader: LiteralReader::default(),
                            };
                        }
                        _ => unreachable!("This instruction cannot be in this state"),
                    }
                }
                EncoderInstructionReaderState::ReadSecondLiteral { reader } => {
                    let val = reader.read(recv)?;

                    qtrace!("[{self}] second literal read {val:?}");
                    match &mut self.instruction {
                        DecodedEncoderInstruction::InsertWithNameLiteral { value, .. } => {
                            *value = val;
                            self.state = EncoderInstructionReaderState::Done;
                        }
                        _ => unreachable!("This instruction cannot be in this state"),
                    }
                }
                EncoderInstructionReaderState::Done => {}
            }
            if matches!(self.state, EncoderInstructionReaderState::Done) {
                self.state = EncoderInstructionReaderState::ReadInstruction;
                break Ok(mem::replace(
                    &mut self.instruction,
                    DecodedEncoderInstruction::NoInstruction,
                ));
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test {

    use super::{EncoderInstruction, EncoderInstructionReader};
    use crate::{Error, reader::test_receiver::TestReceiver};

    fn test_encoding_decoding(instruction: &EncoderInstruction, use_huffman: bool) {
        let mut buf = neqo_common::Encoder::default();
        instruction.marshal(&mut buf, use_huffman);
        let mut test_receiver: TestReceiver = TestReceiver::default();
        test_receiver.write(buf.as_ref());
        let mut reader = EncoderInstructionReader::default();
        assert_eq!(
            reader.read_instructions(&mut test_receiver).unwrap(),
            instruction.into()
        );
    }

    // Segments are kept apart so the prefix bytes stay legible next to the ASCII they carry.
    fn assert_marshals_to(instruction: &EncoderInstruction, segments: &[&[u8]]) {
        let mut buf = neqo_common::Encoder::default();
        instruction.marshal(&mut buf, false);
        assert_eq!(buf.as_ref(), segments.concat());
        // Read back too, pinning these bytes against the reader a peer runs.
        test_encoding_decoding(instruction, false);
    }

    // RFC 9204 Appendix B's encoder stream instructions, against the bytes printed in the RFC.
    // B.2's Insert With Name Reference pair, B.4 and B.5 are here rather than end to end
    // because those variants are `#[cfg(test)]`-gated. B.2's Set Dynamic Table Capacity is not
    // gated, and `encoder::tests::rfc9204_b2_set_dynamic_table_capacity` covers it end to end.
    #[test]
    fn rfc9204_appendix_b_instructions() {
        const AUTHORITY: &[u8] = b"www.example.com";
        const PATH: &[u8] = b"/sample/path";
        const KEY: &[u8] = b"custom-key";
        const VALUE: &[u8] = b"custom-value";
        const VALUE2: &[u8] = b"custom-value2";

        // B.2: Set Dynamic Table Capacity=220.
        assert_marshals_to(
            &EncoderInstruction::Capacity { value: 220 },
            &[&[0x3f, 0xbd, 0x01]],
        );
        // B.2: Insert With Name Reference, static index 0 (`:authority=www.example.com`).
        assert_marshals_to(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 0,
                value: AUTHORITY,
            },
            &[&[0xc0, 0x0f], AUTHORITY],
        );
        // B.2: Insert With Name Reference, static index 1 (`:path=/sample/path`).
        assert_marshals_to(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 1,
                value: PATH,
            },
            &[&[0xc1, 0x0c], PATH],
        );
        // B.3: Insert With Literal Name (`custom-key=custom-value`). The shipping encoder
        // does emit this one; `encoder::tests::rfc9204_b3_insert_with_literal_name` covers it
        // end to end.
        assert_marshals_to(
            &EncoderInstruction::InsertWithNameLiteral {
                name: KEY,
                value: VALUE,
            },
            &[&[0x4a], KEY, &[0x0c], VALUE],
        );
        // B.4: Duplicate, relative index 2 (absolute index 0).
        assert_marshals_to(&EncoderInstruction::Duplicate { index: 2 }, &[&[0x02]]);
        // B.5: Insert With Name Reference, dynamic relative index 1
        // (`custom-key=custom-value2`).
        assert_marshals_to(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 1,
                value: VALUE2,
            },
            &[&[0x81, 0x0d], VALUE2],
        );
    }

    #[test]
    fn encoding_decoding_instructions() {
        test_encoding_decoding(&EncoderInstruction::Capacity { value: 1 }, false);
        test_encoding_decoding(&EncoderInstruction::Capacity { value: 10_000 }, false);

        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );
        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );

        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );
        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );

        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameLiteral {
                name: &[0x62, 0x64, 0x65],
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding(
            &EncoderInstruction::InsertWithNameLiteral {
                name: &[0x62, 0x64, 0x65],
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );

        test_encoding_decoding(&EncoderInstruction::Duplicate { index: 1 }, false);
        test_encoding_decoding(&EncoderInstruction::Duplicate { index: 10_000 }, false);
    }

    fn test_encoding_decoding_slow_reader(instruction: &EncoderInstruction, use_huffman: bool) {
        let mut buf = neqo_common::Encoder::default();
        instruction.marshal(&mut buf, use_huffman);
        let mut test_receiver: TestReceiver = TestReceiver::default();
        let mut decoder = EncoderInstructionReader::default();
        for i in 0..buf.len() - 1 {
            test_receiver.write(&buf.as_ref()[i..=i]);
            assert_eq!(
                decoder.read_instructions(&mut test_receiver),
                Err(Error::NeedMoreData)
            );
        }
        test_receiver.write(&buf.as_ref()[buf.len() - 1..buf.len()]);
        assert_eq!(
            decoder.read_instructions(&mut test_receiver).unwrap(),
            instruction.into()
        );
    }

    #[test]
    fn encoding_decoding_instructions_slow_reader() {
        test_encoding_decoding_slow_reader(&EncoderInstruction::Capacity { value: 1 }, false);
        test_encoding_decoding_slow_reader(&EncoderInstruction::Capacity { value: 10_000 }, false);

        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );
        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefStatic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );

        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 1,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );
        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameRefDynamic {
                index: 10_000,
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );

        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameLiteral {
                name: &[0x62, 0x64, 0x65],
                value: &[0x62, 0x64, 0x65],
            },
            false,
        );
        test_encoding_decoding_slow_reader(
            &EncoderInstruction::InsertWithNameLiteral {
                name: &[0x62, 0x64, 0x65],
                value: &[0x62, 0x64, 0x65],
            },
            true,
        );

        test_encoding_decoding_slow_reader(&EncoderInstruction::Duplicate { index: 1 }, false);
        test_encoding_decoding_slow_reader(&EncoderInstruction::Duplicate { index: 10_000 }, false);
    }

    #[test]
    fn decoding_error() {
        let mut test_receiver: TestReceiver = TestReceiver::default();
        // EncoderInstruction::Capacity with overflow
        test_receiver.write(&[
            0x3f, 0xc1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xff, 0x02,
        ]);
        let mut decoder = EncoderInstructionReader::default();
        assert_eq!(
            decoder.read_instructions(&mut test_receiver),
            Err(Error::IntegerOverflow)
        );

        let mut test_receiver: TestReceiver = TestReceiver::default();
        // EncoderInstruction::InsertWithNameRefStatic with overflow of index value.
        test_receiver.write(&[
            0xff, 0xc1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xff, 0x02, 0x00, 0x00,
        ]);
        let mut decoder = EncoderInstructionReader::default();
        assert_eq!(
            decoder.read_instructions(&mut test_receiver),
            Err(Error::IntegerOverflow)
        );

        let mut test_receiver: TestReceiver = TestReceiver::default();
        // EncoderInstruction::InsertWithNameRefStatic with a garbage value.
        test_receiver.write(&[0xc1, 0x81, 0x00]);
        let mut decoder = EncoderInstructionReader::default();
        assert_eq!(
            decoder.read_instructions(&mut test_receiver),
            Err(Error::HuffmanDecompression)
        );
    }
}
