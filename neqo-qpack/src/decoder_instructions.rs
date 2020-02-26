// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::qpack_helper::{IntReader, ReadByte};
use crate::qpack_send_buf::QPData;
use crate::{Error, Prefix, Res};
use neqo_common::{qdebug, qtrace};
use std::mem;

// Decoder instructions prefix
const DECODER_HEADER_ACK: Prefix = Prefix {
    prefix: 0x80,
    len: 1,
};
const DECODER_STREAM_CANCELLATION: Prefix = Prefix {
    prefix: 0x40,
    len: 2,
};
const DECODER_INSERT_COUNT_INCREMENT: Prefix = Prefix {
    prefix: 0x00,
    len: 2,
};

const MASK_1: u8 = 0x80;
const MASK_2: u8 = 0xC0;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DecoderInstruction {
    InsertCountIncrement { increment: u64 },
    HeaderAck { stream_id: u64 },
    StreamCancellation { stream_id: u64 },
    NoInstruction,
}

impl DecoderInstruction {
    fn get_instruction(b: u8) -> Self {
        if (b & MASK_1) == DECODER_HEADER_ACK.prefix {
            Self::HeaderAck { stream_id: 0 }
        } else if (b & MASK_2) == DECODER_STREAM_CANCELLATION.prefix {
            Self::StreamCancellation { stream_id: 0 }
        } else {
            Self::InsertCountIncrement { increment: 0 }
        }
    }

    pub(crate) fn marshal(&self, enc: &mut QPData) {
        match self {
            Self::InsertCountIncrement { increment } => {
                enc.encode_prefixed_encoded_int(DECODER_INSERT_COUNT_INCREMENT, *increment);
            }
            Self::HeaderAck { stream_id } => {
                enc.encode_prefixed_encoded_int(DECODER_HEADER_ACK, *stream_id);
            }
            Self::StreamCancellation { stream_id } => {
                enc.encode_prefixed_encoded_int(DECODER_STREAM_CANCELLATION, *stream_id);
            }
            Self::NoInstruction => {}
        }
    }
}

#[derive(Debug)]
enum DecoderInstructionReaderState {
    ReadInstruction,
    ReadInt { reader: IntReader },
}

#[derive(Debug)]
pub struct DecoderInstructionReader {
    state: DecoderInstructionReaderState,
    instruction: DecoderInstruction,
}

impl ::std::fmt::Display for DecoderInstructionReader {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "InstructionReader")
    }
}

impl DecoderInstructionReader {
    pub fn new() -> Self {
        Self {
            state: DecoderInstructionReaderState::ReadInstruction,
            instruction: DecoderInstruction::NoInstruction,
        }
    }

    pub fn read_instructions(
        &mut self,
        recv: &mut dyn ReadByte,
    ) -> Res<Option<DecoderInstruction>> {
        qdebug!([self], "read a new instraction");
        loop {
            match &mut self.state {
                DecoderInstructionReaderState::ReadInstruction => match recv.read_byte() {
                    Ok(b) => {
                        self.instruction = DecoderInstruction::get_instruction(b);
                        self.state = DecoderInstructionReaderState::ReadInt {
                            reader: IntReader::new(b, if (b & MASK_1) != 0 { 1 } else { 2 }),
                        };
                    }
                    Err(Error::NoMoreData) => break Ok(None),
                    Err(Error::ClosedCriticalStream) => break Err(Error::ClosedCriticalStream),
                    _ => break Err(Error::DecoderStreamError),
                },
                DecoderInstructionReaderState::ReadInt { reader } => match reader.read(recv) {
                    Ok(Some(val)) => {
                        qtrace!([self], "varint read {}", val);
                        match &mut self.instruction {
                            DecoderInstruction::InsertCountIncrement { increment: v }
                            | DecoderInstruction::HeaderAck { stream_id: v }
                            | DecoderInstruction::StreamCancellation { stream_id: v } => {
                                *v = val;
                                self.state = DecoderInstructionReaderState::ReadInstruction;
                                break Ok(Some(mem::replace(
                                    &mut self.instruction,
                                    DecoderInstruction::NoInstruction,
                                )));
                            }
                            _ => unreachable!("This instruction cannot be in this state."),
                        }
                    }
                    Ok(None) => break Ok(None),
                    Err(Error::ClosedCriticalStream) => break Err(Error::ClosedCriticalStream),
                    Err(_) => break Err(Error::DecoderStreamError),
                },
            }
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::qpack_helper::TestReceiver;

    fn test_encoding_decoding(instruction: DecoderInstruction) {
        let mut buf = QPData::default();
        instruction.marshal(&mut buf);
        let mut test_receiver: TestReceiver = Default::default();
        test_receiver.write(&buf);
        let mut decoder = DecoderInstructionReader::new();
        assert_eq!(
            decoder
                .read_instructions(&mut test_receiver)
                .unwrap()
                .unwrap(),
            instruction
        );
    }

    #[test]
    fn test_encoding_decoding_instructions() {
        test_encoding_decoding(DecoderInstruction::InsertCountIncrement { increment: 1 });
        test_encoding_decoding(DecoderInstruction::InsertCountIncrement { increment: 10_000 });

        test_encoding_decoding(DecoderInstruction::HeaderAck { stream_id: 1 });
        test_encoding_decoding(DecoderInstruction::HeaderAck { stream_id: 10_000 });

        test_encoding_decoding(DecoderInstruction::StreamCancellation { stream_id: 1 });
        test_encoding_decoding(DecoderInstruction::StreamCancellation { stream_id: 10_000 });
    }

    fn test_encoding_decoding_slow_reader(instruction: DecoderInstruction) {
        let mut buf = QPData::default();
        instruction.marshal(&mut buf);
        let mut test_receiver: TestReceiver = Default::default();
        let mut decoder = DecoderInstructionReader::new();
        for i in 0..buf.len() - 1 {
            test_receiver.write(&buf[i..i + 1]);
            assert!(decoder
                .read_instructions(&mut test_receiver)
                .unwrap()
                .is_none());
        }
        test_receiver.write(&buf[buf.len() - 1..buf.len()]);
        assert_eq!(
            decoder
                .read_instructions(&mut test_receiver)
                .unwrap()
                .unwrap(),
            instruction
        );
    }

    #[test]
    fn test_encoding_decoding_instructions_slow_reader() {
        test_encoding_decoding_slow_reader(DecoderInstruction::InsertCountIncrement {
            increment: 10_000,
        });
        test_encoding_decoding_slow_reader(DecoderInstruction::HeaderAck { stream_id: 10_000 });
        test_encoding_decoding_slow_reader(DecoderInstruction::StreamCancellation {
            stream_id: 10_000,
        });
    }

    #[test]
    fn test_decoding_error() {
        let mut test_receiver: TestReceiver = Default::default();
        // InsertCountIncrement with overflow
        test_receiver.write(&[
            0x3f, 0xc1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xff, 0x02,
        ]);
        let mut decoder = DecoderInstructionReader::new();
        assert_eq!(
            decoder.read_instructions(&mut test_receiver),
            Err(Error::DecoderStreamError)
        );

        let mut test_receiver: TestReceiver = Default::default();
        // StreamCancellation with overflow
        test_receiver.write(&[
            0x7f, 0xc1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xff, 0x02,
        ]);
        let mut decoder = DecoderInstructionReader::new();
        assert_eq!(
            decoder.read_instructions(&mut test_receiver),
            Err(Error::DecoderStreamError)
        );

        let mut test_receiver: TestReceiver = Default::default();
        // HeaderAck with overflow
        test_receiver.write(&[
            0x7f, 0xc1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xff, 0x02,
        ]);
        let mut decoder = DecoderInstructionReader::new();
        assert_eq!(
            decoder.read_instructions(&mut test_receiver),
            Err(Error::DecoderStreamError)
        );
    }
}
