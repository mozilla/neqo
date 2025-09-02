// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod decoder;
mod decoder_instructions;
pub mod encoder;
mod encoder_instructions;
mod header_block;
pub mod huffman;
mod huffman_decode_helper;
pub mod huffman_table;
mod prefix;
mod qlog;
mod qpack_send_buf;
pub mod reader;
mod static_table;
mod stats;
mod table;

pub use stats::Stats;
use thiserror::Error;

pub use crate::{decoder::Decoder, encoder::Encoder};

type Res<T> = Result<T, Error>;

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone, Copy)]
#[expect(clippy::struct_field_names, reason = "That's how they are called.")]
pub struct Settings {
    pub max_table_size_decoder: u64,
    pub max_table_size_encoder: u64,
    pub max_blocked_streams: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("Decompression error")]
    Decompression,
    #[error("Encoder stream error")]
    EncoderStream,
    #[error("Decoder stream error")]
    DecoderStream,
    #[error("Critical stream closed")]
    ClosedCriticalStream,
    #[error("Internal error")]
    Internal,

    // These are internal errors, they will be transformed into one of the above.
    ///
    /// Return when an input stream does not have more data that a decoder needs.
    /// It does not mean that a stream is closed.
    #[error("Need more data")]
    NeedMoreData,
    #[error("Header lookup failed")]
    HeaderLookup,
    #[error("Huffman decompression error")]
    HuffmanDecompression,
    #[error("Bad UTF-8 encoding")]
    BadUtf8,
    #[error("Change capacity error")]
    ChangeCapacity,
    #[error("Dynamic table full")]
    DynamicTableFull,
    #[error("Incremented ack is larger than inserts")]
    IncrementAck,
    #[error("Integer overflow")]
    IntegerOverflow,
    #[error("Wrong stream count")]
    WrongStreamCount,
    #[error("Decoding error")]
    Decoding, // Decoding internal error that is not one of the above.
    #[error("Encoder stream blocked")]
    EncoderStreamBlocked,

    #[error(transparent)]
    Transport(#[from] neqo_transport::Error),
    #[error("Qlog error")]
    Qlog,
}

impl Error {
    #[must_use]
    pub const fn code(&self) -> neqo_transport::AppError {
        match self {
            Self::Decompression => 0x200,
            Self::EncoderStream => 0x201,
            Self::DecoderStream => 0x202,
            Self::ClosedCriticalStream => 0x104,
            // These are all internal errors.
            _ => 3,
        }
    }

    /// # Errors
    ///
    /// Any error is mapped to the indicated type.
    fn map_error<R>(r: Result<R, Self>, err: Self) -> Result<R, Self> {
        r.map_err(|e| {
            if matches!(e, Self::ClosedCriticalStream) {
                e
            } else {
                err
            }
        })
    }
}
