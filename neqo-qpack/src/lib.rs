// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]

pub mod decoder;
pub mod encoder;
pub mod huffman;
mod huffman_decode_helper;
pub mod huffman_table;
pub mod qpack_helper;
mod qpack_send_buf;
mod static_table;
mod table;

pub type Header = (String, String);
type Res<T> = Result<T, Error>;

#[derive(Debug)]
enum QPackSide {
    Encoder,
    Decoder,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    DecompressionFailed,
    EncoderStreamError,
    DecoderStreamError,
    ClosedCriticalStream,

    // These are internal errors, they will be transfromed into one of the above.
    HeaderLookupError,
    NoMoreData,
    IntegerOverflow,
    WrongStreamCount,

    TransportError(neqo_transport::Error),
}

impl Error {
    pub fn code(&self) -> neqo_transport::AppError {
        // TODO(mt): use real codes once QPACK defines some.
        3
    }
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            Error::TransportError(e) => Some(e),
            _ => None,
        }
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "QPACK error: {:?}", self)
    }
}

impl From<neqo_transport::Error> for Error {
    fn from(err: neqo_transport::Error) -> Self {
        Error::TransportError(err)
    }
}
