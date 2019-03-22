#![deny(warnings)]

#[macro_use]
extern crate neqo_common;

pub mod decoder;
pub mod encoder;
pub mod qpack_helper;
pub mod huffman;
mod huffman_decode_helper;
pub mod huffman_table;
mod qpack_send_buf;
mod static_table;
mod table;

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

    TransportError(neqo_transport::Error),
}

impl Error {
    pub fn code(&self) -> u16 {
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
