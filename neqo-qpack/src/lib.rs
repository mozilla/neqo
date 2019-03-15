#![deny(warnings)]

pub mod huffman;
mod huffman_decode_helper;
pub mod huffman_table;
mod static_table;

type Res<T> = Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    DecompressionFailed,
    EncoderStreamError,
    DecoderStreamError,
}

impl Error {
    pub fn code(&self) -> u16 {
        // TODO(mt): use real codes once QPACK defines some.
        3
    }
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        None
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "QPACK error: {:?}", self)
    }
}
