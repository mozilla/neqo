#![deny(warnings)]

#[macro_use]
extern crate neqo_common;

use neqo_crypto;

pub mod connection;
pub mod frame;
mod nss;
pub mod nss_stub;
pub mod packet;
pub mod recv_stream;
pub mod send_stream;
mod tparams;

pub use self::connection::{Connection, Datagram, State};
pub use recv_stream::Recvable;
pub use send_stream::Sendable;

type TransportError = u16;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NoError,
    InternalError,
    ServerBusy,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ProtocolViolation,
    InvalidMigration,
    CryptoError(neqo_crypto::Error),
    CryptoAlert(u8),
    IoError(neqo_common::Error),
    NoMoreData,
    TooMuchData,
    UnknownFrameType,
    InvalidPacket,
    DecryptError,
    InvalidStreamId,
    DecodingFrame,
    UnexpectedMessage,
    HandshakeFailed,
    KeysNotFound,
    UnknownTransportParameter,
}

impl Error {
    pub fn code(&self) -> TransportError {
        match self {
            Error::NoError => 0,
            Error::InternalError => 1,
            Error::ServerBusy => 2,
            Error::FlowControlError => 3,
            Error::StreamLimitError => 4,
            Error::StreamStateError => 5,
            Error::FinalSizeError => 6,
            Error::FrameEncodingError => 7,
            Error::TransportParameterError => 8,
            Error::ProtocolViolation => 10,
            Error::InvalidMigration => 12,
            Error::CryptoAlert(a) => 0x100 + (*a as u16),
            Error::CryptoError(_)
            | Error::IoError(..)
            | Error::NoMoreData
            | Error::TooMuchData
            | Error::UnknownFrameType
            | Error::InvalidPacket
            | Error::DecryptError
            | Error::InvalidStreamId
            | Error::DecodingFrame
            | Error::UnexpectedMessage
            | Error::HandshakeFailed
            | Error::KeysNotFound
            | Error::UnknownTransportParameter => 1,
        }
    }
}

impl From<neqo_crypto::Error> for Error {
    fn from(err: neqo_crypto::Error) -> Self {
        qinfo!("Crypto operation failed {:?}", err);
        Error::CryptoError(err)
    }
}

impl From<neqo_common::Error> for Error {
    fn from(err: neqo_common::Error) -> Self {
        qinfo!("IO error {:?}", err);
        Error::IoError(err)
    }
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn::std::error::Error + 'static)> {
        match self {
            Error::CryptoError(e) => Some(e),
            Error::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Transport error: {:?}", self)
    }
}

pub type AppError = u16;

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionError {
    Transport(Error),
    Application(AppError),
}

impl ConnectionError {
    pub fn app_code(&self) -> Option<AppError> {
        match self {
            ConnectionError::Application(e) => Some(*e),
            _ => None,
        }
    }
}

pub type Res<T> = std::result::Result<T, Error>;

pub fn hex(label: &str, buf: &[u8]) -> String {
    let mut ret = String::with_capacity(label.len() + 10 + buf.len() * 3);
    ret.push_str(&format!("{}[{}]: ", label, buf.len()));
    for b in buf {
        ret.push_str(&format!("{:02x}", b));
    }
    ret
}
