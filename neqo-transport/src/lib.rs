// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::qinfo;
use neqo_crypto;

mod connection;
mod crypto;
mod dump;
mod events;
mod flow_mgr;
mod frame;
mod packet;
mod recovery;
mod recv_stream;
mod send_stream;
pub mod server;
mod stats;
mod stream_id;
mod tparams;
mod tracking;

pub use self::connection::{Connection, Output, Role, State};
pub use self::events::ConnectionEvent;
pub use self::frame::CloseError;
pub use self::frame::StreamType;

/// The supported version of the QUIC protocol.
pub const QUIC_VERSION: u32 = 0xff00_0016;

type TransportError = u64;

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
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
    ConnectionState,
    AckedUnsentPacket,
    VersionNegotiation,
    InvalidResumptionToken,
    WrongRole,
    InvalidInput,
    IdleTimeout,
    PeerError(TransportError),
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
            Error::CryptoAlert(a) => 0x100 + u64::from(*a),
            Error::PeerError(a) => *a,
            // TODO(ekr@rtfm.com): Map these errors.
            Error::CryptoError(_)
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
            | Error::ConnectionState
            | Error::AckedUnsentPacket
            | Error::VersionNegotiation
            | Error::WrongRole
            | Error::InvalidResumptionToken
            | Error::InvalidInput
            | Error::IdleTimeout => 1,
        }
    }
}

impl From<neqo_crypto::Error> for Error {
    fn from(err: neqo_crypto::Error) -> Self {
        qinfo!("Crypto operation failed {:?}", err);
        Error::CryptoError(err)
    }
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            Error::CryptoError(e) => Some(e),
            _ => None,
        }
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Transport error: {:?}", self)
    }
}

pub type AppError = u64;

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
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

impl From<CloseError> for ConnectionError {
    fn from(err: CloseError) -> Self {
        match err {
            CloseError::Transport(c) => ConnectionError::Transport(Error::PeerError(c)),
            CloseError::Application(c) => ConnectionError::Application(c),
        }
    }
}

pub type Res<T> = std::result::Result<T, Error>;
