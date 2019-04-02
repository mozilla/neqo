// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

pub mod connection;
pub mod hframe;
mod recvable;
mod transport;

use neqo_qpack;
use neqo_transport;

use self::hframe::HFrameType;

type Res<T> = Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NoError,
    WrongSettingsDirection,
    PushRefused,
    InternalError,
    PushAlreadyInCache,
    RequestCancelled,
    IncompleteRequest,
    ConnectError,
    ExcessiveLoad,
    VersionFallback,
    WrongStream,
    LimitExceeded,
    DuplicatePush,
    UnknownStreamType,
    WrongStreamCount,
    ClosedCriticalStream,
    WrongStreamDirection,
    EarlyResponse,
    MissingSettings,
    UnexpectedFrame,
    RequestRejected,
    GeneralProtocolError,
    MalformedFrame(HFrameType),
    NoMoreData,
    DecodingFrame,
    NotEnoughData,
    Unexpected,
    // So we can wrap and report these errors.
    TransportError(neqo_transport::Error),
    IoError(neqo_common::Error),
    QpackError(neqo_qpack::Error),
}

impl Error {
    pub fn code(&self) -> neqo_transport::AppError {
        match self {
            Error::NoError => 0,
            Error::WrongSettingsDirection => 1,
            Error::PushRefused => 2,
            Error::InternalError => 3,
            Error::PushAlreadyInCache => 4,
            Error::RequestCancelled => 5,
            Error::IncompleteRequest => 6,
            Error::ConnectError => 7,
            Error::ExcessiveLoad => 8,
            Error::VersionFallback => 9,
            Error::WrongStream => 10,
            Error::LimitExceeded => 11,
            Error::DuplicatePush => 12,
            Error::UnknownStreamType => 13,
            Error::WrongStreamCount => 14,
            Error::ClosedCriticalStream => 15,
            Error::WrongStreamDirection => 16,
            Error::EarlyResponse => 17,
            Error::MissingSettings => 18,
            Error::UnexpectedFrame => 19,
            Error::RequestRejected => 20,
            Error::GeneralProtocolError => 0xff,
            Error::MalformedFrame(t) => match t {
                0...0xfe => (*t as neqo_transport::AppError) + 0x100,
                _ => 0x1ff,
            },
            // These are all internal errors.
            Error::NoMoreData
            | Error::DecodingFrame
            | Error::NotEnoughData
            | Error::Unexpected
            | Error::TransportError(..)
            | Error::IoError(..) => 3,
            Error::QpackError(e) => e.code() as neqo_transport::AppError,
        }
    }

    pub fn is_stream_error(&self) -> bool {
        // TODO(mt): check that these are OK.  They all look fatal to me.
        *self == Error::UnexpectedFrame
            || *self == Error::WrongStreamDirection
            || *self == Error::WrongStream
    }
}

impl From<neqo_transport::Error> for Error {
    fn from(err: neqo_transport::Error) -> Self {
        Error::TransportError(err)
    }
}

impl From<neqo_qpack::Error> for Error {
    fn from(err: neqo_qpack::Error) -> Self {
        Error::QpackError(err)
    }
}

impl From<neqo_common::Error> for Error {
    fn from(err: neqo_common::Error) -> Self {
        Error::IoError(err)
    }
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            Error::TransportError(e) => Some(e),
            Error::QpackError(e) => Some(e),
            _ => None,
        }
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "HTTP/3 error: {:?}", self)
    }
}
