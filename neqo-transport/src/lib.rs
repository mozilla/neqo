// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::{self, Display, Formatter};

use neqo_common::qwarn;
use neqo_crypto::Error as CryptoError;

mod ackrate;
mod addr_valid;
mod cc;
mod cid;
mod connection;
mod crypto;
pub mod ecn;
mod events;
mod fc;
#[cfg(fuzzing)]
pub mod frame;
#[cfg(not(fuzzing))]
mod frame;
mod pace;
#[cfg(any(fuzzing, feature = "bench"))]
pub mod packet;
#[cfg(not(any(fuzzing, feature = "bench")))]
mod packet;
mod path;
mod pmtud;
mod qlog;
mod quic_datagrams;
#[cfg(feature = "bench")]
pub mod recovery;
#[cfg(not(feature = "bench"))]
mod recovery;
mod saved;
// #[cfg(feature = "bench")]
pub mod recv_stream;
// #[cfg(not(feature = "bench"))]
// mod recv_stream;
mod rtt;
// #[cfg(feature = "bench")]
pub mod send_stream;
// #[cfg(not(feature = "bench"))]
// mod send_stream;
mod sender;
pub mod server;
mod sni;
mod stats;
pub mod stream_id;
pub mod streams;
pub mod tparams;
mod tracking;
pub mod version;

pub use self::{
    cc::CongestionControlAlgorithm,
    cid::{
        ConnectionId, ConnectionIdDecoder, ConnectionIdGenerator, ConnectionIdRef,
        EmptyConnectionIdGenerator, RandomConnectionIdGenerator,
    },
    connection::{
        params::ConnectionParameters, Connection, Output, OutputBatch, State, ZeroRttState,
    },
    events::{ConnectionEvent, ConnectionEvents},
    frame::CloseError,
    packet::MIN_INITIAL_PACKET_SIZE,
    pmtud::Pmtud,
    quic_datagrams::DatagramTracking,
    recv_stream::INITIAL_RECV_WINDOW_SIZE,
    rtt::DEFAULT_INITIAL_RTT,
    sni::find_sni,
    stats::Stats,
    stream_id::{StreamId, StreamType},
    version::Version,
};

pub type TransportError = u64;
const ERROR_APPLICATION_CLOSE: TransportError = 12;
const ERROR_CRYPTO_BUFFER_EXCEEDED: TransportError = 13;
const ERROR_AEAD_LIMIT_REACHED: TransportError = 15;

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum Error {
    None,
    // Each time this error is returned a different parameter is supplied.
    // This will be used to distinguish each occurrence of this error.
    Internal,
    ConnectionRefused,
    FlowControl,
    StreamLimit,
    StreamState,
    FinalSize,
    FrameEncoding,
    TransportParameter,
    ProtocolViolation,
    InvalidToken,
    Application,
    CryptoBufferExceeded,
    Crypto(CryptoError),
    Qlog,
    CryptoAlert(u8),
    EchRetry(Vec<u8>),

    // All internal errors from here.  Please keep these sorted.
    AckedUnsentPacket,
    ConnectionIdLimitExceeded,
    ConnectionIdsExhausted,
    ConnectionState,
    Decrypt,
    DisabledVersion,
    IdleTimeout,
    IntegerOverflow,
    InvalidInput,
    InvalidMigration,
    InvalidPacket,
    InvalidResumptionToken,
    InvalidRetry,
    InvalidStreamId,
    KeysDiscarded(crypto::Epoch),
    /// Packet protection keys are exhausted.
    /// Also used when too many key updates have happened.
    KeysExhausted,
    /// Packet protection keys aren't available yet for the identified space.
    KeysPending(crypto::Epoch),
    /// An attempt to update keys can be blocked if
    /// a packet sent with the current keys hasn't been acknowledged.
    KeyUpdateBlocked,
    NoAvailablePath,
    NoMoreData,
    NotAvailable,
    NotConnected,
    PacketNumberOverlap,
    PeerApplication(AppError),
    Peer(TransportError),
    StatelessReset,
    TooMuchData,
    UnexpectedMessage,
    UnknownConnectionId,
    UnknownFrameType,
    VersionNegotiation,
    WrongRole,
    UnknownTransportParameter,
}

impl Error {
    #[must_use]
    pub fn code(&self) -> TransportError {
        match self {
            Self::None | Self::IdleTimeout | Self::Peer(_) | Self::PeerApplication(_) => 0,
            Self::ConnectionRefused => 2,
            Self::FlowControl => 3,
            Self::StreamLimit => 4,
            Self::StreamState => 5,
            Self::FinalSize => 6,
            Self::FrameEncoding => 7,
            Self::TransportParameter => 8,
            Self::ProtocolViolation => 10,
            Self::InvalidToken => 11,
            Self::KeysExhausted => ERROR_AEAD_LIMIT_REACHED,
            Self::Application => ERROR_APPLICATION_CLOSE,
            Self::NoAvailablePath => 16,
            Self::CryptoBufferExceeded => ERROR_CRYPTO_BUFFER_EXCEEDED,
            Self::CryptoAlert(a) => 0x100 + u64::from(*a),
            // As we have a special error code for ECH fallbacks, we lose the alert.
            // Send the server "ech_required" directly.
            Self::EchRetry(_) => 0x100 + 121,
            Self::VersionNegotiation => 0x53f8,
            // All the rest are internal errors.
            _ => 1,
        }
    }
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        qwarn!("Crypto operation failed {err:?}");
        match err {
            CryptoError::EchRetry(config) => Self::EchRetry(config),
            _ => Self::Crypto(err),
        }
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_: std::num::TryFromIntError) -> Self {
        Self::IntegerOverflow
    }
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Transport error: {self:?}")
    }
}

pub type AppError = u64;

#[deprecated(note = "use `CloseReason` instead")]
pub type ConnectionError = CloseReason;

/// Reason why a connection closed.
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum CloseReason {
    Transport(Error),
    Application(AppError),
}

impl CloseReason {
    /// Checks enclosed error for [`Error::None`] and
    /// [`CloseReason::Application(0)`].
    #[must_use]
    pub const fn is_error(&self) -> bool {
        !matches!(self, Self::Transport(Error::None) | Self::Application(0),)
    }
}

pub type Res<T> = Result<T, Error>;
