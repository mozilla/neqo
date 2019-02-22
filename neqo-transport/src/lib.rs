#![allow(unused_macros)]

// Cribbed from the |matches| crate, for simplicity.
macro_rules! matches {
    ($expression:expr, $($pattern:tt)+) => {
        match $expression {
            $($pattern)+ => true,
            _ => false
        }
    }
}

// Map logging to println for now until we can figure out how to get it in
// unit tests without putting env_logger::try_init() at the top of every test.
#[allow(unused_macros)]
macro_rules! error { ($($arg:tt)*) => ( println!($($arg)*);) }
#[allow(unused_macros)]
macro_rules! warn { ($($arg:tt)*) => ( println!($($arg)*);) }
#[allow(unused_macros)]
macro_rules! info { ($($arg:tt)*) => ( println!($($arg)*);) }
#[allow(unused_macros)]
macro_rules! debug { ($($arg:tt)*) => ( println!($($arg)*);) }
#[allow(unused_macros)]
macro_rules! trace { ($($arg:tt)*) => ( println!($($arg)*);) }

pub mod connection;
pub mod data;
pub mod frame;
mod nss_stub;
pub mod packet;
pub mod stream;
pub mod varint;

#[derive(PartialEq, Debug)]
pub enum Error {
    ErrNoError = 0x0,
    ErrInternalError = 0x1,
    ErrServerBusy = 0x2,
    ErrFlowControlError = 0x3,
    ErrStreamLimitError = 0x4,
    ErrStreamStateError = 0x5,
    ErrFinalSizeError = 0x6,
    ErrFrameEncodingError = 0x7,
    ErrTransportParameterError = 0x8,
    ErrProtocolViolation = 0xa,
    ErrInvalidMigration = 0xc,
    ErrCryptoError = 0x100,
    ErrNoMoreData,
    ErrTooMuchData,
    ErrUnknownFrameType,
    ErrInternal,
    ErrInvalidPacket,
    ErrDecryptError,
    ErrInvalidStreamId,
    ErrDecodingFrame,
    ErrUnexpectedMessage,
}

pub type Res<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {}
