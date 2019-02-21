extern crate num_traits;
#[macro_use]
extern crate derive_more;

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
macro_rules! error { ($($arg:tt)*) => ( println!($($arg)*);) }
macro_rules! warn { ($($arg:tt)*) => ( println!($($arg)*);) }
macro_rules! info { ($($arg:tt)*) => ( println!($($arg)*);) }
macro_rules! debug { ($($arg:tt)*) => ( println!($($arg)*);) }
macro_rules! trace { ($($arg:tt)*) => ( println!($($arg)*);) }

pub mod connection;
pub mod data;
pub mod frame;
pub mod packet;
pub mod stream;
pub mod varint;
mod nss_stub;

#[derive(PartialEq, Debug)]
pub enum Error {
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
