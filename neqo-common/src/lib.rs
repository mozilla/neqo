#![deny(warnings)]

pub mod data;
pub mod log;
pub mod readbuf;
pub mod varint;
use std::time::SystemTime;

// Cribbed from the |matches| crate, for simplicity.
#[macro_export]
macro_rules! matches {
    ($expression:expr, $($pattern:tt)+) => {
        match $expression {
            $($pattern)+ => true,
            _ => false
        }
    }
}

type Res<T> = Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    NoMoreData,
    ReadError, // TODO (mt): Copy the reader error through.
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        None
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Reader error: {:?}", self)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
