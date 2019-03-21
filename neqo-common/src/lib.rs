#![deny(warnings)]

pub mod data;
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

// Map logging to println for now until we can figure out how to get it in
// unit tests without putting env_logger::try_init() at the top of every test.
#[allow(dead_code)]
enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}
#[macro_export]
macro_rules! log { ($lvl:expr, $($arg:tt)+) => (eprintln!($($arg)+)) }
#[macro_export]
macro_rules! log_with_ctx { ($lvl:expr, $ctx: expr, $($arg:tt)*) => ( log!($lvl, "[{}] {}", $ctx.label(), format!($($arg)*));) }
#[macro_export]
macro_rules! qerror {
    ($ctx:ident, $($arg:tt)*) => ( log_with_ctx!(Level::Error, $ctx, $($arg)*););
    ($($arg:tt)*) => ( log!(Level::Error, $($arg)*);)
}
#[macro_export]
macro_rules! qwarn {
    ($ctx:ident, $($arg:tt)*) => ( log_with_ctx!(Level::Warn, $ctx, $($arg)*););
    ($($arg:tt)*) => ( log!(Level::Warn, $($arg)*);)
}
#[macro_export]
macro_rules! qinfo {
    ($ctx:ident, $($arg:tt)*) => ( log_with_ctx!(Level::Info, $ctx, $($arg)*););
    ($($arg:tt)*) => ( log!(Level::Info, $($arg)*);)
}
#[macro_export]
macro_rules! qdebug {
    ($ctx:ident, $($arg:tt)*) => ( log_with_ctx!(Level::Debug, $ctx, $($arg)*););
    ($($arg:tt)*) => ( log!(Level::Debug, $($arg)*);)
}
#[macro_export]
macro_rules! qtrace {
    ($ctx:ident, $($arg:tt)*) => ( log_with_ctx!(Level::Trace, $ctx, $($arg)*););
    ($($arg:tt)*) => ( log!(Level::Trace, $($arg)*);)
}

type Res<T> = Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    NoMoreData,
    ReadError, // TODO (mt): Copy the reader error through.
}

impl ::std::error::Error for Error {
    fn source(&self) -> Option<&(dyn::std::error::Error + 'static)> {
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
        .as_millis() as u64
}
