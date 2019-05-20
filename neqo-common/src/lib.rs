// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

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

pub fn hex(buf: &[u8]) -> String {
    let mut ret = String::with_capacity(10 + buf.len() * 3);
    ret.push_str(&format!("[{}]: ", buf.len()));
    for b in buf {
        ret.push_str(&format!("{:02x}", b));
    }
    ret
}
