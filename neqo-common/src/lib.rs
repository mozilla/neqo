// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod bytes;
mod codec;
pub mod datagram;
pub mod event;
#[cfg(feature = "build-fuzzing-corpus")]
mod fuzz;
pub mod header;
pub mod hex;
pub mod hrtime;
mod incrdecoder;
pub mod json;
pub mod log;
pub mod qlog;
pub mod tos;

use enum_map::Enum;
use static_assertions::const_assert_eq;
use strum::Display;

#[cfg(feature = "build-fuzzing-corpus")]
pub use self::fuzz::write_item_to_fuzzing_corpus;
pub use self::{
    bytes::Bytes,
    codec::{Buffer, Decoder, Encoder, MAX_VARINT},
    datagram::Datagram,
    header::Header,
    incrdecoder::{IncrementalDecoderBuffer, IncrementalDecoderIgnore, IncrementalDecoderUint},
    tos::{Dscp, Ecn, Tos},
};

#[must_use]
pub const fn const_max(a: usize, b: usize) -> usize {
    [a, b][(a <= b) as usize]
}
#[must_use]
pub const fn const_min(a: usize, b: usize) -> usize {
    [a, b][(a > b) as usize]
}

// Both conversions below are safe on all targets where usize and u64 are the
// same width (i.e., 64-bit targets). The assertion enforces this at compile time.
const_assert_eq!(usize::BITS, u64::BITS);

/// A trait for values that represent a length or byte count, convertible
/// to the wire domain (`u64`).
pub trait Length: Copy {
    fn as_u64(self) -> u64;
}

impl Length for u64 {
    fn as_u64(self) -> u64 {
        self
    }
}

impl Length for usize {
    fn as_u64(self) -> u64 {
        to_u64(self)
    }
}

/// Convert a `usize` to `u64`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "debug_assert roundtrip `v as u64 as usize` contains a u64→usize cast; \
              const_assert_eq above ensures it is lossless on all supported targets"
)]
#[inline]
#[must_use]
pub const fn to_u64(v: usize) -> u64 {
    debug_assert!(v as u64 as usize == v);
    v as u64
}

/// Convert a `u64` to `usize`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "const_assert_eq above ensures usize::BITS == u64::BITS"
)]
#[inline]
#[must_use]
pub const fn to_usize(v: u64) -> usize {
    debug_assert!(v as usize as u64 == v);
    v as usize
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Enum, Display)]
/// Client or Server.
pub enum Role {
    Client,
    Server,
}

impl Role {
    #[must_use]
    pub const fn remote(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Request,
    Response,
}

/// Dispatch a method call on an enum to its variants' inner values.
///
/// The variant list is given once in a local wrapper; method bodies stay clean:
///
/// ```ignore
/// // Once per enum, in the impl module:
/// macro_rules! dispatch {
///     ($self:ident . $method:ident $args:tt) => {
///         neqo_common::dispatch!([Variant1, Variant2, Variant3] $self . $method $args)
///     };
/// }
///
/// impl SomeTrait for MyEnum {
///     fn method(&self) -> T { dispatch!(self.method()) }
/// }
/// ```
#[macro_export]
macro_rules! dispatch {
    ([$($variant:ident),+ $(,)?] $self:ident . $method:ident $args:tt) => {
        match $self {
            $( Self::$variant(v) => v.$method $args, )+
        }
    };
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{const_max, const_min};

    #[test]
    fn const_minmax() {
        for (a, b, min, max) in [(2, 5, 2, 5), (5, 2, 2, 5), (3, 3, 3, 3)] {
            assert_eq!(const_min(a, b), min);
            assert_eq!(const_max(a, b), max);
        }
    }
}
