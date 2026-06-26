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
pub mod hrtime;
mod incrdecoder;
pub mod log;
pub mod qlog;
pub mod tos;

use std::{
    cmp::{max, min},
    fmt,
};

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

macro_rules! hex_struct {
    {$(#[$m:meta])* $n:ident, $f:item} => {
$(#[$m])*
pub struct $n<T>(T);

impl<T> $n<T> {
    /// Wrap an object (or reference) for hex formatting.
    ///
    /// For example:
    /// ```
    #[doc = concat!("# use neqo_common::", stringify!($n), ";")]
    /// struct Example(String, Vec<u8>);
    /// impl std::fmt::Debug for Example {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         f.debug_tuple("Example")
    ///          .field(&self.0)
    #[doc = concat!(r#"          .field(&"#, stringify!($n), "::new(&self.1))")]
    ///          .finish()
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    /// Propagates and errors from the formatter.
    pub const fn new(v: T) -> Self {
        Self(v)
    }
}

impl<T: AsRef<[u8]>> $n<T> {
    /// Write hex-formatted text to the formatter.
    ///
    /// For example:
    /// ```
    #[doc = concat!("# use neqo_common::", stringify!($n), ";")]
    /// struct VecWrapper(Vec<u8>);
    /// impl std::fmt::Display for VecWrapper {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    #[doc = concat!("        ", stringify!($n), "::fmt(f, &self.0)")]
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    /// Propagates and errors from the formatter.
    pub fn fmt(f: &mut fmt::Formatter<'_>, v: T) -> fmt::Result {
        write!(f, "{}", &Self::new(v))
    }
}

impl<T: AsRef<[u8]>> fmt::Display for $n<T> {
    $f
}

impl<T: AsRef<[u8]>> fmt::Debug for $n<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}
    };
}

/// A fast hex implementation with fixed overhead.
fn chunk_hex<T: AsRef<[u8]>>(f: &mut fmt::Formatter<'_>, v: T) -> fmt::Result {
    const HEX: &[u8] = b"0123456789abcdef";
    const CHUNK_SIZE: usize = 128;
    let mut chunk = [0u8; CHUNK_SIZE * 2];
    for slice in v.as_ref().chunks(CHUNK_SIZE) {
        for (i, &b) in slice.iter().enumerate() {
            chunk[i * 2] = HEX[usize::from(b >> 4)];
            chunk[i * 2 + 1] = HEX[usize::from(b & 0xf)];
        }
        // SAFETY: only ASCII hex is written to the chunk
        f.write_str(unsafe { std::str::from_utf8_unchecked(&chunk[..slice.len() * 2]) })?;
    }
    Ok(())
}

hex_struct! {
    /// Simple Hex converter for formatting.
    Hex,
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        chunk_hex(f, &self.0)
    }
}

hex_struct! {
    /// Hex converter for formatting that trims long sequences.
    HexSnipMiddle,
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const SHOW_LEN: usize = 8;
        let buf = self.0.as_ref();
        write!(f, "[{}]", buf.len())?;
        if !buf.is_empty() {
            f.write_str(": ")?;
        }
        let first = min(buf.len(), SHOW_LEN);
        chunk_hex(f, &buf[..first])?;
        let last = max(buf.len().saturating_sub(SHOW_LEN), first);
        if last > first {
            write!(f, "..")?;
        }
        chunk_hex(f, &buf[last..])
    }
}

hex_struct! {
    /// Hex converter for formatting that reports the length of the sequence.
    HexWithLen,
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let buf = self.0.as_ref();
        write!(f, "[{}]", buf.len())?;
        if !buf.is_empty() {
            f.write_str(": ")?;
        }
        chunk_hex(f, buf)
    }
}

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
    use super::{Hex, HexSnipMiddle, HexWithLen, const_max, const_min};

    #[test]
    fn hex_output() {
        assert_eq!(format!("{}", &Hex::new([])), "");
        assert_eq!(format!("{}", &Hex::new([0xab, 0xcd])), "abcd");

        assert_eq!(format!("{}", &HexSnipMiddle::new([])), "[0]");
        assert_eq!(format!("{}", &HexWithLen::new([])), "[0]");

        assert_eq!(
            format!("{}", &HexSnipMiddle::new([0xab, 0xcd])),
            "[2]: abcd"
        );
        assert_eq!(format!("{}", &HexWithLen::new([0xab, 0xcd])), "[2]: abcd");
    }

    #[test]
    fn const_minmax() {
        for (a, b, min, max) in [(2, 5, 2, 5), (5, 2, 2, 5), (3, 3, 3, 3)] {
            assert_eq!(const_min(a, b), min);
            assert_eq!(const_max(a, b), max);
        }
    }

    #[test]
    fn hex_snip_middle_boundary() {
        // Exactly SHOW_LEN*2 = 16 bytes: should use full hex (no "..").
        let short: Vec<u8> = (0..16).collect();
        let s = format!("{}", &HexSnipMiddle::new(&short));
        assert!(!s.contains(".."), "16 bytes should not be truncated");
        assert!(s.ends_with("0e0f"));

        // 17 bytes: one over the boundary, should be truncated.
        let just_over: Vec<u8> = (0..17).collect();
        assert!(format!("{}", &HexSnipMiddle::new(&just_over)).contains(".."));

        // 20 bytes: truncated, check first 8 and last 8 bytes are exact.
        let long: Vec<u8> = (0..20).collect();
        let s = format!("{}", &HexSnipMiddle::new(&long));
        assert!(s.starts_with("[20]: 0001020304050607"));
        assert!(s.contains(".."));
        // Last 8 bytes (12..20 = 0x0c..0x13) must be exactly "0c0d0e0f10111213".
        assert!(s.ends_with("0c0d0e0f10111213"));
    }
}
