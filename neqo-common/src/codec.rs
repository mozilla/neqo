// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Debug, Formatter, Write},
    io::{self, Cursor},
};

use crate::hex_with_len;

pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// Decoder is a view into a byte array that has a read offset.  Use it for parsing.
pub struct Decoder<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// Make a new view of the provided slice.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// Get the number of bytes remaining until the end.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.offset
    }

    /// The number of bytes from the underlying slice that have been decoded.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Skip n bytes.
    ///
    /// # Panics
    ///
    /// If the remaining quantity is less than `n`.
    pub fn skip(&mut self, n: usize) {
        assert!(self.remaining() >= n, "insufficient data");
        self.offset += n;
    }

    /// Skip helper that panics if `n` is `None` or not able to fit in `usize`.
    /// Only use this for tests because we panic rather than reporting a result.
    #[cfg(any(test, feature = "test-fixture"))]
    fn skip_inner(&mut self, n: Option<u64>) {
        #[expect(clippy::unwrap_used, reason = "Only used in tests.")]
        self.skip(usize::try_from(n.expect("invalid length")).unwrap());
    }

    /// Skip a vector.  Panics if there isn't enough space.
    /// Only use this for tests because we panic rather than reporting a result.
    #[cfg(any(test, feature = "test-fixture"))]
    pub fn skip_vec(&mut self, n: usize) {
        let len = self.decode_n(n);
        self.skip_inner(len);
    }

    /// Skip a variable length vector.  Panics if there isn't enough space.
    /// Only use this for tests because we panic rather than reporting a result.
    #[cfg(any(test, feature = "test-fixture"))]
    pub fn skip_vvec(&mut self) {
        let len = self.decode_varint();
        self.skip_inner(len);
    }

    /// Skip while the current byte is `predicate`. Returns the number of bytes
    /// skipped.
    pub fn skip_while(&mut self, predicate: u8) -> usize {
        let until = self
            .as_ref() // remaining bytes
            .iter()
            .position(|v| *v != predicate)
            .unwrap_or_else(|| self.remaining());
        self.skip(until);
        until
    }

    /// Provides the next byte without moving the read position.
    #[must_use]
    pub const fn peek_byte(&self) -> Option<u8> {
        if self.remaining() < 1 {
            None
        } else {
            Some(self.buf[self.offset])
        }
    }

    /// Decodes arbitrary data.
    pub fn decode(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let res = &self.buf[self.offset..self.offset + n];
        self.offset += n;
        Some(res)
    }

    #[inline]
    pub(crate) fn decode_n(&mut self, n: usize) -> Option<u64> {
        debug_assert!(n > 0 && n <= 8);
        if self.remaining() < n {
            return None;
        }
        Some(if n == 1 {
            let v = u64::from(self.buf[self.offset]);
            self.offset += 1;
            v
        } else {
            let mut buf = [0; 8];
            buf[8 - n..].copy_from_slice(&self.buf[self.offset..self.offset + n]);
            self.offset += n;
            u64::from_be_bytes(buf)
        })
    }

    /// Decodes a big-endian, unsigned integer value into the target type.
    /// This returns `None` if there is not enough data remaining
    /// or if the conversion to the identified type fails.
    /// Conversion is via `u64`, so failures are impossible for
    /// unsigned integer types: `u8`, `u16`, `u32`, or `u64`.
    /// Signed types will fail if the high bit is set.
    pub fn decode_uint<T: TryFrom<u64>>(&mut self) -> Option<T> {
        let v = self.decode_n(size_of::<T>());
        T::try_from(v?).ok()
    }

    /// Decodes a QUIC varint.
    pub fn decode_varint(&mut self) -> Option<u64> {
        let b1 = self.decode_n(1)?;
        match b1 >> 6 {
            0 => Some(b1),
            1 => Some(((b1 & 0x3f) << 8) | self.decode_n(1)?),
            2 => Some(((b1 & 0x3f) << 24) | self.decode_n(3)?),
            3 => Some(((b1 & 0x3f) << 56) | self.decode_n(7)?),
            _ => unreachable!(),
        }
    }

    /// Decodes the rest of the buffer.  Infallible.
    pub fn decode_remainder(&mut self) -> &'a [u8] {
        let res = &self.buf[self.offset..];
        self.offset = self.buf.len();
        res
    }

    fn decode_checked(&mut self, n: Option<u64>) -> Option<&'a [u8]> {
        if let Ok(l) = usize::try_from(n?) {
            self.decode(l)
        } else {
            // sizeof(usize) < sizeof(u64) and the value is greater than
            // usize can hold. Throw away the rest of the input.
            self.offset = self.buf.len();
            None
        }
    }

    /// Decodes a TLS-style length-prefixed buffer.
    pub fn decode_vec(&mut self, n: usize) -> Option<&'a [u8]> {
        let len = self.decode_n(n);
        self.decode_checked(len)
    }

    /// Decodes a QUIC varint-length-prefixed buffer.
    pub fn decode_vvec(&mut self) -> Option<&'a [u8]> {
        let len = self.decode_varint();
        self.decode_checked(len)
    }
}

// Implement `AsRef` for `Decoder` so that values can be examined without
// moving the cursor.
impl<'a> AsRef<[u8]> for Decoder<'a> {
    fn as_ref(&self) -> &'a [u8] {
        &self.buf[self.offset..]
    }
}

impl Debug for Decoder<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&hex_with_len(self.as_ref()))
    }
}

impl<'a> From<&'a [u8]> for Decoder<'a> {
    fn from(buf: &'a [u8]) -> Self {
        Decoder::new(buf)
    }
}

impl<'a, T> From<&'a T> for Decoder<'a>
where
    T: AsRef<[u8]>,
{
    fn from(buf: &'a T) -> Self {
        Decoder::new(buf.as_ref())
    }
}

impl<'b> PartialEq<Decoder<'b>> for Decoder<'_> {
    fn eq(&self, other: &Decoder<'b>) -> bool {
        self.buf == other.buf
    }
}

/// Encoder is good for building data structures.
#[derive(Clone, PartialEq, Eq)]
pub struct Encoder<B = Vec<u8>> {
    buf: B,
    /// Tracks the starting position of the buffer when the [`Encoder`] is created.
    /// This allows distinguishing between bytes that existed in the buffer before
    /// encoding began and those written by the [`Encoder`] itself.
    start: usize,
}

impl<B: Buffer> Encoder<B> {
    /// Get the length of the [`Encoder`].
    ///
    /// Note that the length of the underlying buffer might be larger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.position() - self.start
    }

    /// Returns true if the encoder buffer contains no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Create a view of the current contents of the buffer.
    /// Note: for a view of a slice, use `Decoder::new(&enc[s..e])`
    #[must_use]
    pub fn as_decoder(&self) -> Decoder<'_> {
        Decoder::new(self.buf.as_slice())
    }

    /// Generic encode routine for arbitrary data.
    ///
    /// # Panics
    ///
    /// When writing to the underlying buffer fails.
    pub fn encode(&mut self, data: &[u8]) -> &mut Self {
        self.buf
            .write_all(data)
            .expect("Buffer has enough capacity.");
        self
    }

    /// Encode a single byte.
    ///
    /// # Panics
    ///
    /// When writing to the underlying buffer fails.
    pub fn encode_byte(&mut self, data: u8) -> &mut Self {
        self.buf
            .write_all(&[data])
            .expect("Buffer has enough capacity.");
        self
    }

    /// Encode an integer of any size up to u64.
    ///
    /// # Panics
    ///
    /// When `n` is outside the range `1..=8`.
    pub fn encode_uint<T: Into<u64>>(&mut self, n: usize, v: T) -> &mut Self {
        let v = v.into();
        assert!(n > 0 && n <= 8);
        for i in 0..n {
            self.encode_byte(((v >> (8 * (n - i - 1))) & 0xff) as u8);
        }
        self
    }

    /// Encode a QUIC varint.
    ///
    /// # Panics
    ///
    /// When `v >= 1<<62`.
    pub fn encode_varint<T: Into<u64>>(&mut self, v: T) -> &mut Self {
        let v = v.into();
        match () {
            () if v < (1 << 6) => self.encode_uint(1, v),
            () if v < (1 << 14) => self.encode_uint(2, v | (1 << 14)),
            () if v < (1 << 30) => self.encode_uint(4, v | (2 << 30)),
            () if v < (1 << 62) => self.encode_uint(8, v | (3 << 62)),
            () => panic!("Varint value too large"),
        };
        self
    }

    /// Encode a vector in TLS style.
    ///
    /// # Panics
    ///
    /// When `v` is longer than 2^n.
    pub fn encode_vec(&mut self, n: usize, v: &[u8]) -> &mut Self {
        self.encode_uint(
            n,
            u64::try_from(v.as_ref().len()).expect("v is longer than 2^64"),
        )
        .encode(v)
    }

    /// Encode a vector in TLS style using a closure for the contents.
    ///
    /// # Panics
    ///
    /// When `f()` returns a length larger than `2^8n`.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "AND'ing with 0xff makes this OK."
    )]
    pub fn encode_vec_with<F: FnOnce(&mut Self)>(&mut self, n: usize, f: F) -> &mut Self {
        let start = self.buf.position();
        self.pad_to(n, 0);
        f(self);
        let len = self.buf.position() - start - n;
        assert!(len < (1 << (n * 8)));
        for i in 0..n {
            self.buf
                .write_at(start + i, ((len >> (8 * (n - i - 1))) & 0xff) as u8);
        }
        self
    }

    /// Encode a vector with a varint length.
    ///
    /// # Panics
    ///
    /// When `v` is longer than 2^62.
    pub fn encode_vvec(&mut self, v: &[u8]) -> &mut Self {
        self.encode_varint(u64::try_from(v.as_ref().len()).expect("v is longer than 2^64"))
            .encode(v)
    }

    /// Encode a vector with a varint length using a closure.
    ///
    /// # Panics
    ///
    /// When `f()` writes more than 2^62 bytes.
    pub fn encode_vvec_with<F: FnOnce(&mut Self)>(&mut self, f: F) -> &mut Self {
        let start = self.buf.position();
        // Optimize for short buffers, reserve a single byte for the length.
        self.buf
            .write_all(&[0])
            .expect("Buffer has enough capacity.");
        f(self);
        let len = self.buf.position() - start - 1;

        // Now to insert a varint for `len` before the encoded block.
        //
        // We now have one zero byte at `start`, followed by `len` encoded bytes:
        //   |  0  | ... encoded ... |
        // We are going to encode a varint by putting the low bytes in that spare byte.
        // Any additional bytes for the varint are put after the encoded blob:
        //   | low | ... encoded ... | varint high |
        // Then we will rotate that entire piece right, by however many bytes we add:
        //   | varint high | low | ... encoded ... |
        // As long as encoding more than 63 bytes is rare, this won't cost much relative
        // to the convenience of being able to use this function.

        let v = u64::try_from(len).expect("encoded value fits in a u64");
        // The lower order byte fits before the inserted block of bytes.
        self.buf.write_at(start, (v & 0xff) as u8);
        let (count, bits) = match () {
            // Great.  The byte we have is enough.
            () if v < (1 << 6) => return self,
            () if v < (1 << 14) => (1, 1 << 6),
            () if v < (1 << 30) => (3, 2 << 22),
            () if v < (1 << 62) => (7, 3 << 54),
            () => panic!("Varint value too large"),
        };
        // Now, we need to encode the high bits after the main block, ...
        self.encode_uint(count, (v >> 8) | bits);
        // ..., then rotate the entire thing right by the same amount.
        self.buf.rotate_right(start, count);
        self
    }

    /// Truncate the encoder to the given size.
    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len + self.start);
    }

    /// Pad the [`Encoder`] to `len` with bytes set to `v`.
    pub fn pad_to(&mut self, len: usize, v: u8) {
        let buffer_len = self.start + len;
        if buffer_len > self.buf.position() {
            self.buf.pad_to(buffer_len, v);
        }
    }
}

impl Encoder<Vec<u8>> {
    /// Default construction of an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Static helper function for previewing the results of encoding without doing it.
    ///
    /// # Panics
    ///
    /// When `v` is too large.
    #[must_use]
    pub const fn varint_len(v: u64) -> usize {
        match () {
            () if v < (1 << 6) => 1,
            () if v < (1 << 14) => 2,
            () if v < (1 << 30) => 4,
            () if v < (1 << 62) => 8,
            () => panic!("Varint value too large"),
        }
    }

    /// Static helper to determine how long a varint-prefixed array encodes to.
    ///
    /// # Panics
    ///
    /// When `len` doesn't fit in a `u64`.
    #[must_use]
    pub fn vvec_len(len: usize) -> usize {
        Self::varint_len(u64::try_from(len).expect("usize should fit into u64")) + len
    }

    /// Construction of a buffer with a predetermined capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            start: 0,
        }
    }

    /// Don't use this except in testing.
    ///
    /// # Panics
    ///
    /// When `s` contains non-hex values or an odd number of values.
    #[cfg(any(test, feature = "test-fixture"))]
    #[must_use]
    pub fn from_hex<A: AsRef<str>>(s: A) -> Self {
        let s = s.as_ref();
        assert_eq!(s.len() % 2, 0, "Needs to be even length");

        let cap = s.len() / 2;
        let mut enc = Self::with_capacity(cap);

        for i in 0..cap {
            #[expect(clippy::unwrap_used, reason = "Only used in tests.")]
            let v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
            enc.encode_byte(v);
        }
        enc
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
        }
    }
}

impl Debug for Encoder {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&hex_with_len(self))
    }
}

impl<B: Buffer> AsRef<[u8]> for Encoder<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buf.as_slice()[self.start..]
    }
}

impl<B: Buffer> AsMut<[u8]> for Encoder<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[self.start..]
    }
}

impl From<&[u8]> for Encoder {
    fn from(buf: &[u8]) -> Self {
        Self {
            buf: Vec::from(buf),
            start: 0,
        }
    }
}

impl From<Encoder> for Vec<u8> {
    fn from(buf: Encoder) -> Self {
        buf.buf
    }
}

#[expect(
    clippy::unwrap_in_result,
    reason = "successful writing to buffer needs to be guaranteed by caller"
)]
impl<B: io::Write> Write for Encoder<B> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.buf
            .write_all(s.as_bytes())
            .expect("Buffer has enough capacity.");
        Ok(())
    }
}

#[expect(clippy::unnecessary_safety_doc, reason = "relevant for created object")]
impl<'a> Encoder<Cursor<&'a mut [u8]>> {
    /// # Safety
    ///
    /// Any mutable method on [`Encoder<Cursor<&mut [u8]>>`] assumes the
    /// underlying buffer has enough capacity for the called operation. This
    /// invariant needs to be upheld by the caller.
    #[must_use]
    pub fn new_borrowed_slice(buf: &'a mut [u8]) -> Self {
        Encoder {
            buf: Cursor::new(buf),
            start: 0,
        }
    }
}

impl<'a> Encoder<&'a mut Vec<u8>> {
    #[must_use]
    pub fn new_borrowed_vec(buf: &'a mut Vec<u8>) -> Self {
        Encoder {
            start: buf.position(),
            buf,
        }
    }
}

/// Extends a memory buffer with methods beyond [`std::io::Write`]. Needed for
/// [`Encoder`].
///
/// Note that each method operates on the bytes written, not the entire buffer.
/// E.g. [`Buffer::as_slice`] returns the bytes written, not all bytes of the
/// underlying buffer.
pub trait Buffer: io::Write {
    fn position(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.position() == 0
    }

    fn as_slice(&self) -> &[u8];

    fn as_mut(&mut self) -> &mut [u8];

    fn truncate(&mut self, len: usize);

    fn pad_to(&mut self, n: usize, v: u8);

    // Functions needed for `Encoder::encode_vvec_with` and `Encoder::encode_vec_with`.

    fn write_at(&mut self, pos: usize, data: u8);

    fn rotate_right(&mut self, start: usize, count: usize);
}

impl Buffer for Vec<u8> {
    fn position(&self) -> usize {
        self.len()
    }

    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn truncate(&mut self, len: usize) {
        Self::truncate(self, len);
    }

    fn pad_to(&mut self, n: usize, v: u8) {
        self.resize(n, v);
    }

    fn write_at(&mut self, pos: usize, data: u8) {
        self[pos] = data;
    }

    fn rotate_right(&mut self, start: usize, count: usize) {
        self[start..].rotate_right(count);
    }
}

impl Buffer for &mut Vec<u8> {
    fn position(&self) -> usize {
        Vec::len(self)
    }

    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }

    fn pad_to(&mut self, n: usize, v: u8) {
        self.resize(n, v);
    }

    fn write_at(&mut self, pos: usize, data: u8) {
        self[pos] = data;
    }

    fn rotate_right(&mut self, start: usize, count: usize) {
        self[start..].rotate_right(count);
    }
}

impl Buffer for Cursor<&mut [u8]> {
    fn position(&self) -> usize {
        usize::try_from(self.position()).expect("memory allocation not to exceed usize")
    }

    fn as_slice(&self) -> &[u8] {
        &self.get_ref()[..Buffer::position(self)]
    }

    fn as_mut(&mut self) -> &mut [u8] {
        let len = Buffer::position(self);
        &mut self.get_mut()[..len]
    }

    fn truncate(&mut self, len: usize) {
        let old_position = Buffer::position(self);
        if len < old_position {
            self.set_position(u64::try_from(len).expect("Position cannot exceed u64"));
            self.get_mut()[len..old_position].fill(0);
        }
    }

    fn pad_to(&mut self, n: usize, v: u8) {
        let start = usize::try_from(self.position()).expect("Buffer length does not exceed usize");

        self.get_mut()[start..n].fill(v);
        self.set_position(u64::try_from(n).expect("Position cannot exceed u64"));
    }

    fn write_at(&mut self, pos: usize, data: u8) {
        self.get_mut()[pos] = data;
    }

    fn rotate_right(&mut self, start: usize, count: usize) {
        let len = Buffer::position(self);
        self.get_mut()[start..len].rotate_right(count);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{Buffer, Decoder, Encoder};

    #[test]
    fn decode() {
        let enc = Encoder::from_hex("012345");
        let mut dec = enc.as_decoder();
        assert_eq!(dec.decode(2).unwrap(), &[0x01, 0x23]);
        assert!(dec.decode(2).is_none());
    }

    #[test]
    fn decode_byte() {
        let enc = Encoder::from_hex("0123");
        let mut dec = enc.as_decoder();

        assert_eq!(dec.decode_uint::<u8>().unwrap(), 0x01);
        assert_eq!(dec.decode_uint::<u8>().unwrap(), 0x23);
        assert!(dec.decode_uint::<u8>().is_none());
    }

    #[test]
    fn peek_byte() {
        let enc = Encoder::from_hex("01");
        let mut dec = enc.as_decoder();

        assert_eq!(dec.offset(), 0);
        assert_eq!(dec.peek_byte().unwrap(), 0x01);
        dec.skip(1);
        assert_eq!(dec.offset(), 1);
        assert!(dec.peek_byte().is_none());
    }

    #[test]
    fn decode_byte_short() {
        let enc = Encoder::from_hex("");
        let mut dec = enc.as_decoder();
        assert!(dec.decode_uint::<u8>().is_none());
    }

    #[test]
    fn decode_remainder() {
        let enc = Encoder::from_hex("012345");
        let mut dec = enc.as_decoder();
        assert_eq!(dec.decode_remainder(), &[0x01, 0x23, 0x45]);
        assert!(dec.decode(2).is_none());

        let mut dec = Decoder::from(&[]);
        assert!(dec.decode_remainder().is_empty());
    }

    #[test]
    fn decode_vec() {
        let enc = Encoder::from_hex("012345");
        let mut dec = enc.as_decoder();
        assert_eq!(dec.decode_vec(1).expect("read one octet length"), &[0x23]);
        assert_eq!(dec.remaining(), 1);

        let enc = Encoder::from_hex("00012345");
        let mut dec = enc.as_decoder();
        assert_eq!(dec.decode_vec(2).expect("read two octet length"), &[0x23]);
        assert_eq!(dec.remaining(), 1);
    }

    #[test]
    fn decode_vec_short() {
        // The length is too short.
        let enc = Encoder::from_hex("02");
        let mut dec = enc.as_decoder();
        assert!(dec.decode_vec(2).is_none());

        // The body is too short.
        let enc = Encoder::from_hex("0200");
        let mut dec = enc.as_decoder();
        assert!(dec.decode_vec(1).is_none());
    }

    #[test]
    fn decode_vvec() {
        let enc = Encoder::from_hex("012345");
        let mut dec = enc.as_decoder();
        assert_eq!(dec.decode_vvec().expect("read one octet length"), &[0x23]);
        assert_eq!(dec.remaining(), 1);

        let enc = Encoder::from_hex("40012345");
        let mut dec = enc.as_decoder();
        assert_eq!(dec.decode_vvec().expect("read two octet length"), &[0x23]);
        assert_eq!(dec.remaining(), 1);
    }

    #[test]
    fn decode_vvec_short() {
        // The length field is too short.
        let enc = Encoder::from_hex("ff");
        let mut dec = enc.as_decoder();
        assert!(dec.decode_vvec().is_none());

        let enc = Encoder::from_hex("405500");
        let mut dec = enc.as_decoder();
        assert!(dec.decode_vvec().is_none());
    }

    #[test]
    fn skip() {
        let enc = Encoder::from_hex("ffff");
        let mut dec = enc.as_decoder();
        dec.skip(1);
        assert_eq!(dec.remaining(), 1);
    }

    #[test]
    #[should_panic(expected = "insufficient data")]
    fn skip_too_much() {
        let enc = Encoder::from_hex("ff");
        let mut dec = enc.as_decoder();
        dec.skip(2);
    }

    #[test]
    fn skip_vec() {
        let enc = Encoder::from_hex("012345");
        let mut dec = enc.as_decoder();
        dec.skip_vec(1);
        assert_eq!(dec.remaining(), 1);
    }

    #[test]
    #[should_panic(expected = "insufficient data")]
    fn skip_vec_too_much() {
        let enc = Encoder::from_hex("ff1234");
        let mut dec = enc.as_decoder();
        dec.skip_vec(1);
    }

    #[test]
    #[should_panic(expected = "invalid length")]
    fn skip_vec_short_length() {
        let enc = Encoder::from_hex("ff");
        let mut dec = enc.as_decoder();
        dec.skip_vec(4);
    }
    #[test]
    fn skip_vvec() {
        let enc = Encoder::from_hex("012345");
        let mut dec = enc.as_decoder();
        dec.skip_vvec();
        assert_eq!(dec.remaining(), 1);
    }

    #[test]
    #[should_panic(expected = "insufficient data")]
    fn skip_vvec_too_much() {
        let enc = Encoder::from_hex("0f1234");
        let mut dec = enc.as_decoder();
        dec.skip_vvec();
    }

    #[test]
    #[should_panic(expected = "invalid length")]
    fn skip_vvec_short_length() {
        let enc = Encoder::from_hex("ff");
        let mut dec = enc.as_decoder();
        dec.skip_vvec();
    }

    #[test]
    fn skip_while() {
        let enc = Encoder::from_hex("000001020202");
        let mut dec = enc.as_decoder();

        // Skip all zeros
        let skipped = dec.skip_while(0);
        assert_eq!(skipped, 2);
        assert_eq!(dec.offset(), 2);
        assert_eq!(dec.remaining(), 4);
        assert_eq!(dec.as_ref(), &[0x01, 0x02, 0x02, 0x02]);

        // Skip until 0x02
        let skipped = dec.skip_while(0x01);
        assert_eq!(skipped, 1);
        assert_eq!(dec.offset(), 3);
        assert_eq!(dec.remaining(), 3);
        assert_eq!(dec.as_ref(), &[0x02, 0x02, 0x02]);

        // Don't skip on no match.
        let skipped = dec.skip_while(0xFF);
        assert_eq!(skipped, 0);
        assert_eq!(dec.offset(), 3);
        assert_eq!(dec.remaining(), 3);
        assert_eq!(dec.as_ref(), &[0x02, 0x02, 0x02]);

        // Skip till end.
        let skipped = dec.skip_while(0x02);
        assert_eq!(skipped, 3);
        assert_eq!(dec.offset(), 6);
        assert_eq!(dec.remaining(), 0);
        assert_eq!(dec.as_ref(), &[0u8; 0]);
    }

    #[test]
    fn encoded_lengths() {
        assert_eq!(Encoder::varint_len(0), 1);
        assert_eq!(Encoder::varint_len(0x3f), 1);
        assert_eq!(Encoder::varint_len(0x40), 2);
        assert_eq!(Encoder::varint_len(0x3fff), 2);
        assert_eq!(Encoder::varint_len(0x4000), 4);
        assert_eq!(Encoder::varint_len(0x3fff_ffff), 4);
        assert_eq!(Encoder::varint_len(0x4000_0000), 8);
    }

    #[test]
    #[should_panic(expected = "Varint value too large")]
    const fn encoded_length_oob() {
        _ = Encoder::varint_len(1 << 62);
    }

    #[test]
    fn encoded_vvec_lengths() {
        assert_eq!(Encoder::vvec_len(0), 1);
        assert_eq!(Encoder::vvec_len(0x3f), 0x40);
        assert_eq!(Encoder::vvec_len(0x40), 0x42);
        assert_eq!(Encoder::vvec_len(0x3fff), 0x4001);
        assert_eq!(Encoder::vvec_len(0x4000), 0x4004);
        assert_eq!(Encoder::vvec_len(0x3fff_ffff), 0x4000_0003);
        assert_eq!(Encoder::vvec_len(0x4000_0000), 0x4000_0008);
    }

    #[test]
    #[cfg(target_pointer_width = "64")] // Test does not compile on 32-bit targets.
    #[should_panic(expected = "Varint value too large")]
    fn encoded_vvec_length_oob() {
        _ = Encoder::vvec_len(1 << 62);
    }

    #[test]
    fn encode_byte() {
        let mut enc = Encoder::default();

        enc.encode_byte(1);
        assert_eq!(enc, Encoder::from_hex("01"));

        enc.encode_byte(0xfe);
        assert_eq!(enc, Encoder::from_hex("01fe"));
    }

    #[test]
    fn encode() {
        let mut enc = Encoder::default();
        enc.encode(&[1, 2, 3]);
        assert_eq!(enc, Encoder::from_hex("010203"));
    }

    #[test]
    fn encode_uint() {
        let mut enc = Encoder::default();
        enc.encode_uint(2, 10_u8); // 000a
        enc.encode_uint(1, 257_u16); // 01
        enc.encode_uint(3, 0xff_ffff_u32); // ffffff
        enc.encode_uint(8, 0xfedc_ba98_7654_3210_u64);
        assert_eq!(enc, Encoder::from_hex("000a01fffffffedcba9876543210"));
    }

    #[test]
    fn builder_from_slice() {
        let slice = &[1, 2, 3];
        let enc = Encoder::from(&slice[..]);
        assert_eq!(enc, Encoder::from_hex("010203"));
    }

    #[test]
    fn builder_inas_decoder() {
        let enc = Encoder::from_hex("010203");
        let buf = &[1, 2, 3];
        assert_eq!(enc.as_decoder(), Decoder::new(buf));
    }

    struct UintTestCase {
        v: u64,
        b: String,
    }

    macro_rules! uint_tc {
        [$( $v:expr => $b:expr ),+ $(,)?] => {
            vec![ $( UintTestCase { v: $v, b: String::from($b) } ),+]
        };
    }

    #[test]
    fn varint_encode_decode() {
        let cases = uint_tc![
            0 => "00",
            1 => "01",
            63 => "3f",
            64 => "4040",
            16383 => "7fff",
            16384 => "80004000",
            (1 << 30) - 1 => "bfffffff",
            1 << 30 => "c000000040000000",
            (1 << 62) - 1 => "ffffffffffffffff",
        ];

        for c in cases {
            assert_eq!(Encoder::varint_len(c.v), c.b.len() / 2);

            let mut enc = Encoder::default();
            enc.encode_varint(c.v);
            let encoded = Encoder::from_hex(&c.b);
            assert_eq!(enc, encoded);

            let mut dec = encoded.as_decoder();
            let v = dec.decode_varint().expect("should decode");
            assert_eq!(dec.remaining(), 0);
            assert_eq!(v, c.v);
        }
    }

    #[test]
    fn varint_decode_long_zero() {
        for c in &["4000", "80000000", "c000000000000000"] {
            let encoded = Encoder::from_hex(c);
            let mut dec = encoded.as_decoder();
            let v = dec.decode_varint().expect("should decode");
            assert_eq!(dec.remaining(), 0);
            assert_eq!(v, 0);
        }
    }

    #[test]
    fn varint_decode_short() {
        for c in &["40", "800000", "c0000000000000"] {
            let encoded = Encoder::from_hex(c);
            let mut dec = encoded.as_decoder();
            assert!(dec.decode_varint().is_none());
        }
    }

    #[test]
    fn encode_vec() {
        let mut enc = Encoder::default();
        enc.encode_vec(2, &[1, 2, 0x34]);
        assert_eq!(enc, Encoder::from_hex("0003010234"));
    }

    #[test]
    fn encode_vec_with() {
        let mut enc = Encoder::default();
        enc.encode_vec_with(2, |enc_inner| {
            enc_inner.encode(Encoder::from_hex("02").as_ref());
        });
        assert_eq!(enc, Encoder::from_hex("000102"));
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn encode_vec_with_overflow() {
        let mut enc = Encoder::default();
        enc.encode_vec_with(1, |enc_inner| {
            enc_inner.encode(&[0xb0; 256]);
        });
    }

    #[test]
    fn encode_vvec() {
        let mut enc = Encoder::default();
        enc.encode_vvec(&[1, 2, 0x34]);
        assert_eq!(enc, Encoder::from_hex("03010234"));
    }

    #[test]
    fn encode_vvec_with() {
        let mut enc = Encoder::default();
        enc.encode_vvec_with(|enc_inner| {
            enc_inner.encode(Encoder::from_hex("02").as_ref());
        });
        assert_eq!(enc, Encoder::from_hex("0102"));
    }

    #[test]
    fn encode_vvec_with_longer() {
        let mut enc = Encoder::default();
        enc.encode_vvec_with(|enc_inner| {
            enc_inner.encode(&[0xa5; 65]);
        });
        let v: Vec<u8> = enc.into();
        assert_eq!(&v[..3], &[0x40, 0x41, 0xa5]);
    }

    // Test that Deref to &[u8] works for Encoder.
    #[test]
    fn encode_builder() {
        let mut enc = Encoder::from_hex("ff");
        let enc2 = Encoder::from_hex("010234");
        enc.encode(enc2.as_ref());
        assert_eq!(enc, Encoder::from_hex("ff010234"));
    }

    // Test that Deref to &[u8] works for Decoder.
    #[test]
    fn encode_view() {
        let mut enc = Encoder::from_hex("ff");
        let enc2 = Encoder::from_hex("010234");
        let v = enc2.as_decoder();
        enc.encode(v.as_ref());
        assert_eq!(enc, Encoder::from_hex("ff010234"));
    }

    #[test]
    fn encode_mutate() {
        let mut enc = Encoder::from_hex("010234");
        enc.as_mut()[0] = 0xff;
        assert_eq!(enc, Encoder::from_hex("ff0234"));
    }

    #[test]
    fn pad() {
        let mut enc = Encoder::from_hex("010234");
        enc.pad_to(5, 0);
        assert_eq!(enc, Encoder::from_hex("0102340000"));
        enc.pad_to(4, 0);
        assert_eq!(enc, Encoder::from_hex("0102340000"));
        enc.pad_to(7, 0xc2);
        assert_eq!(enc, Encoder::from_hex("0102340000c2c2"));
    }

    #[test]
    fn buffer_write_zeroes() {
        fn check_write_zeroes<B: Buffer>(mut buf: B) {
            const NUM_BYTES: usize = 5;

            assert!(buf.is_empty());

            buf.pad_to(NUM_BYTES, 0);

            assert_eq!(buf.position(), NUM_BYTES);
            let written = &buf.as_slice()[..NUM_BYTES];
            assert!(written.iter().all(|&b| b == 0));
        }

        check_write_zeroes(Vec::<u8>::new());

        let mut buf = Vec::<u8>::new();
        check_write_zeroes(&mut buf);

        let mut buf = [0; 16];
        check_write_zeroes(Cursor::new(&mut buf[..]));
    }

    #[test]
    fn buffer_rotate_right() {
        fn check_rotate_right<B: Buffer>(mut buf: B) {
            const DATA: [u8; 5] = [1, 2, 3, 4, 5];
            const EXPECTED: [u8; 5] = [1, 4, 5, 2, 3];
            const START: usize = 1;
            const COUNT: usize = 2;

            buf.write_all(&DATA).expect("Buffer has enough capacity.");

            buf.rotate_right(START, COUNT);

            assert_eq!(&buf.as_slice()[..EXPECTED.len()], EXPECTED);
        }

        check_rotate_right(Vec::<u8>::new());

        let mut buf = Vec::<u8>::new();
        check_rotate_right(&mut buf);

        let mut buf = [0; 16];
        check_rotate_right(Cursor::new(&mut buf[..]));
    }

    #[test]
    fn encoder_as_mut() {
        fn check_as_mut<B: Buffer>(mut enc: Encoder<B>) {
            enc.encode_byte(41);
            enc.as_mut()[0] = 42;
            assert_eq!(enc.as_ref(), &[42]);
        }

        check_as_mut(Encoder::default());

        let mut buf = Vec::<u8>::new();
        check_as_mut(Encoder::new_borrowed_vec(&mut buf));

        let mut buf = [0; 16];
        check_as_mut(Encoder::new_borrowed_slice(&mut buf[..]));
    }

    /// When reusing one [`Buffer`] across [`Encoder`]s, [`Buffer::position`]
    /// can be larger than [`Encoder::len`].
    #[test]
    fn buffer_vs_encoder_len() {
        let mut non_empty_vec = vec![1, 2, 3, 4];
        assert_eq!(non_empty_vec.len(), Buffer::position(&non_empty_vec));

        let mut enc = Encoder::new_borrowed_vec(&mut non_empty_vec);
        assert!(enc.is_empty());
        enc.encode_byte(5);
        assert_eq!(enc.len(), 1);

        assert_eq!(non_empty_vec.len(), 5);
        assert_eq!(non_empty_vec.len(), Buffer::position(&non_empty_vec));
    }

    /// [`Buffer::position`] returns the number of bytes written to and not the
    /// length of the underyling buffer.
    ///
    /// When using [`Vec<u8>`] length and position are equal. When using
    /// [`Cursor<&mut [u8]>`] they are not.
    #[test]
    fn buffer_position() {
        let mut a = [0; 16];
        let buf = Cursor::new(&mut a[..]);
        assert_eq!(Buffer::position(&buf), 0);
    }
}
