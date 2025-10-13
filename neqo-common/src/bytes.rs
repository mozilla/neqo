// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Owned contiguous byte array with an optional offset.
///
/// Inspired by `bytes` crate's `Bytes`.
#[derive(Debug, Clone)]
pub struct Bytes {
    data: Vec<u8>,
    offset: usize,
}

impl Bytes {
    /// Create a new `Bytes` with the given data and offset.
    ///
    /// # Panics
    ///
    /// Panics if `offset > data.len()`.
    #[must_use]
    pub fn new(data: Vec<u8>, offset: usize) -> Self {
        assert!(
            offset <= data.len(),
            "offset {offset} is out of bounds for data of length {}",
            data.len()
        );
        Self { data, offset }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len() - self.offset
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Skips the first `n` bytes, consuming and returning `self`.
    ///
    /// # Panics
    ///
    /// Panics if `n > self.len()`.
    #[must_use]
    pub fn skip(mut self, n: usize) -> Self {
        assert!(
            n <= self.len(),
            "cannot skip {n} bytes when only {} bytes remain",
            self.len()
        );
        self.offset += n;
        self
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.data[self.offset..]
    }
}

impl AsMut<[u8]> for Bytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.offset..]
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Bytes {}

impl From<Vec<u8>> for Bytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data, 0)
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Bytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_ref() == other.as_slice()
    }
}

impl PartialEq<[u8]> for Bytes {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_ref() == other
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::Bytes;

    #[test]
    #[should_panic(expected = "offset 4 is out of bounds for data of length 3")]
    fn illegal_offset() {
        _ = Bytes::new(vec![1, 2, 3], 4);
    }

    #[test]
    fn len() {
        let b = Bytes::new(vec![1, 2, 3, 4], 1);
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn is_empty() {
        let b = Bytes::new(vec![1, 2, 3, 4], 4);
        assert!(b.is_empty());
    }

    #[test]
    fn skip() {
        let b = Bytes::new(vec![1, 2, 3, 4], 1).skip(2);
        assert_eq!(b.as_ref(), &[4]);
    }

    #[test]
    #[should_panic(expected = "cannot skip 4 bytes when only 3 bytes remain")]
    fn illegal_skip() {
        _ = Bytes::new(vec![1, 2, 3, 4], 1).skip(4);
    }

    #[test]
    fn is_equal() {
        let a = Bytes::new(vec![1, 2, 3, 4], 1);
        let b = Bytes::from(vec![2, 3, 4]);
        assert_eq!(a, b);
    }
}
