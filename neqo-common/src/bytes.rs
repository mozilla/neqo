// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes {
    data: Vec<u8>,
    offset: usize,
}

impl Bytes {
    #[must_use]
    pub const fn new(data: Vec<u8>, offset: usize) -> Self {
        Self { data, offset }
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data[self.offset..]
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(payload: Bytes) -> Self {
        payload.data().to_vec()
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Bytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.data() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Bytes {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.data() == other.as_slice()
    }
}

impl PartialEq<[u8]> for Bytes {
    fn eq(&self, other: &[u8]) -> bool {
        self.data() == other
    }
}
