// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Debug)]
pub struct Chunk<'a> {
    data: &'a [u8],
    offset: u64,
}

impl Chunk<'_> {
    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.data
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn split_at(&self, at: usize) -> (Self, Self) {
        let (left, right) = self.data.split_at(at);
        (
            Chunk {
                data: left,
                offset: self.offset,
            },
            Chunk {
                data: right,
                offset: self.offset + at as u64,
            },
        )
    }

    pub const fn limit_to(&mut self, limit: usize) {
        let (left, _) = self.data.split_at(limit);
        self.data = left;
    }
}

impl<'a> From<Chunk<'a>> for (u64, usize) {
    fn from(val: Chunk<'a>) -> Self {
        (val.offset, val.data.len())
    }
}

impl<'a> From<(u64, &'a [u8])> for Chunk<'a> {
    fn from(value: (u64, &'a [u8])) -> Self {
        Chunk {
            data: value.1,
            offset: value.0,
        }
    }
}

#[derive(Debug)]
pub struct ChunkRange {
    offset: u64,
    len: usize,
}

impl ChunkRange {
    #[must_use]
    pub const fn new(offset: u64, len: usize) -> Self {
        Self { offset, len }
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
}

impl From<&Chunk<'_>> for ChunkRange {
    fn from(chunk: &Chunk<'_>) -> Self {
        Self {
            offset: chunk.offset,
            len: chunk.len(),
        }
    }
}

impl From<ChunkRange> for (u64, usize) {
    fn from(val: ChunkRange) -> Self {
        (val.offset, val.len)
    }
}
