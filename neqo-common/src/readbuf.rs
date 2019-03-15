use crate::data::DataBuf;
use crate::varint::*;
use crate::{Error, Res};

#[derive(Copy, Clone, PartialEq, Debug)]
enum ReadBufState {
    Uninit,
    CollectingVarint,
    CollectingLen,
    Done,
}

pub trait Reader {
    fn read(&mut self, buf: &mut [u8]) -> Res<(usize, bool)>;
}

pub struct ReadBuf {
    state: ReadBufState,
    buf: Vec<u8>,
    offset: usize,
    bits_read: u8, // use for bit reading. It is number of bits read in buf[offset] byte.
    len: usize,
}

impl DataBuf<Error> for ReadBuf {
    fn peek_byte(&mut self) -> Res<u8> {
        self.check_remaining(1)?;

        Ok(self.buf[self.offset])
    }

    fn decode_byte(&mut self) -> Res<u8> {
        self.check_remaining(1)?;

        let res = self.buf[self.offset];
        self.offset += 1;

        Ok(res)
    }
}

impl ReadBuf {
    pub fn new() -> ReadBuf {
        ReadBuf {
            state: ReadBufState::Uninit,
            buf: vec![0; 2], //TODO set this to a better value. I set it to 2 for better testing.
            offset: 0,       // this offset is first used for writing then for reading.
            bits_read: 0,
            len: 0,
        }
    }

    // Use for tests
    pub fn from(v: &[u8]) -> ReadBuf {
        let len = v.len();
        ReadBuf {
            state: ReadBufState::Done,
            buf: Vec::from(v),
            offset: 0,
            bits_read: 0,
            len: len,
        }
    }

    pub fn done(&self) -> bool {
        self.state == ReadBufState::Done
    }

    pub fn len(&self) -> usize {
        self.len
    }

    // We need to propagate fin as well.
    // returns number of read byte and bool (stream has been closed or not)
    pub fn get_varint<T: Reader>(&mut self, reader: &mut T) -> Res<(u64, bool)> {
        if self.state == ReadBufState::Uninit {
            self.state = ReadBufState::CollectingVarint;
            self.offset = 0;
            self.len = 1; // this will get updated when we get varint length.
        }

        assert!(self.len - self.offset > 0);

        let (rv, fin) = self.read(reader)?;
        if rv == 0 {
            return Ok((rv, fin));
        }

        if self.len == 1 && self.offset == 1 {
            // we have the first byte, get the varint length.
            self.len = decode_varint_size_from_byte(self.buf[0]);
        }

        if self.len == self.offset {
            self.state = ReadBufState::Done;
            self.offset = 0;
            self.bits_read = 0;
        }

        return Ok((rv, fin));
    }

    pub fn get_len(&mut self, len: u64) {
        if self.state == ReadBufState::Uninit {
            self.state = ReadBufState::CollectingLen;
            self.offset = 0;
            self.len = len as usize;
        }
    }

    // We need to propagate fin as well.
    // returns number of read byte and bool (stream has been closed or not)
    pub fn get<T: Reader>(&mut self, reader: &mut T) -> Res<(u64, bool)> {
        let r = self.read(reader)?;
        if self.len == self.offset {
            self.state = ReadBufState::Done;
            self.offset = 0;
            self.bits_read = 0;
        }
        Ok(r)
    }

    fn read<T: Reader>(&mut self, reader: &mut T) -> Res<(u64, bool)> {
        assert!(
            self.state == ReadBufState::CollectingVarint
                || self.state == ReadBufState::CollectingLen
        );
        assert!(self.len - self.offset > 0);

        if self.len > self.buf.len() {
            let ext = self.len - self.buf.len();
            self.buf.append(&mut vec![0; ext]);
        }

        let (rv, fin) = reader.read(&mut self.buf[self.offset..self.len])?;

        self.offset += rv;
        Ok((rv as u64, fin))
    }

    fn check_remaining(&mut self, needs: usize) -> Res<()> {
        if self.len < self.offset + needs || self.buf.len() < self.offset + needs {
            return Err(Error::NoMoreData);
        }
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        (self.len - self.offset) as u64
    }

    pub fn reset(&mut self) {
        self.offset = 0;
        self.len = 0;
        self.state = ReadBufState::Uninit;
    }

    // This checks only up to 8 bits!
    fn check_remaining_read_bits(&mut self, needs: u8) -> u8 {
        assert!(self.len <= self.buf.len());
        if self.offset >= self.len {
            0
        } else if self.offset + 1 == self.len && (8 - self.bits_read) < needs {
            8 - self.bits_read
        } else {
            needs
        }
    }

    // Here we can read only up to 8 bits!
    // this returns read bit and amount of bits read.
    pub fn read_bits(&mut self, needs: u8) -> (u8, u8) {
        if needs > 8 {
            panic!("Here, we can read only up to 8 bits");
        }
        // check how much we have.
        let bits = self.check_remaining_read_bits(needs);
        if bits == 0 {
            return (0, 0);
        }

        if bits == 8 && self.bits_read == 0 {
            // it is allined with a buffered byte.
            let c = self.buf[self.offset];
            self.offset += 1;
            (c, bits)
        } else if bits <= (8 - self.bits_read) {
            // we need to read only the current byte(buf[offset])
            let c = (self.buf[self.offset] >> (8 - self.bits_read - bits)) & ((1 << bits) - 1);
            self.bits_read += bits;
            if self.bits_read == 8 {
                self.offset += 1;
                self.bits_read = 0;
            }
            (c, bits)
        } else {
            let mut c = self.buf[self.offset] & ((1 << (8 - self.bits_read)) - 1);
            c = c << (bits - (8 - self.bits_read));
            self.offset += 1;
            self.bits_read = bits - (8 - self.bits_read);
            c = c | (self.buf[self.offset] >> (8 - self.bits_read));
            (c, bits)
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO(mt): Add some tests for this.
}
