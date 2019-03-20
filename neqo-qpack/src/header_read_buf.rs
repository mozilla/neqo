use crate::{Error, Res};
use neqo_transport::Recvable;

pub struct HeaderReadBuf {
    buf: Vec<u8>,
    write_offset: usize,
    read_offset: usize,
    bits_read: u8,
}

impl HeaderReadBuf {
    pub fn new(len: usize) -> HeaderReadBuf {
        HeaderReadBuf {
            buf: vec![0; len],
            write_offset: 0,
            read_offset: 0,
            bits_read: 0,
        }
    }

    pub fn write(&mut self, s: &mut Recvable) -> Res<(u64, bool)> {
        let (rv, fin) = s.read(&mut self.buf[self.write_offset..])?;
        self.write_offset += rv as usize;
        Ok((rv, fin))
    }

    pub fn done(&self) -> bool {
        self.write_offset == self.buf.len()
    }

    pub fn remaining(&self) -> u64 {
        (self.buf.len() - self.read_offset) as u64
    }

    // This checks only up to 8 bits!
    fn check_remaining_read_bits(&mut self, needs: u8) -> u8 {
        if self.read_offset >= self.buf.len() {
            0
        } else if self.read_offset + 1 == self.buf.len() && (8 - self.bits_read) < needs {
            8 - self.bits_read
        } else {
            needs
        }
    }

    pub fn read_bytes(&mut self, v: &mut Vec<u8>, len: u64) -> Res<()> {
        if len > self.remaining() {
            return Err(Error::DecompressionFailed);
        }
        v.extend_from_slice(&self.buf[self.read_offset..self.read_offset + (len as usize)]);
        self.read_offset += len as usize;
        Ok(())
    }

    // Here we can read only up to 8 bits!
    // this returns read bit and amount of bits read.
    pub fn read_bits(&mut self, needs: u8) -> (u8, u8) {
        assert!(self.done());
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
            let c = self.buf[self.read_offset];
            self.read_offset += 1;
            (c, bits)
        } else if bits <= (8 - self.bits_read) {
            // we need to read only the current byte(buf[offset])
            let c = (self.buf[self.read_offset] >> (8 - self.bits_read - bits)) & ((1 << bits) - 1);
            self.bits_read += bits;
            if self.bits_read == 8 {
                self.read_offset += 1;
                self.bits_read = 0;
            }
            (c, bits)
        } else {
            let mut c = self.buf[self.read_offset] & ((1 << (8 - self.bits_read)) - 1);
            c = c << (bits - (8 - self.bits_read));
            self.read_offset += 1;
            self.bits_read = bits - (8 - self.bits_read);
            c = c | (self.buf[self.read_offset] >> (8 - self.bits_read));
            (c, bits)
        }
    }

    // This is the same as read_bits just it returns error if there sre not 'needs' bits available.
    pub fn read_bits2(&mut self, needs: u8) -> Res<u8> {
        if self.check_remaining_read_bits(needs) != needs {
            Err(Error::DecompressionFailed)
        } else {
            let (v, r) = self.read_bits(needs);
            assert_eq!(r, needs);
            Ok(v)
        }
    }

    pub fn from(v: &[u8]) -> HeaderReadBuf {
        HeaderReadBuf {
            buf: Vec::from(v),
            write_offset: v.len(),
            read_offset: 0,
            bits_read: 0,
        }
    }
}

impl ReadByte for HeaderReadBuf {
    fn read_byte(&mut self) -> Res<u8> {
        assert!(self.done());
        if self.read_offset == self.buf.len() {
            return Err(Error::DecompressionFailed);
        }
        let b = self.buf[self.read_offset];
        self.read_offset += 1;
        Ok(b)
    }
}

pub trait ReadByte {
    fn read_byte(&mut self) -> Res<u8>;
}

struct ReceiverHelper<'a> {
    receiver: &'a mut Recvable,
}

impl<'a> ReadByte for ReceiverHelper<'a> {
    fn read_byte(&mut self) -> Res<u8> {
        let mut b = [0];
        let (amount, fin) = self.receiver.read(&mut b)?;
        if fin {
            return Err(Error::ClosedCriticalStream);
        }
        if amount != 1 {
            return Err(Error::NoMoreData);
        }
        Ok(b[0])
    }
}

pub fn read_prefixed_encoded_int_with_recvable(
    s: &mut Recvable,
    val: &mut u64,
    cnt: &mut u8,
    prefix_len: u8,
    first_byte: u8,
    have_first_byte: bool,
) -> Res<bool> {
    let mut recv = ReceiverHelper { receiver: s };
    match read_prefixed_encoded_int(&mut recv, val, cnt, prefix_len, first_byte, have_first_byte) {
        Ok(()) => Ok(true),
        Err(Error::NoMoreData) => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn read_prefixed_encoded_int_header_read_buf(
    s: &mut HeaderReadBuf,
    prefix_len: u8,
) -> Res<u64> {
    assert!(prefix_len < 8);
    let mut val: u64 = 0;
    let mut cnt: u8 = 0;
    let b = s.read_bits2(8 - prefix_len)?;
    match read_prefixed_encoded_int(s, &mut val, &mut cnt, prefix_len, b, true) {
        Err(_) => Err(Error::DecompressionFailed),
        Ok(()) => Ok(val),
    }
}

pub fn read_prefixed_encoded_int(
    s: &mut ReadByte,
    val: &mut u64,
    cnt: &mut u8,
    prefix_len: u8,
    first_byte: u8,
    have_first_byte: bool,
) -> Res<()> {
    if have_first_byte {
        let mask = if prefix_len == 0 {
            0xff
        } else {
            (1 << (8 - prefix_len)) - 1
        };
        *val = (first_byte & mask) as u64;

        if *val < mask as u64 {
            return Ok(());
        }
    }
    let mut b: u8;
    loop {
        b = s.read_byte()?;

        if (*cnt == 63) && (b > 1 || (b == 1 && ((*val >> 63) == 1))) {
            break Err(Error::IntegerOverflow);
        }
        *val += ((b & 0x7f) as u64) << *cnt;
        if (b & 0x80) == 0 {
            break Ok(());
        }
        *cnt += 7;
        if *cnt >= 64 {
            break Ok(());
        }
    }
}
