use super::varint::*;
use super::*;
use num_traits::Num;
use std::convert::Into;

#[derive(Default, Debug, PartialEq)]
pub struct Data {
    buf: Vec<u8>,
    offset: usize,
}

impl Data {
    pub fn encode_byte(&mut self, b: u8) {
        self.buf.push(b)
    }

    pub fn encode_data(&mut self, d: &Data) {
        self.buf.extend(&d.buf);
    }

    pub fn encode_vec(&mut self, d: &[u8]) {
        self.buf.extend(d);
    }

    pub fn encode_vec_and_len(&mut self, d: &[u8]) {
        self.encode_varint(d.len() as u64);
        self.buf.extend(d);
    }

    // Note: to encode a usize you will have to cast because
    // you can't From usize into u64 and vice versa.
    pub fn encode_uint<T: Into<u64>>(&mut self, v: T, l: usize) {
        let u: u64 = v.into();
        for i in 0..l {
            self.encode_byte((u >> ((l - 1) - i) * 8) as u8);
        }
    }

    pub fn encode_varint<T: Into<u64>>(&mut self, v: T) {
        encode_varint(self, v.into());
    }

    // You can't safely use this with arbitrary data, but I'm just using it
    // in tests for
    pub fn from_hex(s: &str) -> Data {
        let mut d = Data::default();

        if s.len() % 2 != 0 {
            panic!("Needs to be even length");
        }
        for i in 0..s.len() / 2 {
            let x = s.get(i * 2..i * 2 + 2);
            let v = <u8 as Num>::from_str_radix(x.unwrap(), 16).unwrap();
            d.encode_byte(v);
        }
        d
    }

    fn check_remaining(&self, needed: usize) -> Res<usize> {
        if (self.buf.len() - self.offset) < needed {
            return Err(Error::ErrNoMoreData);
        }
        Ok(needed)
    }

    pub fn decode_byte(&mut self) -> Res<u8> {
        let _ = self.check_remaining(1)?;

        let res = self.buf[self.offset];
        self.offset += 1;

        Ok(res)
    }

    pub fn peek_byte(&mut self) -> Res<u8> {
        let _ = self.check_remaining(1)?;

        let res = self.buf[self.offset];

        Ok(res)
    }

    pub fn decode_uint(&mut self, l: usize) -> Res<u64> {
        let mut res: u64 = 0;
        for _ in 0..l {
            res <<= 8;
            let z = self.decode_byte()?;
            res += z as u64;
        }

        Ok(res)
    }

    pub fn decode_data(&mut self, l: usize) -> Res<Vec<u8>> {
        let _ = self.check_remaining(l)?;

        let mut res = Vec::with_capacity(l);
        res.extend(&self.buf[self.offset..self.offset + l]);
        self.offset += l;

        Ok(res)
    }

    pub fn decode_data_and_len(&mut self) -> Res<Vec<u8>> {
        let l = self.decode_varint()?;
        self.decode_data(l as usize)
    }

    pub fn decode_remainder(&mut self) -> Res<Vec<u8>> {
        let l = self.buf.len() - self.offset;
        let mut res = Vec::with_capacity(l);
        res.extend(&self.buf[self.offset..]);
        self.offset += l;
        Ok(res)
    }

    pub fn decode_varint(&mut self) -> Res<u64> {
        decode_varint(self)
    }

    pub fn clear(&mut self) {
        self.buf.truncate(0);
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_byte() {
        let mut d = Data::default();

        d.encode_byte(1);
        assert!(d == Data::from_hex("01"));

        d.encode_byte(0xfe);
        assert!(d == Data::from_hex("01fe"));
    }

    #[test]
    fn test_encode_vec() {
        let mut d = Data::default();
        let v = vec![1, 2, 0x34];

        d.encode_vec(&v);
        assert_eq!(d, Data::from_hex("010234"));

        let d2 = Data::from_hex("5678");
        d.encode_data(&d2);
        assert_eq!(d, Data::from_hex("0102345678"))
    }

    #[test]
    fn test_decode_byte() {
        let mut d = Data::from_hex("0123");

        assert_eq!(d.decode_byte().unwrap(), 0x01);
        assert_eq!(d.decode_byte().unwrap(), 0x23);
        assert_eq!(d.decode_byte().unwrap_err(), Error::ErrNoMoreData);
    }

    #[test]
    fn test_decode_data() {
        let mut d = Data::from_hex("012345");
        assert_eq!(d.decode_data(2).unwrap(), vec![0x01, 0x23]);
        assert_eq!(d.decode_data(2).unwrap_err(), Error::ErrNoMoreData);
    }

    #[test]
    fn test_decode_remainder() {
        let mut d = Data::from_hex("012345");
        assert_eq!(d.decode_remainder().unwrap(), vec![0x01, 0x23, 0x45]);
        assert_eq!(d.decode_data(2).unwrap_err(), Error::ErrNoMoreData);
    }
}
