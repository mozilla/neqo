use super::data::*;
use super::*;

// Encode a QUIC-style variable length integer

pub fn encode_varint(d: &mut Data, v: u64) {
    if v < (1 << 6) {
        return d.encode_uint(v, 1);
    }
    if v < (1 << 14) {
        return d.encode_uint(v | (1 << 14), 2);
    }

    if v < (1 << 30) {
        return d.encode_uint(v | (2 << 30), 4);
    }

    if v < (1 << 62) {
        return d.encode_uint(v | (3 << 62), 8);
    }

    panic!("Varint value too large")
}

pub fn get_varint_len(v: u64) -> u64 {
    if v < (1 << 6) {
        return 1;
    }
    if v < (1 << 14) {
        return 2;
    }

    if v < (1 << 30) {
        return 4;
    }

    if v < (1 << 62) {
        return 8;
    }

    panic!("Varint value too large")
}

fn decode_uint(d: &mut Data, l: usize) -> Res<u64> {
    let mut res: u64 = 0;
    let mut mask = 0x3f;
    for _ in 0..l {
        res <<= 8;
        let z = d.decode_byte()? & mask;
        mask = 0xff;
        res += z as u64;
    }

    Ok(res)
}

pub fn decode_varint(d: &mut Data) -> Res<u64> {
    let l = match (d.peek_byte()? & 0xc0) >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => panic!("Can't happen"),
    };
    decode_uint(d, l)
}

pub fn decode_varint_size(d: &mut Data) -> Res<usize> {
    let l = match (d.peek_byte()? & 0xc0) >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => panic!("Can't happen"),
    };
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        v: u64,
        b: String,
    }

    #[test]
    fn test_varint() {
        let cases = vec![
            TestCase {
                v: 0,
                b: String::from("00"),
            },
            TestCase {
                v: 1,
                b: String::from("01"),
            },
            TestCase {
                v: 63,
                b: String::from("3f"),
            },
            TestCase {
                v: 64,
                b: String::from("4040"),
            },
            TestCase {
                v: 16383,
                b: String::from("7fff"),
            },
            TestCase {
                v: 16384,
                b: String::from("80004000"),
            },
            TestCase {
                v: (1 << 30) - 1,
                b: String::from("bfffffff"),
            },
            TestCase {
                v: 1 << 30,
                b: String::from("c000000040000000"),
            },
            TestCase {
                v: (1 << 62) - 1,
                b: String::from("ffffffffffffffff"),
            },
        ];

        for c in cases {
            let mut d = Data::default();

            encode_varint(&mut d, c.v);
            assert_eq!(Data::from_hex(&c.b), d);

            assert_eq!(c.v, decode_varint(&mut d).unwrap());
        }
    }
}
