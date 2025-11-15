// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(test)]
use neqo_common::Encoder;
use neqo_common::{Bytes, Decoder};

use crate::Res;

pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Capsule {
    Datagram { payload: Bytes },
}

impl Capsule {
    #[cfg(test)]
    #[must_use]
    pub const fn capsule_type(&self) -> u64 {
        match self {
            Self::Datagram { .. } => CAPSULE_TYPE_DATAGRAM,
        }
    }

    #[cfg(test)]
    pub fn encode(&self, enc: &mut Encoder) {
        enc.encode_varint(self.capsule_type());
        match self {
            Self::Datagram { payload } => {
                enc.encode_vvec(payload.as_ref());
            }
        }
    }

    pub fn decode(decoder: &mut Decoder) -> Res<Option<Self>> {
        let Some(capsule_type) = decoder.decode_varint() else {
            return Ok(None);
        };

        let Some(capsule_length) = decoder.decode_varint() else {
            return Ok(None);
        };

        let capsule_length_usize =
            usize::try_from(capsule_length).map_err(|_| crate::Error::HttpFrame)?;

        if decoder.remaining() < capsule_length_usize {
            return Ok(None);
        }

        if capsule_type == CAPSULE_TYPE_DATAGRAM {
            let payload = decoder
                .decode(capsule_length_usize)
                .ok_or(crate::Error::HttpFrame)?
                .to_vec();
            Ok(Some(Self::Datagram {
                payload: Bytes::from(payload),
            }))
        } else {
            decoder.skip(capsule_length_usize);
            Ok(None)
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neqo_common::Encoder;

    use super::*;

    #[test]
    fn encode_datagram_capsule_empty_payload() {
        let capsule = Capsule::Datagram {
            payload: Bytes::from(Vec::new()),
        };
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);
        let encoded = enc.as_ref();

        assert!(encoded.len() > 1);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x00);
        assert_eq!(encoded.len(), 2);
    }

    #[test]
    fn encode_datagram_capsule_with_payload() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let capsule = Capsule::Datagram {
            payload: Bytes::from(payload.clone()),
        };
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);
        let encoded = enc.as_ref();

        assert!(encoded.len() > 1);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x05);
        assert_eq!(&encoded[2..], &payload[..]);
        assert_eq!(encoded.len(), 7);
    }

    #[test]
    fn decode_datagram_capsule_empty_payload() {
        let data = [0x00, 0x00];
        let mut decoder = Decoder::from(&data[..]);
        let capsule = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(
            capsule,
            Some(Capsule::Datagram {
                payload: Bytes::from(Vec::new())
            })
        );
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn decode_datagram_capsule_with_payload() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut data = vec![0x00, 0x05];
        data.extend_from_slice(&payload);

        let mut decoder = Decoder::from(&data[..]);
        let capsule = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(
            capsule,
            Some(Capsule::Datagram {
                payload: Bytes::from(payload)
            })
        );
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn decode_unknown_capsule_type() {
        let data = [0x17, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];
        let mut decoder = Decoder::from(&data[..]);
        let capsule = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(capsule, None);
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn decode_incomplete_capsule_type() {
        let data = [];
        let mut decoder = Decoder::from(&data[..]);
        let capsule = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(capsule, None);
    }

    #[test]
    fn decode_incomplete_capsule_length() {
        let data = [0x00];
        let mut decoder = Decoder::from(&data[..]);
        let capsule = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(capsule, None);
    }

    #[test]
    fn decode_incomplete_capsule_payload() {
        let data = [0x00, 0x05, 0x01, 0x02];
        let mut decoder = Decoder::from(&data[..]);
        let capsule = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(capsule, None);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let original = Capsule::Datagram {
            payload: Bytes::from(payload.clone()),
        };

        let mut enc = Encoder::default();
        original.encode(&mut enc);

        let mut dec = Decoder::from(enc.as_ref());
        let result = Capsule::decode(&mut dec).unwrap().unwrap();

        assert_eq!(original, result);
        assert_eq!(dec.remaining(), 0);
    }

    #[test]
    fn decode_large_payload_length_encoding() {
        let payload = vec![0x42; 300];
        let capsule = Capsule::Datagram {
            payload: Bytes::from(payload.clone()),
        };
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);

        let mut decoder = Decoder::from(enc.as_ref());
        let result = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(
            result,
            Some(Capsule::Datagram {
                payload: Bytes::from(payload)
            })
        );
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn decode_capsule_length_exceeds_buffer() {
        let data = [
            0x00, // capsule type = DATAGRAM
            0x41, 0x00, // length = 64 (2-byte varint)
            0x42, 0x43, // only 2 bytes of data
        ];
        let mut decoder = Decoder::from(&data[..]);
        let result = Capsule::decode(&mut decoder).unwrap();

        assert_eq!(result, None);
    }
}
