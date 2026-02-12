// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Bytes, Encoder, qdebug};

use super::{hframe::HFrameType, reader::FrameDecoder};
use crate::Res;

pub const CAPSULE_TYPE_DATAGRAM: HFrameType = HFrameType(0x00);

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Capsule {
    Datagram { payload: Bytes },
}

impl Capsule {
    pub const fn capsule_type(&self) -> u64 {
        match self {
            Self::Datagram { .. } => CAPSULE_TYPE_DATAGRAM.0,
        }
    }

    pub fn encode(&self, enc: &mut Encoder) {
        enc.encode_varint(self.capsule_type());
        match self {
            Self::Datagram { payload } => {
                enc.encode_vvec(payload.as_ref());
            }
        }
    }
}

impl FrameDecoder<Self> for Capsule {
    fn decode(frame_type: HFrameType, _frame_len: u64, data: Option<&[u8]>) -> Res<Option<Self>> {
        if frame_type == CAPSULE_TYPE_DATAGRAM
            && let Some(payload) = data
        {
            qdebug!("Decoded Datagram Capsule len={}", payload.len());
            return Ok(Some(Self::Datagram {
                payload: Bytes::from(payload.to_vec()),
            }));
        }
        Ok(None)
    }

    fn is_known_type(frame_type: HFrameType) -> bool {
        frame_type == CAPSULE_TYPE_DATAGRAM
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn encode_datagram_capsule_empty_payload() {
        let capsule = Capsule::Datagram {
            payload: Bytes::from(Vec::new()),
        };
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);
        let encoded = enc.as_ref();

        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x00);
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

        assert_eq!(encoded.len(), 7);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x05);
        assert_eq!(&encoded[2..], &payload[..]);
    }

    #[test]
    fn decode_datagram_capsule_empty_payload() {
        let res = Capsule::decode(CAPSULE_TYPE_DATAGRAM, 0, Some(&[])).unwrap();
        assert_eq!(
            res,
            Some(Capsule::Datagram {
                payload: Bytes::from(Vec::new())
            })
        );
    }

    #[test]
    fn decode_datagram_capsule_with_payload() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let res = Capsule::decode(CAPSULE_TYPE_DATAGRAM, 5, Some(&payload)).unwrap();
        assert_eq!(
            res,
            Some(Capsule::Datagram {
                payload: Bytes::from(payload)
            })
        );
    }

    #[test]
    fn decode_unknown_capsule_type() {
        let res = Capsule::decode(HFrameType(0x17), 4, Some(&[0xaa, 0xbb, 0xcc, 0xdd])).unwrap();
        assert_eq!(res, None);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let original = Capsule::Datagram {
            payload: Bytes::from(payload),
        };

        let mut enc = Encoder::default();
        original.encode(&mut enc);
        let encoded = enc.as_ref();

        let mut decoder = neqo_common::Decoder::from(encoded);
        let type_int = decoder.decode_varint().unwrap();
        let len = decoder.decode_varint().unwrap();
        let data = decoder.decode(usize::try_from(len).unwrap()).unwrap();

        let result = Capsule::decode(HFrameType(type_int), len, Some(data))
            .unwrap()
            .unwrap();

        assert_eq!(original, result);
    }
}
