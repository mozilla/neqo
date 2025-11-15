// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Bytes, Decoder};

use super::{capsule::Capsule, hframe::HFrameType};
use crate::{frames::reader::FrameDecoder, Res};

pub const CAPSULE_TYPE_DATAGRAM: HFrameType = HFrameType(0x00);

#[derive(PartialEq, Eq, Debug)]
pub enum Frame {
    Datagram { payload: Bytes },
}

impl FrameDecoder<Self> for Frame {
    fn decode(frame_type: HFrameType, _frame_len: u64, data: Option<&[u8]>) -> Res<Option<Self>> {
        if frame_type == CAPSULE_TYPE_DATAGRAM {
            if let Some(payload) = data {
                let mut decoder = Decoder::from(payload);
                if let Some(capsule) = Capsule::decode(&mut decoder)? {
                    match capsule {
                        Capsule::Datagram { payload } => {
                            return Ok(Some(Self::Datagram { payload }));
                        }
                    }
                }
            }
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
    use neqo_common::Encoder;

    use super::*;
    use crate::frames::{capsule::Capsule, reader::FrameDecoder};

    #[test]
    fn datagram_frame_empty_payload() {
        let capsule = Capsule::Datagram {
            payload: Bytes::from(Vec::new()),
        };
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);
        let data = enc.as_ref().to_vec();

        let frame_len = data.len() as u64;
        let result =
            <Frame as FrameDecoder<Frame>>::decode(CAPSULE_TYPE_DATAGRAM, frame_len, Some(&data));
        let frame = result.unwrap().unwrap();

        assert_eq!(
            frame,
            Frame::Datagram {
                payload: Bytes::from(Vec::new())
            }
        );
    }

    #[test]
    fn datagram_frame_with_payload() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let capsule = Capsule::Datagram {
            payload: Bytes::from(payload.clone()),
        };
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);
        let data = enc.as_ref().to_vec();

        let frame_len = data.len() as u64;
        let result =
            <Frame as FrameDecoder<Frame>>::decode(CAPSULE_TYPE_DATAGRAM, frame_len, Some(&data));
        let frame = result.unwrap().unwrap();

        assert_eq!(
            frame,
            Frame::Datagram {
                payload: Bytes::from(payload)
            }
        );
    }

    #[test]
    fn is_known_type() {
        assert!(<Frame as FrameDecoder<Frame>>::is_known_type(
            CAPSULE_TYPE_DATAGRAM
        ));
        assert!(!<Frame as FrameDecoder<Frame>>::is_known_type(HFrameType(
            0x01
        )));
    }

    #[test]
    fn decode_incomplete_capsule() {
        let data = vec![0x00];
        let frame_len = data.len() as u64;
        let result =
            <Frame as FrameDecoder<Frame>>::decode(CAPSULE_TYPE_DATAGRAM, frame_len, Some(&data));
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn decode_unknown_frame_type() {
        let data = vec![0x01, 0x02, 0x03];
        let frame_len = data.len() as u64;
        let result =
            <Frame as FrameDecoder<Frame>>::decode(HFrameType(0x99), frame_len, Some(&data));
        assert_eq!(result.unwrap(), None);
    }
}
