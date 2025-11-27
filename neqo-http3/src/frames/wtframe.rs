// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Decoder, Encoder};

use super::hframe::HFrameType;
use crate::{frames::reader::FrameDecoder, Error, Res};

pub type WebTransportFrameType = u64;

#[derive(PartialEq, Eq, Debug)]
pub enum WebTransportFrame {
    CloseSession { error: u32, message: String },
}

impl WebTransportFrame {
    /// The frame type for WebTransport `CLOSE_SESSION`, as defined in
    /// [WebTransport over HTTP/3 (RFC 9297, Section 4.6)](https://datatracker.ietf.org/doc/html/rfc9297#section-4.6).
    /// The value 0x2843 is assigned for `CLOSE_SESSION`.
    const CLOSE_SESSION: WebTransportFrameType = 0x2843;

    /// The maximum allowed message size for `CLOSE_SESSION` messages, as recommended
    /// in [WebTransport over HTTP/3 (RFC 9297, Section 4.6)](https://datatracker.ietf.org/doc/html/rfc9297#section-4.6).
    /// The value 1024 is used to limit the message size for security and interoperability.
    const CLOSE_MAX_MESSAGE_SIZE: u64 = 1024;

    pub fn encode(&self, enc: &mut Encoder) {
        #[cfg(feature = "build-fuzzing-corpus")]
        let start = enc.len();

        enc.encode_varint(Self::CLOSE_SESSION);
        let Self::CloseSession { error, message } = &self;
        enc.encode_varint(4 + message.len() as u64);
        enc.encode_uint(4, *error);
        enc.encode(message.as_bytes());

        #[cfg(feature = "build-fuzzing-corpus")]
        neqo_common::write_item_to_fuzzing_corpus("wtframe", &enc.as_ref()[start..]);
    }

    #[cfg(feature = "build-fuzzing-corpus")]
    /// Write `WebTransportFrame` data to fuzzing corpus.
    fn write_to_fuzzing_corpus(frame_type: HFrameType, frame_len: u64, data: &[u8]) {
        let mut encoder = Encoder::default();
        encoder.encode_varint(frame_type.0);
        encoder.encode_varint(frame_len);
        encoder.encode(data);
        neqo_common::write_item_to_fuzzing_corpus("wtframe", encoder.as_ref());
    }
}

impl FrameDecoder<Self> for WebTransportFrame {
    fn decode(frame_type: HFrameType, frame_len: u64, data: Option<&[u8]>) -> Res<Option<Self>> {
        if let Some(payload) = data {
            #[cfg(feature = "build-fuzzing-corpus")]
            Self::write_to_fuzzing_corpus(frame_type, frame_len, payload);

            let mut dec = Decoder::from(payload);
            if frame_type == HFrameType(Self::CLOSE_SESSION) {
                if frame_len > Self::CLOSE_MAX_MESSAGE_SIZE + 4 {
                    return Err(Error::HttpMessage);
                }
                let error = dec.decode_uint().ok_or(Error::HttpMessage)?;
                let Ok(message) = String::from_utf8(dec.decode_remainder().to_vec()) else {
                    return Err(Error::HttpMessage);
                };
                Ok(Some(Self::CloseSession { error, message }))
            } else {
                Ok(None)
            }
        } else {
            #[cfg(feature = "build-fuzzing-corpus")]
            Self::write_to_fuzzing_corpus(frame_type, frame_len, &[]);

            Ok(None)
        }
    }

    fn is_known_type(frame_type: HFrameType) -> bool {
        frame_type == HFrameType(Self::CLOSE_SESSION)
    }
}
