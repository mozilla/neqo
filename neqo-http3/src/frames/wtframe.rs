// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Decoder, Encoder};

use super::hframe::HFrameType;
use crate::{Error, Res, frames::reader::FrameDecoder};

pub type WebTransportFrameType = u64;

#[derive(PartialEq, Eq, Debug)]
pub enum WebTransportFrame {
    CloseSession { error: u32, message: String },
    DrainSession,
}

impl WebTransportFrame {
    /// The frame type for WebTransport `CLOSE_SESSION`, as defined in
    /// [WebTransport over HTTP/3 (draft-ietf-webtrans-http3-14, Section 4.6)](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.6).
    /// The value 0x2843 is assigned for `CLOSE_SESSION`.
    const CLOSE_SESSION: WebTransportFrameType = 0x2843;

    /// The frame type for WebTransport `WT_DRAIN_SESSION`, as defined in
    /// [WebTransport over HTTP/3 (draft-ietf-webtrans-http3-14, Section 4.7)](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.7).
    /// The value 0x78ae is assigned for `WT_DRAIN_SESSION`.
    const WT_DRAIN_SESSION: WebTransportFrameType = 0x78ae;

    /// The maximum allowed message size for `CLOSE_SESSION` messages, as recommended
    /// in [WebTransport over HTTP/3 (draft-ietf-webtrans-http3-14, Section 4.6)](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.6).
    /// The value 1024 is used to limit the message size for security and interoperability.
    const CLOSE_MAX_MESSAGE_SIZE: u64 = 1024;

    pub fn encode(&self, enc: &mut Encoder) {
        #[cfg(feature = "build-fuzzing-corpus")]
        let start = enc.len();

        match self {
            Self::CloseSession { error, message } => {
                enc.encode_varint(Self::CLOSE_SESSION);
                enc.encode_varint(4 + message.len() as u64);
                enc.encode_uint(4, *error);
                enc.encode(message.as_bytes());
            }
            Self::DrainSession => {
                enc.encode_varint(Self::WT_DRAIN_SESSION);
                enc.encode_varint(0u64);
            }
        }

        #[cfg(feature = "build-fuzzing-corpus")]
        neqo_common::write_item_to_fuzzing_corpus("wtframe", &enc.as_ref()[start..]);
    }
}

impl FrameDecoder<Self> for WebTransportFrame {
    #[cfg(feature = "build-fuzzing-corpus")]
    const FUZZING_CORPUS: Option<&'static str> = Some("wtframe");

    fn decode(frame_type: HFrameType, frame_len: u64, data: Option<&[u8]>) -> Res<Option<Self>> {
        if frame_type == HFrameType(Self::CLOSE_SESSION) {
            if let Some(payload) = data {
                let mut dec = Decoder::from(payload);
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
        } else if frame_type == HFrameType(Self::WT_DRAIN_SESSION) {
            if frame_len != 0 {
                return Err(Error::HttpMessage);
            }
            Ok(Some(Self::DrainSession))
        } else {
            Ok(None)
        }
    }

    fn is_known_type(frame_type: HFrameType) -> bool {
        frame_type == HFrameType(Self::CLOSE_SESSION)
            || frame_type == HFrameType(Self::WT_DRAIN_SESSION)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{HFrameType, WebTransportFrame};
    use crate::frames::reader::FrameDecoder as _;

    #[test]
    fn is_known_type_close_session() {
        assert!(WebTransportFrame::is_known_type(HFrameType(
            WebTransportFrame::CLOSE_SESSION
        )));
    }

    #[test]
    fn is_known_type_unknown() {
        assert!(!WebTransportFrame::is_known_type(HFrameType(0x1234)));
        assert!(!WebTransportFrame::is_known_type(HFrameType(0)));
    }

    #[test]
    fn decode_close_session_too_large() {
        // Message size exceeds CLOSE_MAX_MESSAGE_SIZE (1024) + 4 bytes for error code.
        let large_message = vec![0u8; 1025];
        let mut payload = vec![0, 0, 0, 0]; // 4-byte error code
        payload.extend(&large_message);
        let frame_len = payload.len() as u64;

        let result = WebTransportFrame::decode(
            HFrameType(WebTransportFrame::CLOSE_SESSION),
            frame_len,
            Some(&payload),
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_close_session_at_limit() {
        // Message size exactly at CLOSE_MAX_MESSAGE_SIZE (1024).
        let message = vec![b'a'; 1024];
        let mut payload = vec![0, 0, 0, 0]; // 4-byte error code
        payload.extend(&message);
        let frame_len = payload.len() as u64;

        let result = WebTransportFrame::decode(
            HFrameType(WebTransportFrame::CLOSE_SESSION),
            frame_len,
            Some(&payload),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn is_known_type_drain_session() {
        assert!(WebTransportFrame::is_known_type(HFrameType(
            WebTransportFrame::WT_DRAIN_SESSION
        )));
    }

    #[test]
    fn encode_drain_session() {
        use neqo_common::Encoder;
        let mut enc = Encoder::default();
        WebTransportFrame::DrainSession.encode(&mut enc);
        // 0x78ae (30894) as a 4-byte QUIC varint: [0x80, 0x00, 0x78, 0xae],
        // followed by a 1-byte varint length of 0: [0x00].
        assert_eq!(enc.as_ref(), &[0x80, 0x00, 0x78, 0xae, 0x00]);
    }

    #[test]
    fn decode_drain_session_valid() {
        let result = WebTransportFrame::decode(
            HFrameType(WebTransportFrame::WT_DRAIN_SESSION),
            0,
            Some(&[]),
        );
        assert_eq!(result.unwrap(), Some(WebTransportFrame::DrainSession));
    }

    #[test]
    fn decode_drain_session_nonzero_len() {
        // WT_DRAIN_SESSION must have a zero-length body; non-zero is a protocol error.
        let result = WebTransportFrame::decode(
            HFrameType(WebTransportFrame::WT_DRAIN_SESSION),
            1,
            Some(&[0x00]),
        );
        assert!(result.is_err());
    }
}
