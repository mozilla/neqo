// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Decoder, Encoder, MAX_VARINT, to_u64};
use neqo_transport::StreamType;
use static_assertions::const_assert;

use super::hframe::HFrameType;
use crate::{Error, Res, frames::reader::FrameDecoder};

pub type WebTransportFrameType = u64;

#[derive(PartialEq, Eq, Debug)]
pub enum WebTransportFrame {
    CloseSession {
        error: u32,
        message: String,
    },
    DrainSession,
    /// `WT_MAX_STREAMS` capsule: the cumulative number of streams of
    /// `stream_type` the peer permits us to open over the session's
    /// lifetime (draft-15 §5.6.2).
    MaxStreams {
        stream_type: StreamType,
        maximum: u64,
    },
}

const_assert!(WebTransportFrame::CLOSE_MAX_MESSAGE_SIZE <= to_u64(usize::MAX) - 4);

impl WebTransportFrame {
    /// The frame type for WebTransport `CLOSE_SESSION`, as defined in
    /// [WebTransport over HTTP/3 (draft-ietf-webtrans-http3-14, Section 4.6)](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.6).
    /// The value 0x2843 is assigned for `CLOSE_SESSION`.
    const CLOSE_SESSION: WebTransportFrameType = 0x2843;

    /// The frame type for WebTransport `WT_DRAIN_SESSION`, as defined in
    /// [WebTransport over HTTP/3 (draft-ietf-webtrans-http3-14, Section 4.7)](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.7).
    /// The value 0x78ae is assigned for `WT_DRAIN_SESSION`.
    const WT_DRAIN_SESSION: WebTransportFrameType = 0x78ae;

    /// `WT_MAX_STREAMS` capsule types (draft-15 §5.6.2 / §9.3): one for
    /// bidirectional and one for unidirectional streams.
    const WT_MAX_STREAMS_BIDI: WebTransportFrameType = 0x190b_4d3f;
    const WT_MAX_STREAMS_UNI: WebTransportFrameType = 0x190b_4d40;

    /// The maximum allowed message size for `CLOSE_SESSION` messages, as recommended
    /// in [WebTransport over HTTP/3 (draft-ietf-webtrans-http3-14, Section 4.6)](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-4.6).
    /// The value 1024 is used to limit the message size for security and interoperability.
    const CLOSE_MAX_MESSAGE_SIZE: u64 = 1024;

    /// Limit on the declared length of a `CLOSE_SESSION` frame.
    #[expect(clippy::cast_possible_truncation, reason = "value is checked above")]
    pub const MAX_CLOSE_SESSION_BYTES: usize = Self::CLOSE_MAX_MESSAGE_SIZE as usize + 4;

    pub fn encode(&self, enc: &mut Encoder) {
        #[cfg(feature = "build-fuzzing-corpus")]
        let start = enc.len();

        match self {
            Self::CloseSession { error, message } => {
                enc.encode_varint(Self::CLOSE_SESSION);
                enc.encode_len(4 + message.len());
                enc.encode_uint(4, *error);
                enc.encode(message.as_bytes());
            }
            Self::DrainSession => {
                enc.encode_varint(Self::WT_DRAIN_SESSION);
                enc.encode_varint(0u64);
            }
            // We do not yet send WT_MAX_STREAMS ourselves; this arm exists for
            // round-trip testing and future use.
            Self::MaxStreams {
                stream_type,
                maximum,
            } => {
                let frame_type = match stream_type {
                    StreamType::BiDi => Self::WT_MAX_STREAMS_BIDI,
                    StreamType::UniDi => Self::WT_MAX_STREAMS_UNI,
                };
                let mut body = Encoder::default();
                body.encode_varint(*maximum);
                enc.encode_varint(frame_type);
                enc.encode_len(body.len());
                enc.encode(body.as_ref());
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
        match frame_type {
            HFrameType(Self::CLOSE_SESSION) => {
                let Some(payload) = data else {
                    return Ok(None);
                };
                if frame_len > Self::CLOSE_MAX_MESSAGE_SIZE + 4 {
                    return Err(Error::HttpMessage);
                }
                let mut dec = Decoder::from(payload);
                let error = dec.decode_uint().ok_or(Error::HttpMessage)?;
                let Ok(message) = String::from_utf8(dec.decode_remainder().to_vec()) else {
                    return Err(Error::HttpMessage);
                };
                Ok(Some(Self::CloseSession { error, message }))
            }
            HFrameType(Self::WT_DRAIN_SESSION) => {
                if frame_len != 0 {
                    return Err(Error::HttpMessage);
                }
                Ok(Some(Self::DrainSession))
            }
            HFrameType(Self::WT_MAX_STREAMS_BIDI | Self::WT_MAX_STREAMS_UNI) => {
                let Some(payload) = data else {
                    return Ok(None);
                };
                let mut dec = Decoder::from(payload);
                let maximum = dec.decode_varint().ok_or(Error::HttpMessage)?;
                // The payload is exactly one varint, so anything left over is a
                // malformed capsule rather than something to ignore.
                if dec.remaining() != 0 {
                    return Err(Error::HttpMessage);
                }
                // The Maximum Streams value range (<= 2^60) is validated by the
                // session, which maps a violation to the spec-required
                // H3_DATAGRAM_ERROR.
                let stream_type = if frame_type == HFrameType(Self::WT_MAX_STREAMS_BIDI) {
                    StreamType::BiDi
                } else {
                    StreamType::UniDi
                };
                Ok(Some(Self::MaxStreams {
                    stream_type,
                    maximum,
                }))
            }
            _ => Ok(None),
        }
    }

    fn is_known_type(frame_type: HFrameType) -> bool {
        matches!(
            frame_type,
            HFrameType(
                Self::CLOSE_SESSION
                    | Self::WT_DRAIN_SESSION
                    | Self::WT_MAX_STREAMS_BIDI
                    | Self::WT_MAX_STREAMS_UNI
            )
        )
    }

    fn max_frame_data(frame_type: HFrameType) -> usize {
        match frame_type {
            HFrameType(Self::CLOSE_SESSION) => Self::MAX_CLOSE_SESSION_BYTES,
            // WT_DRAIN_SESSION carries no payload, so reject any declared length.
            HFrameType(Self::WT_DRAIN_SESSION) => 0,
            // WT_MAX_STREAMS carries a single varint, so a peer cannot make us
            // buffer more than that before we decode it.
            HFrameType(Self::WT_MAX_STREAMS_BIDI | Self::WT_MAX_STREAMS_UNI) => {
                Encoder::varint_len(MAX_VARINT)
            }
            _ => usize::MAX,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neqo_common::{Encoder, MAX_VARINT, to_u64};

    use super::{HFrameType, WebTransportFrame};
    use crate::{Error, frames::reader::FrameDecoder as _};

    #[test]
    fn is_known_type_close_session() {
        assert!(WebTransportFrame::is_known_type(HFrameType(
            WebTransportFrame::CLOSE_SESSION
        )));
    }

    #[test]
    fn max_frame_data_unknown_type_is_unbounded() {
        assert_eq!(
            WebTransportFrame::max_frame_data(HFrameType(0x1230)),
            usize::MAX
        );
    }

    #[test]
    fn max_frame_data_max_streams_is_one_varint() {
        // A known frame type must not be left unbounded: WT_MAX_STREAMS carries a
        // single varint, so anything longer is not a frame we should buffer.
        for frame_type in [
            WebTransportFrame::WT_MAX_STREAMS_BIDI,
            WebTransportFrame::WT_MAX_STREAMS_UNI,
        ] {
            assert_eq!(
                WebTransportFrame::max_frame_data(HFrameType(frame_type)),
                Encoder::varint_len(MAX_VARINT)
            );
        }
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
        let frame_len = to_u64(payload.len());

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
        let frame_len = to_u64(payload.len());

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

    #[test]
    fn is_known_type_max_streams() {
        assert!(WebTransportFrame::is_known_type(HFrameType(
            WebTransportFrame::WT_MAX_STREAMS_BIDI
        )));
        assert!(WebTransportFrame::is_known_type(HFrameType(
            WebTransportFrame::WT_MAX_STREAMS_UNI
        )));
    }

    #[test]
    fn max_streams_round_trip() {
        use neqo_transport::StreamType;

        for (stream_type, frame_type) in [
            (StreamType::BiDi, WebTransportFrame::WT_MAX_STREAMS_BIDI),
            (StreamType::UniDi, WebTransportFrame::WT_MAX_STREAMS_UNI),
        ] {
            let frame = WebTransportFrame::MaxStreams {
                stream_type,
                maximum: 17,
            };
            let mut enc = Encoder::default();
            frame.encode(&mut enc);

            // Skip the frame type varint, then decode the length-prefixed body.
            let mut dec = neqo_common::Decoder::from(enc.as_ref());
            assert_eq!(dec.decode_varint(), Some(frame_type));
            let body = dec.decode_vvec().unwrap();
            let decoded =
                WebTransportFrame::decode(HFrameType(frame_type), to_u64(body.len()), Some(body));
            assert_eq!(
                decoded.unwrap(),
                Some(WebTransportFrame::MaxStreams {
                    stream_type,
                    maximum: 17,
                })
            );
        }
    }

    #[test]
    fn max_streams_trailing_bytes_are_rejected() {
        // The payload is a single varint. Trailing bytes still fit under
        // `max_frame_data` (one varint is up to 8 bytes), so decoding must reject
        // them explicitly rather than silently ignoring the remainder.
        for frame_type in [
            WebTransportFrame::WT_MAX_STREAMS_BIDI,
            WebTransportFrame::WT_MAX_STREAMS_UNI,
        ] {
            let mut enc = Encoder::default();
            enc.encode_varint(17u64);
            enc.encode_byte(0);
            let body = enc.as_ref();

            assert_eq!(
                WebTransportFrame::decode(
                    HFrameType(frame_type),
                    to_u64(body.len()),
                    Some(body)
                ),
                Err(Error::HttpMessage)
            );
        }
    }
}
