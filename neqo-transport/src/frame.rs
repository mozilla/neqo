// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Directly relating to QUIC frames.

use neqo_common::{qdebug, Decoder, Encoder};

use crate::stream_id::StreamIndex;
use crate::{AppError, TransportError};
use crate::{ConnectionError, Error, Res};

pub type FrameType = u64;

const FRAME_TYPE_PADDING: FrameType = 0x0;
const FRAME_TYPE_PING: FrameType = 0x1;
const FRAME_TYPE_ACK: FrameType = 0x2;
const FRAME_TYPE_ACK_ECN: FrameType = 0x3;
const FRAME_TYPE_RST_STREAM: FrameType = 0x4;
const FRAME_TYPE_STOP_SENDING: FrameType = 0x5;
const FRAME_TYPE_CRYPTO: FrameType = 0x6;
const FRAME_TYPE_NEW_TOKEN: FrameType = 0x7;
const FRAME_TYPE_STREAM: FrameType = 0x8;
const FRAME_TYPE_STREAM_MAX: FrameType = 0xf;
const FRAME_TYPE_MAX_DATA: FrameType = 0x10;
const FRAME_TYPE_MAX_STREAM_DATA: FrameType = 0x11;
const FRAME_TYPE_MAX_STREAMS_BIDI: FrameType = 0x12;
const FRAME_TYPE_MAX_STREAMS_UNIDI: FrameType = 0x13;
const FRAME_TYPE_DATA_BLOCKED: FrameType = 0x14;
const FRAME_TYPE_STREAM_DATA_BLOCKED: FrameType = 0x15;
const FRAME_TYPE_STREAMS_BLOCKED_BIDI: FrameType = 0x16;
const FRAME_TYPE_STREAMS_BLOCKED_UNIDI: FrameType = 0x17;
const FRAME_TYPE_NEW_CONNECTION_ID: FrameType = 0x18;
const FRAME_TYPE_RETIRE_CONNECTION_ID: FrameType = 0x19;
const FRAME_TYPE_PATH_CHALLENGE: FrameType = 0x1a;
const FRAME_TYPE_PATH_RESPONSE: FrameType = 0x1b;
const FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT: FrameType = 0x1c;
const FRAME_TYPE_CONNECTION_CLOSE_APPLICATION: FrameType = 0x1d;

const STREAM_FRAME_BIT_FIN: u64 = 0x01;
const STREAM_FRAME_BIT_LEN: u64 = 0x02;
const STREAM_FRAME_BIT_OFF: u64 = 0x04;

#[derive(PartialEq, Debug, Copy, Clone, PartialOrd, Eq, Ord, Hash)]
pub enum StreamType {
    BiDi,
    UniDi,
}

impl StreamType {
    fn frame_type_bit(self) -> u64 {
        match self {
            StreamType::BiDi => 0,
            StreamType::UniDi => 1,
        }
    }
    fn from_type_bit(bit: u64) -> StreamType {
        if (bit & 0x01) == 0 {
            StreamType::BiDi
        } else {
            StreamType::UniDi
        }
    }
}

#[derive(PartialEq, Eq, Debug, PartialOrd, Ord, Clone, Copy)]
pub enum CloseError {
    Transport(TransportError),
    Application(AppError),
}

impl CloseError {
    fn frame_type_bit(self) -> u64 {
        match self {
            CloseError::Transport(_) => 0,
            CloseError::Application(_) => 1,
        }
    }

    fn from_type_bit(bit: u64, code: u64) -> CloseError {
        if (bit & 0x01) == 0 {
            CloseError::Transport(code)
        } else {
            CloseError::Application(code)
        }
    }

    fn code(&self) -> u64 {
        match self {
            CloseError::Transport(c) => *c,
            CloseError::Application(c) => *c,
        }
    }
}

impl From<ConnectionError> for CloseError {
    fn from(err: ConnectionError) -> Self {
        match err {
            ConnectionError::Transport(c) => CloseError::Transport(c.code()),
            ConnectionError::Application(c) => CloseError::Application(c),
        }
    }
}

#[derive(PartialEq, Debug, Default, Clone)]
pub struct AckRange {
    pub(crate) gap: u64,
    pub(crate) range: u64,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Frame {
    Padding,
    Ping,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: Vec<AckRange>,
    },
    ResetStream {
        stream_id: u64,
        application_error_code: AppError,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        application_error_code: AppError,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    NewToken {
        token: Vec<u8>,
    },
    Stream {
        fin: bool,
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
    },
    MaxData {
        maximum_data: u64,
    },
    MaxStreamData {
        stream_id: u64,
        maximum_stream_data: u64,
    },
    MaxStreams {
        stream_type: StreamType,
        maximum_streams: StreamIndex,
    },
    DataBlocked {
        data_limit: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        stream_data_limit: u64,
    },
    StreamsBlocked {
        stream_type: StreamType,
        stream_limit: StreamIndex,
    },
    NewConnectionId {
        sequence_number: u64,
        retire_prior: u64,
        connection_id: Vec<u8>,
        stateless_reset_token: [u8; 16],
    },
    RetireConnectionId {
        sequence_number: u64,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    ConnectionClose {
        error_code: CloseError,
        frame_type: u64,
        reason_phrase: Vec<u8>,
    },
}

impl Frame {
    pub fn get_type(&self) -> FrameType {
        match self {
            Frame::Padding => FRAME_TYPE_PADDING,
            Frame::Ping => FRAME_TYPE_PING,
            Frame::Ack { .. } => FRAME_TYPE_ACK, // We don't do ACK ECN.
            Frame::ResetStream { .. } => FRAME_TYPE_RST_STREAM,
            Frame::StopSending { .. } => FRAME_TYPE_STOP_SENDING,
            Frame::Crypto { .. } => FRAME_TYPE_CRYPTO,
            Frame::NewToken { .. } => FRAME_TYPE_NEW_TOKEN,
            Frame::Stream { fin, offset, .. } => {
                let mut t = FRAME_TYPE_STREAM;
                if *fin {
                    t |= STREAM_FRAME_BIT_FIN;
                }
                if *offset > 0 {
                    t |= STREAM_FRAME_BIT_OFF;
                }
                t |= STREAM_FRAME_BIT_LEN;
                t
            }
            Frame::MaxData { .. } => FRAME_TYPE_MAX_DATA,
            Frame::MaxStreamData { .. } => FRAME_TYPE_MAX_STREAM_DATA,
            Frame::MaxStreams { stream_type, .. } => {
                FRAME_TYPE_MAX_STREAMS_BIDI + stream_type.frame_type_bit()
            }
            Frame::DataBlocked { .. } => FRAME_TYPE_DATA_BLOCKED,
            Frame::StreamDataBlocked { .. } => FRAME_TYPE_STREAM_DATA_BLOCKED,
            Frame::StreamsBlocked { stream_type, .. } => {
                FRAME_TYPE_STREAMS_BLOCKED_BIDI + stream_type.frame_type_bit()
            }
            Frame::NewConnectionId { .. } => FRAME_TYPE_NEW_CONNECTION_ID,
            Frame::RetireConnectionId { .. } => FRAME_TYPE_RETIRE_CONNECTION_ID,
            Frame::PathChallenge { .. } => FRAME_TYPE_PATH_CHALLENGE,
            Frame::PathResponse { .. } => FRAME_TYPE_PATH_RESPONSE,
            Frame::ConnectionClose { error_code, .. } => {
                FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT + error_code.frame_type_bit()
            }
        }
    }

    pub fn marshal(&self, enc: &mut Encoder) {
        enc.encode_varint(self.get_type());

        match self {
            Frame::Padding => (),
            Frame::Ping => (),
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
            } => {
                enc.encode_varint(*largest_acknowledged);
                enc.encode_varint(*ack_delay);
                enc.encode_varint(ack_ranges.len() as u64);
                enc.encode_varint(*first_ack_range);
                for r in ack_ranges {
                    enc.encode_varint(r.gap);
                    enc.encode_varint(r.range);
                }
            }
            Frame::ResetStream {
                stream_id,
                application_error_code,
                final_size,
            } => {
                enc.encode_varint(*stream_id);
                enc.encode_varint(*application_error_code);
                enc.encode_varint(*final_size);
            }
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => {
                enc.encode_varint(*stream_id);
                enc.encode_varint(*application_error_code);
            }
            Frame::Crypto { offset, data } => {
                enc.encode_varint(*offset);
                enc.encode_vvec(&data);
            }
            Frame::NewToken { token } => {
                enc.encode_vvec(token);
            }
            Frame::Stream {
                stream_id,
                offset,
                data,
                ..
            } => {
                enc.encode_varint(*stream_id);
                if *offset > 0 {
                    enc.encode_varint(*offset);
                }
                enc.encode_vvec(&data);
            }
            Frame::MaxData { maximum_data } => {
                enc.encode_varint(*maximum_data);
            }
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                enc.encode_varint(*stream_id);
                enc.encode_varint(*maximum_stream_data);
            }
            Frame::MaxStreams {
                maximum_streams, ..
            } => {
                enc.encode_varint(maximum_streams.as_u64());
            }
            Frame::DataBlocked { data_limit } => {
                enc.encode_varint(*data_limit);
            }
            Frame::StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => {
                enc.encode_varint(*stream_id);
                enc.encode_varint(*stream_data_limit);
            }
            Frame::StreamsBlocked { stream_limit, .. } => {
                enc.encode_varint(stream_limit.as_u64());
            }
            Frame::NewConnectionId {
                sequence_number,
                retire_prior,
                connection_id,
                stateless_reset_token,
            } => {
                enc.encode_varint(*sequence_number);
                enc.encode_varint(*retire_prior);
                enc.encode_uint(1, connection_id.len() as u64);
                enc.encode(connection_id);
                enc.encode(stateless_reset_token);
            }
            Frame::RetireConnectionId { sequence_number } => {
                enc.encode_varint(*sequence_number);
            }
            Frame::PathChallenge { data } => {
                enc.encode(data);
            }
            Frame::PathResponse { data } => {
                enc.encode(data);
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason_phrase,
            } => {
                enc.encode_varint(error_code.code());
                enc.encode_varint(*frame_type);
                enc.encode_vvec(reason_phrase);
            }
        }
    }

    pub fn ack_eliciting(&self) -> bool {
        match self {
            Frame::Ack { .. } | Frame::Padding => false,
            _ => true,
        }
    }

    /// Converts AckRanges as encoded in a ACK frame (see -transport
    /// 19.3.1) into ranges of acked packets (end, start), inclusive of
    /// start and end values.
    pub fn decode_ack_frame(
        largest_acked: u64,
        first_ack_range: u64,
        ack_ranges: Vec<AckRange>,
    ) -> Res<Vec<(u64, u64)>> {
        let mut acked_ranges = Vec::new();

        if largest_acked < first_ack_range {
            return Err(Error::FrameEncodingError);
        }
        acked_ranges.push((largest_acked, largest_acked - first_ack_range));
        if !ack_ranges.is_empty() && largest_acked < first_ack_range + 1 {
            return Err(Error::FrameEncodingError);
        }
        let mut cur = if !ack_ranges.is_empty() {
            largest_acked - first_ack_range - 1
        } else {
            0
        };
        for r in ack_ranges {
            if cur < r.gap + 1 {
                return Err(Error::FrameEncodingError);
            }
            cur = cur - r.gap - 1;

            if cur < r.range {
                return Err(Error::FrameEncodingError);
            }
            acked_ranges.push((cur, cur - r.range));

            if cur > r.range + 1 {
                cur -= r.range - 1;
            } else {
                cur -= r.range;
            }
        }

        Ok(acked_ranges)
    }

    pub fn dump(&self) -> Option<String> {
        match self {
            Frame::Crypto { offset, data } => Some(format!(
                "Crypto {{ offset: {}, len: {} }}",
                offset,
                data.len()
            )),
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => Some(format!(
                "Stream {{ stream_id: {}, offset: {}, len: {} fin: {} }}",
                stream_id,
                offset,
                data.len(),
                fin,
            )),
            Frame::Padding => None,
            _ => Some(format!("{:?}", self)),
        }
    }
}

pub fn decode_frame(dec: &mut Decoder) -> Res<Frame> {
    macro_rules! d {
        ($d:expr) => {
            match $d {
                Some(v) => v,
                _ => return Err(Error::NoMoreData),
            }
        };
    }
    macro_rules! dv {
        ($d:expr) => {
            d!($d.decode_varint())
        };
    }

    // TODO(ekr@rtfm.com): check for minimal encoding
    let t = d!(dec.decode_varint());
    qdebug!("Frame type byte={:0x}", t);
    match t {
        FRAME_TYPE_PADDING => Ok(Frame::Padding),
        FRAME_TYPE_PING => Ok(Frame::Ping),
        FRAME_TYPE_RST_STREAM => Ok(Frame::ResetStream {
            stream_id: dv!(dec),
            application_error_code: d!(dec.decode_varint()),
            final_size: match dec.decode_varint() {
                Some(v) => v,
                _ => return Err(Error::NoMoreData),
            },
        }),
        FRAME_TYPE_ACK | FRAME_TYPE_ACK_ECN => {
            let la = dv!(dec);
            let ad = dv!(dec);
            let nr = dv!(dec);
            let fa = dv!(dec);
            let mut arr: Vec<AckRange> = Vec::with_capacity(nr as usize);
            for _ in 0..nr {
                let ar = AckRange {
                    gap: dv!(dec),
                    range: dv!(dec),
                };
                arr.push(ar);
            }

            // Now check for the values for ACK_ECN.
            if t == FRAME_TYPE_ACK_ECN {
                dv!(dec);
                dv!(dec);
                dv!(dec);
            }

            Ok(Frame::Ack {
                largest_acknowledged: la,
                ack_delay: ad,
                first_ack_range: fa,
                ack_ranges: arr,
            })
        }
        FRAME_TYPE_STOP_SENDING => Ok(Frame::StopSending {
            stream_id: dv!(dec),
            application_error_code: d!(dec.decode_varint()),
        }),
        FRAME_TYPE_CRYPTO => {
            let o = dv!(dec);
            Ok(Frame::Crypto {
                offset: o,
                data: d!(dec.decode_vvec()).to_vec(), // TODO(mt) unnecessary copy
            })
        }
        FRAME_TYPE_NEW_TOKEN => {
            Ok(Frame::NewToken {
                token: d!(dec.decode_vvec()).to_vec(), // TODO(mt) unnecessary copy
            })
        }
        FRAME_TYPE_STREAM...FRAME_TYPE_STREAM_MAX => {
            let s = dv!(dec);
            let o = if t & STREAM_FRAME_BIT_OFF != 0 {
                dv!(dec)
            } else {
                0
            };
            qdebug!("STREAM {}", t);
            let data = if (t & STREAM_FRAME_BIT_LEN) != 0 {
                qdebug!("STREAM frame has a length");
                d!(dec.decode_vvec())
            } else {
                qdebug!("STREAM frame extends to the end of the packet");
                dec.decode_remainder()
            };
            Ok(Frame::Stream {
                fin: (t & STREAM_FRAME_BIT_FIN) != 0,
                stream_id: s,
                offset: o,
                data: data.to_vec(), // TODO(mt) unnecessary copy.
            })
        }
        FRAME_TYPE_MAX_DATA => Ok(Frame::MaxData {
            maximum_data: dv!(dec),
        }),
        FRAME_TYPE_MAX_STREAM_DATA => Ok(Frame::MaxStreamData {
            stream_id: dv!(dec),
            maximum_stream_data: dv!(dec),
        }),
        FRAME_TYPE_MAX_STREAMS_BIDI | FRAME_TYPE_MAX_STREAMS_UNIDI => Ok(Frame::MaxStreams {
            stream_type: StreamType::from_type_bit(t),
            maximum_streams: StreamIndex::new(dv!(dec)),
        }),

        FRAME_TYPE_DATA_BLOCKED => Ok(Frame::DataBlocked {
            data_limit: dv!(dec),
        }),
        FRAME_TYPE_STREAM_DATA_BLOCKED => Ok(Frame::StreamDataBlocked {
            stream_id: dv!(dec),
            stream_data_limit: dv!(dec),
        }),
        FRAME_TYPE_STREAMS_BLOCKED_BIDI | FRAME_TYPE_STREAMS_BLOCKED_UNIDI => {
            Ok(Frame::StreamsBlocked {
                stream_type: StreamType::from_type_bit(t),
                stream_limit: StreamIndex::new(dv!(dec)),
            })
        }
        FRAME_TYPE_NEW_CONNECTION_ID => {
            let s = dv!(dec);
            let retire_prior = dv!(dec);
            let cid = d!(dec.decode_vec(1)).to_vec(); // TODO(mt) unnecessary copy
            let srt = d!(dec.decode(16));
            let mut srtv: [u8; 16] = [0; 16];
            srtv.copy_from_slice(&srt);

            Ok(Frame::NewConnectionId {
                sequence_number: s,
                retire_prior,
                connection_id: cid,
                stateless_reset_token: srtv,
            })
        }
        FRAME_TYPE_RETIRE_CONNECTION_ID => Ok(Frame::RetireConnectionId {
            sequence_number: dv!(dec),
        }),
        FRAME_TYPE_PATH_CHALLENGE => {
            let data = d!(dec.decode(8));
            let mut datav: [u8; 8] = [0; 8];
            datav.copy_from_slice(&data);
            Ok(Frame::PathChallenge { data: datav })
        }
        FRAME_TYPE_PATH_RESPONSE => {
            let data = d!(dec.decode(8));
            let mut datav: [u8; 8] = [0; 8];
            datav.copy_from_slice(&data);
            Ok(Frame::PathResponse { data: datav })
        }
        FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT | FRAME_TYPE_CONNECTION_CLOSE_APPLICATION => {
            Ok(Frame::ConnectionClose {
                error_code: CloseError::from_type_bit(t, d!(dec.decode_varint())),
                frame_type: dv!(dec),
                reason_phrase: d!(dec.decode_vvec()).to_vec(), // TODO(mt) unnecessary copy
            })
        }
        _ => Err(Error::UnknownFrameType),
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TxMode {
    Normal,
    #[allow(dead_code)]
    Pto,
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_common::hex;

    fn enc_dec(f: &Frame, s: &str) {
        let mut d = Encoder::default();

        f.marshal(&mut d);
        assert_eq!(d, Encoder::from_hex(s));

        let f2 = decode_frame(&mut d.as_decoder()).unwrap();
        assert_eq!(*f, f2);
    }

    #[test]
    fn test_padding_frame() {
        let f = Frame::Padding;
        enc_dec(&f, "00");
    }

    #[test]
    fn test_ping_frame() {
        let f = Frame::Ping;
        enc_dec(&f, "01");
    }

    #[test]
    fn test_ack() {
        let ar = vec![AckRange { gap: 1, range: 2 }, AckRange { gap: 3, range: 4 }];

        let f = Frame::Ack {
            largest_acknowledged: 0x1234,
            ack_delay: 0x1235,
            first_ack_range: 0x1236,
            ack_ranges: ar,
        };

        enc_dec(&f, "025234523502523601020304");

        // Try to parse ACK_ECN without ECN values
        let enc = Encoder::from_hex("035234523502523601020304");
        let mut dec = enc.as_decoder();
        assert_eq!(decode_frame(&mut dec).unwrap_err(), Error::NoMoreData);

        // Try to parse ACK_ECN without ECN values
        let enc = Encoder::from_hex("035234523502523601020304010203");
        let mut dec = enc.as_decoder();
        assert_eq!(decode_frame(&mut dec).unwrap(), f);
    }

    #[test]
    fn test_reset_stream() {
        let f = Frame::ResetStream {
            stream_id: 0x1234,
            application_error_code: 0x77,
            final_size: 0x3456,
        };

        enc_dec(&f, "04523440777456");
    }

    #[test]
    fn test_stop_sending() {
        let f = Frame::StopSending {
            stream_id: 63,
            application_error_code: 0x77,
        };

        enc_dec(&f, "053F4077")
    }

    #[test]
    fn test_crypto() {
        let f = Frame::Crypto {
            offset: 1,
            data: vec![1, 2, 3],
        };

        enc_dec(&f, "060103010203");
    }

    #[test]
    fn test_new_token() {
        let f = Frame::NewToken {
            token: vec![0x12, 0x34, 0x56],
        };

        enc_dec(&f, "0703123456");
    }

    #[test]
    fn test_stream() {
        // First, just set the length bit.
        let mut f = Frame::Stream {
            fin: false,
            stream_id: 5,
            offset: 0,
            data: vec![1, 2, 3],
        };

        enc_dec(&f, "0a0503010203");

        // Now verify that we can parse without the length
        // bit, because we never generate this.
        let enc = Encoder::from_hex("0805010203");
        let mut dec = enc.as_decoder();
        let f2 = decode_frame(&mut dec).unwrap();
        assert_eq!(f, f2);

        // Now with offset != 0 and FIN
        f = Frame::Stream {
            fin: true,
            stream_id: 5,
            offset: 1,
            data: vec![1, 2, 3],
        };
        enc_dec(&f, "0f050103010203");
    }

    #[test]
    fn test_max_data() {
        let f = Frame::MaxData {
            maximum_data: 0x1234,
        };

        enc_dec(&f, "105234");
    }

    #[test]
    fn test_max_stream_data() {
        let f = Frame::MaxStreamData {
            stream_id: 5,
            maximum_stream_data: 0x1234,
        };

        enc_dec(&f, "11055234");
    }

    #[test]
    fn test_max_streams() {
        let mut f = Frame::MaxStreams {
            stream_type: StreamType::BiDi,
            maximum_streams: StreamIndex::new(0x1234),
        };

        enc_dec(&f, "125234");

        f = Frame::MaxStreams {
            stream_type: StreamType::UniDi,
            maximum_streams: StreamIndex::new(0x1234),
        };

        enc_dec(&f, "135234");
    }

    #[test]
    fn test_data_blocked() {
        let f = Frame::DataBlocked { data_limit: 0x1234 };

        enc_dec(&f, "145234");
    }

    #[test]
    fn test_stream_data_blocked() {
        let f = Frame::StreamDataBlocked {
            stream_id: 5,
            stream_data_limit: 0x1234,
        };

        enc_dec(&f, "15055234");
    }

    #[test]
    fn test_streams_blocked() {
        let mut f = Frame::StreamsBlocked {
            stream_type: StreamType::BiDi,
            stream_limit: StreamIndex::new(0x1234),
        };

        enc_dec(&f, "165234");

        f = Frame::StreamsBlocked {
            stream_type: StreamType::UniDi,
            stream_limit: StreamIndex::new(0x1234),
        };

        enc_dec(&f, "175234");
    }

    #[test]
    fn test_new_connection_id() {
        let f = Frame::NewConnectionId {
            sequence_number: 0x1234,
            retire_prior: 0,
            connection_id: vec![0x01, 0x02],
            stateless_reset_token: [9; 16],
        };

        enc_dec(&f, "1852340002010209090909090909090909090909090909");
    }

    #[test]
    fn test_retire_connection_id() {
        let f = Frame::RetireConnectionId {
            sequence_number: 0x1234,
        };

        enc_dec(&f, "195234");
    }

    #[test]
    fn test_path_challenge() {
        let f = Frame::PathChallenge { data: [9; 8] };

        enc_dec(&f, "1a0909090909090909");
    }

    #[test]
    fn test_path_response() {
        let f = Frame::PathResponse { data: [9; 8] };

        enc_dec(&f, "1b0909090909090909");
    }

    #[test]
    fn test_connection_close() {
        let mut f = Frame::ConnectionClose {
            error_code: CloseError::Transport(0x5678),
            frame_type: 0x1234,
            reason_phrase: vec![0x01, 0x02, 0x03],
        };

        enc_dec(&f, "1c80005678523403010203");

        f = Frame::ConnectionClose {
            error_code: CloseError::Application(0x5678),
            frame_type: 0x1234,
            reason_phrase: vec![0x01, 0x02, 0x03],
        };

        enc_dec(&f, "1d80005678523403010203");
    }

    #[test]
    fn test_compare() {
        let f1 = Frame::Padding;
        let f2 = Frame::Padding;
        let f3 = Frame::Crypto {
            offset: 0,
            data: vec![1, 2, 3],
        };
        let f4 = Frame::Crypto {
            offset: 0,
            data: vec![1, 2, 3],
        };
        let f5 = Frame::Crypto {
            offset: 1,
            data: vec![1, 2, 3],
        };
        let f6 = Frame::Crypto {
            offset: 0,
            data: vec![1, 2, 4],
        };

        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
        assert_eq!(f3, f4);
        assert_ne!(f3, f5);
        assert_ne!(f3, f6);
    }

    #[test]
    fn encode_ack_frame() {
        let ack_frame = Frame::Ack {
            largest_acknowledged: 7,
            ack_delay: 12_000,
            first_ack_range: 2, // [7], 6, 5
            ack_ranges: vec![AckRange {
                gap: 0,   // 4
                range: 1, // 3, 2
            }],
        };
        let mut enc = Encoder::default();
        ack_frame.marshal(&mut enc);
        println!("Encoded ACK={}", hex(&enc[..]));

        let f = decode_frame(&mut enc.as_decoder()).unwrap();
        if let Frame::Ack {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ack_ranges,
        } = f
        {
            assert_eq!(largest_acknowledged, 7);
            assert_eq!(ack_delay, 12_000);
            assert_eq!(first_ack_range, 2);
            assert_eq!(ack_ranges.len(), 1);
            assert_eq!(ack_ranges[0].gap, 0);
            assert_eq!(ack_ranges[0].range, 1);
        }
    }

    #[test]
    fn test_decode_ack_frame() {
        let res = Frame::decode_ack_frame(7, 2, vec![AckRange { gap: 0, range: 3 }]);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), vec![(7, 5), (3, 0)]);
    }
}
