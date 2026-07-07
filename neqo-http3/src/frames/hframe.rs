// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::{self, Debug, Write as _};

use neqo_common::{Buffer, Decoder, Encoder, hex::HexWithLen};
use neqo_transport::StreamId;
use nss::random;

use crate::{Error, Priority, PushId, Res, frames::reader::FrameDecoder, settings::HSettings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HFrameType(pub u64);

/// Limit on the declared length of a HEADERS/`PUSH_PROMISE` frame we'll buffer
/// before decoding.
///
/// A conservative reuse of the QPACK decoded-size limit: encoded size is usually smaller than
/// decoded. Worst-case memory is bounded by the transport's stream concurrency limit, roughly
/// `max_streams_bidi * MAX_HEADER_BYTES`.
pub const MAX_HEADER_BYTES: usize = neqo_qpack::reader::LiteralReader::MAX_LEN;

/// Limit for frame types that carry at most a single varint.
pub const MAX_SINGLE_VARINT_FRAME_BYTES: usize = 8;

/// Limit for other buffered frame types (`SETTINGS`, `PRIORITY_UPDATE_*`).
/// Matches Google quiche's `kPayloadLengthLimit`.
pub const MAX_BUFFERED_FRAME_BYTES: usize = 1024 * 1024;

impl HFrameType {
    pub const DATA: Self = Self(0x0);
    pub const HEADERS: Self = Self(0x1);
    pub const CANCEL_PUSH: Self = Self(0x3);
    pub const SETTINGS: Self = Self(0x4);
    pub const PUSH_PROMISE: Self = Self(0x5);
    pub const GOAWAY: Self = Self(0x7);
    pub const MAX_PUSH_ID: Self = Self(0xd);
    pub const PRIORITY_UPDATE_REQUEST: Self = Self(0xf0700);
    pub const PRIORITY_UPDATE_PUSH: Self = Self(0xf0701);

    /// See <https://www.rfc-editor.org/rfc/rfc9114.html#section-11.2.1> for these reserved types.
    pub const RESERVED: &[Self] = &[Self(0x2), Self(0x6), Self(0x8), Self(0x9)];
}

impl From<HFrameType> for u64 {
    fn from(t: HFrameType) -> Self {
        t.0
    }
}

// data for DATA frame is not read into HFrame::Data.
#[derive(PartialEq, Eq)]
pub enum HFrame {
    Data {
        len: u64, // length of the data
    },
    Headers {
        header_block: Vec<u8>,
    },
    CancelPush {
        push_id: PushId,
    },
    Settings {
        settings: HSettings,
    },
    PushPromise {
        push_id: PushId,
        header_block: Vec<u8>,
    },
    Goaway {
        stream_id: StreamId,
    },
    MaxPushId {
        push_id: PushId,
    },
    Grease,
    PriorityUpdateRequest {
        element_id: u64,
        priority: Priority,
    },
    PriorityUpdatePush {
        element_id: u64,
        priority: Priority,
    },
}

impl HFrame {
    fn get_type(&self) -> HFrameType {
        match self {
            Self::Data { .. } => HFrameType::DATA,
            Self::Headers { .. } => HFrameType::HEADERS,
            Self::CancelPush { .. } => HFrameType::CANCEL_PUSH,
            Self::Settings { .. } => HFrameType::SETTINGS,
            Self::PushPromise { .. } => HFrameType::PUSH_PROMISE,
            Self::Goaway { .. } => HFrameType::GOAWAY,
            Self::MaxPushId { .. } => HFrameType::MAX_PUSH_ID,
            Self::PriorityUpdateRequest { .. } => HFrameType::PRIORITY_UPDATE_REQUEST,
            Self::PriorityUpdatePush { .. } => HFrameType::PRIORITY_UPDATE_PUSH,
            Self::Grease => {
                let r = u64::from_ne_bytes(random::<8>());
                // Zero out the top 7 bits: 2 for being a varint; 5 to account for the *0x1f.
                HFrameType((r >> 7) * 0x1f + 0x21)
            }
        }
    }

    pub fn encode<B: Buffer>(&self, enc: &mut Encoder<B>) {
        enc.encode_varint(self.get_type());

        match self {
            Self::Data { len } => {
                // DATA frame only encode the length here.
                enc.encode_varint(*len);
            }
            Self::Headers { header_block } => {
                enc.encode_vvec(header_block);
            }
            Self::CancelPush { push_id } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(*push_id);
                });
            }
            Self::Settings { settings } => {
                settings.encode_frame_contents(enc);
            }
            Self::PushPromise {
                push_id,
                header_block,
            } => {
                enc.encode_len(header_block.len() + Encoder::varint_len(u64::from(*push_id)));
                enc.encode_varint(*push_id);
                enc.encode(header_block);
            }
            Self::Goaway { stream_id } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(stream_id.as_u64());
                });
            }
            Self::MaxPushId { push_id } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(*push_id);
                });
            }
            Self::Grease => {
                // Encode some number of random bytes.
                let r = random::<8>();
                enc.encode_vvec(&r[1..usize::from(1 + (r[0] & 0x7))]);
            }
            Self::PriorityUpdateRequest {
                element_id,
                priority,
            }
            | Self::PriorityUpdatePush {
                element_id,
                priority,
            } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(*element_id);
                    write!(enc_inner, "{priority}").expect("write OK");
                });
            }
        }
    }
}

impl FrameDecoder<Self> for HFrame {
    #[cfg(feature = "build-fuzzing-corpus")]
    const FUZZING_CORPUS: Option<&'static str> = Some("hframe");

    fn frame_type_allowed(frame_type: HFrameType) -> Res<()> {
        if HFrameType::RESERVED.contains(&frame_type) {
            return Err(Error::HttpFrameUnexpected);
        }
        Ok(())
    }

    fn max_frame_data(frame_type: HFrameType) -> usize {
        match frame_type {
            HFrameType::HEADERS | HFrameType::PUSH_PROMISE => MAX_HEADER_BYTES,
            HFrameType::CANCEL_PUSH | HFrameType::GOAWAY | HFrameType::MAX_PUSH_ID => {
                MAX_SINGLE_VARINT_FRAME_BYTES
            }
            HFrameType::SETTINGS
            | HFrameType::PRIORITY_UPDATE_REQUEST
            | HFrameType::PRIORITY_UPDATE_PUSH => MAX_BUFFERED_FRAME_BYTES,
            _ => usize::MAX,
        }
    }

    fn decode(frame_type: HFrameType, frame_len: u64, data: Option<&[u8]>) -> Res<Option<Self>> {
        if frame_type == HFrameType::DATA {
            Ok(Some(Self::Data { len: frame_len }))
        } else if let Some(payload) = data {
            let mut dec = Decoder::from(payload);
            let f = match frame_type {
                HFrameType::DATA => unreachable!("DATA frame has been handled already"),
                HFrameType::HEADERS => Self::Headers {
                    header_block: dec.decode_remainder().to_vec(),
                },
                HFrameType::CANCEL_PUSH => Self::CancelPush {
                    push_id: dec.decode_varint().ok_or(Error::HttpFrame)?.into(),
                },
                HFrameType::SETTINGS => {
                    let mut settings = HSettings::default();
                    settings.decode_frame_contents(&mut dec).map_err(|e| {
                        if e == Error::HttpSettings {
                            e
                        } else {
                            Error::HttpFrame
                        }
                    })?;
                    Self::Settings { settings }
                }
                HFrameType::PUSH_PROMISE => Self::PushPromise {
                    push_id: dec.decode_varint().ok_or(Error::HttpFrame)?.into(),
                    header_block: dec.decode_remainder().to_vec(),
                },
                HFrameType::GOAWAY => Self::Goaway {
                    stream_id: StreamId::new(dec.decode_varint().ok_or(Error::HttpFrame)?),
                },
                HFrameType::MAX_PUSH_ID => Self::MaxPushId {
                    push_id: dec.decode_varint().ok_or(Error::HttpFrame)?.into(),
                },
                HFrameType::PRIORITY_UPDATE_REQUEST | HFrameType::PRIORITY_UPDATE_PUSH => {
                    let element_id = dec.decode_varint().ok_or(Error::HttpFrame)?;
                    let priority = dec.decode_remainder();
                    let priority = Priority::from_bytes(priority)?;
                    if frame_type == HFrameType::PRIORITY_UPDATE_REQUEST {
                        Self::PriorityUpdateRequest {
                            element_id,
                            priority,
                        }
                    } else {
                        Self::PriorityUpdatePush {
                            element_id,
                            priority,
                        }
                    }
                }
                _ => return Ok(None),
            };
            if dec.remaining() > 0 {
                Err(Error::HttpFrame)
            } else {
                Ok(Some(f))
            }
        } else {
            Ok(None)
        }
    }

    fn is_known_type(frame_type: HFrameType) -> bool {
        matches!(
            frame_type,
            HFrameType::DATA
                | HFrameType::HEADERS
                | HFrameType::CANCEL_PUSH
                | HFrameType::SETTINGS
                | HFrameType::PUSH_PROMISE
                | HFrameType::GOAWAY
                | HFrameType::MAX_PUSH_ID
                | HFrameType::PRIORITY_UPDATE_REQUEST
                | HFrameType::PRIORITY_UPDATE_PUSH
        )
    }
}

impl Debug for HFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data { len } => {
                write!(f, "DATA[{len}]")
            }
            Self::Headers { header_block } => {
                write!(f, "HEADERS {}", HexWithLen::new(header_block))
            }
            Self::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH {push_id}")
            }
            Self::Settings { settings } => {
                write!(f, "SETTINGS {settings:?}")
            }
            Self::PushPromise {
                push_id,
                header_block,
            } => {
                write!(
                    f,
                    "PUSH_PROMISE {push_id} {}",
                    HexWithLen::new(header_block)
                )
            }
            Self::Goaway { stream_id } => {
                write!(f, "GOAWAY {stream_id}")
            }
            Self::MaxPushId { push_id } => {
                write!(f, "MAX_PUSH_ID {push_id}")
            }
            Self::Grease => f.write_str("GREASE"),
            Self::PriorityUpdateRequest {
                element_id,
                priority,
            } => write!(f, "PRIORITY_UPDATE request {element_id} {priority}"),

            Self::PriorityUpdatePush {
                element_id,
                priority,
            } => write!(f, "PRIORITY_UPDATE push {element_id} {priority}"),
        }
    }
}
