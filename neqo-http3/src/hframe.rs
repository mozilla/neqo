// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{
    hex, qdebug, qtrace, Decoder, Encoder, IncrementalDecoder, IncrementalDecoderResult,
};
use neqo_transport::Connection;

use std::mem;

use crate::{Error, Res};

pub type HFrameType = u64;

pub const H3_FRAME_TYPE_DATA: HFrameType = 0x0;
pub const H3_FRAME_TYPE_HEADERS: HFrameType = 0x1;
const H3_FRAME_TYPE_PRIORITY: HFrameType = 0x2;
const H3_FRAME_TYPE_CANCEL_PUSH: HFrameType = 0x3;
const H3_FRAME_TYPE_SETTINGS: HFrameType = 0x4;
const H3_FRAME_TYPE_PUSH_PROMISE: HFrameType = 0x5;
const H3_FRAME_TYPE_GOAWAY: HFrameType = 0x7;
const H3_FRAME_TYPE_MAX_PUSH_ID: HFrameType = 0xd;
const H3_FRAME_TYPE_DUPLICATE_PUSH: HFrameType = 0xe;

type SettingsType = u64;

const SETTINGS_MAX_HEADER_LIST_SIZE: SettingsType = 0x6;
const SETTINGS_NUM_PLACEHOLDERS: SettingsType = 0x8;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: SettingsType = 0x1;
const SETTINGS_QPACK_BLOCKED_STREAMS: SettingsType = 0x7;

#[derive(Copy, Clone, PartialEq)]
pub enum HStreamType {
    Control,
    Request,
    Push,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum PrioritizedElementType {
    RequestStream,
    PushStream,
    Placeholder,
    CurrentStream,
}

fn prior_elem_from_byte(b: u8) -> PrioritizedElementType {
    match b & 0x3 {
        0x0 => PrioritizedElementType::RequestStream,
        0x1 => PrioritizedElementType::PushStream,
        0x2 => PrioritizedElementType::Placeholder,
        0x3 => PrioritizedElementType::CurrentStream,
        _ => panic!("Can't happen"),
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ElementDependencyType {
    RequestStream,
    PushStream,
    Placeholder,
    Root,
}

fn elem_dep_from_byte(b: u8) -> ElementDependencyType {
    match (b & (0x3 << 2)) >> 2 {
        0x0 => ElementDependencyType::RequestStream,
        0x1 => ElementDependencyType::PushStream,
        0x2 => ElementDependencyType::Placeholder,
        0x3 => ElementDependencyType::Root,
        _ => panic!("Can't happen"),
    }
}

#[derive(PartialEq, Debug)]
pub enum HSettingType {
    MaxHeaderListSize,
    NumPlaceholders,
    MaxTableSize,
    BlockedStreams,
    UnknownType,
}

// data for DATA and header blocks for HEADERS anf PUSH_PROMISE are not read into HFrame.
#[derive(PartialEq, Debug)]
pub enum HFrame {
    Data {
        len: u64, // length of the data
    },
    Headers {
        len: u64, // length of the header block
    },
    Priority {
        priorized_elem_type: PrioritizedElementType,
        elem_dependency_type: ElementDependencyType,
        // TODO(mt) exclusive bit
        priority_elem_id: u64,
        elem_dependency_id: u64,
        weight: u8,
    },
    CancelPush {
        push_id: u64,
    },
    Settings {
        settings: Vec<(HSettingType, u64)>,
    },
    PushPromise {
        push_id: u64,
        len: u64, // length of the header block.
    },
    Goaway {
        stream_id: u64,
    },
    MaxPushId {
        push_id: u64,
    },
    DuplicatePush {
        push_id: u64,
    },
}

impl HFrame {
    fn get_type(&self) -> HFrameType {
        match self {
            HFrame::Data { .. } => H3_FRAME_TYPE_DATA,
            HFrame::Headers { .. } => H3_FRAME_TYPE_HEADERS,
            HFrame::Priority { .. } => H3_FRAME_TYPE_PRIORITY,
            HFrame::CancelPush { .. } => H3_FRAME_TYPE_CANCEL_PUSH,
            HFrame::Settings { .. } => H3_FRAME_TYPE_SETTINGS,
            HFrame::PushPromise { .. } => H3_FRAME_TYPE_PUSH_PROMISE,
            HFrame::Goaway { .. } => H3_FRAME_TYPE_GOAWAY,
            HFrame::MaxPushId { .. } => H3_FRAME_TYPE_MAX_PUSH_ID,
            HFrame::DuplicatePush { .. } => H3_FRAME_TYPE_DUPLICATE_PUSH,
        }
    }

    pub fn encode(&self, enc: &mut Encoder) {
        enc.encode_varint(self.get_type());

        match self {
            HFrame::Data { len } | HFrame::Headers { len } => {
                // DATA and HEADERS frames only encode the length here.
                enc.encode_varint(*len);
            }
            HFrame::Priority {
                priorized_elem_type,
                elem_dependency_type,
                priority_elem_id,
                elem_dependency_id,
                weight,
            } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_byte(
                        (*priorized_elem_type as u8) | ((*elem_dependency_type as u8) << 2),
                    );
                    enc_inner.encode_varint(*priority_elem_id);
                    enc_inner.encode_varint(*elem_dependency_id);
                    enc_inner.encode_byte(*weight);
                });
            }
            HFrame::CancelPush { push_id } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(*push_id);
                });
            }
            HFrame::Settings { settings } => {
                enc.encode_vvec_with(|enc_inner| {
                    for iter in settings.iter() {
                        match iter.0 {
                            HSettingType::MaxHeaderListSize => {
                                enc_inner.encode_varint(SETTINGS_MAX_HEADER_LIST_SIZE as u64);
                                enc_inner.encode_varint(iter.1);
                            }
                            HSettingType::NumPlaceholders => {
                                enc_inner.encode_varint(SETTINGS_NUM_PLACEHOLDERS as u64);
                                enc_inner.encode_varint(iter.1);
                            }
                            HSettingType::MaxTableSize => {
                                enc_inner.encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY as u64);
                                enc_inner.encode_varint(iter.1);
                            }
                            HSettingType::BlockedStreams => {
                                enc_inner.encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS as u64);
                                enc_inner.encode_varint(iter.1);
                            }
                            HSettingType::UnknownType => {}
                        }
                    }
                });
            }
            HFrame::PushPromise { push_id, len } => {
                // This one is tricky because we don't encode the body, we encode the length.
                // TODO(mt) work out whether this needs to stay this way.
                enc.encode_varint(*len + (Encoder::varint_len(*push_id) as u64));
                enc.encode_varint(*push_id);
            }
            HFrame::Goaway { stream_id } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(*stream_id);
                });
            }
            HFrame::MaxPushId { push_id } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(*push_id);
                });
            }
            HFrame::DuplicatePush { push_id } => {
                enc.encode_vvec_with(|enc_inner| {
                    enc_inner.encode_varint(*push_id);
                });
            }
        }
    }

    pub fn is_allowed(&self, s: HStreamType) -> bool {
        match self {
            HFrame::Data { .. } => !(s == HStreamType::Control),
            HFrame::Headers { .. } => !(s == HStreamType::Control),
            HFrame::Priority { .. } => !(s == HStreamType::Control),
            HFrame::CancelPush { .. } => (s == HStreamType::Control),
            HFrame::Settings { .. } => (s == HStreamType::Control),
            HFrame::PushPromise { .. } => (s == HStreamType::Request),
            HFrame::Goaway { .. } => (s == HStreamType::Control),
            HFrame::MaxPushId { .. } => (s == HStreamType::Control),
            HFrame::DuplicatePush { .. } => (s == HStreamType::Request),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum HFrameReaderState {
    BeforeFrame,
    GetType,
    GetLength,
    GetPushPromiseData,
    GetData,
    UnknownFrameDischargeData,
    Done,
}

#[derive(Debug)]
pub struct HFrameReader {
    state: HFrameReaderState,
    decoder: IncrementalDecoder,
    hframe_type: u64,
    hframe_len: u64,
    push_id_len: usize,
    payload: Vec<u8>,
}

impl Default for HFrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl HFrameReader {
    pub fn new() -> HFrameReader {
        HFrameReader {
            state: HFrameReaderState::GetType,
            hframe_type: 0,
            hframe_len: 0,
            push_id_len: 0, // TODO(mt) remove this, it's bad
            decoder: IncrementalDecoder::decode_varint(),
            payload: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.state = HFrameReaderState::BeforeFrame;
        self.decoder = IncrementalDecoder::decode_varint();
    }

    // returns true if quic stream was closed.
    pub fn receive(&mut self, conn: &mut Connection, stream_id: u64) -> Res<bool> {
        loop {
            let to_read = std::cmp::min(self.decoder.min_remaining(), 4096);
            let mut buf = vec![0; to_read];
            let mut input = match conn.stream_recv(stream_id, &mut buf[..]) {
                Ok((_, true)) => {
                    break match self.state {
                        HFrameReaderState::BeforeFrame => Ok(true),
                        _ => Err(Error::MalformedFrame(0xff)),
                    };
                }
                Ok((0, false)) => break Ok(false),
                Ok((amount, false)) => Decoder::from(&buf[..amount]),
                Err(e) => {
                    qdebug!([conn] "Error reading data from stream {}: {:?}", stream_id, e);
                    break Err(e.into());
                }
            };

            // TODO(mt) this amount_read thing is terrible.
            let mut amount_read = input.remaining();
            let progress = self.decoder.consume(&mut input);
            amount_read -= input.remaining();
            match self.state {
                HFrameReaderState::BeforeFrame | HFrameReaderState::GetType => match progress {
                    IncrementalDecoderResult::Uint(v) => {
                        self.hframe_type = v;
                        self.decoder = IncrementalDecoder::decode_varint();
                        self.state = HFrameReaderState::GetLength;
                    }
                    IncrementalDecoderResult::InProgress => {
                        self.state = HFrameReaderState::GetType;
                    }
                    _ => {
                        break Err(Error::MalformedFrame(0xff));
                    }
                },

                HFrameReaderState::GetLength => {
                    match progress {
                        IncrementalDecoderResult::Uint(len) => {
                            self.hframe_len = len;
                            self.state = match self.hframe_type {
                                // DATA and HEADERS payload are left on the quic stream and picked up separately
                                H3_FRAME_TYPE_DATA | H3_FRAME_TYPE_HEADERS => {
                                    HFrameReaderState::Done
                                }
                                // For push frame we only decode the first varint. Headers blocks will be picked up separately.
                                H3_FRAME_TYPE_PUSH_PROMISE => {
                                    self.decoder = IncrementalDecoder::decode_varint();
                                    HFrameReaderState::GetPushPromiseData
                                }
                                // for other frames get all data before decoding.
                                H3_FRAME_TYPE_PRIORITY
                                | H3_FRAME_TYPE_CANCEL_PUSH
                                | H3_FRAME_TYPE_SETTINGS
                                | H3_FRAME_TYPE_GOAWAY
                                | H3_FRAME_TYPE_MAX_PUSH_ID
                                | H3_FRAME_TYPE_DUPLICATE_PUSH => {
                                    self.decoder = IncrementalDecoder::decode(len as usize);
                                    HFrameReaderState::GetData
                                }
                                _ => {
                                    self.decoder = IncrementalDecoder::ignore(len as usize);
                                    HFrameReaderState::UnknownFrameDischargeData
                                }
                            };
                        }
                        IncrementalDecoderResult::InProgress => {}
                        _ => break Err(Error::NoMoreData),
                    }
                }
                HFrameReaderState::GetPushPromiseData => {
                    self.push_id_len += amount_read;
                    match progress {
                        IncrementalDecoderResult::Uint(push_id) => {
                            // put the push ID back into the payload
                            // TODO(mt) this is not a good design
                            let mut enc = Encoder::with_capacity(8);
                            enc.encode_uint(8, push_id);
                            self.payload = enc.into();
                            self.state = HFrameReaderState::Done;
                            break Ok(false);
                        }
                        IncrementalDecoderResult::InProgress => {}
                        _ => break Err(Error::NoMoreData),
                    };
                }
                HFrameReaderState::GetData => {
                    match progress {
                        IncrementalDecoderResult::Buffer(data) => {
                            qtrace!([conn] "received frame {}: {}", self.hframe_type, hex(&data[..]));
                            self.payload = data;
                            self.state = HFrameReaderState::Done;
                            break Ok(false);
                        }
                        IncrementalDecoderResult::InProgress => {}
                        _ => break Err(Error::NoMoreData),
                    };
                }
                HFrameReaderState::UnknownFrameDischargeData => {
                    match progress {
                        IncrementalDecoderResult::Ignored => {
                            self.reset();
                            break Ok(false);
                        }
                        IncrementalDecoderResult::InProgress => {}
                        _ => break Err(Error::NoMoreData),
                    };
                }
                HFrameReaderState::Done => {
                    break Ok(false);
                }
            }
        }
    }

    pub fn done(&self) -> bool {
        self.state == HFrameReaderState::Done
    }

    pub fn get_frame(&mut self) -> Res<HFrame> {
        if self.state != HFrameReaderState::Done {
            return Err(Error::NotEnoughData);
        }

        let payload = mem::replace(&mut self.payload, Vec::new());
        let mut dec = Decoder::from(&payload[..]);
        let f = match self.hframe_type {
            H3_FRAME_TYPE_DATA => HFrame::Data {
                len: self.hframe_len,
            },
            H3_FRAME_TYPE_HEADERS => HFrame::Headers {
                len: self.hframe_len,
            },
            H3_FRAME_TYPE_PRIORITY => {
                let tb = match dec.decode_byte() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                };
                let pe = match dec.decode_varint() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                };
                let de = match dec.decode_varint() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                };
                let w = match dec.decode_byte() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                };
                HFrame::Priority {
                    priorized_elem_type: prior_elem_from_byte(tb),
                    elem_dependency_type: elem_dep_from_byte(tb),
                    priority_elem_id: pe,
                    elem_dependency_id: de,
                    weight: w,
                }
            }
            H3_FRAME_TYPE_CANCEL_PUSH => HFrame::CancelPush {
                push_id: match dec.decode_varint() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                },
            },
            H3_FRAME_TYPE_SETTINGS => {
                let mut settings: Vec<(HSettingType, u64)> = Vec::new();
                while dec.remaining() > 0 {
                    let st_read = match dec.decode_varint() {
                        Some(v) => v,
                        _ => return Err(Error::NotEnoughData),
                    };
                    let st = match st_read {
                        SETTINGS_MAX_HEADER_LIST_SIZE => HSettingType::MaxHeaderListSize,
                        SETTINGS_NUM_PLACEHOLDERS => HSettingType::NumPlaceholders,
                        SETTINGS_QPACK_MAX_TABLE_CAPACITY => HSettingType::MaxTableSize,
                        SETTINGS_QPACK_BLOCKED_STREAMS => HSettingType::BlockedStreams,
                        _ => HSettingType::UnknownType,
                    };
                    let v = match dec.decode_varint() {
                        Some(v) => v,
                        _ => return Err(Error::NotEnoughData),
                    };
                    if st != HSettingType::UnknownType {
                        settings.push((st, v));
                    }
                }
                HFrame::Settings { settings }
            }
            H3_FRAME_TYPE_PUSH_PROMISE => {
                let push_id = match dec.decode_uint(8) {
                    Some(v) => v,
                    _ => unreachable!(),
                };
                let len = self.hframe_len - self.push_id_len as u64;
                HFrame::PushPromise { push_id, len }
            }
            H3_FRAME_TYPE_GOAWAY => HFrame::Goaway {
                stream_id: match dec.decode_varint() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                },
            },
            H3_FRAME_TYPE_MAX_PUSH_ID => HFrame::MaxPushId {
                push_id: match dec.decode_varint() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                },
            },
            H3_FRAME_TYPE_DUPLICATE_PUSH => HFrame::DuplicatePush {
                push_id: match dec.decode_varint() {
                    Some(v) => v,
                    _ => return Err(Error::NotEnoughData),
                },
            },
            _ => panic!("We should not be in state Done with unknown frame type!"),
        };
        self.reset();
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_transport::StreamType;
    use num_traits::Num;
    use test_fixture::*;

    #[allow(clippy::many_single_char_names)]
    fn enc_dec(f: &HFrame, st: &str, remaining: usize) {
        let mut d = Encoder::default();

        f.encode(&mut d);

        // For data, headers and push_promise we do not read all bytes from the buffer
        let d2 = Encoder::from_hex(st);
        assert_eq!(&d[..], &d2[..d.len()]);

        let mut conn_c = default_client();
        let mut conn_s = default_server();
        let out = conn_c.process(None, now());
        let out = conn_s.process(out.dgram(), now());
        let out = conn_c.process(out.dgram(), now());
        conn_s.process(out.dgram(), now());

        // create a stream
        let stream_id = conn_s.stream_create(StreamType::BiDi).unwrap();

        let mut fr: HFrameReader = HFrameReader::new();

        // conver string into u8 vector
        let mut buf: Vec<u8> = Vec::new();
        if st.len() % 2 != 0 {
            panic!("Needs to be even length");
        }
        for i in 0..st.len() / 2 {
            let x = st.get(i * 2..i * 2 + 2);
            let v = <u8 as Num>::from_str_radix(x.unwrap(), 16).unwrap();
            buf.push(v);
        }
        conn_s.stream_send(stream_id, &buf).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());

        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        // Check remaining data.
        let mut buf = [0u8; 100];
        let (amount, _) = conn_c.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(amount, remaining);

        assert!(fr.done());
        if let Ok(f2) = fr.get_frame() {
            assert_eq!(*f, f2);
        } else {
            panic!("wrong frame type");
        }
    }

    #[test]
    fn test_data_frame() {
        let f = HFrame::Data { len: 3 };
        enc_dec(&f, "0003010203", 3);
    }

    #[test]
    fn test_headers_frame() {
        let f = HFrame::Headers { len: 3 };
        enc_dec(&f, "0103010203", 3);
    }

    #[test]
    fn test_priority_frame1() {
        let f = HFrame::Priority {
            priorized_elem_type: PrioritizedElementType::RequestStream,
            elem_dependency_type: ElementDependencyType::RequestStream,
            priority_elem_id: 2,
            elem_dependency_id: 1,
            weight: 3,
        };
        enc_dec(&f, "020400020103", 0);
    }

    #[test]
    fn test_priority_frame2() {
        let f = HFrame::Priority {
            priorized_elem_type: PrioritizedElementType::PushStream,
            elem_dependency_type: ElementDependencyType::PushStream,
            priority_elem_id: 2,
            elem_dependency_id: 1,
            weight: 3,
        };
        enc_dec(&f, "020405020103", 0);
    }

    #[test]
    fn test_priority_frame3() {
        let f = HFrame::Priority {
            priorized_elem_type: PrioritizedElementType::Placeholder,
            elem_dependency_type: ElementDependencyType::Placeholder,
            priority_elem_id: 2,
            elem_dependency_id: 1,
            weight: 3,
        };
        enc_dec(&f, "02040a020103", 0);
    }

    #[test]
    fn test_priority_frame4() {
        let f = HFrame::Priority {
            priorized_elem_type: PrioritizedElementType::CurrentStream,
            elem_dependency_type: ElementDependencyType::Root,
            priority_elem_id: 2,
            elem_dependency_id: 1,
            weight: 3,
        };
        enc_dec(&f, "02040f020103", 0);
    }

    #[test]
    fn test_cancel_push_frame4() {
        let f = HFrame::CancelPush { push_id: 5 };
        enc_dec(&f, "030105", 0);
    }

    #[test]
    fn test_settings_frame4() {
        let f = HFrame::Settings {
            settings: vec![
                (HSettingType::MaxHeaderListSize, 4),
                (HSettingType::NumPlaceholders, 4),
            ],
        };
        enc_dec(&f, "040406040804", 0);
    }

    #[test]
    fn test_push_promise_frame4() {
        let f = HFrame::PushPromise { push_id: 4, len: 4 };
        enc_dec(&f, "05050401020304", 4);
    }

    #[test]
    fn test_goaway_frame4() {
        let f = HFrame::Goaway { stream_id: 5 };
        enc_dec(&f, "070105", 0);
    }

    #[test]
    fn test_max_push_id_frame4() {
        let f = HFrame::MaxPushId { push_id: 5 };
        enc_dec(&f, "0d0105", 0);
    }

    #[test]
    fn test_duplicate_push_frame4() {
        let f = HFrame::DuplicatePush { push_id: 5 };
        enc_dec(&f, "0e0105", 0);
    }

    // We have 3 code paths in frame_reader:
    // 1) All frames except DATA, HEADERES and PUSH_PROMISE (here we test SETTING and SETTINGS with larger varints)
    // 2) PUSH_PROMISE and
    // 1) DATA and HEADERS frame (for this we will test DATA)

    // Test SETTINGS
    #[test]
    fn test_frame_reading_with_stream_settings1() {
        let (mut conn_c, mut conn_s) = connect();

        // create a stream
        let stream_id = conn_s.stream_create(StreamType::BiDi).unwrap();

        let mut fr: HFrameReader = HFrameReader::new();

        // Send and read settings frame 040406040804
        conn_s.stream_send(stream_id, &[0x4]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x4]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x6]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x4]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x8]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x4]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        assert!(fr.done());
        let f = fr.get_frame();
        assert!(f.is_ok());
        if let HFrame::Settings { settings } = f.unwrap() {
            assert!(settings.len() == 2);
            //            for i in settings.iter() {
            assert!(settings[0] == (HSettingType::MaxHeaderListSize, 4));
            assert!(settings[1] == (HSettingType::NumPlaceholders, 4));
        } else {
            panic!("wrong frame type");
        }
    }

    // Test SETTINGS with larger varints
    #[test]
    fn test_frame_reading_with_stream_settings2() {
        let (mut conn_c, mut conn_s) = connect();

        // create a stream
        let stream_id = conn_s.stream_create(StreamType::BiDi).unwrap();

        let mut fr: HFrameReader = HFrameReader::new();

        // Read settings frame 400406064004084100
        conn_s.stream_send(stream_id, &[0x40]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x4]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x6]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x6]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x40]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x4]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x8]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x41]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x0]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        assert!(fr.done());
        let f = fr.get_frame();
        assert!(f.is_ok());
        if let HFrame::Settings { settings } = f.unwrap() {
            assert!(settings.len() == 2);
            assert!(settings[0] == (HSettingType::MaxHeaderListSize, 4));
            assert!(settings[1] == (HSettingType::NumPlaceholders, 256));
        } else {
            panic!("wrong frame type");
        }
    }

    // Test PUSH_PROMISE
    #[test]
    fn test_frame_reading_with_stream_push_promise() {
        let (mut conn_c, mut conn_s) = connect();

        // create a stream
        let stream_id = conn_s.stream_create(StreamType::BiDi).unwrap();

        let mut fr: HFrameReader = HFrameReader::new();

        // Read pushpromise frame 05054101010203
        conn_s.stream_send(stream_id, &[0x5]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x5]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s.stream_send(stream_id, &[0x41]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        conn_s
            .stream_send(stream_id, &[0x1, 0x1, 0x2, 0x3])
            .unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        // headers are still on the stream.
        // assert that we have 3 bytes in the stream
        let mut buf = [0u8; 100];
        let (amount, _) = conn_c.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(amount, 3);

        assert!(fr.done());
        let f = fr.get_frame();
        assert!(f.is_ok());
        if let HFrame::PushPromise { push_id, len } = f.unwrap() {
            assert!(push_id == 257);
            assert!(len == 3);
        } else {
            panic!("wrong frame type");
        }
    }

    // Test DATA
    #[test]
    fn test_frame_reading_with_stream_data() {
        let (mut conn_c, mut conn_s) = connect();

        // create a stream
        let stream_id = conn_s.stream_create(StreamType::BiDi).unwrap();

        let mut fr: HFrameReader = HFrameReader::new();

        // Read data frame 0003010203
        conn_s
            .stream_send(stream_id, &[0x0, 0x3, 0x1, 0x2, 0x3])
            .unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        // payloead is still on the stream.
        // assert that we have 3 bytes in the stream
        let mut buf = [0u8; 100];
        let (amount, _) = conn_c.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(amount, 3);

        assert!(fr.done());
        let f = fr.get_frame();
        assert!(f.is_ok());
        if let HFrame::Data { len } = f.unwrap() {
            assert!(len == 3);
        } else {
            panic!("wrong frame type");
        }
    }

    // Test an unknown frame
    #[test]
    fn test_unknown_frame() {
        let (mut conn_c, mut conn_s) = connect();

        // create a stream
        let stream_id = conn_s.stream_create(StreamType::BiDi).unwrap();

        let mut fr: HFrameReader = HFrameReader::new();

        // Construct an unknown frame.
        const UNKNOWN_FRAME_LEN: usize = 832;
        let mut enc = Encoder::with_capacity(UNKNOWN_FRAME_LEN + 4);
        enc.encode_varint(1028u64); // Arbitrary type.
        enc.encode_varint(UNKNOWN_FRAME_LEN as u64);
        let mut buf: Vec<_> = enc.into();
        buf.resize(UNKNOWN_FRAME_LEN + buf.len(), 0);
        conn_s.stream_send(stream_id, &buf).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        // now receive a CANCEL_PUSH fram to see that frame reader is ok.
        conn_s.stream_send(stream_id, &[0x03, 0x01, 0x05]).unwrap();
        let out = conn_s.process(None, now());
        conn_c.process(out.dgram(), now());
        assert_eq!(Ok(false), fr.receive(&mut conn_c, stream_id));

        assert!(fr.done());
        let f = fr.get_frame();
        assert!(f.is_ok());
        if let HFrame::CancelPush { push_id } = f.unwrap() {
            assert!(push_id == 5);
        } else {
            panic!("wrong frame type");
        }
    }
}
