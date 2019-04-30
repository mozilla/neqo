// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// TOTO(dragana) remove this
#![allow(unused_variables, dead_code)]

use neqo_common::data::*;
use neqo_common::readbuf::ReadBuf;
use neqo_common::varint::*;

#[cfg(test)]
use crate::transport::Connection;

#[cfg(not(test))]
use neqo_transport::Connection;

use crate::recvable::RecvableWrapper;
use crate::{Error, Res};

pub type HFrameType = u64;

const H3_FRAME_TYPE_DATA: HFrameType = 0x0;
const H3_FRAME_TYPE_HEADERS: HFrameType = 0x1;
const H3_FRAME_TYPE_PRIORITY: HFrameType = 0x2;
const H3_FRAME_TYPE_CANCEL_PUSH: HFrameType = 0x3;
const H3_FRAME_TYPE_SETTINGS: HFrameType = 0x4;
const H3_FRAME_TYPE_PUSH_PROMISE: HFrameType = 0x5;
const H3_FRAME_TYPE_GOAWAY: HFrameType = 0x7;
const H3_FRAME_TYPE_MAX_PUSH_ID: HFrameType = 0xd;
const H3_FRAME_TYPE_DUPLICATE_PUSH: HFrameType = 0xe;

const H3_FRAME_TYPE_UNKNOWN: u64 = 0xff; // this is only internal!!!

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
        elem_dependensy_type: ElementDependencyType,
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

    pub fn encode(&self, d: &mut Data) -> Res<()> {
        d.encode_varint(self.get_type());

        match self {
            HFrame::Data { len } => {
                d.encode_varint(*len);
            }
            HFrame::Headers { len } => {
                d.encode_varint(*len);
            }
            HFrame::Priority {
                priorized_elem_type,
                elem_dependensy_type,
                priority_elem_id,
                elem_dependency_id,
                weight,
            } => {
                d.encode_varint(
                    1 + get_varint_len(*priority_elem_id) + get_varint_len(*elem_dependency_id) + 1,
                );
                d.encode_byte((*priorized_elem_type as u8) | ((*elem_dependensy_type as u8) << 2));
                d.encode_varint(*priority_elem_id);
                d.encode_varint(*elem_dependency_id);
                d.encode_byte(*weight);
            }
            HFrame::CancelPush { push_id } => {
                d.encode_varint(get_varint_len(*push_id));
                d.encode_varint(*push_id);
            }
            HFrame::Settings { settings } => {
                let mut len = 0;
                // finding the length in this way ok since we only have 2 setting types
                for iter in settings.iter() {
                    if iter.0 != HSettingType::UnknownType {
                        len += 1 + get_varint_len(iter.1); // setting types are 6 and 8 so day fit in one byte
                    }
                }
                d.encode_varint(len);
                for iter in settings.iter() {
                    match iter.0 {
                        HSettingType::MaxHeaderListSize => {
                            d.encode_varint(SETTINGS_MAX_HEADER_LIST_SIZE as u64);
                            d.encode_varint(iter.1);
                        }
                        HSettingType::NumPlaceholders => {
                            d.encode_varint(SETTINGS_NUM_PLACEHOLDERS as u64);
                            d.encode_varint(iter.1);
                        }
                        HSettingType::MaxTableSize => {
                            d.encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY as u64);
                            d.encode_varint(iter.1);
                        }
                        HSettingType::BlockedStreams => {
                            d.encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS as u64);
                            d.encode_varint(iter.1);
                        }
                        HSettingType::UnknownType => {}
                    }
                }
            }
            HFrame::PushPromise { push_id, len } => {
                d.encode_varint(*len + get_varint_len(*push_id));
                d.encode_varint(*push_id);
            }
            HFrame::Goaway { stream_id } => {
                d.encode_varint(get_varint_len(*stream_id));
                d.encode_varint(*stream_id);
            }
            HFrame::MaxPushId { push_id } => {
                d.encode_varint(get_varint_len(*push_id));
                d.encode_varint(*push_id);
            }
            HFrame::DuplicatePush { push_id } => {
                d.encode_varint(get_varint_len(*push_id));
                d.encode_varint(*push_id);
            }
        }
        Ok(())
    }

    pub fn is_allowed(&self, s: HStreamType) -> bool {
        match self {
            HFrame::Data { .. } => {
                if s == HStreamType::Control {
                    false
                } else {
                    true
                }
            }
            HFrame::Headers { .. } => {
                if s == HStreamType::Control {
                    false
                } else {
                    true
                }
            }
            HFrame::Priority { .. } => {
                if s == HStreamType::Push {
                    false
                } else {
                    true
                }
            }
            HFrame::CancelPush { .. } => {
                if s == HStreamType::Control {
                    true
                } else {
                    false
                }
            }
            HFrame::Settings { .. } => {
                if s == HStreamType::Control {
                    true
                } else {
                    false
                }
            }
            HFrame::PushPromise { .. } => {
                if s == HStreamType::Request {
                    true
                } else {
                    false
                }
            }
            HFrame::Goaway { .. } => {
                if s == HStreamType::Control {
                    true
                } else {
                    false
                }
            }
            HFrame::MaxPushId { .. } => {
                if s == HStreamType::Control {
                    true
                } else {
                    false
                }
            }
            HFrame::DuplicatePush { .. } => {
                if s == HStreamType::Request {
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum HFrameReaderState {
    GetType,
    GetLength,
    GetPushPromiseData,
    GetData,
    Done,
}

#[derive(Debug)]
pub struct HFrameReader {
    state: HFrameReaderState,
    reader: ReadBuf,
    hframe_type: u64,
    hframe_len: u64,
}

impl HFrameReader {
    pub fn new() -> HFrameReader {
        HFrameReader {
            state: HFrameReaderState::GetType,
            hframe_type: 0,
            hframe_len: 0,
            reader: ReadBuf::new(),
        }
    }

    pub fn reset(&mut self) {
        self.state = HFrameReaderState::GetType;
        self.reader.reset();
    }

    // returns true if quic stream was closed.
    pub fn receive(&mut self, conn: &mut Connection, stream_id: u64) -> Res<bool> {
        let mut w = RecvableWrapper::wrap(conn, stream_id);
        loop {
            match self.state {
                HFrameReaderState::GetType => {
                    let (rv, fin) = self.reader.get_varint(&mut w)?;

                    if rv == 0 {
                        break Ok(fin);
                    }

                    if self.reader.done() {
                        self.hframe_type = decode_varint(&mut self.reader)?;
                        self.reader.reset();
                        self.state = HFrameReaderState::GetLength;
                    }

                    if fin {
                        break Ok(fin);
                    }
                }

                HFrameReaderState::GetLength => {
                    let (rv, fin) = self.reader.get_varint(&mut w)?;
                    if rv == 0 {
                        break Ok(fin);
                    }
                    if self.reader.done() {
                        self.hframe_len = decode_varint(&mut self.reader)?;
                        self.reader.reset();

                        // DATA and HEADERS payload are left on the quic stream and picked up separately
                        if self.hframe_type == H3_FRAME_TYPE_DATA
                            || self.hframe_type == H3_FRAME_TYPE_HEADERS
                        {
                            self.state = HFrameReaderState::Done;

                        // For push frame we only decode the first varint. Headers blocks will be picked up separately.
                        } else if self.hframe_type == H3_FRAME_TYPE_PUSH_PROMISE {
                            self.state = HFrameReaderState::GetPushPromiseData;

                        // for othere frame get all data before decoding.
                        } else {
                            if self.hframe_len > 0 {
                                self.reader.get_len(self.hframe_len);
                                self.state = HFrameReaderState::GetData;
                            } else {
                                self.state = HFrameReaderState::Done;
                            }
                        }
                    }

                    if fin {
                        break Ok(fin);
                    }
                }
                HFrameReaderState::GetPushPromiseData => {
                    let (rv, fin) = self.reader.get_varint(&mut w)?;
                    if rv == 0 {
                        break Ok(fin);
                    }
                    if self.reader.done() {
                        // we will read payload when we decode th frame.
                        self.state = HFrameReaderState::Done
                    }

                    if fin {
                        break Ok(fin);
                    }
                }
                HFrameReaderState::GetData => {
                    let (rv, fin) = self.reader.get(&mut w)?;
                    if rv == 0 {
                        break Ok(fin);
                    }
                    if self.reader.done() {
                        self.state = HFrameReaderState::Done;
                    }

                    if fin {
                        break Ok(fin);
                    }
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
            Err(Error::NotEnoughData)
        } else {
            let f = match self.hframe_type {
                H3_FRAME_TYPE_DATA => HFrame::Data {
                    len: self.hframe_len,
                },
                H3_FRAME_TYPE_HEADERS => HFrame::Headers {
                    len: self.hframe_len,
                },
                H3_FRAME_TYPE_PRIORITY => {
                    let tb = self.reader.decode_byte()?;
                    let pe = decode_varint(&mut self.reader)?;
                    let de = decode_varint(&mut self.reader)?;
                    let w = self.reader.decode_byte()?;
                    HFrame::Priority {
                        priorized_elem_type: prior_elem_from_byte(tb),
                        elem_dependensy_type: elem_dep_from_byte(tb),
                        priority_elem_id: pe,
                        elem_dependency_id: de,
                        weight: w,
                    }
                }
                H3_FRAME_TYPE_CANCEL_PUSH => HFrame::CancelPush {
                    push_id: decode_varint(&mut self.reader)?,
                },
                H3_FRAME_TYPE_SETTINGS => {
                    let mut settings: Vec<(HSettingType, u64)> = Vec::new();
                    while self.reader.remaining() > 0 {
                        let st_read = decode_varint(&mut self.reader)?;
                        let mut st = HSettingType::UnknownType;
                        match st_read {
                            SETTINGS_MAX_HEADER_LIST_SIZE => {
                                st = HSettingType::MaxHeaderListSize;
                            },
                            SETTINGS_NUM_PLACEHOLDERS => {
                                st = HSettingType::NumPlaceholders;
                            },
                            SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                                st = HSettingType::MaxTableSize;
                            },
                            SETTINGS_QPACK_BLOCKED_STREAMS => {
                                st = HSettingType::BlockedStreams;
                            },
                            _ => {}
                        };
                        let v = decode_varint(&mut self.reader)?;
                        if st != HSettingType::UnknownType {
                            settings.push((st, v));
                        }
                    }
                    HFrame::Settings { settings: settings }
                }
                H3_FRAME_TYPE_PUSH_PROMISE => {
                    let p = decode_varint(&mut self.reader)?;
                    let len = self.hframe_len - self.reader.len() as u64;
                    HFrame::PushPromise {
                        push_id: p,
                        len: len,
                    }
                }
                H3_FRAME_TYPE_GOAWAY => HFrame::Goaway {
                    stream_id: decode_varint(&mut self.reader)?,
                },
                H3_FRAME_TYPE_MAX_PUSH_ID => HFrame::MaxPushId {
                    push_id: decode_varint(&mut self.reader)?,
                },
                H3_FRAME_TYPE_DUPLICATE_PUSH => HFrame::DuplicatePush {
                    push_id: decode_varint(&mut self.reader)?,
                },
                _ => panic!("We should not be in sate Done with unknown frame type!"),
            };
            self.reset();
            Ok(f)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_transport::connection::Role;
    use num_traits::Num;

    fn enc_dec(f: &HFrame, st: &str, r: usize) {
        let mut d = Data::default();

        f.encode(&mut d).unwrap();

        // For data, headers and push_promise we do not read all bytes from the buffer
        let mut d2 = Data::from_hex(st);
        let len = d2.remaining();
        assert_eq!(d.as_mut_vec()[..], d2.as_mut_vec()[..len - r]);

        let mut conn = Connection::new_client();
        let mut stream_id = 0;
        match conn.stream_create_net(Role::Server, StreamType::UniDi) {
            Ok(s) => stream_id = s,
            Err(_) => assert!(false, "We must be able to create a stream"),
        };
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
        conn.stream_recv_net(stream_id, &buf);

        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert_eq!(conn.recv_data_ready_amount(stream_id), r);
        if !fr.done() {
            assert!(false);
        }
        if let Ok(f2) = fr.get_frame() {
            assert_eq!(*f, f2);
        } else {
            assert!(false)
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
            elem_dependensy_type: ElementDependencyType::RequestStream,
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
            elem_dependensy_type: ElementDependencyType::PushStream,
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
            elem_dependensy_type: ElementDependencyType::Placeholder,
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
            elem_dependensy_type: ElementDependencyType::Root,
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

    use neqo_transport::frame::StreamType;

    // We have 3 code paths in frame_reader:
    // 1) All frames except DATA, HEADERES and PUSH_PROMISE (here we test SETTING and SETTINGS with larger varints)
    // 2) PUSH_PUROMISE and
    // 1) DATA and HEADERS frame (for this we will test DATA)

    // Test SETTINGS
    #[test]
    fn test_frame_reading_with_stream_settings1() {
        let mut conn = Connection::new_client();
        let mut stream_id = 0;
        match conn.stream_create_net(Role::Server, StreamType::UniDi) {
            Ok(s) => stream_id = s,
            Err(_) => assert!(false, "We must be able to create a stream"),
        };
        let mut fr: HFrameReader = HFrameReader::new();

        // Read settings frame 040406040804
        conn.stream_recv_net(stream_id, &vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x6]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x8]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        if !fr.done() {
            assert!(false);
        }
        let f1 = fr.get_frame();
        if let Ok(f) = f1 {
            if let HFrame::Settings { settings } = f {
                assert!(settings.len() == 2);
                //            for i in settings.iter() {
                assert!(settings[0] == (HSettingType::MaxHeaderListSize, 4));
                assert!(settings[1] == (HSettingType::NumPlaceholders, 4));
            } else {
                assert!(false);
            }
        } else {
            assert!(false);
        }
    }

    // Test SETTINGS with larger varints
    #[test]
    fn test_frame_reading_with_stream_settings2() {
        let mut conn = Connection::new_client();
        let mut stream_id = 0;
        match conn.stream_create_net(Role::Server, StreamType::UniDi) {
            Ok(s) => stream_id = s,
            Err(_) => assert!(false, "We must be able to create a stream"),
        };
        let mut fr: HFrameReader = HFrameReader::new();

        // Read settings frame 400406064004084100
        conn.stream_recv_net(stream_id, &vec![0x40]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        conn.stream_recv_net(stream_id, &vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x6]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x6]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        conn.stream_recv_net(stream_id, &vec![0x40]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x8]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        conn.stream_recv_net(stream_id, &vec![0x41]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x0]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        if !fr.done() {
            assert!(false);
        }
        let f1 = fr.get_frame();
        if let Ok(f) = f1 {
            if let HFrame::Settings { settings } = f {
                assert!(settings.len() == 2);
                assert!(settings[0] == (HSettingType::MaxHeaderListSize, 4));
                assert!(settings[1] == (HSettingType::NumPlaceholders, 256));
            } else {
                assert!(false);
            }
        } else {
            assert!(false);
        }
    }

    // Test PUSH_PROMISE
    #[test]
    fn test_frame_reading_with_stream_push_promise() {
        let mut conn = Connection::new_client();
        let mut stream_id = 0;
        match conn.stream_create_net(Role::Server, StreamType::UniDi) {
            Ok(s) => stream_id = s,
            Err(_) => assert!(false, "We must be able to create a stream"),
        };
        let mut fr: HFrameReader = HFrameReader::new();

        // Read pushpromise frame 05054101010203
        conn.stream_recv_net(stream_id, &vec![0x5]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x5]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x41]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(!conn.data_ready(stream_id));
        conn.stream_recv_net(stream_id, &vec![0x1, 0x1, 0x2, 0x3]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));

        // headers are still on the stream.
        assert_eq!(conn.recv_data_ready_amount(stream_id), 3);
        if !fr.done() {
            assert!(false);
        }
        let f1 = fr.get_frame();
        if let Ok(f) = f1 {
            if let HFrame::PushPromise { push_id, len } = f {
                assert!(push_id == 257);
                assert!(len == 3);
            } else {
                assert!(false);
            }
        } else {
            assert!(false);
        }
    }

    // Test DATA
    #[test]
    fn test_frame_reading_with_stream_data() {
        let mut conn = Connection::new_client();
        let mut stream_id = 0;
        match conn.stream_create_net(Role::Server, StreamType::UniDi) {
            Ok(s) => stream_id = s,
            Err(_) => assert!(false, "We must be able to create a stream"),
        };
        let mut fr: HFrameReader = HFrameReader::new();

        // Read data frame 0003010203
        conn.stream_recv_net(stream_id, &vec![0x0, 0x3, 0x1, 0x2, 0x3]);
        assert_eq!(Ok(false), fr.receive(&mut conn, stream_id));
        assert!(conn.recv_data_ready_amount(stream_id) == 3);
        if !fr.done() {
            assert!(false);
        }
        let f1 = fr.get_frame();
        if let Ok(f) = f1 {
            if let HFrame::Data { len } = f {
                assert!(len == 3);
            } else {
                assert!(false);
            }
        } else {
            assert!(false);
        }
    }
}
