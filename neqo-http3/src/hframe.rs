// TOTO(dragana) remove this
#![allow(unused_variables, dead_code)]

use neqo_transport::data::*;
use neqo_transport::stream::Recvable;
use neqo_transport::varint::*;
use neqo_transport::{Error, Res};

const H3_FRAME_TYPE_DATA: u64 = 0x0;
const H3_FRAME_TYPE_HEADERS: u64 = 0x1;
const H3_FRAME_TYPE_PRIORITY: u64 = 0x2;
const H3_FRAME_TYPE_CANCEL_PUSH: u64 = 0x3;
const H3_FRAME_TYPE_SETTINGS: u64 = 0x4;
const H3_FRAME_TYPE_PUSH_PROMISE: u64 = 0x5;
const H3_FRAME_TYPE_GOAWAY: u64 = 0x7;
const H3_FRAME_TYPE_MAX_PUSH_ID: u64 = 0xd;
const H3_FRAME_TYPE_DUPLICATE_PUSH: u64 = 0xe;

const SETTINGS_MAX_HEADER_LIST_SIZE: u64 = 0x6;
const SETTINGS_NUM_PLACEHOLDERS: u64 = 0x8;

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

fn prior_elem_from_byte(b: u8) -> Res<PrioritizedElementType> {
    match b {
        0x0 => Ok(PrioritizedElementType::RequestStream),
        0x1 => Ok(PrioritizedElementType::PushStream),
        0x2 => Ok(PrioritizedElementType::Placeholder),
        0x3 => Ok(PrioritizedElementType::CurrentStream),
        _ => Err(Error::ErrDecodingFrame),
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ElementDependencyType {
    RequestStream,
    PushStream,
    Placeholder,
    Root,
}

fn elem_dep_from_byte(b: u8) -> Res<ElementDependencyType> {
    match b {
        0x0 => Ok(ElementDependencyType::RequestStream),
        0x1 => Ok(ElementDependencyType::PushStream),
        0x2 => Ok(ElementDependencyType::Placeholder),
        0x3 => Ok(ElementDependencyType::Root),
        _ => Err(Error::ErrDecodingFrame),
    }
}

#[derive(PartialEq, Debug)]
pub enum HSettingType {
    MaxHeaderListSize,
    NumPlaceholders,
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
    fn get_type(&self) -> u64 {
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
pub fn decode_hframe(d: &mut Data) -> Res<HFrame> {
    let t = d.decode_varint()?;
    let len = d.decode_varint()?;
    decode_payload(d, t, len)
}

fn decode_payload(d: &mut Data, t: u64, mut len: u64) -> Res<HFrame> {
    match t {
        H3_FRAME_TYPE_DATA => Ok(HFrame::Data { len: len }),
        H3_FRAME_TYPE_HEADERS => Ok(HFrame::Headers { len: len }),
        H3_FRAME_TYPE_PRIORITY => {
            if len < 1 {
                return Err(Error::ErrNoMoreData);
            }
            let tb = d.decode_byte()?;
            len -= 1;
            let mut s: u64 = decode_varint_size(d)? as u64;
            if len < s {
                return Err(Error::ErrNoMoreData);
            }
            let pe = d.decode_varint()?;
            len -= s;
            s = decode_varint_size(d)? as u64;
            if len < s {
                return Err(Error::ErrNoMoreData);
            }
            let de = d.decode_varint()?;
            len -= s;
            if len < 1 {
                return Err(Error::ErrNoMoreData);
            }
            let w = d.decode_byte()?;
            Ok(HFrame::Priority {
                priorized_elem_type: prior_elem_from_byte(tb & 0x3)?,
                elem_dependensy_type: elem_dep_from_byte((tb & (0x3 << 2)) >> 2)?,
                priority_elem_id: pe,
                elem_dependency_id: de,
                weight: w,
            })
        }
        H3_FRAME_TYPE_CANCEL_PUSH => {
            if len < decode_varint_size(d)? as u64 {
                return Err(Error::ErrNoMoreData);
            }
            Ok(HFrame::CancelPush {
                push_id: d.decode_varint()?,
            })
        }
        H3_FRAME_TYPE_SETTINGS => {
            let mut settings: Vec<(HSettingType, u64)> = Vec::new();
            while len > 0 {
                let mut s: u64 = decode_varint_size(d)? as u64;
                if len < s {
                    return Err(Error::ErrNoMoreData);
                }
                let st_read = d.decode_varint()?;
                len -= s;
                let mut st = HSettingType::UnknownType;
                match st_read {
                    SETTINGS_MAX_HEADER_LIST_SIZE => {
                        st = HSettingType::MaxHeaderListSize;
                    }
                    SETTINGS_NUM_PLACEHOLDERS => {
                        st = HSettingType::NumPlaceholders;
                    }
                    _ => {}
                }
                s = decode_varint_size(d)? as u64;
                if len < s {
                    return Err(Error::ErrNoMoreData);
                }
                let v = d.decode_varint()?;
                len -= s;
                if st != HSettingType::UnknownType {
                    settings.push((st, v));
                }
            }
            Ok(HFrame::Settings { settings: settings })
        }
        H3_FRAME_TYPE_PUSH_PROMISE => {
            let s: u64 = decode_varint_size(d)? as u64;
            if len < s {
                return Err(Error::ErrNoMoreData);
            }
            let p = d.decode_varint()?;
            len -= s;
            Ok(HFrame::PushPromise {
                push_id: p,
                len: len,
            })
        }
        H3_FRAME_TYPE_GOAWAY => {
            let s: u64 = decode_varint_size(d)? as u64;
            if len < s {
                return Err(Error::ErrNoMoreData);
            }
            let id = d.decode_varint()?;
            Ok(HFrame::Goaway { stream_id: id })
        }
        H3_FRAME_TYPE_MAX_PUSH_ID => {
            let s: u64 = decode_varint_size(d)? as u64;
            if len < s {
                return Err(Error::ErrNoMoreData);
            }
            let id = d.decode_varint()?;
            Ok(HFrame::MaxPushId { push_id: id })
        }
        H3_FRAME_TYPE_DUPLICATE_PUSH => {
            let s: u64 = decode_varint_size(d)? as u64;
            if len < s {
                return Err(Error::ErrNoMoreData);
            }
            let id = d.decode_varint()?;
            Ok(HFrame::DuplicatePush { push_id: id })
        }
        _ => Err(Error::ErrUnknownFrameType),
    }
}

#[derive(Copy, Clone, PartialEq)]
enum HFrameReaderState {
    GetType,
    GetLength,
    GetPushPromiseData,
    GetData,
    Done,
}

pub struct HFrameReader {
    state: HFrameReaderState,
    buf: Vec<u8>,
    offset: usize,
    needs: usize,
    hframe_type: u64,
    hframe_len: u64,
}

impl HFrameReader {
    pub fn new() -> HFrameReader {
        HFrameReader {
            state: HFrameReaderState::GetType,
            offset: 0,
            needs: 1,
            hframe_type: 0,
            hframe_len: 0,
            buf: vec![0; 2], //TODO set this to a better value. I set it to 2 for better testing.
        }
    }

    pub fn reset(&mut self) {
        self.state = HFrameReaderState::GetType;
        self.offset = 0;
        self.needs = 1;
    }

    pub fn receive(&mut self, s: &mut Recvable) -> Res<bool> {
        let r = loop {
            match self.state {
                HFrameReaderState::GetType => {
                    if let Some(v) = self.get_varint(s)? {
                        self.hframe_type = v;
                        self.state = HFrameReaderState::GetLength;
                        self.offset = 0;
                        self.needs = 1;
                    } else {
                        break Ok(false);
                    }
                }

                HFrameReaderState::GetLength => {
                    if let Some(v) = self.get_varint(s)? {
                        self.hframe_len = v;
                        if self.hframe_type == H3_FRAME_TYPE_DATA
                            || self.hframe_type == H3_FRAME_TYPE_HEADERS
                        {
                            self.state = HFrameReaderState::Done;
                            self.offset = 0;
                            self.needs = 0;
                        } else if self.hframe_type == H3_FRAME_TYPE_PUSH_PROMISE {
                            self.offset = 0;
                            self.needs = 1;
                            self.state = HFrameReaderState::GetPushPromiseData;
                        } else {
                            self.offset = 0;
                            self.needs = self.hframe_len as usize;
                            self.state = HFrameReaderState::GetData;
                        }
                    } else {
                        break Ok(false);
                    }
                }
                HFrameReaderState::GetPushPromiseData => {
                    assert!(self.needs > 0);
                    if self.get(s)? == 0 {
                        break Ok(false);
                    }
                    if self.needs == 0 {
                        if self.offset == 1 {
                            self.needs = decode_varint_size_from_byte(self.buf[0])? - 1;
                            if self.needs == 0 {
                                self.state = HFrameReaderState::Done;
                            }
                        } else {
                            self.state = HFrameReaderState::Done;
                        }
                    }
                }
                HFrameReaderState::GetData => {
                    if self.needs != 0 && self.get(s)? == 0 {
                        break Ok(false);
                    }
                    if self.needs == 0 {
                        self.state = HFrameReaderState::Done;
                    } else {
                        break Ok(false);
                    }
                }
                HFrameReaderState::Done => {
                    break Ok(true);
                }
            }
        };
        r
    }

    pub fn done(&self) -> bool {
        self.state == HFrameReaderState::Done
    }

    pub fn get_frame(&self) -> Res<HFrame> {
        let mut d = Data::from_slice(&self.buf);
        decode_payload(&mut d, self.hframe_type, self.hframe_len)
    }

    fn get_varint(&mut self, s: &mut Recvable) -> Res<Option<u64>> {
        assert!(self.needs > 0);
        if self.get(s)? == 0 {
            return Ok(None);
        }
        if self.needs == 0 {
            if self.offset == 1 {
                self.needs = decode_varint_size_from_byte(self.buf[0])? - 1;
                if self.needs == 0 {
                    let v = decode_varint(&self.buf)?;
                    return Ok(Some(v));
                }
            } else {
                let v = decode_varint(&self.buf)?;
                return Ok(Some(v));
            }
        }
        return Ok(None);
    }
    fn get(&mut self, s: &mut Recvable) -> Res<usize> {
        if self.needs > (self.buf.len() - self.offset) {
            let ext = self.needs - (self.buf.len() - self.offset);
            self.buf.append(&mut vec![0; ext]);
        }
        let r = s.read_with_amount(&mut self.buf[self.offset..], self.needs as u64)?;
        self.needs -= r as usize;
        self.offset += r as usize;
        Ok(r as usize)
    }
}

pub fn decode_varint_size_from_byte(b: u8) -> Res<usize> {
    let l = match (b & 0xc0) >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => panic!("Can't happen"),
    };
    Ok(l as usize)
}

pub fn decode_varint(b: &[u8]) -> Res<u64> {
    if b.len() < 1 {
        return Err(Error::ErrDecodingFrame);
    }
    let l = decode_varint_size_from_byte(b[0])?;

    if b.len() < l {
        return Err(Error::ErrDecodingFrame);
    }
    let mut res: u64 = 0;
    let mut mask = 0x3f;
    for i in 0..l {
        res <<= 8;
        let z = b[i] & mask;
        mask = 0xff;
        res += z as u64;
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_dec(f: &HFrame, s: &str) {
        let mut d = Data::default();

        f.encode(&mut d).unwrap();
        assert_eq!(d, Data::from_hex(s));

        let f2 = decode_hframe(&mut d).unwrap();
        assert_eq!(*f, f2);
    }

    #[test]
    fn test_data_frame() {
        let f = HFrame::Data { len: 3 };
        enc_dec(&f, "0003");
    }

    #[test]
    fn test_headers_frame() {
        let f = HFrame::Headers { len: 3 };
        enc_dec(&f, "0103");
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
        enc_dec(&f, "020400020103");
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
        enc_dec(&f, "020405020103");
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
        enc_dec(&f, "02040a020103");
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
        enc_dec(&f, "02040f020103");
    }

    #[test]
    fn test_cancel_push_frame4() {
        let f = HFrame::CancelPush { push_id: 5 };
        enc_dec(&f, "030105");
    }

    #[test]
    fn test_settings_frame4() {
        let f = HFrame::Settings {
            settings: vec![
                (HSettingType::MaxHeaderListSize, 4),
                (HSettingType::NumPlaceholders, 4),
            ],
        };
        enc_dec(&f, "040406040804");
    }

    #[test]
    fn test_push_promise_frame4() {
        let f = HFrame::PushPromise { push_id: 4, len: 4 };
        enc_dec(&f, "050504");
    }

    #[test]
    fn test_goaway_frame4() {
        let f = HFrame::Goaway { stream_id: 5 };
        enc_dec(&f, "070105");
    }

    #[test]
    fn test_max_push_id_frame4() {
        let f = HFrame::MaxPushId { push_id: 5 };
        enc_dec(&f, "0d0105");
    }

    #[test]
    fn test_duplicate_push_frame4() {
        let f = HFrame::DuplicatePush { push_id: 5 };
        enc_dec(&f, "0e0105");
    }

    use crate::stream_test::{get_stream_type, Stream};
    use neqo_transport::connection::Role;
    use neqo_transport::frame::StreamType;

    // We have 3 code paths in frame_reader:
    // 1) All frames except DATA, HEADERES and PUSH_PROMISE (here we test SETTING and SETTINGS with larger varints)
    // 2) PUSH_PUROMISE and
    // 1) DATA and HEADERS frame (for this we will test DATA)

    // Test SETTINGS
    #[test]
    fn test_frame_reading_with_stream_settings1() {
        let mut s = Stream::new(get_stream_type(Role::Client, StreamType::UniDi));
        let mut fr: HFrameReader = HFrameReader::new();

        // Read settings frame 040406040804
        s.recv_buf.extend(vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x6]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x8]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x4]);
        assert_eq!(Ok(true), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
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
        let mut s = Stream::new(get_stream_type(Role::Client, StreamType::UniDi));
        let mut fr: HFrameReader = HFrameReader::new();

        // Read settings frame 400406064004084100
        s.recv_buf.extend(vec![0x40]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        s.recv_buf.extend(vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x6]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x6]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        s.recv_buf.extend(vec![0x40]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x4]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x8]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        s.recv_buf.extend(vec![0x41]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x0]);
        assert_eq!(Ok(true), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
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
        let mut s = Stream::new(get_stream_type(Role::Client, StreamType::UniDi));
        let mut fr: HFrameReader = HFrameReader::new();

        // Read pushpromise frame 05054101010203
        s.recv_buf.extend(vec![0x5]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x5]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x41]);
        assert_eq!(Ok(false), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 0);
        s.recv_buf.extend(vec![0x1, 0x1, 0x2, 0x3]);
        assert_eq!(Ok(true), fr.receive(&mut s));

        // headers are still on the stream.
        assert!(s.recv_data_ready() == 3);
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
        let mut s = Stream::new(get_stream_type(Role::Client, StreamType::UniDi));
        let mut fr: HFrameReader = HFrameReader::new();

        // Read data frame 0003010203
        s.recv_buf.extend(vec![0x0, 0x3, 0x1, 0x2, 0x3]);
        assert_eq!(Ok(true), fr.receive(&mut s));
        assert!(s.recv_data_ready() == 3);
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
