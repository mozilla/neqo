// TOTO(dragana) remove this
#![allow(unused_variables, dead_code)]

//extern crate quarta;
//use super::*;
use neqo_transport::data::*;
use neqo_transport::varint::*;
use neqo_transport::*;

const H3_FRAME_TYPE_DATA: u64 = 0x0;
const H3_FRAME_TYPE_HEADERS: u64 = 0x1;
const H3_FRAME_TYPE_PRIORITY: u64 = 0x2;
const H3_FRAME_TYPE_CANCEL_PUSH: u64 = 0x3;
const H3_FRAME_TYPE_SETTINGS: u64 = 0x4;
const H3_FRAME_TYPE_PUSH_PROMISE: u64 = 0x5;
const H3_FRAME_TYPE_GOAWAY: u64 = 0x6;
const H3_FRAME_TYPE_MAX_PUSH_ID: u64 = 0x7;
const H3_FRAME_TYPE_DUPLICATE_PUSH: u64 = 0x8;

const SETTINGS_MAX_HEADER_LIST_SIZE: u64 = 0x6;
const SETTINGS_NUM_PLACEHOLDERS: u64 = 0x8;

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
pub enum SettingType {
    MaxHeaderListSize,
    NumPlaceholders,
    UnknownType,
}

#[derive(PartialEq, Debug)]
pub enum HFrame {
    Data {
        data: Vec<u8>,
    },
    Headers {
        data: Vec<u8>,
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
        settings: Vec<(SettingType, u64)>,
    },
    PushPromise {
        push_id: u64,
        data: Vec<u8>,
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

    fn encode(&self, d: &mut Data) -> Res<()> {
        println!("DDD {}", self.get_type());
        d.encode_varint(self.get_type());

        match self {
            HFrame::Data { data } => {
                d.encode_varint(data.len() as u64);
                d.encode_vec(data);
            }
            HFrame::Headers { data } => {
                d.encode_varint(data.len() as u64);
                d.encode_vec(data);
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
                // thos is ok for now since we only have 2 setting types
                for iter in settings.iter() {
                    if iter.0 != SettingType::UnknownType {
                        len += 1 + get_varint_len(iter.1); // setting types are 6 and 8 so day fit in one byte
                    }
                }
                d.encode_varint(len);
                for iter in settings.iter() {
                    match iter.0 {
                        SettingType::MaxHeaderListSize => {
                            d.encode_varint(SETTINGS_MAX_HEADER_LIST_SIZE as u64);
                            d.encode_varint(iter.1);
                        }
                        SettingType::NumPlaceholders => {
                            d.encode_varint(SETTINGS_NUM_PLACEHOLDERS as u64);
                            d.encode_varint(iter.1);
                        }
                        SettingType::UnknownType => {}
                    }
                }
            }
            HFrame::PushPromise { push_id, data } => {
                d.encode_varint(data.len() as u64 + get_varint_len(*push_id));
                d.encode_varint(*push_id);
                d.encode_vec(data);
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
}
pub fn decode_hframe(d: &mut Data) -> Res<HFrame> {
    let c = d.peek_byte()?;
    println!("DDD3 {}", c);
    let t = d.decode_varint()?;
    println!("DDD2 {}", t);
    let mut len = d.decode_varint()?;

    match t {
        H3_FRAME_TYPE_DATA => {
            let mut data: Vec<u8>;
            data = d.decode_data(len as usize)?;
            Ok(HFrame::Data { data: data })
        }
        H3_FRAME_TYPE_HEADERS => {
            let mut data: Vec<u8>;
            data = d.decode_data(len as usize)?;
            Ok(HFrame::Headers { data: data })
        }
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
            let mut settings: Vec<(SettingType, u64)> = Vec::new();
            while len > 0 {
                let mut s: u64 = decode_varint_size(d)? as u64;
                if len < s {
                    return Err(Error::ErrNoMoreData);
                }
                let st_read = d.decode_varint()?;
                len -= s;
                let mut st = SettingType::UnknownType;
                match st_read {
                    SETTINGS_MAX_HEADER_LIST_SIZE => {
                        st = SettingType::MaxHeaderListSize;
                    }
                    SETTINGS_NUM_PLACEHOLDERS => {
                        st = SettingType::NumPlaceholders;
                    }
                    _ => {}
                }
                s = decode_varint_size(d)? as u64;
                if len < s {
                    return Err(Error::ErrNoMoreData);
                }
                let v = d.decode_varint()?;
                len -= s;
                if st != SettingType::UnknownType {
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
            len -= 1;
            let p = d.decode_varint()?;
            let mut data: Vec<u8>;
            data = d.decode_data(len as usize)?;
            Ok(HFrame::PushPromise {
                push_id: p,
                data: data,
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
        let f = HFrame::Data {
            data: vec![1, 2, 3],
        };
        enc_dec(&f, "0003010203");
    }

    #[test]
    fn test_headers_frame() {
        let f = HFrame::Headers {
            data: vec![1, 2, 3],
        };
        enc_dec(&f, "0103010203");
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
                (SettingType::MaxHeaderListSize, 4),
                (SettingType::NumPlaceholders, 4),
            ],
        };
        enc_dec(&f, "040406040804");
    }

    #[test]
    fn test_push_promise_frame4() {
        let f = HFrame::PushPromise {
            push_id: 4,
            data: vec![1, 2, 3],
        };
        enc_dec(&f, "050404010203");
    }

    #[test]
    fn test_goaway_frame4() {
        let f = HFrame::Goaway { stream_id: 5 };
        enc_dec(&f, "060105");
    }

    #[test]
    fn test_max_push_id_frame4() {
        let f = HFrame::MaxPushId { push_id: 5 };
        enc_dec(&f, "070105");
    }

    #[test]
    fn test_duplicate_push_frame4() {
        let f = HFrame::DuplicatePush { push_id: 5 };
        enc_dec(&f, "080105");
    }
}
