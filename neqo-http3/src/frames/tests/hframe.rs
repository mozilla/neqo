// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Decoder, Encoder};
use neqo_transport::StreamId;
use test_fixture::fixture_init;

use super::enc_dec_hframe;
use crate::{
    Priority,
    frames::{HFrame, HFrameType, reader::FrameDecoder as _},
    settings::{HSetting, HSettingType, HSettings},
};

#[test]
fn max_frame_data_unknown_type_is_unbounded() {
    assert_eq!(HFrame::max_frame_data(HFrameType(0x124b)), usize::MAX);
}

#[test]
fn data_frame() {
    let f = HFrame::Data { len: 3 };
    enc_dec_hframe(&f, "0003010203", 3, true);
}

#[test]
fn headers_frame() {
    let f = HFrame::Headers {
        header_block: vec![0x01, 0x02, 0x03],
    };
    enc_dec_hframe(&f, "0103010203", 0, true);
}

#[test]
fn settings_frame4() {
    let f = HFrame::Settings {
        settings: HSettings::new(&[HSetting::new(HSettingType::MaxHeaderListSize, 4)]),
    };
    enc_dec_hframe(&f, "04020604", 0, false);
}

#[test]
fn goaway_frame4() {
    let f = HFrame::Goaway {
        stream_id: StreamId::new(5),
    };
    enc_dec_hframe(&f, "070105", 0, false);
}

#[test]
fn grease() {
    fn make_grease() -> u64 {
        let mut enc = Encoder::default();
        HFrame::Grease.encode(&mut enc);
        let mut dec = Decoder::from(&enc);
        let ft = dec.decode_varint().unwrap();
        assert_eq!((ft - 0x21) % 0x1f, 0);
        let body = dec.decode_vvec().unwrap();
        assert!(body.len() <= 7);
        ft
    }

    fixture_init();
    let t1 = make_grease();
    let t2 = make_grease();
    assert_ne!(t1, t2);
}

#[test]
fn priority_update_request_default() {
    let f = HFrame::PriorityUpdateRequest {
        element_id: 6,
        priority: Priority::default(),
    };
    enc_dec_hframe(&f, "800f07000106", 0, true);
}

#[test]
fn priority_update_request_incremental_default() {
    let f = HFrame::PriorityUpdateRequest {
        element_id: 7,
        priority: Priority::new(6, false),
    };
    enc_dec_hframe(&f, "800f07000407753d36", 0, true); // "u=6"
}

#[test]
fn priority_update_request_urgency_default() {
    let f = HFrame::PriorityUpdateRequest {
        element_id: 8,
        priority: Priority::new(3, true),
    };
    enc_dec_hframe(&f, "800f0700020869", 0, true); // "i"
}
