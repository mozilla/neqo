// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::time::Instant;

use neqo_common::{qlog::Qlog, to_u64};
use neqo_transport::StreamId;
use qlog::events::{
    DataRecipient, EventData, RawInfo,
    http3::{Initiator, ParametersSet},
    quic::StreamDataMoved,
};

use crate::settings::{HSettingType, HSettings};

fn h3_data_moved(
    qlog: &mut Qlog,
    stream_id: StreamId,
    amount: usize,
    from: DataRecipient,
    to: DataRecipient,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::QuicStreamDataMoved(StreamDataMoved {
                stream_id: Some(stream_id.as_u64()),
                offset: None,
                from: Some(from),
                to: Some(to),
                additional_info: None,
                raw: Some(RawInfo {
                    length: Some(to_u64(amount)),
                    payload_length: None,
                    data: None,
                }),
            }))
        },
        now,
    );
}

pub fn h3_data_moved_up(qlog: &mut Qlog, stream_id: StreamId, amount: usize, now: Instant) {
    h3_data_moved(
        qlog,
        stream_id,
        amount,
        DataRecipient::Transport,
        DataRecipient::Application,
        now,
    );
}

pub fn h3_data_moved_down(qlog: &mut Qlog, stream_id: StreamId, amount: usize, now: Instant) {
    h3_data_moved(
        qlog,
        stream_id,
        amount,
        DataRecipient::Application,
        DataRecipient::Transport,
        now,
    );
}

pub fn parameters_set(
    qlog: &mut Qlog,
    initiator: Initiator,
    http3_frame_settings: &HSettings,
    wait_for_settings: Option<bool>,
    now: Instant,
) {
    qlog.add_event_at(
        || {
            Some(EventData::Http3ParametersSet(ParametersSet {
                initiator: Some(initiator),
                max_field_section_size: Some(
                    http3_frame_settings.get(HSettingType::MaxHeaderListSize),
                ),
                max_table_capacity: Some(http3_frame_settings.get(HSettingType::MaxTableCapacity)),
                blocked_streams_count: Some(http3_frame_settings.get(HSettingType::BlockedStreams)),
                extended_connect: u16::try_from(
                    http3_frame_settings.get(HSettingType::EnableConnect),
                )
                .ok(),
                h3_datagram: u16::try_from(
                    http3_frame_settings.get(HSettingType::EnableH3Datagram),
                )
                .ok(),
                waits_for_settings: wait_for_settings,
            }))
        },
        now,
    );
}

#[cfg(test)]
mod tests {

    use qlog::events::http3::Initiator;
    use test_fixture::new_neqo_qlog;

    use super::parameters_set;
    use crate::settings::{HSetting, HSettingType, HSettings};

    #[test]
    fn parameters_set_works() {
        let (mut qlog, contents) = new_neqo_qlog();
        let settings = HSettings::new(&[
            HSetting::new(HSettingType::BlockedStreams, 300),
            HSetting::new(HSettingType::EnableConnect, 1),
            HSetting::new(HSettingType::EnableH3Datagram, 1),
            HSetting::new(HSettingType::MaxHeaderListSize, 100),
            HSetting::new(HSettingType::MaxTableCapacity, 200),
        ]);
        parameters_set(
            &mut qlog,
            Initiator::Local,
            &settings,
            None,
            test_fixture::now(),
        );
        drop(qlog);
        let output = contents.to_string();
        assert!(output.contains(r#""initiator":"local""#));
        assert!(output.contains(r#""max_field_section_size":100"#));
        assert!(output.contains(r#""max_table_capacity":200"#));
        assert!(output.contains(r#""blocked_streams_count":300"#));
        assert!(output.contains(r#""extended_connect":1"#));
        assert!(output.contains(r#""h3_datagram":1"#));
        assert!(!output.contains(r#""waits_for_settings":true"#));
    }
}
