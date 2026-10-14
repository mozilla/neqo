// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::time::Instant;

use neqo_common::{qlog::Qlog, to_u64};
use neqo_transport::StreamId;
use qlog::events::{DataRecipient, EventData, RawInfo, quic::StreamDataMoved};

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
