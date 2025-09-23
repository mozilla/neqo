// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::time::Instant;

use neqo_common::qlog::Qlog;
use neqo_transport::StreamId;
#[cfg(feature = "qlog")]
use qlog::events::{DataRecipient, EventData};

/// # Panics
///
/// If values don't fit in QLOG types.
#[cfg_attr(
    not(feature = "qlog"),
    expect(
        unused_variables,
        clippy::missing_const_for_fn,
        reason = "Only used with qlog."
    )
)]
pub fn h3_data_moved_up(qlog: &Qlog, stream_id: StreamId, amount: usize, now: Instant) {
    #[cfg(feature = "qlog")]
    qlog.add_event_data_with_instant(
        || {
            let ev_data = EventData::DataMoved(qlog::events::quic::DataMoved {
                stream_id: Some(stream_id.as_u64()),
                offset: None,
                length: Some(u64::try_from(amount).expect("usize fits in u64")),
                from: Some(DataRecipient::Transport),
                to: Some(DataRecipient::Application),
                raw: None,
            });

            Some(ev_data)
        },
        now,
    );
}

/// # Panics
///
/// If values don't fit in QLOG types.
#[cfg_attr(
    not(feature = "qlog"),
    expect(
        unused_variables,
        clippy::missing_const_for_fn,
        reason = "Only used with qlog."
    )
)]
pub fn h3_data_moved_down(qlog: &Qlog, stream_id: StreamId, amount: usize, now: Instant) {
    #[cfg(feature = "qlog")]
    qlog.add_event_data_with_instant(
        || {
            let ev_data = EventData::DataMoved(qlog::events::quic::DataMoved {
                stream_id: Some(stream_id.as_u64()),
                offset: None,
                length: Some(u64::try_from(amount).expect("usize fits in u64")),
                from: Some(DataRecipient::Application),
                to: Some(DataRecipient::Transport),
                raw: None,
            });

            Some(ev_data)
        },
        now,
    );
}
