// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::time::Instant;

#[cfg(feature = "qlog")]
use neqo_common::hex;
use neqo_common::qlog::Qlog;
#[cfg(feature = "qlog")]
use qlog::events::{
    qpack::{QPackInstruction, QpackInstructionParsed, QpackInstructionTypeName},
    EventData, RawInfo,
};

#[cfg_attr(
    not(feature = "qlog"),
    expect(
        unused_variables,
        clippy::missing_const_for_fn,
        reason = "only without qlog"
    )
)]
pub fn qpack_read_insert_count_increment_instruction(
    qlog: &Qlog,
    increment: u64,
    data: &[u8],
    now: Instant,
) {
    #[cfg(feature = "qlog")]
    qlog.add_event_data_with_instant(
        || {
            let raw = RawInfo {
                length: Some(8),
                payload_length: None,
                data: Some(hex(data)),
            };
            let ev_data = EventData::QpackInstructionParsed(QpackInstructionParsed {
                instruction: QPackInstruction::InsertCountIncrementInstruction {
                    instruction_type: QpackInstructionTypeName::InsertCountIncrementInstruction,
                    increment,
                },
                raw: Some(raw),
            });

            Some(ev_data)
        },
        now,
    );
}
