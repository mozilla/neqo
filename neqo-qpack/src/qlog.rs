// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::time::Instant;

use neqo_common::NeqoQlogRef;
use qlog::{
    EventCategory, EventData::QpackInstructionReceived, EventField,
    QPackInstruction::InsertCountIncrementInstruction, QpackInstructionTypeName,
};

fn slice_to_string<T: ToString>(slice: &[T]) -> String {
    slice
        .iter()
        .fold("".to_string(), |acc, x| acc + &x.to_string())
}

pub fn qpack_read_insert_count_increment_instruction(
    qlog: &Option<NeqoQlogRef>,
    now: Instant,
    increment: u64,
    data: &[u8],
) {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();
        let elapsed = now.duration_since(qlog.zero_time);
        let instruction_received_data = QpackInstructionReceived {
            instruction: InsertCountIncrementInstruction {
                instruction_type: QpackInstructionTypeName::InsertCountIncrementInstruction,
                increment,
            },
            byte_length: Some(8.to_string()),
            raw: Some(slice_to_string(data)),
        };
        qlog.trace.events.push(vec![
            EventField::Category(EventCategory::Qpack),
            EventField::RelativeTime(format!("{}", elapsed.as_micros())),
            EventField::Data(instruction_received_data),
        ]);
    }
}
