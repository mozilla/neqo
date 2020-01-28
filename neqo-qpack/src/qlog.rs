// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use neqo_common::NeqoQlogRef;
use qlog::{
    EventCategory, EventData::QpackInstructionReceived, EventField,
    QPackInstruction::InsertCountIncrementInstruction, QpackInstructionTypeName,
};
use std::fmt::LowerHex;
use std::time::Instant;

fn slice_to_hex_string<T: LowerHex>(slice: &[T]) -> String {
    if slice.is_empty() {
        "0x0".to_string()
    } else {
        slice
            .iter()
            .fold("0x".to_string(), |acc, x| acc + &format!("{:x}", x))
    }
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
            raw: Some(slice_to_hex_string(data)),
        };
        qlog.trace.events.push(vec![
            EventField::Category(EventCategory::Qpack),
            EventField::RelativeTime(format!("{}", elapsed.as_micros())),
            EventField::Data(instruction_received_data),
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_slice_to_hex_string() {
        let s = slice_to_hex_string(&[10, 9, 8]);
        assert_eq!(r#"0xa98"#, s);
        let s = slice_to_hex_string(&Vec::<u8>::new());
        assert_eq!(r#"0x0"#, s);
        let s = slice_to_hex_string(&[128]);
        assert_eq!(r#"0x80"#, s);
    }
}
