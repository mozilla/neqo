// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use crate::Res;
use neqo_common::NeqoQlogRef;
use qlog::{event::Event, QPackInstruction, QpackInstructionTypeName};
use std::fmt::LowerHex;

// TODO(hawkinsw@obs.cr): There is a copy of this in neqo-transports/src/qlog.rs.
// Refactor both uses into something in neqo-common.
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
    increment: u64,
    data: &[u8],
) -> Res<()> {
    if let Some(qlog) = qlog {
        let mut qlog = qlog.borrow_mut();

        let event = Event::qpack_instruction_received(
            QPackInstruction::InsertCountIncrementInstruction {
                instruction_type: QpackInstructionTypeName::InsertCountIncrementInstruction,
                increment,
            },
            Some(8.to_string()),
            Some(slice_to_hex_string(data)),
        );

        qlog.streamer.add_event(event)?;
    }
    Ok(())
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
