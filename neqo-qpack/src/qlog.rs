// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Functions that handle capturing QLOG traces.

use std::time::Instant;

use neqo_common::qlog::Qlog;

// The QPACK events module was removed in qlog 0.18.
pub const fn qpack_read_insert_count_increment_instruction(
    _qlog: &mut Qlog,
    _increment: u64,
    _data: &[u8],
    _now: Instant,
) {
}
