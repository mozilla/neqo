// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cell::Cell;

// Send-group IDs only need to be unique within a connection: the transport keys its
// per-connection send-group map by this raw value, and one connection can carry several
// WebTransport sessions. A process-wide monotonic counter is a simple way to guarantee
// that; it also makes IDs unique across connections, which is harmless but not required.
thread_local! {
    static NEXT_ID: Cell<u64> = const { Cell::new(1) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(u64);

/// `Id(0)` is never valid; 0 is reserved as a sentinel.
impl Default for Id {
    /// # Panics
    ///
    /// Panics if the `Id` counter overflows `u64::MAX`.
    fn default() -> Self {
        let id = NEXT_ID.with(|n| {
            let id = n.get();
            n.set(id.checked_add(1).expect("SendGroup ID overflow"));
            id
        });
        Self(id)
    }
}

impl Id {
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}
