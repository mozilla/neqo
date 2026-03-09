// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cell::Cell;

use neqo_transport::StreamId;

thread_local! {
    static NEXT_ID: Cell<u64> = const { Cell::new(1) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(u64);

/// Backward-compatible alias so callers using `send_group::SendGroupId` still compile.
#[expect(
    clippy::module_name_repetitions,
    reason = "backward-compatible re-export"
)]
pub use Id as SendGroupId;

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

#[derive(Debug)]
pub struct SendGroup {
    id: Id,
    session_id: StreamId,
}

impl SendGroup {
    #[must_use]
    pub const fn new(id: Id, session_id: StreamId) -> Self {
        Self { id, session_id }
    }

    #[must_use]
    pub const fn id(&self) -> Id {
        self.id
    }

    #[must_use]
    pub const fn session_id(&self) -> StreamId {
        self.session_id
    }
}
