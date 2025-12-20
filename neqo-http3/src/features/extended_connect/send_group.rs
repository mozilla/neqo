// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::atomic::{AtomicU64, Ordering};

use neqo_transport::StreamId;

static NEXT_SEND_GROUP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendGroupId(u64);

// Note: 0 is not a valid SendGroupId
impl SendGroupId {
    pub fn new() -> Self {
        Self(NEXT_SEND_GROUP_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for SendGroupId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Debug)]
pub struct SendGroup {
    id: SendGroupId,
    session_id: StreamId,
}

impl SendGroup {
    pub const fn new(id: SendGroupId, session_id: StreamId) -> Self {
        Self { id, session_id }
    }

    pub const fn id(&self) -> SendGroupId {
        self.id
    }

    pub const fn session_id(&self) -> StreamId {
        self.session_id
    }
}
