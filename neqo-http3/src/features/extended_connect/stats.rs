// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct WebTransportSessionStats {
    pub timestamp: Option<Instant>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub streams_opened_local: u64,
    pub streams_opened_remote: u64,
}

impl WebTransportSessionStats {
    #[must_use]
    pub fn new() -> Self {
        Self {
            timestamp: Some(Instant::now()),
            ..Default::default()
        }
    }
}
