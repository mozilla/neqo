// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Per-session statistics exposed to the WebTransport API consumer.
//! These are distinct from the connection-level stats in `neqo_transport::Stats`,
//! which are internal counters reported to Glean.

use std::time::Instant;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WebTransportSessionStats {
    pub timestamp: Option<Instant>,
    /// Payload bytes sent (excludes framing overhead and retransmissions).
    pub bytes_sent: u64,
    /// Framing overhead bytes for sent datagrams (excludes retransmissions).
    pub bytes_sent_overhead: u64,
    pub bytes_received: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub streams_opened_local: u64,
    pub streams_opened_remote: u64,
    pub expired_outgoing: u64,
    pub expired_incoming: u64,
    pub lost_outgoing: u64,
    pub dropped_incoming: u64,
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
