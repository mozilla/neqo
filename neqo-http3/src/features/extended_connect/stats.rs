// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Per-session statistics exposed to the WebTransport API consumer.
//! These are distinct from the connection-level stats in `neqo_transport::Stats`,
//! which are internal counters reported to Glean.

#[expect(
    clippy::module_name_repetitions,
    reason = "stats::SessionStats is clearer than stats::Session"
)]
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub streams_opened_local: u64,
    pub streams_opened_remote: u64,
    pub datagrams_expired_outgoing: u64,
    pub datagrams_expired_incoming: u64,
    pub datagrams_lost_outgoing: u64,
    pub datagrams_dropped_incoming: u64,
}
