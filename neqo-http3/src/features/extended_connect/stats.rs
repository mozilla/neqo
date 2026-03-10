// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Per-session statistics exposed to the WebTransport API consumer.
//! These are distinct from the connection-level stats in [`neqo_transport::Stats`],
//! which are internal counters reported to Glean.

/// Statistics for a single `WebTransport` session.
///
/// These are specific to `WebTransport`; the other extended CONNECT protocols
/// have no use for them and do not track them.
#[expect(
    clippy::module_name_repetitions,
    reason = "stats::SessionStats is clearer than stats::Session"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Payload bytes sent in WebTransport datagrams (excludes stream data).
    pub datagram_bytes_sent: u64,
    /// Framing overhead bytes for sent datagrams (excludes retransmissions).
    pub bytes_sent_overhead: u64,
    /// Payload bytes received in WebTransport datagrams (excludes stream data).
    pub datagram_bytes_received: u64,
    /// Number of WebTransport datagrams sent.
    pub datagrams_sent: u64,
    /// Number of WebTransport datagrams received.
    pub datagrams_received: u64,
    /// Streams opened by the local endpoint on this session.
    pub streams_opened_local: u64,
    /// Streams opened by the remote endpoint on this session.
    pub streams_opened_remote: u64,
    /// Outgoing datagrams that expired before being sent.
    ///
    /// Currently always zero; populated once datagram expiry is wired up.
    pub datagrams_expired_outgoing: u64,
}
