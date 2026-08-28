// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Per-session statistics exposed to the WebTransport API consumer.
//!
//! Limited to the members of [`WebTransportDatagramStats`], which describe
//! per-session datagram queue behaviour and so cannot be derived from the
//! connection-level counters in [`neqo_transport::Stats`]. Everything else
//! `getStats()` reports is scoped to the underlying connection, and is only
//! exposed at all when that connection is dedicated to a single session.
//!
//! [`WebTransportDatagramStats`]: https://w3c.github.io/webtransport#dictdef-webtransportdatagramstats

/// Statistics for a single `WebTransport` session.
///
/// These are specific to `WebTransport`; the other extended CONNECT protocols
/// have no use for them and do not track them.
#[expect(
    clippy::module_name_repetitions,
    reason = "stats::SessionStats is clearer than stats::Session"
)]
#[expect(
    clippy::struct_field_names,
    reason = "the shared `datagrams_` prefix matches the WebIDL getStats() \
              field names this struct feeds"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Outgoing datagrams that expired before being sent.
    pub datagrams_expired_outgoing: u64,
    /// Outgoing datagrams successfully handed to the QUIC layer.
    pub datagrams_sent_outgoing: u64,
    /// Outgoing datagrams dropped: evicted from the queue to make room under
    /// its byte budget, or refused by the QUIC layer at handoff. Counted
    /// regardless of whether the datagram was sent with a tracking id, since
    /// this is meant to feed an aggregate delta rather than per-datagram
    /// outcomes.
    pub datagrams_dropped_outgoing: u64,
}
