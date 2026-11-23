// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Per-session statistics exposed to the WebTransport API consumer.
//!
//! Per-session datagram queue counters, which cannot be derived from
//! [`neqo_transport::Stats`].  Only [`OutgoingDatagramStats::expired`] is a
//! [`WebTransportDatagramStats`] member (`expiredOutgoing`).  Everything else
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub outgoing_datagrams: OutgoingDatagramStats,
}

/// What became of the datagrams handed to a session's outgoing queue.
#[expect(
    clippy::module_name_repetitions,
    reason = "stats::OutgoingDatagramStats is clearer than stats::OutgoingDatagram"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutgoingDatagramStats {
    /// Written into a packet, or to the control stream for the capsule
    /// fallback.  Not a delivery guarantee.
    pub sent: u64,
    /// Expired (per `outgoingMaxAge`) before being sent.
    pub expired: u64,
    /// Discarded unsent and unexpired: evicted or refused by the queue, too
    /// big for the path MTU, or still queued at close.
    pub dropped: u64,
}
