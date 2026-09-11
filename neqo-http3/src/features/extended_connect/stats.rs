// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Per-session statistics exposed to the WebTransport API consumer.
//!
//! Per-session datagram queue counters, which cannot be derived from
//! [`neqo_transport::Stats`].  Only `datagrams_expired_outgoing` is a
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
#[expect(
    clippy::struct_field_names,
    reason = "all three name the same queue, differing only in outcome"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Outgoing datagrams written into a packet, or to the control stream for
    /// the capsule fallback.  Not a delivery guarantee.
    pub datagrams_sent_outgoing: u64,
    /// Outgoing datagrams that expired (per `outgoingMaxAge`) before being sent.
    pub datagrams_expired_outgoing: u64,
    /// Outgoing datagrams discarded unsent and unexpired: evicted or refused
    /// by the queue, too big for the path MTU, or still queued at close.
    pub datagrams_dropped_outgoing: u64,
}
