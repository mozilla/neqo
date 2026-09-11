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
/// have no use for them and do not track them.  The sent and dropped counts
/// let an application-level caller reconcile its own view of the queue
/// against this one (e.g. to release local backpressure credit once a
/// datagram it handed in has actually left).
///
/// Once a session's queue is empty, every datagram `send_datagram` accepted
/// has been counted in exactly one of these three.  That is why `dropped`
/// includes close-time drops, and why closing a session drops its queue
/// before snapshotting these.
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
    /// Outgoing datagrams actually handed to the packet builder (or, for the
    /// HTTP DATAGRAM Capsule fallback, to the control stream's send buffer).
    /// Not a delivery guarantee: the transport's per-datagram Acked/Lost
    /// report is not forwarded by this crate.
    pub datagrams_sent_outgoing: u64,
    /// Outgoing datagrams that expired (per `outgoingMaxAge`) before being sent.
    pub datagrams_expired_outgoing: u64,
    /// Outgoing datagrams discarded without being sent and without expiring:
    /// evicted at the queue's byte budget, refused outright because they
    /// were the lowest-priority thing that would exist in the queue, dropped
    /// at packet-build time as too big for the path MTU (enqueueing only
    /// checks the peer's limit), or still queued when the session closed.
    pub datagrams_dropped_outgoing: u64,
}
