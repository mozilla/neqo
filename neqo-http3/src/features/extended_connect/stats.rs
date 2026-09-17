// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Per-session statistics exposed to the WebTransport API consumer.
//!
//! Describes per-session datagram queue behaviour, which cannot be derived
//! from the connection-level counters in [`neqo_transport::Stats`].
//! `expiredOutgoing` mirrors the field of the same name in
//! [`WebTransportDatagramStats`]; the others are not part of that
//! dictionary, but are needed by an application-level caller reconciling
//! its own view of the queue against this one (e.g. to release local
//! backpressure credit once a datagram it handed in has actually left).
//! Everything else `getStats()` reports is scoped to the underlying
//! connection, and is only exposed at all when that connection is dedicated
//! to a single session.
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
    /// Outgoing datagrams actually handed to the packet builder (or, for the
    /// HTTP DATAGRAM Capsule fallback, to the control stream's send buffer).
    /// Not a delivery guarantee; the transport reports a QUIC datagram's
    /// eventual fate separately via `ConnectionEvent::OutgoingDatagramOutcome`.
    pub datagrams_sent_outgoing: u64,
    /// Outgoing datagrams that expired (per `outgoingMaxAge`) before being sent.
    pub datagrams_expired_outgoing: u64,
    /// Outgoing datagrams discarded without being sent and without expiring:
    /// evicted at the queue's byte budget, refused outright because they
    /// were the lowest-priority thing that would exist in the queue, or
    /// still queued when the session closed. Counts tracked and untracked
    /// datagrams alike, unlike the `DatagramOutcome::Dropped` event, which
    /// only fires for tracked ones.
    ///
    /// Excludes `OutgoingDatagramOutcome::DroppedTooBig` (counted in
    /// `Stats::datagram_tx`) - only possible if the path MTU shrinks after
    /// acceptance, since oversized datagrams are now refused up front.
    pub datagrams_dropped_outgoing: u64,
}
