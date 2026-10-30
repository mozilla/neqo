// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Collecting a list of events relevant to whoever is using the Connection.

use std::{cell::RefCell, mem, net::SocketAddr, num::NonZeroU64, rc::Rc};

use enum_map::EnumMap;
use neqo_common::event::{Provider as EventProvider, Queue as EventQueue};
use nss::ResumptionToken;
use rustc_hash::FxHashSet as HashSet;

use crate::{
    AppError,
    connection::State,
    quic_datagrams::DatagramTracking,
    scone::Bitrate,
    stream_id::{StreamId, StreamType},
};

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum OutgoingDatagramOutcome {
    DroppedTooBig,
    Lost,
    Acked,
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// Cert authentication needed
    AuthenticationNeeded,
    /// Encrypted client hello fallback occurred.  The certificate for the
    /// public name needs to be authenticated.
    EchFallbackAuthenticationNeeded {
        public_name: String,
    },
    /// A new uni (read) or bidi stream has been opened by the peer.
    NewStream {
        stream_id: StreamId,
    },
    /// Space available in the buffer for an application write to succeed.
    SendStreamWritable {
        stream_id: StreamId,
    },
    /// New bytes available for reading.
    RecvStreamReadable {
        stream_id: StreamId,
    },
    /// Peer reset the stream.
    RecvStreamReset {
        stream_id: StreamId,
        app_error: AppError,
    },
    /// Peer has sent `STOP_SENDING`
    SendStreamStopSending {
        stream_id: StreamId,
        app_error: AppError,
    },
    /// Peer has acked everything sent on the stream.
    SendStreamComplete {
        stream_id: StreamId,
    },
    /// Peer increased `MAX_STREAMS`
    SendStreamCreatable {
        stream_type: StreamType,
    },
    /// Connection state change.
    StateChange(State),
    /// The server rejected 0-RTT.
    /// This event invalidates all state in streams that has been created.
    /// Any data written to streams needs to be written again.
    ZeroRttRejected,
    ResumptionToken(ResumptionToken),
    Datagram(Vec<u8>),
    OutgoingDatagramOutcome {
        id: u64,
        outcome: OutgoingDatagramOutcome,
    },
    /// The outgoing QUIC datagram queue has space again after having been full.
    OutgoingDatagramSpaceAvailable,
    /// An update was received to SCONE throughput advice.
    /// The value is the approximate rate in bits per second; None = unknown.
    SconeUpdated(Option<NonZeroU64>),
    /// A path migration completed; the connection is now sending on this path.
    PathMigrated {
        local: SocketAddr,
        remote: SocketAddr,
    },
}

/// The keys of the de-duplicated events in the queue, by kind.
#[derive(Debug, Default)]
struct Queued {
    readable: HashSet<StreamId>,
    reset: HashSet<StreamId>,
    writable: HashSet<StreamId>,
    stop_sending: HashSet<StreamId>,
    complete: HashSet<StreamId>,
    creatable: EnumMap<StreamType, bool>,
}

impl Queued {
    fn remove(&mut self, event: &ConnectionEvent) {
        match event {
            ConnectionEvent::RecvStreamReadable { stream_id } => self.readable.remove(stream_id),
            ConnectionEvent::RecvStreamReset { stream_id, .. } => self.reset.remove(stream_id),
            ConnectionEvent::SendStreamWritable { stream_id } => self.writable.remove(stream_id),
            ConnectionEvent::SendStreamStopSending { stream_id, .. } => {
                self.stop_sending.remove(stream_id)
            }
            ConnectionEvent::SendStreamComplete { stream_id } => self.complete.remove(stream_id),
            ConnectionEvent::SendStreamCreatable { stream_type } => {
                mem::take(&mut self.creatable[*stream_type])
            }
            _ => false,
        };
    }
}

#[derive(Debug, Default, Clone)]
pub struct ConnectionEvents {
    events: EventQueue<ConnectionEvent>,
    queued: Rc<RefCell<Queued>>,
}

impl ConnectionEvents {
    fn clear(&self) {
        self.events.clear();
        *self.queued.borrow_mut() = Queued::default();
    }

    pub fn authentication_needed(&self) {
        self.events.push(ConnectionEvent::AuthenticationNeeded);
    }

    pub fn ech_fallback_authentication_needed(&self, public_name: String) {
        self.events
            .push_unique(ConnectionEvent::EchFallbackAuthenticationNeeded { public_name });
    }

    pub fn new_stream(&self, stream_id: StreamId) {
        self.events.push(ConnectionEvent::NewStream { stream_id });
    }

    pub fn recv_stream_readable(&self, stream_id: StreamId) {
        if self.queued.borrow_mut().readable.insert(stream_id) {
            self.events
                .push(ConnectionEvent::RecvStreamReadable { stream_id });
        }
    }

    pub fn recv_stream_reset(&self, stream_id: StreamId, app_error: AppError) {
        let mut queued = self.queued.borrow_mut();
        // If reset, no longer readable.
        if queued.readable.remove(&stream_id) {
            self.events.remove_matching(|evt| matches!(evt, ConnectionEvent::RecvStreamReadable { stream_id: x } if *x == stream_id.as_u64()));
        }

        // A duplicate is any reset for the stream, even with a different error.
        if queued.reset.insert(stream_id) {
            self.events.push(ConnectionEvent::RecvStreamReset {
                stream_id,
                app_error,
            });
        }
    }

    pub fn send_stream_writable(&self, stream_id: StreamId) {
        if self.queued.borrow_mut().writable.insert(stream_id) {
            self.events
                .push(ConnectionEvent::SendStreamWritable { stream_id });
        }
    }

    pub fn send_stream_stop_sending(&self, stream_id: StreamId, app_error: AppError) {
        let mut queued = self.queued.borrow_mut();
        // If stopped, no longer writable.
        if queued.writable.remove(&stream_id) {
            self.events.remove_matching(|evt| matches!(evt, ConnectionEvent::SendStreamWritable { stream_id: x } if *x == stream_id));
        }

        // A duplicate is any stop for the stream, even with a different error.
        if queued.stop_sending.insert(stream_id) {
            self.events.push(ConnectionEvent::SendStreamStopSending {
                stream_id,
                app_error,
            });
        }
    }

    pub fn send_stream_complete(&self, stream_id: StreamId) {
        let mut queued = self.queued.borrow_mut();
        let writable = queued.writable.remove(&stream_id);
        let stop_sending = queued.stop_sending.remove(&stream_id);
        if !queued.complete.insert(stream_id) || writable || stop_sending {
            self.events.remove_matching(|evt| {
                matches!(evt,
                    ConnectionEvent::SendStreamWritable { stream_id: x } |
                    ConnectionEvent::SendStreamStopSending { stream_id: x, .. } |
                    ConnectionEvent::SendStreamComplete { stream_id: x }
                    if *x == stream_id)
            });
        }

        self.events
            .push(ConnectionEvent::SendStreamComplete { stream_id });
    }

    pub fn send_stream_creatable(&self, stream_type: StreamType) {
        if !mem::replace(&mut self.queued.borrow_mut().creatable[stream_type], true) {
            self.events
                .push(ConnectionEvent::SendStreamCreatable { stream_type });
        }
    }

    pub fn connection_state_change(&self, state: State) {
        // If closing, existing events no longer relevant.
        match state {
            State::Closing { .. } | State::Closed(_) => self.clear(),
            _ => (),
        }
        self.events.push_unique(ConnectionEvent::StateChange(state));
    }

    pub fn client_resumption_token(&self, token: ResumptionToken) {
        self.events.push(ConnectionEvent::ResumptionToken(token));
    }

    pub fn client_0rtt_rejected(&self) {
        // If 0rtt rejected, must start over and existing events are no longer
        // relevant.
        self.clear();
        self.events.push(ConnectionEvent::ZeroRttRejected);
    }

    pub fn recv_stream_complete(&self, stream_id: StreamId) {
        // If stopped, no longer readable.
        if self.queued.borrow_mut().readable.remove(&stream_id) {
            self.events.remove_matching(|evt| matches!(evt, ConnectionEvent::RecvStreamReadable { stream_id: x } if *x == stream_id.as_u64()));
        }
    }

    pub fn scone_updated(&self, scone: Bitrate) {
        self.events
            .remove_matching(|evt| matches!(evt, ConnectionEvent::SconeUpdated(_)));
        self.events
            .push_unique(ConnectionEvent::SconeUpdated(Option::from(scone)));
    }

    pub fn add_datagram(&self, data: &[u8]) {
        self.events.push(ConnectionEvent::Datagram(data.to_vec()));
    }

    pub fn datagram_space_available(&self) {
        self.events
            .push_unique(ConnectionEvent::OutgoingDatagramSpaceAvailable);
    }

    pub fn datagram_outcome(
        &self,
        dgram_tracker: &DatagramTracking,
        outcome: OutgoingDatagramOutcome,
    ) {
        if let DatagramTracking::Id(id) = dgram_tracker {
            self.events
                .push(ConnectionEvent::OutgoingDatagramOutcome { id: *id, outcome });
        }
    }

    pub fn path_migrated(&self, local: SocketAddr, remote: SocketAddr) {
        self.events
            .push(ConnectionEvent::PathMigrated { local, remote });
    }
}

impl EventProvider for ConnectionEvents {
    type Event = ConnectionEvent;

    fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    #[inline]
    fn next_event(&mut self) -> Option<Self::Event> {
        self.events
            .next_event()
            .inspect(|event| self.queued.borrow_mut().remove(event))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{iter, mem};

    use neqo_common::event::Provider as _;

    use super::Queued;
    use crate::{
        AppError, CloseReason, ConnectionEvent, ConnectionEvents, Error, State, StreamId,
        StreamType,
    };

    /// Asserts that the index holds exactly one key per queued de-duplicated event.
    fn assert_index(evts: &ConnectionEvents) {
        let events = evts.events.take_all();
        let mut expected = Queued::default();
        for event in &events {
            assert!(match event {
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    expected.readable.insert(*stream_id)
                }
                ConnectionEvent::RecvStreamReset { stream_id, .. } => {
                    expected.reset.insert(*stream_id)
                }
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    expected.writable.insert(*stream_id)
                }
                ConnectionEvent::SendStreamStopSending { stream_id, .. } => {
                    expected.stop_sending.insert(*stream_id)
                }
                ConnectionEvent::SendStreamComplete { stream_id } => {
                    expected.complete.insert(*stream_id)
                }
                ConnectionEvent::SendStreamCreatable { stream_type } => {
                    !mem::replace(&mut expected.creatable[*stream_type], true)
                }
                _ => true,
            });
        }
        let queued = evts.queued.borrow();
        assert_eq!(queued.readable, expected.readable);
        assert_eq!(queued.reset, expected.reset);
        assert_eq!(queued.writable, expected.writable);
        assert_eq!(queued.stop_sending, expected.stop_sending);
        assert_eq!(queued.complete, expected.complete);
        assert_eq!(queued.creatable, expected.creatable);
        for event in events {
            evts.events.push(event);
        }
    }

    const fn readable(id: u64) -> ConnectionEvent {
        ConnectionEvent::RecvStreamReadable {
            stream_id: StreamId::new(id),
        }
    }

    const fn reset(id: u64, app_error: AppError) -> ConnectionEvent {
        ConnectionEvent::RecvStreamReset {
            stream_id: StreamId::new(id),
            app_error,
        }
    }

    const fn writable(id: u64) -> ConnectionEvent {
        ConnectionEvent::SendStreamWritable {
            stream_id: StreamId::new(id),
        }
    }

    const fn stop(id: u64, app_error: AppError) -> ConnectionEvent {
        ConnectionEvent::SendStreamStopSending {
            stream_id: StreamId::new(id),
            app_error,
        }
    }

    const fn complete(id: u64) -> ConnectionEvent {
        ConnectionEvent::SendStreamComplete {
            stream_id: StreamId::new(id),
        }
    }

    const fn creatable(stream_type: StreamType) -> ConnectionEvent {
        ConnectionEvent::SendStreamCreatable { stream_type }
    }

    fn take(evts: &mut ConnectionEvents) -> Vec<ConnectionEvent> {
        assert_index(evts);
        let events = evts.events().collect();
        assert_index(evts);
        events
    }

    /// Raises one event of every de-duplicated kind, plus duplicates and culls.
    fn raise_all(evts: &ConnectionEvents) {
        evts.recv_stream_readable(0.into());
        evts.recv_stream_readable(4.into());
        evts.recv_stream_readable(0.into());
        evts.send_stream_writable(1.into());
        evts.send_stream_writable(5.into());
        evts.send_stream_writable(1.into());
        evts.send_stream_stop_sending(5.into(), 1);
        evts.send_stream_stop_sending(5.into(), 2);
        evts.send_stream_creatable(StreamType::BiDi);
        evts.send_stream_creatable(StreamType::UniDi);
        evts.send_stream_creatable(StreamType::BiDi);
        evts.recv_stream_reset(4.into(), 3);
        evts.recv_stream_reset(4.into(), 4);
        evts.recv_stream_complete(0.into());
        evts.send_stream_complete(9.into());
        evts.send_stream_complete(1.into());
        evts.send_stream_complete(9.into());
    }

    fn all_raised() -> Vec<ConnectionEvent> {
        vec![
            stop(5, 1),
            creatable(StreamType::BiDi),
            creatable(StreamType::UniDi),
            reset(4, 3),
            complete(1),
            complete(9),
        ]
    }

    #[test]
    fn event_culling() {
        let mut evts = ConnectionEvents::default();
        assert!(!evts.has_events());

        evts.client_0rtt_rejected();
        assert!(evts.has_events());
        evts.client_0rtt_rejected();
        assert_eq!(evts.events().count(), 1);
        assert_eq!(evts.events().count(), 0);

        evts.recv_stream_readable(6.into());
        evts.recv_stream_reset(6.into(), 66);
        evts.recv_stream_reset(6.into(), 65);
        assert_eq!(evts.events().count(), 1);

        evts.send_stream_writable(8.into());
        evts.send_stream_writable(8.into());
        evts.send_stream_stop_sending(8.into(), 55);
        evts.send_stream_stop_sending(8.into(), 56);
        let events = evts.events().collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            ConnectionEvent::SendStreamStopSending {
                stream_id: StreamId::new(8),
                app_error: 55
            }
        );

        evts.send_stream_writable(8.into());
        evts.send_stream_writable(8.into());
        evts.send_stream_stop_sending(8.into(), 55);
        evts.send_stream_stop_sending(8.into(), 56);
        evts.send_stream_complete(8.into());
        assert_eq!(evts.events().count(), 1);

        evts.send_stream_writable(8.into());
        evts.send_stream_writable(9.into());
        evts.send_stream_stop_sending(10.into(), 55);
        evts.send_stream_stop_sending(11.into(), 56);
        evts.send_stream_complete(12.into());
        assert_eq!(evts.events().count(), 5);

        evts.send_stream_writable(8.into());
        evts.send_stream_writable(9.into());
        evts.send_stream_stop_sending(10.into(), 55);
        evts.send_stream_stop_sending(11.into(), 56);
        evts.send_stream_complete(12.into());
        evts.client_0rtt_rejected();
        assert_eq!(evts.events().count(), 1);

        evts.send_stream_writable(9.into());
        evts.send_stream_stop_sending(10.into(), 55);
        evts.connection_state_change(State::Closed(CloseReason::Transport(Error::StreamState)));
        assert_eq!(evts.events().count(), 1);
    }

    #[test]
    fn raise_all_culls_and_dedups() {
        let mut evts = ConnectionEvents::default();
        raise_all(&evts);
        assert_eq!(take(&mut evts), all_raised());
        raise_all(&evts);
        assert_eq!(take(&mut evts), all_raised());
    }

    #[test]
    fn readable_again_after_taken() {
        let mut evts = ConnectionEvents::default();
        evts.recv_stream_readable(4.into());
        evts.recv_stream_readable(8.into());
        evts.recv_stream_readable(4.into());
        assert_eq!(take(&mut evts), [readable(4), readable(8)]);
        evts.recv_stream_readable(4.into());
        evts.recv_stream_readable(4.into());
        assert_eq!(take(&mut evts), [readable(4)]);
    }

    #[test]
    fn writable_again_after_taken() {
        let mut evts = ConnectionEvents::default();
        evts.send_stream_writable(4.into());
        evts.send_stream_writable(8.into());
        evts.send_stream_writable(4.into());
        assert_eq!(take(&mut evts), [writable(4), writable(8)]);
        evts.send_stream_writable(4.into());
        evts.send_stream_writable(4.into());
        assert_eq!(take(&mut evts), [writable(4)]);
    }

    #[test]
    fn stop_sending_replaces_writable() {
        let mut evts = ConnectionEvents::default();
        evts.send_stream_writable(4.into());
        evts.send_stream_writable(8.into());
        evts.send_stream_stop_sending(4.into(), 1);
        evts.send_stream_writable(4.into());
        evts.send_stream_stop_sending(4.into(), 2);
        assert_eq!(take(&mut evts), [writable(8), stop(4, 1)]);
        evts.send_stream_stop_sending(4.into(), 3);
        assert_eq!(take(&mut evts), [stop(4, 3)]);
    }

    #[test]
    fn creatable_once_per_type() {
        let mut evts = ConnectionEvents::default();
        evts.send_stream_creatable(StreamType::UniDi);
        evts.send_stream_creatable(StreamType::BiDi);
        evts.send_stream_creatable(StreamType::UniDi);
        let expected = [creatable(StreamType::UniDi), creatable(StreamType::BiDi)];
        assert_eq!(take(&mut evts), expected);
        evts.send_stream_creatable(StreamType::BiDi);
        evts.send_stream_creatable(StreamType::BiDi);
        assert_eq!(take(&mut evts), [creatable(StreamType::BiDi)]);
    }

    #[test]
    fn culls_only_the_stream() {
        let mut evts = ConnectionEvents::default();
        evts.recv_stream_readable(4.into());
        evts.recv_stream_readable(8.into());
        evts.send_stream_writable(4.into());
        evts.send_stream_writable(8.into());
        evts.send_stream_stop_sending(12.into(), 1);
        evts.send_stream_stop_sending(16.into(), 2);
        evts.recv_stream_reset(4.into(), 3);
        evts.recv_stream_complete(8.into());
        evts.send_stream_complete(4.into());
        evts.send_stream_complete(12.into());
        let expected = [
            writable(8),
            stop(16, 2),
            reset(4, 3),
            complete(4),
            complete(12),
        ];
        assert_eq!(take(&mut evts), expected);
        evts.recv_stream_readable(4.into());
        evts.recv_stream_reset(4.into(), 5);
        evts.send_stream_complete(4.into());
        assert_eq!(take(&mut evts), [reset(4, 5), complete(4)]);
    }

    #[test]
    fn clear_then_new_events() {
        let mut evts = ConnectionEvents::default();
        raise_all(&evts);
        evts.client_0rtt_rejected();
        raise_all(&evts);
        let mut expected = vec![ConnectionEvent::ZeroRttRejected];
        expected.extend(all_raised());
        assert_eq!(take(&mut evts), expected);

        raise_all(&evts);
        let closed = State::Closed(CloseReason::Transport(Error::StreamState));
        evts.connection_state_change(closed.clone());
        raise_all(&evts);
        let mut expected = vec![ConnectionEvent::StateChange(closed)];
        expected.extend(all_raised());
        assert_eq!(take(&mut evts), expected);
    }

    #[test]
    fn dedup_after_next_event() {
        let mut evts = ConnectionEvents::default();
        raise_all(&evts);
        assert_eq!(evts.next_event(), Some(stop(5, 1)));
        assert_index(&evts);
        raise_all(&evts);
        let expected = [
            creatable(StreamType::BiDi),
            creatable(StreamType::UniDi),
            reset(4, 3),
            stop(5, 1),
            complete(1),
            complete(9),
        ];
        assert_eq!(take(&mut evts), expected);
    }

    #[test]
    fn behind_datagrams() {
        const DATAGRAMS: usize = 1000;
        let mut evts = ConnectionEvents::default();
        for _ in 0..DATAGRAMS {
            evts.add_datagram(&[]);
        }
        raise_all(&evts);
        let mut expected: Vec<_> = iter::repeat_with(|| ConnectionEvent::Datagram(vec![]))
            .take(DATAGRAMS)
            .collect();
        expected.extend(all_raised());
        assert_eq!(take(&mut evts), expected);
    }
}
