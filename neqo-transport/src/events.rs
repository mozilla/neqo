// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Collecting a list of events relevant to whoever is using the Connection.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use crate::connection::State;
use crate::frame::StreamType;
use crate::stream_id::StreamId;
use crate::AppError;

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// Cert authentication needed
    AuthenticationNeeded,
    /// A new uni (read) or bidi stream has been opened by the peer.
    NewStream {
        stream_id: u64,
        stream_type: StreamType,
    },
    /// Space available in the buffer for an application write to succeed.
    SendStreamWritable { stream_id: u64 },
    /// New bytes available for reading.
    RecvStreamReadable { stream_id: u64 },
    /// Peer reset the stream.
    RecvStreamReset { stream_id: u64, app_error: AppError },
    /// Peer has sent STOP_SENDING
    SendStreamStopSending { stream_id: u64, app_error: AppError },
    /// Peer has acked everything sent on the stream.
    SendStreamComplete { stream_id: u64 },
    /// Peer increased MAX_STREAMS
    SendStreamCreatable { stream_type: StreamType },
    /// Connection state change.
    StateChange(State),
    /// The server rejected 0-RTT.
    /// This event invalidates all state in streams that has been created.
    /// Any data written to streams needs to be written again.
    ZeroRttRejected,
}

#[derive(Debug, Default, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct ConnectionEvents {
    events: Rc<RefCell<BTreeSet<ConnectionEvent>>>,
}

impl ConnectionEvents {
    pub fn authentication_needed(&self) {
        self.insert(ConnectionEvent::AuthenticationNeeded);
    }

    pub fn new_stream(&self, stream_id: StreamId, stream_type: StreamType) {
        self.insert(ConnectionEvent::NewStream {
            stream_id: stream_id.as_u64(),
            stream_type,
        });
    }

    pub fn send_stream_writable(&self, stream_id: StreamId) {
        self.insert(ConnectionEvent::SendStreamWritable {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn recv_stream_readable(&self, stream_id: StreamId) {
        self.insert(ConnectionEvent::RecvStreamReadable {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn recv_stream_reset(&self, stream_id: StreamId, app_error: AppError) {
        self.insert(ConnectionEvent::RecvStreamReset {
            stream_id: stream_id.as_u64(),
            app_error,
        });
    }

    pub fn send_stream_stop_sending(&self, stream_id: StreamId, app_error: AppError) {
        self.insert(ConnectionEvent::SendStreamStopSending {
            stream_id: stream_id.as_u64(),
            app_error,
        });
    }

    pub fn send_stream_complete(&self, stream_id: StreamId) {
        self.insert(ConnectionEvent::SendStreamComplete {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn send_stream_creatable(&self, stream_type: StreamType) {
        self.insert(ConnectionEvent::SendStreamCreatable { stream_type });
    }

    pub fn connection_state_change(&self, state: State) {
        self.insert(ConnectionEvent::StateChange(state));
    }

    pub fn client_0rtt_rejected(&self) {
        self.events.borrow_mut().clear();
        self.insert(ConnectionEvent::ZeroRttRejected);
    }

    pub fn events(&self) -> BTreeSet<ConnectionEvent> {
        self.events.replace(BTreeSet::new())
    }

    fn insert(&self, event: ConnectionEvent) {
        self.events.borrow_mut().insert(event);
    }
}
