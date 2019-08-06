// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Collecting a list of events relevant to whoever is using the Connection.

use std::collections::BTreeSet;
use std::mem;

use crate::frame::{CloseError, StreamType};
use crate::stream_id::StreamId;
use crate::AppError;

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum ConnectionEvent {
    Connected,
    /// A new uni (read) or bidi stream has been opened by the peer.
    NewStream {
        stream_id: u64,
        stream_type: StreamType,
    },
    /// Space available in the buffer for an application write to succeed.
    SendStreamWritable {
        stream_id: u64,
    },
    /// New bytes available for reading.
    RecvStreamReadable {
        stream_id: u64,
    },
    /// Peer reset the stream.
    RecvStreamReset {
        stream_id: u64,
        app_error: AppError,
    },
    /// Peer has sent STOP_SENDIconnectioNG
    SendStreamStopSending {
        stream_id: u64,
        app_error: AppError,
    },
    /// Peer has acked everything sent on the stream.
    SendStreamComplete {
        stream_id: u64,
    },
    /// Peer increased MAX_STREAMS
    SendStreamCreatable {
        stream_type: StreamType,
    },
    /// Connection closed
    ConnectionClosed {
        error_code: CloseError,
        frame_type: u64,
        reason_phrase: String,
    },
    /// The server rejected 0-RTT.
    /// This event invalidates all state in streams that has been created.
    /// Any data written to streams needs to be written again.
    ZeroRttRejected,
}

#[derive(Debug, Default)]
pub struct ConnectionEvents {
    events: BTreeSet<ConnectionEvent>,
}

impl ConnectionEvents {
    pub fn connected(&mut self) {
        self.events.insert(ConnectionEvent::Connected);
    }

    pub fn new_stream(&mut self, stream_id: StreamId, stream_type: StreamType) {
        self.events.insert(ConnectionEvent::NewStream {
            stream_id: stream_id.as_u64(),
            stream_type,
        });
    }

    pub fn send_stream_writable(&mut self, stream_id: StreamId) {
        self.events.insert(ConnectionEvent::SendStreamWritable {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn recv_stream_readable(&mut self, stream_id: StreamId) {
        self.events.insert(ConnectionEvent::RecvStreamReadable {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn recv_stream_reset(&mut self, stream_id: StreamId, app_error: AppError) {
        self.events.insert(ConnectionEvent::RecvStreamReset {
            stream_id: stream_id.as_u64(),
            app_error,
        });
    }

    pub fn send_stream_stop_sending(&mut self, stream_id: StreamId, app_error: AppError) {
        self.events.insert(ConnectionEvent::SendStreamStopSending {
            stream_id: stream_id.as_u64(),
            app_error,
        });
    }

    pub fn send_stream_complete(&mut self, stream_id: StreamId) {
        self.events.insert(ConnectionEvent::SendStreamComplete {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn send_stream_creatable(&mut self, stream_type: StreamType) {
        self.events
            .insert(ConnectionEvent::SendStreamCreatable { stream_type });
    }

    pub fn connection_closed(
        &mut self,
        error_code: CloseError,
        frame_type: u64,
        reason_phrase: &str,
    ) {
        self.events.insert(ConnectionEvent::ConnectionClosed {
            error_code,
            frame_type,
            reason_phrase: reason_phrase.to_owned(),
        });
    }

    pub fn client_0rtt_rejected(&mut self) {
        self.events.clear();
        self.events.insert(ConnectionEvent::ZeroRttRejected);
    }

    pub fn events(&mut self) -> BTreeSet<ConnectionEvent> {
        mem::replace(&mut self.events, BTreeSet::new())
    }

    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }
}
