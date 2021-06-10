// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::Http3State;
use crate::send_message::SendMessageEvents;
use crate::{Header, Priority, RecvMessageEvents, WtEvents};

use neqo_transport::AppError;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Http3ServerConnEvent {
    /// Headers are ready.
    Headers {
        stream_id: u64,
        headers: Vec<Header>,
        fin: bool,
    },
    PriorityUpdate {
        stream_id: u64,
        priority: Priority,
    },
    /// Request data is ready.
    DataReadable {
        stream_id: u64,
    },
    //TODO: This is never used. Do we need it?
    // Peer reset the stream.
    //Reset { stream_id: u64, error: AppError },
    /// Connection state change.
    StateChange(Http3State),
    WebTransportNewSession {
        stream_id: u64,
        headers: Vec<Header>,
    },
    WebTransportNewStream {
        stream_id: u64,
    },
    WebTransportDataReadable {
        stream_id: u64,
    },
    WebTransportStreamReset {
        stream_id: u64,
        error: AppError,
    },
    WebTransportDataWritable {
        stream_id: u64,
    },
    WebTransportStreamStopSending {
        stream_id: u64,
        error: AppError,
    },
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Http3ServerConnEvents {
    events: Rc<RefCell<VecDeque<Http3ServerConnEvent>>>,
}

impl RecvMessageEvents for Http3ServerConnEvents {
    /// Add a new `HeaderReady` event.
    fn header_ready(&self, stream_id: u64, headers: Vec<Header>, _interim: bool, fin: bool) {
        self.insert(Http3ServerConnEvent::Headers {
            stream_id,
            headers,
            fin,
        });
    }

    /// Add a new `DataReadable` event
    fn data_readable(&self, stream_id: u64) {
        self.insert(Http3ServerConnEvent::DataReadable { stream_id });
    }

    fn reset(&self, _stream_id: u64, _error: AppError, _local: bool) {}

    fn web_transport_new_session(&self, stream_id: u64, headers: Vec<Header>) {
        self.insert(Http3ServerConnEvent::WebTransportNewSession { stream_id, headers });
    }
}

impl SendMessageEvents for Http3ServerConnEvents {
    fn data_writable(&self, _stream_id: u64) {
        // Curently not used on the server side.
    }

    fn remove_send_side_event(&self, _stream_id: u64) {}

    fn stop_sending(&self, _stream_id: u64, _app_err: AppError) {}
}

impl WtEvents for Http3ServerConnEvents {
    fn web_transport_session_negotiated(&self, _stream_id: u64, _success: bool) {}

    fn web_transport_new_stream(&self, stream_id: u64) {
        self.insert(Http3ServerConnEvent::WebTransportNewStream { stream_id });
    }

    fn web_transport_data_readable(&self, stream_id: u64) {
        self.insert(Http3ServerConnEvent::WebTransportDataReadable { stream_id });
    }

    fn web_transport_stream_reset(&self, stream_id: u64, error: AppError) {
        self.insert(Http3ServerConnEvent::WebTransportStreamReset { stream_id, error });
    }

    fn web_transport_data_writable(&self, stream_id: u64) {
        self.insert(Http3ServerConnEvent::WebTransportDataWritable { stream_id });
    }

    fn web_transport_stream_stop_sending(&self, stream_id: u64, error: AppError) {
        self.insert(Http3ServerConnEvent::WebTransportStreamStopSending { stream_id, error });
    }

    fn clone_box(&self) -> Box<dyn WtEvents> {
        Box::new(self.clone())
    }
}

impl Http3ServerConnEvents {
    fn insert(&self, event: Http3ServerConnEvent) {
        self.events.borrow_mut().push_back(event);
    }

    fn remove<F>(&self, f: F)
    where
        F: Fn(&Http3ServerConnEvent) -> bool,
    {
        self.events.borrow_mut().retain(|evt| !f(evt))
    }

    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }

    pub fn next_event(&self) -> Option<Http3ServerConnEvent> {
        self.events.borrow_mut().pop_front()
    }

    pub fn connection_state_change(&self, state: Http3State) {
        self.insert(Http3ServerConnEvent::StateChange(state));
    }

    pub fn priority_update(&self, stream_id: u64, priority: Priority) {
        self.insert(Http3ServerConnEvent::PriorityUpdate {
            stream_id,
            priority,
        })
    }

    pub fn remove_events_for_stream_id(&self, stream_id: u64) {
        self.remove(|evt| {
            matches!(evt,
                Http3ServerConnEvent::Headers { stream_id: x, .. } | Http3ServerConnEvent::DataReadable { stream_id: x, .. } if *x == stream_id)
        });
    }
}
