// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::Http3State;
use crate::{
    CloseType, Header, HttpRecvStreamEvents, Priority, RecvStreamEvents, SendStreamEvents,
};

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
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Http3ServerConnEvents {
    events: Rc<RefCell<VecDeque<Http3ServerConnEvent>>>,
}

impl SendStreamEvents for Http3ServerConnEvents {}

impl RecvStreamEvents for Http3ServerConnEvents {
    /// Add a new `DataReadable` event
    fn data_readable(&self, stream_id: u64) {
        self.insert(Http3ServerConnEvent::DataReadable { stream_id });
    }

    fn recv_closed(&self, stream_id: u64, close_type: CloseType) {
        if close_type != CloseType::Done {
            self.remove_events_for_stream_id(stream_id);
        }
    }
}

impl HttpRecvStreamEvents for Http3ServerConnEvents {
    /// Add a new `HeaderReady` event.
    fn header_ready(&self, stream_id: u64, headers: Vec<Header>, _interim: bool, fin: bool) {
        self.insert(Http3ServerConnEvent::Headers {
            stream_id,
            headers,
            fin,
        });
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
        self.events.borrow_mut().retain(|evt| !f(evt));
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
        });
    }

    fn remove_events_for_stream_id(&self, stream_id: u64) {
        self.remove(|evt| {
            matches!(evt,
                Http3ServerConnEvent::Headers { stream_id: x, .. } | Http3ServerConnEvent::DataReadable { stream_id: x, .. } if *x == stream_id)
        });
    }
}
