// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::Http3State;
use neqo_common::{matches, qtrace};
use neqo_transport::{AppError, StreamType};

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub enum Http3ClientEvent {
    /// Headers available for reading
    HeaderReady {
        stream_id: u64,
    },
    /// A stream can accept new data.
    DataWritable {
        stream_id: u64,
    },
    /// New bytes available for reading.
    DataReadable {
        stream_id: u64,
    },
    /// Peer reset the stream.
    Reset {
        stream_id: u64,
        error: AppError,
    },
    /// Peer has send STOP_SENDING with error code EarlyResponse, other error will post a reset event.
    StopSending {
        stream_id: u64,
        error: AppError,
    },
    /// A new push promise and assotiated headers
    Push {
        push_id: u64,
        ref_stream_id: u64,
        headers: Vec<u8>,
    },
    /// Duplicate push, push_id now referse to request ref_stream_id as well.
    PushDuplicate {
        push_id: u64,
        ref_stream_id: u64,
    },
    /// Header on a pushed stream are ready to be read
    PushHeaderReady {
        push_id: u64,
    },
    /// New bytes available on a push stream for reading.
    PushDataReadable {
        push_id: u64,
    },
    PushCancelled {
        push_id: u64,
    },
    /// New stream can be created
    RequestsCreatable,
    /// Cert authentication needed
    AuthenticationNeeded,
    /// Client has received a GOAWAY frame
    GoawayReceived,
    /// Connection state change.
    StateChange(Http3State),
}

#[derive(Debug, Default, Clone)]
pub struct Http3ClientEvents {
    events: Rc<RefCell<VecDeque<Http3ClientEvent>>>,
}

impl Http3ClientEvents {
    pub fn header_ready(&self, stream_id: u64) {
        self.insert(Http3ClientEvent::HeaderReady { stream_id });
    }

    pub fn data_writable(&self, stream_id: u64) {
        self.insert(Http3ClientEvent::DataWritable { stream_id });
    }

    pub fn data_readable(&self, stream_id: u64) {
        self.insert(Http3ClientEvent::DataReadable { stream_id });
    }

    pub fn stop_sending(&self, stream_id: u64, error: AppError) {
        // Remove DataWritable event if any.
        self.remove(|evt| {
            matches!(evt, Http3ClientEvent::DataWritable {
                    stream_id: x } if *x == stream_id)
        });
        self.insert(Http3ClientEvent::StopSending { stream_id, error });
    }

    pub fn push(&self, push_id: u64, ref_stream_id: u64, headers: Vec<u8>) {
        self.insert(Http3ClientEvent::Push {
            push_id,
            ref_stream_id,
            headers,
        });
    }

    pub fn push_duplicate(&self, push_id: u64, ref_stream_id: u64) {
        self.insert(Http3ClientEvent::PushDuplicate {
            push_id,
            ref_stream_id,
        });
    }

    pub fn push_header_ready(&self, push_id: u64) {
        self.insert(Http3ClientEvent::PushHeaderReady { push_id });
    }

    pub fn push_data_readable(&self, push_id: u64) {
        self.insert(Http3ClientEvent::PushDataReadable { push_id });
    }

    pub fn push_cancelled(&self, push_id: u64) {
        self.insert(Http3ClientEvent::PushCancelled { push_id });
    }

    pub fn new_requests_creatable(&self, stream_type: StreamType) {
        if stream_type == StreamType::BiDi {
            self.insert(Http3ClientEvent::RequestsCreatable);
        }
    }

    pub fn authentication_needed(&self) {
        self.insert(Http3ClientEvent::AuthenticationNeeded);
    }

    pub fn goaway_received(&self) {
        self.remove(|evt| matches!(evt, Http3ClientEvent::RequestsCreatable));
        self.insert(Http3ClientEvent::GoawayReceived);
    }

    pub fn events(&self) -> impl Iterator<Item = Http3ClientEvent> {
        self.events.replace(VecDeque::new()).into_iter()
    }

    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }

    pub fn next_event(&self) -> Option<Http3ClientEvent> {
        self.events.borrow_mut().pop_front()
    }

    fn insert(&self, event: Http3ClientEvent) {
        self.events.borrow_mut().push_back(event);
    }

    fn remove<F>(&self, f: F)
    where
        F: Fn(&Http3ClientEvent) -> bool,
    {
        self.events.borrow_mut().retain(|evt| !f(evt))
    }

    pub fn reset(&self, stream_id: u64, error: AppError) {
        self.remove_events_for_stream_id(stream_id);
        self.insert(Http3ClientEvent::Reset { stream_id, error });
    }

    pub fn connection_state_change(&self, state: Http3State) {
        self.insert(Http3ClientEvent::StateChange(state));
    }

    pub fn remove_events_for_stream_id(&self, stream_id: u64) {
        self.remove(|evt| {
            matches!(evt,
                Http3ClientEvent::HeaderReady { stream_id: x }
                | Http3ClientEvent::DataWritable { stream_id: x }
                | Http3ClientEvent::DataReadable { stream_id: x }
                | Http3ClientEvent::Push { ref_stream_id: x, .. }
                | Http3ClientEvent::Reset { stream_id: x, .. }
                | Http3ClientEvent::StopSending { stream_id: x, .. } if *x == stream_id)
        });
    }

    pub fn has_push(&self, push_id: u64) -> bool {
        for iter in self.events.borrow().iter() {
            qtrace!("has_push: {:?}", iter);
            if matches!(iter, Http3ClientEvent::Push{push_id:x, ..} if *x == push_id) {
                return true;
            }
        }
        false
    }

    pub fn remove_events_for_push_id(&self, push_id: u64) {
        self.remove(|evt| {
            matches!(evt,
                Http3ClientEvent::Push{push_id:x, ..}
                | Http3ClientEvent::PushDuplicate{push_id:x, ..}
                | Http3ClientEvent::PushHeaderReady{push_id:x, ..}
                | Http3ClientEvent::PushDataReadable{push_id:x, ..}
                | Http3ClientEvent::PushCancelled{push_id:x, ..} if *x == push_id)
        });
    }
}
