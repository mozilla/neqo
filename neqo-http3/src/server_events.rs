// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::{Http3Events, Http3State};
use crate::Header;
use neqo_transport::{AppError, StreamType};

use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub enum Http3ServerEvent {
    /// Headers are ready.
    Headers {
        stream_id: u64,
        headers: Option<Vec<Header>>,
        fin: bool,
    },
    /// Request data is ready.
    Data {
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
    },
    /// Peer reset the stream.
    Reset { stream_id: u64, error: AppError },
    /// Connection state change.
    StateChange(Http3State),
}

#[derive(Debug, Default, Clone)]
pub struct Http3ServerEvents {
    events: Rc<RefCell<BTreeSet<Http3ServerEvent>>>,
}

impl Http3ServerEvents {
    fn insert(&self, event: Http3ServerEvent) {
        self.events.borrow_mut().insert(event);
    }

    pub fn remove(&self, event: &Http3ServerEvent) -> bool {
        self.events.borrow_mut().remove(event)
    }

    pub fn headers(&self, stream_id: u64, headers: Option<Vec<Header>>, fin: bool) {
        self.insert(Http3ServerEvent::Headers {
            stream_id,
            headers,
            fin,
        });
    }

    pub fn data(&self, stream_id: u64, data: Vec<u8>, fin: bool) {
        self.insert(Http3ServerEvent::Data {
            stream_id,
            data,
            fin,
        });
    }

    pub fn events(&self) -> impl Iterator<Item = Http3ServerEvent> {
        self.events.replace(BTreeSet::new()).into_iter()
    }
}

impl Http3Events for Http3ServerEvents {
    fn data_writable(&self, _stream_id: u64) {}

    fn reset(&self, stream_id: u64, error: AppError) {
        self.insert(Http3ServerEvent::Reset { stream_id, error });
    }

    fn new_requests_creatable(&self, _stream_type: StreamType) {}

    fn connection_state_change(&self, state: Http3State) {
        self.insert(Http3ServerEvent::StateChange(state));
    }

    fn remove_events_for_stream_id(&self, remove_stream_id: u64) {
        let events_to_remove = self
            .events
            .borrow()
            .iter()
            .filter(|evt| match evt {
                Http3ServerEvent::Reset { stream_id, .. } => *stream_id == remove_stream_id,
                _ => false,
            })
            .cloned()
            .collect::<SmallVec<[_; 8]>>();

        for evt in events_to_remove {
            self.remove(&evt);
        }
    }
}
