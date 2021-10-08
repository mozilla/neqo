// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{ExtendedConnectEvents, ExtendedConnectType};
use crate::{CloseType, Error, HttpRecvStreamEvents, RecvStreamEvents, SendStreamEvents};
use neqo_common::{qtrace, Headers};
use neqo_transport::{AppError, StreamId};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, PartialEq)]
enum SessionState {
    Negotiating,
    Active,
    Done,
}

#[derive(Debug)]
pub struct ExtendedConnectSession {
    connect_type: ExtendedConnectType,
    state: SessionState,
    events: Box<dyn ExtendedConnectEvents>,
}

impl ::std::fmt::Display for ExtendedConnectSession {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "ExtendedConnectSesssion for {}",
            self.connect_type.string(),
        )
    }
}

impl ExtendedConnectSession {
    pub fn new(connect_type: ExtendedConnectType, events: Box<dyn ExtendedConnectEvents>) -> Self {
        Self {
            connect_type,
            state: SessionState::Negotiating,
            events,
        }
    }

    fn close(&mut self, stream_id: StreamId, error: Option<AppError>) {
        if self.state == SessionState::Done {
            return;
        }
        qtrace!("ExtendedConnect close the session");
        self.state = SessionState::Done;
        self.events
            .extended_connect_session_closed(self.connect_type, stream_id, error);
    }

    fn negotiation_done(&mut self, stream_id: StreamId, succeeded: bool) {
        if self.state == SessionState::Done {
            return;
        }
        self.state = if succeeded {
            self.events
                .extended_connect_session_established(self.connect_type, stream_id);
            SessionState::Active
        } else {
            self.events
                .extended_connect_session_closed(self.connect_type, stream_id, None);
            SessionState::Done
        };
    }
}

impl RecvStreamEvents for Rc<RefCell<ExtendedConnectSession>> {
    fn data_readable(&self, stream_id: StreamId) {
        // A session request is not expected to receive any data. This may change in
        // the future.
        self.borrow_mut()
            .close(stream_id, Some(Error::HttpGeneralProtocolStream.code()));
    }

    fn recv_closed(&self, stream_id: StreamId, close_type: CloseType) {
        self.borrow_mut().close(stream_id, close_type.error());
    }
}

impl HttpRecvStreamEvents for Rc<RefCell<ExtendedConnectSession>> {
    fn header_ready(&self, stream_id: StreamId, headers: Headers, _interim: bool, _fin: bool) {
        qtrace!("ExtendedConnect response headers {:?}", headers);
        self.borrow_mut().negotiation_done(
            stream_id,
            headers
                .iter()
                .find_map(|h| {
                    if h.name() == ":status" && h.value() == "200" {
                        Some(())
                    } else {
                        None
                    }
                })
                .is_some(),
        );
    }
}

impl SendStreamEvents for Rc<RefCell<ExtendedConnectSession>> {
    fn data_writable(&self, _stream_id: StreamId) {}

    /// Add a new `StopSending` event
    fn send_closed(&self, stream_id: StreamId, close_type: CloseType) {
        self.borrow_mut().close(stream_id, close_type.error());
    }
}
