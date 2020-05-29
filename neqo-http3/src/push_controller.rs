// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::client_events::{Http3ClientEvent, Http3ClientEvents};
use crate::connection::Http3Connection;
use crate::hframe::HFrame;
use crate::RecvMessageEvents;
use crate::{Error, Header, Res};
use neqo_common::{matches, qerror, qinfo, qtrace};
use neqo_transport::{AppError, Connection};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::mem;
use std::rc::Rc;

#[derive(Debug, PartialEq)]
enum PushState {
    Init,
    PushPromise {
        headers: Vec<u8>,
    },
    OnlyPushStream {
        stream_id: u64,
        events: Vec<Http3ClientEvent>,
    },
    Active {
        stream_id: u64,
        headers: Vec<u8>,
    },
}

// PushController keeps information about push stream states.
//
// PushStates:
//   Init: there is no push stream nor a push_promise. This state is only used to keep track of opened and closed
//         push streams.
//   PushPromise: the push has only ever receive a push_promise frame
//   OnlyPushStream: there is only a push stream. All push stream events, i.e. PushHeaderReady and PushDataReadable
//                   will be delayed until a push_promise is received (they are kept in `events`).
//   Active: there is a push steam and at least one push_promise frame.
//
// push_ids smaller than next_push_id_to_open are all in one of the above state or they are closed. The closed pushes
// are removed from push_streams. push_ids >= next_push_id_to_open have not been opened yet.
//
// A PushStream calls `add_new_push_stream` that may change the push state from Init to OnlyPushStream or from
// PushPromise to Active. If a stream has already been closed `add_new_push_stream` returns false (the PushStream
// will close the transport stream).
// A PushStream calls `push_stream_reset` if the transport stream has been canceled.
// When a push stream is done it calls `close`.
//
// The PushController handles:
//  PUSH_PROMISE frame: frames may change the push state from Init to PushPromise and from OnlyPushStream to
//                      Active. Frames for a closed steam is ignored.
//  CANCEL_PUSH frame: (`handle_cancel_push` will be called). If a push is in state PushPromise or Active, any
//                     posted events will be removed and a push_canceled event will be posted. If a push is in
//                     state `OnlyPushStream` or `Active` the transport stream and the `PushStream` will be closed.
//                     The frame will be ignored for already closed pushes.
//  Application calling cancel: the actions are similar to the CANCEL_PUSH frame. The difference is that
//                              `push_canceled` will not be posted and a CANCEL_PUSH frame may be sent.

#[derive(Debug)]
pub(crate) struct PushController {
    max_concurent_push: u64,
    current_max_push_id: u64,
    // push_streams holds the states of push streams.
    // We keep a stream until the stream has been closed.
    push_streams: BTreeMap<u64, PushState>,
    // The keeps the next consecutive push_id that should be open.
    // All push_id < next_push_id_to_open are in the push_stream lists. If they are not in the list they have
    // been already closed.
    next_push_id_to_open: u64,
    conn_events: Http3ClientEvents,
}

impl PushController {
    pub fn new(max_concurent_push: u64, conn_events: Http3ClientEvents) -> Self {
        PushController {
            max_concurent_push,
            current_max_push_id: 0,
            push_streams: BTreeMap::new(),
            next_push_id_to_open: 0,
            conn_events,
        }
    }
}

impl Display for PushController {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Push controler")
    }
}

impl PushController {
    /// A new `push_promise` has been received.
    /// # Errors
    /// `HttpId` if `push_id` greater than it is allowed has been received.
    pub fn new_push_promise(
        &mut self,
        push_id: u64,
        ref_stream_id: u64,
        header_block: Vec<u8>,
    ) -> Res<()> {
        qtrace!(
            [self],
            "New push promise push_id={} header_block={:?} max_push={}",
            push_id,
            header_block,
            self.max_concurent_push
        );
        qtrace!("A new push promise {} {:?}", push_id, header_block);

        self.check_push_id_and_create_stream_state(push_id)?;

        match self.push_streams.get_mut(&push_id) {
            None => {
                qtrace!(
                    "Push has been closed already {} {}.",
                    self.next_push_id_to_open,
                    push_id
                );
                Ok(())
            }
            Some(push_state) => match push_state {
                PushState::Init => {
                    self.conn_events
                        .push_promise(push_id, ref_stream_id, header_block.clone());
                    *push_state = PushState::PushPromise {
                        headers: header_block,
                    };
                    Ok(())
                }
                PushState::PushPromise { headers } | PushState::Active { headers, .. } => {
                    if header_block != *headers {
                        return Err(Error::HttpGeneralProtocol);
                    }
                    self.conn_events
                        .push_promise(push_id, ref_stream_id, header_block);
                    Ok(())
                }
                PushState::OnlyPushStream { stream_id, events } => {
                    let stream_id_tmp = *stream_id;
                    self.conn_events
                        .push_promise(push_id, ref_stream_id, header_block.clone());

                    for e in events.drain(..) {
                        self.conn_events.insert(e);
                    }
                    *push_state = PushState::Active {
                        stream_id: stream_id_tmp,
                        headers: header_block,
                    };
                    Ok(())
                }
            },
        }
    }

    pub fn add_new_push_stream(&mut self, push_id: u64, stream_id: u64) -> Res<bool> {
        qtrace!(
            "A new push stream with push_id={} stream_id={}",
            push_id,
            stream_id
        );

        self.check_push_id_and_create_stream_state(push_id)?;

        match self.push_streams.get_mut(&push_id) {
            None => {
                qinfo!("Push has been closed already.");
                Ok(false)
            }
            Some(push_state) => match push_state {
                PushState::Init => {
                    *push_state = PushState::OnlyPushStream {
                        stream_id,
                        events: Vec::new(),
                    };
                    Ok(true)
                }
                PushState::PushPromise { headers } => {
                    let tmp = mem::replace(headers, Vec::new());
                    *push_state = PushState::Active {
                        stream_id,
                        headers: tmp,
                    };
                    Ok(true)
                }
                // The following state have already have a push stream:
                // PushState::OnlyPushStream | PushState::Active
                _ => {
                    qerror!("Duplicate push stream.");
                    Err(Error::HttpId)
                }
            },
        }
    }

    fn check_push_id_and_create_stream_state(&mut self, push_id: u64) -> Res<()> {
        // Check if push id is greater than what we allow.
        if push_id > self.current_max_push_id {
            qerror!("Push id is greater than current_max_push_id.");
            return Err(Error::HttpId);
        }

        while self.next_push_id_to_open <= push_id {
            self.push_streams
                .insert(self.next_push_id_to_open, PushState::Init);
            self.next_push_id_to_open += 1;
        }

        Ok(())
    }

    pub fn handle_cancel_push(
        &mut self,
        push_id: u64,
        conn: &mut Connection,
        base_handler: &mut Http3Connection,
    ) -> Res<()> {
        qtrace!("CANCEL_PUSH frame has been received, push_id={}", push_id);

        self.check_push_id_and_create_stream_state(push_id)?;

        match self.push_streams.remove(&push_id) {
            None => {
                qtrace!("Push has already been closed (push_id={}).", push_id);
                Ok(())
            }
            Some(ps) => match ps {
                PushState::Init => Ok(()),
                PushState::PushPromise { .. } => {
                    self.conn_events.remove_events_for_push_id(push_id);
                    self.conn_events.push_canceled(push_id);
                    Ok(())
                }
                PushState::OnlyPushStream { stream_id, .. } => {
                    qerror!(
                        "A server should not send CANCEL_PUSH after a push stream has been opened."
                    );
                    let _ = base_handler.stream_reset(
                        conn,
                        stream_id,
                        Error::HttpRequestCancelled.code(),
                    );
                    Ok(())
                }
                PushState::Active { stream_id, .. } => {
                    qerror!(
                        "A server should not send CANCEL_PUSH after a push stream has been opened."
                    );
                    let _ = base_handler.stream_reset(
                        conn,
                        stream_id,
                        Error::HttpRequestCancelled.code(),
                    );
                    self.conn_events.remove_events_for_push_id(push_id);
                    self.conn_events.push_canceled(push_id);
                    Ok(())
                }
            },
        }
    }

    pub fn close(&mut self, push_id: u64) {
        qtrace!("Push stream has been closed.");
        if let Some(push_state) = self.push_streams.remove(&push_id) {
            debug_assert!(matches!(push_state, PushState::Active{..}));
        } else {
            debug_assert!(false, "Closing non existing push stream!");
        }
    }

    pub fn cancel(
        &mut self,
        push_id: u64,
        conn: &mut Connection,
        base_handler: &mut Http3Connection,
    ) -> Res<()> {
        qtrace!("Cancel push_id={}", push_id);

        self.check_push_id_and_create_stream_state(push_id)
            .map_err(|_| Error::InvalidStreamId)?;

        match self.push_streams.get(&push_id) {
            None => {
                qtrace!("Push has already been closed.");
                // If we have some events for the push_id in the event queue, the caller still does not
                // not know that the push has been closed. Otherwise return InvalidStreamId.
                if self.conn_events.has_push(push_id) {
                    self.conn_events.remove_events_for_push_id(push_id);
                    Ok(())
                } else {
                    Err(Error::InvalidStreamId)
                }
            }
            Some(PushState::PushPromise { .. }) => {
                self.conn_events.remove_events_for_push_id(push_id);
                base_handler.queue_control_frame(&HFrame::CancelPush { push_id });
                self.push_streams.remove(&push_id);
                Ok(())
            }
            Some(PushState::Active { stream_id, .. }) => {
                self.conn_events.remove_events_for_push_id(push_id);
                // Cancel the stream. the transport steam may already be done, so ignore an error.
                let _ =
                    base_handler.stream_reset(conn, *stream_id, Error::HttpRequestCancelled.code());
                self.push_streams.remove(&push_id);
                Ok(())
            }
            _ => Err(Error::InvalidStreamId),
        }
    }

    pub fn push_stream_reset(&mut self, push_id: u64) {
        qtrace!("Push stream has been reset, push_id={}", push_id);

        if let Some(push_state) = self.push_streams.get(&push_id) {
            match push_state {
                PushState::OnlyPushStream { .. } => {
                    self.push_streams.remove(&push_id);
                }
                PushState::Active { .. } => {
                    self.push_streams.remove(&push_id);
                    self.conn_events.remove_events_for_push_id(push_id);
                    self.conn_events.push_canceled(push_id);
                }
                _ => {
                    debug_assert!(
                        false,
                        "Reset cannot actually happen because we do not have a stream."
                    );
                }
            }
        }
    }

    pub fn get_active_stream_id(&self, push_id: u64) -> Option<u64> {
        match self.push_streams.get(&push_id) {
            Some(PushState::Active { stream_id, .. }) => Some(*stream_id),
            _ => None,
        }
    }

    pub fn maybe_send_max_push_id_frame(&mut self, base_handler: &mut Http3Connection) {
        let push_done = self.next_push_id_to_open - u64::try_from(self.push_streams.len()).unwrap();
        if self.max_concurent_push > 0
            && (self.current_max_push_id - push_done) <= (self.max_concurent_push / 2)
        {
            self.current_max_push_id = push_done + self.max_concurent_push;
            base_handler.queue_control_frame(&HFrame::MaxPushId {
                push_id: self.current_max_push_id,
            });
        }
    }

    pub fn handle_zero_rtt_rejected(&mut self) {
        self.current_max_push_id = 0;
    }

    pub fn clear(&mut self) {
        self.push_streams.clear();
    }

    pub fn can_receive_push(&self) -> bool {
        self.max_concurent_push > 0
    }

    pub fn new_stream_event(&mut self, push_id: u64, event: Http3ClientEvent) {
        match self.push_streams.get_mut(&push_id) {
            None => {
                debug_assert!(false, "Push has been closed already.");
            }
            Some(PushState::OnlyPushStream { events, .. }) => {
                events.push(event);
            }
            Some(PushState::Active { .. }) => {
                self.conn_events.insert(event);
            }
            _ => {
                debug_assert!(false, "No record of a stream!");
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct RecvPushEvents {
    push_id: u64,
    push_handler: Rc<RefCell<PushController>>,
}

impl RecvPushEvents {
    pub fn new(push_id: u64, push_handler: Rc<RefCell<PushController>>) -> Self {
        Self {
            push_id,
            push_handler,
        }
    }
}

impl RecvMessageEvents for RecvPushEvents {
    fn header_ready(&self, _stream_id: u64, headers: Option<Vec<Header>>, fin: bool) {
        self.push_handler.borrow_mut().new_stream_event(
            self.push_id,
            Http3ClientEvent::PushHeaderReady {
                push_id: self.push_id,
                headers,
                fin,
            },
        );
    }

    fn data_readable(&self, _stream_id: u64) {
        self.push_handler.borrow_mut().new_stream_event(
            self.push_id,
            Http3ClientEvent::PushDataReadable {
                push_id: self.push_id,
            },
        );
    }

    fn reset(&self, _stream_id: u64, _error: AppError) {}
}
