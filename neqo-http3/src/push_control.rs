// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::client_events::Http3ClientEvents;
use crate::connection::Http3Connection;
use crate::hframe::HFrame;
use crate::response_stream::PushInfo;
use crate::stream_type_reader::NewStreamTypeReader;
use crate::transaction_client::TransactionClient;
use crate::{Error, Res};
use neqo_common::{qerror, qinfo, qtrace};
use neqo_transport::Connection;

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::mem;

#[derive(Debug, PartialEq)]
enum PushState {
    Init,
    DuplicatePush(Vec<u64>),
    PushPromise,
    OnlyPushStream {
        stream_id: u64,
        dups: Vec<u64>,
    },
    Active(u64),
    // CANCEL_PUSH frame receive but not PUSH_PROMISE or a push stream
    CancelPush,
    CancelPushAndPushPromise {
        client: bool,
        server_frame: bool,
    },
    CancelPushAndPushStream {
        client: bool,
        server_frame: bool,
        server_stream_reset: bool,
    },
}

pub struct PushControl {
    max_concurent_push: u64,
    current_max_push_id: u64,
    num_push_done: u64,
    // push_streams holds the states of push streams.
    // We keep a stream until the stream has been closed and all streams with a smaller
    // push_id has been closed. This help us enforce push_id not to be reused.
    push_streams: BTreeMap<u64, PushState>,
    // The keeps the next consecutive push_id that should be open.
    next_push_id_to_open: u64,
    // New Push stream will be added to this HashMap until push_id is read.
    new_push_streams: HashMap<u64, NewStreamTypeReader>,
}

impl PushControl {
    pub fn new(max_concurent_push: u64) -> Self {
        PushControl {
            max_concurent_push,
            current_max_push_id: 0,
            num_push_done: 0,
            push_streams: BTreeMap::new(),
            next_push_id_to_open: 0,
            new_push_streams: HashMap::new(),
        }
    }

    pub fn handle_push_info(
        &mut self,
        push: PushInfo,
        ref_stream_id: u64,
        events: &mut Http3ClientEvents,
        base_handler: &mut Http3Connection<TransactionClient>,
    ) -> Res<Option<u64>> {
        if push.header_block.is_some() {
            self.handle_push_promise_frame(push, ref_stream_id, events, base_handler)
        } else {
            self.handle_duplicate_push_frame(push, ref_stream_id, events)?;
            Ok(None)
        }
    }

    fn create_new_push_stream_state(&mut self, push_id: u64, state: PushState) {
        assert!(self.next_push_id_to_open <= push_id);

        while self.next_push_id_to_open < push_id {
            self.push_streams
                .insert(self.next_push_id_to_open, PushState::Init);
            self.next_push_id_to_open += 1;
        }

        self.push_streams.insert(push_id, state);
        self.next_push_id_to_open += 1;
    }

    fn handle_push_promise_frame(
        &mut self,
        push: PushInfo,
        ref_stream_id: u64,
        events: &mut Http3ClientEvents,
        base_handler: &mut Http3Connection<TransactionClient>,
    ) -> Res<Option<u64>> {
        qtrace!("A push promise frame {} {}", push.push_id, ref_stream_id);

        // Check if push id is greater than what we allow.
        if self.current_max_push_id < push.push_id {
            qerror!("Push id is greater than current_max_push_id.");
            return Err(Error::HttpIdError);
        }

        let ps = self.push_streams.get_mut(&push.push_id);
        match ps {
            None => {
                if self.next_push_id_to_open > push.push_id {
                    qerror!(
                        "Push has been closed already {} {}.",
                        self.next_push_id_to_open,
                        push.push_id
                    );
                    return Err(Error::HttpIdError);
                }
                self.create_new_push_stream_state(push.push_id, PushState::PushPromise);
                events.push(push.push_id, ref_stream_id, push.header_block.unwrap());
                Ok(None)
            }
            Some(push_state) => match push_state {
                PushState::Init => {
                    events.push(push.push_id, ref_stream_id, push.header_block.unwrap());
                    *push_state = PushState::PushPromise;
                    Ok(None)
                }
                PushState::DuplicatePush(dups) => {
                    events.push(push.push_id, ref_stream_id, push.header_block.unwrap());
                    // We have received some DuplicatePush before PushPromise. We can now
                    // add PushDuplicate events for them.
                    for id in dups {
                        events.push_duplicate(push.push_id, *id);
                    }
                    *push_state = PushState::PushPromise;
                    Ok(None)
                }
                PushState::OnlyPushStream { stream_id, dups } => {
                    let stream_id_tmp = *stream_id;
                    events.push(push.push_id, ref_stream_id, push.header_block.unwrap());
                    // We have received PushPromise. We can now add PushDuplicate events
                    // if we have received some.
                    for id in dups {
                        events.push_duplicate(push.push_id, *id);
                    }

                    // Add the stream to base_handler.transactions, becasue after receiving
                    // PUSH_PROMSE frame we can now read the data from the stream.
                    base_handler.transactions.insert(
                        stream_id_tmp,
                        TransactionClient::new_push(stream_id_tmp, push.push_id, events.clone()),
                    );
                    *push_state = PushState::Active(stream_id_tmp);
                    Ok(Some(stream_id_tmp))
                }
                PushState::CancelPush => {
                    *push_state = PushState::CancelPushAndPushPromise {
                        client: false,
                        server_frame: true,
                    };
                    Ok(None)
                }
                PushState::CancelPushAndPushStream { .. } => {
                    // We have received a PUSH_PROMISE frame and a stream -> we can remove
                    // this push_stream.
                    self.push_streams.remove(&push.push_id);
                    Ok(None)
                }
                // The following state have already received a PUSH_PROMISE frame:
                // PushState::PushPromise | PushState::Active | PushSTate::CancelPushAndPushPromise
                _ => {
                    qerror!("Duplicate push id in PushPromise frame.");
                    Err(Error::HttpIdError)
                }
            },
        }
    }

    pub fn handle_new_push_stream(&mut self, stream_id: u64) -> Res<()> {
        qtrace!("A new PUSH stream stream_id={}", stream_id);
        if self.max_concurent_push == 0 {
            return Err(Error::HttpIdError);
        }
        match self.new_push_streams.entry(stream_id) {
            Entry::Occupied(_) => {
                debug_assert!(false, "We have received multiple ConnectionEvent::NewStream with the same stream_id {}", stream_id);
            }
            Entry::Vacant(v) => {
                v.insert(NewStreamTypeReader::new());
            }
        }
        Ok(())
    }

    pub fn handle_read_new_push_stream(
        &mut self,
        stream_id: u64,
        base_handler: &mut Http3Connection<TransactionClient>,
        conn: &mut Connection,
        events: &mut Http3ClientEvents,
    ) -> Res<Option<bool>> {
        if let Some(ps) = self.new_push_streams.get_mut(&stream_id) {
            let push_id = ps.get_type(conn, stream_id);
            let fin = ps.fin();
            if fin {
                self.new_push_streams.remove(&stream_id);
                return Ok(Some(false));
            }
            let mut is_active = false;
            if let Some(p) = push_id {
                self.new_push_streams.remove(&stream_id);

                is_active = self.add_new_push_stream(p, stream_id, base_handler, conn, events)?;
            }
            return Ok(Some(is_active));
        }
        Ok(None)
    }

    fn add_new_push_stream(
        &mut self,
        push_id: u64,
        stream_id: u64,
        base_handler: &mut Http3Connection<TransactionClient>,
        conn: &mut Connection,
        events: &mut Http3ClientEvents,
    ) -> Res<bool> {
        qtrace!(
            "A new push stream with push_id={} stream_id={}",
            push_id,
            stream_id
        );

        // Check if push id is greater than what we allow.
        if self.current_max_push_id < push_id {
            qerror!("Push id is greater than current_max_push_id.");
            return Err(Error::HttpIdError);
        }

        let ps = self.push_streams.get_mut(&push_id);
        match ps {
            None => {
                if self.next_push_id_to_open > push_id {
                    qerror!("Push has been closed already.");
                    return Err(Error::HttpIdError);
                }
                self.create_new_push_stream_state(
                    push_id,
                    PushState::OnlyPushStream {
                        stream_id,
                        dups: Vec::new(),
                    },
                );
                Ok(false)
            }
            Some(push_state) => match push_state {
                PushState::Init => {
                    *push_state = PushState::OnlyPushStream {
                        stream_id,
                        dups: Vec::new(),
                    };
                    Ok(false)
                }
                PushState::DuplicatePush(dups) => {
                    let d = mem::replace(dups, Vec::new());
                    *push_state = PushState::OnlyPushStream { stream_id, dups: d };
                    Ok(false)
                }
                PushState::PushPromise => {
                    base_handler.transactions.insert(
                        stream_id,
                        TransactionClient::new_push(stream_id, push_id, events.clone()),
                    );
                    *push_state = PushState::Active(stream_id);
                    Ok(true)
                }
                PushState::CancelPush => {
                    *push_state = PushState::CancelPushAndPushStream {
                        client: false,
                        server_frame: true,
                        server_stream_reset: false,
                    };
                    let _ = base_handler.stream_reset(
                        conn,
                        stream_id,
                        Error::HttpRequestCancelled.code(),
                    );
                    Ok(false)
                }
                PushState::CancelPushAndPushPromise { .. } => {
                    // We have received a PUSH_PROMISE frame and a stream -> we can remove
                    // this push_stream.
                    self.push_streams.remove(&push_id);
                    let _ = base_handler.stream_reset(
                        conn,
                        stream_id,
                        Error::HttpRequestCancelled.code(),
                    );
                    Ok(false)
                }
                // The following state have already received a PUSH_PROMISE frame:
                // PushState::OnlyPushStream | PushState::Active | PushSTate::CancelPushAndPushStream
                _ => {
                    qerror!("Duplicate push id in PushPromise frame.");
                    Err(Error::HttpIdError)
                }
            },
        }
    }

    fn handle_duplicate_push_frame(
        &mut self,
        push: PushInfo,
        ref_stream_id: u64,
        events: &mut Http3ClientEvents,
    ) -> Res<()> {
        qtrace!("A duplicate push frame {} {}", push.push_id, ref_stream_id);

        // Check if push id is greater than what we allow.
        if self.current_max_push_id < push.push_id {
            qerror!("Push id is greater than current_max_push_id.");
            return Err(Error::HttpIdError);
        }

        let ps = self.push_streams.get_mut(&push.push_id);
        match ps {
            None => {
                if self.next_push_id_to_open > push.push_id {
                    qinfo!("Push has been closed already, ignore the DUPLICATE_PUSH.");
                } else {
                    self.create_new_push_stream_state(
                        push.push_id,
                        PushState::DuplicatePush(vec![ref_stream_id]),
                    );
                }
            }
            Some(push_state) => match push_state {
                PushState::Init => {
                    *push_state = PushState::DuplicatePush(vec![ref_stream_id]);
                }
                PushState::DuplicatePush(dups) | PushState::OnlyPushStream { dups, .. } => {
                    dups.push(ref_stream_id);
                }
                PushState::PushPromise | PushState::Active(_) => {
                    events.push_duplicate(push.push_id, ref_stream_id);
                }
                _ => {
                    // It is cancelled or closed no need to send dup events.
                }
            },
        }
        Ok(())
    }

    fn push_done(&mut self, base_handler: &mut Http3Connection<TransactionClient>) {
        self.num_push_done += 1;
        self.maybe_send_max_push_id_frame(base_handler);
    }

    pub fn handle_cancel_push(
        &mut self,
        push_id: u64,
        base_handler: &mut Http3Connection<TransactionClient>,
        conn: &mut Connection,
        events: &mut Http3ClientEvents,
    ) -> Res<()> {
        qtrace!("CANCEL_PUSH frame has been received, push_id={}", push_id);

        // Check if push id is greater than what we allow.
        if self.current_max_push_id < push_id {
            qerror!("Push id is greater than current_max_push_id.");
            return Err(Error::HttpIdError);
        }

        let ps = self.push_streams.get_mut(&push_id);
        match ps {
            None => {
                if self.next_push_id_to_open > push_id {
                    qtrace!("Push has already been closed.");
                    return Ok(());
                }
                self.create_new_push_stream_state(push_id, PushState::CancelPush);
                self.push_done(base_handler);
                Ok(())
            }
            Some(push_state) => match push_state {
                PushState::Init | PushState::DuplicatePush(_) => {
                    *push_state = PushState::CancelPush;
                    self.push_done(base_handler);
                    Ok(())
                }
                PushState::PushPromise => {
                    *push_state = PushState::CancelPushAndPushPromise {
                        client: false,
                        server_frame: true,
                    };
                    if events.has_push(push_id) {
                        // If app has not picked up Push event, just remove it,
                        events.remove_events_for_push_id(push_id);
                    } else {
                        // otherwise add a PushCancelled even.
                        events.push_cancelled(push_id);
                    }
                    self.push_done(base_handler);
                    Ok(())
                }
                PushState::OnlyPushStream { stream_id, .. } => {
                    qerror!("A server should not send CANCEL_PUSH after a push streanm has been opened.");
                    let _ = base_handler.stream_reset(
                        conn,
                        *stream_id,
                        Error::HttpRequestCancelled.code(),
                    );
                    *push_state = PushState::CancelPushAndPushStream {
                        client: false,
                        server_frame: true,
                        server_stream_reset: false,
                    };
                    self.push_done(base_handler);
                    Ok(())
                }
                PushState::Active(stream_id) => {
                    let _ = base_handler.stream_reset(
                        conn,
                        *stream_id,
                        Error::HttpRequestCancelled.code(),
                    );
                    self.push_streams.remove(&push_id);
                    if events.has_push(push_id) {
                        // If app has not picked up Push event, just remove it,
                        events.remove_events_for_push_id(push_id);
                    } else {
                        // otherwise add a PushCancelled even.
                        events.push_cancelled(push_id);
                    }
                    self.push_done(base_handler);
                    Ok(())
                }
                PushState::CancelPush => {
                    qerror!("CANCEL_PUSH has already been received.");
                    Err(Error::HttpIdError)
                }
                PushState::CancelPushAndPushPromise { server_frame, .. }
                | PushState::CancelPushAndPushStream { server_frame, .. }
                    if *server_frame =>
                {
                    qerror!("CANCEL_PUSH has already been received.");
                    Err(Error::HttpIdError)
                }
                PushState::CancelPushAndPushPromise { server_frame, .. }
                | PushState::CancelPushAndPushStream { server_frame, .. } => {
                    *server_frame = true;
                    Ok(())
                }
            },
        }
    }

    pub fn close(
        &mut self,
        push_id: u64,
        base_handler: &mut Http3Connection<TransactionClient>,
    ) -> Res<Option<u64>> {
        qtrace!("Push stream has been closed.");
        if let Some(p) = self.push_streams.get_mut(&push_id) {
            match p {
                PushState::Active(_) => {
                    self.push_streams.remove(&push_id);
                    self.push_done(base_handler);
                    Ok(None)
                }
                _ => Err(Error::HttpInternalError),
            }
        } else {
            qerror!("There must be a push stream");
            Err(Error::HttpInternalError)
        }
    }

    pub fn cancel(
        &mut self,
        push_id: u64,
        base_handler: &mut Http3Connection<TransactionClient>,
        conn: &mut Connection,
        events: &mut Http3ClientEvents,
    ) -> Res<()> {
        qtrace!("Cancel push_id={}", push_id);

        // Check if push id is greater than what we allow.
        if self.current_max_push_id < push_id {
            qerror!("Push id is greater than current_max_push_id.");
            return Err(Error::InvalidStreamId);
        }

        let ps = self.push_streams.get_mut(&push_id);
        match ps {
            None => {
                if self.next_push_id_to_open > push_id {
                    qtrace!("Push has already been closed.");
                    return Err(Error::InvalidStreamId);
                }
                qerror!("this function is only call for already existing pushes.");
                Err(Error::InvalidStreamId)
            }
            Some(push_state) => match push_state {
                PushState::PushPromise => {
                    *push_state = PushState::CancelPushAndPushPromise {
                        client: true,
                        server_frame: false,
                    };
                    events.remove_events_for_push_id(push_id);
                    base_handler.queue_control_frame(HFrame::CancelPush { push_id });
                    self.push_done(base_handler);
                    Ok(())
                }
                PushState::Active(stream_id) => {
                    events.remove_events_for_push_id(push_id);
                    // Cancel the stream. the transport steam may already be done, so ignore an error.
                    let _ = base_handler.stream_reset(
                        conn,
                        *stream_id,
                        Error::HttpRequestCancelled.code(),
                    );
                    self.push_streams.remove(&push_id);
                    self.push_done(base_handler);
                    Ok(())
                }

                PushState::CancelPushAndPushPromise { client, .. } if *client => {
                    qerror!("The push has already been cancelled.");
                    Err(Error::InvalidStreamId)
                }
                PushState::CancelPushAndPushPromise { client, .. } => {
                    events.remove_events_for_push_id(push_id);
                    *client = true;
                    Ok(())
                }
                _ => Err(Error::InvalidStreamId),
            },
        }
    }

    pub fn push_stream_reset(
        &mut self,
        push_id: u64,
        base_handler: &mut Http3Connection<TransactionClient>,
        events: &mut Http3ClientEvents,
    ) -> Res<()> {
        qtrace!("Push stream has been reset, push_id={}", push_id);

        // This function will be called when a push stream has been reseted, therefore we must
        // the stream state must be in OnlyPushStream, Active, CancelPushAndPushStream
        // or closed(not in the table). In any other state this is an internal error.

        // Check if push id is greater than what we allow.
        if self.current_max_push_id < push_id {
            qerror!("Push id is greater than current_max_push_id.");
            return Err(Error::HttpInternalError);
        }

        let ps = self.push_streams.get_mut(&push_id);
        match ps {
            None => {
                if self.next_push_id_to_open > push_id {
                    qtrace!("Push has already been closed.");
                    return Ok(());
                }
                Err(Error::HttpInternalError)
            }
            Some(push_state) => {
                match push_state {
                    PushState::OnlyPushStream { .. } => {
                        qerror!("A srevr should not send CANCEL_PUSH after a push streanm has been opened.");
                        *push_state = PushState::CancelPushAndPushStream {
                            client: false,
                            server_frame: false,
                            server_stream_reset: true,
                        };
                        self.push_done(base_handler);
                        Ok(())
                    }
                    PushState::Active { .. } => {
                        self.push_streams.remove(&push_id);
                        self.push_done(base_handler);
                        if events.has_push(push_id) {
                            // If app has not picked up Push event, just remove it,
                            events.remove_events_for_push_id(push_id);
                        } else {
                            // otherwise add a PushCancelled even.
                            events.push_cancelled(push_id);
                        }
                        Ok(())
                    }
                    PushState::CancelPushAndPushStream {
                        server_stream_reset,
                        ..
                    } if *server_stream_reset => {
                        qerror!("Resetting the stream two times?");
                        Err(Error::HttpInternalError)
                    }
                    PushState::CancelPushAndPushStream {
                        server_stream_reset,
                        ..
                    } => {
                        *server_stream_reset = true;
                        Ok(())
                    }
                    _ => {
                        qerror!("Reset cannot actually happen because we do not have a stream.");
                        Err(Error::HttpInternalError)
                    }
                }
            }
        }
    }

    pub fn get_active_stream_id(&self, push_id: u64) -> Option<u64> {
        match self.push_streams.get(&push_id) {
            Some(PushState::Active(stream_id)) => Some(*stream_id),
            _ => None,
        }
    }

    pub fn maybe_send_max_push_id_frame(
        &mut self,
        base_handler: &mut Http3Connection<TransactionClient>,
    ) {
        if self.max_concurent_push > 0
            && (self.current_max_push_id - self.num_push_done) <= (self.max_concurent_push / 2)
        {
            self.current_max_push_id = self.num_push_done + self.max_concurent_push;
            base_handler.queue_control_frame(HFrame::MaxPushId {
                push_id: self.current_max_push_id,
            });
        }
    }

    pub fn reset_max_push_id_sent(&mut self) {
        self.current_max_push_id = 0;
    }

    pub fn clear(&mut self) {
        self.push_streams.clear();
        self.new_push_streams.clear();
    }
}
