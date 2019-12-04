// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::client_events::{Http3ClientEvent, Http3ClientEvents};
use crate::connection::{Http3Connection, Http3State, Http3Transaction};
use crate::hframe::HFrame;
use crate::response_stream::PushInfo;
use crate::stream_type_reader::NewStreamTypeReader;
use crate::transaction_client::TransactionClient;
use crate::Header;
use neqo_common::{matches, qdebug, qerror, qinfo, qtrace, Datagram};
use neqo_crypto::{agent::CertificateInfo, AuthenticationStatus, SecretAgentInfo};
use neqo_transport::{
    AppError, Connection, ConnectionEvent, ConnectionIdManager, Output, Role, StreamType,
};
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

use crate::{Error, Res};

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

struct PushControl {
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

    fn handle_cancel_push(
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

    fn maybe_send_max_push_id_frame(
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

    pub fn clear(&mut self) {
        self.push_streams.clear();
        self.new_push_streams.clear();
    }
}

pub struct Http3Client {
    conn: Connection,
    base_handler: Http3Connection<TransactionClient>,
    events: Http3ClientEvents,
    push_control: PushControl,
}

impl ::std::fmt::Display for Http3Client {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http3 client")
    }
}

impl Http3Client {
    pub fn new(
        server_name: &str,
        protocols: &[impl AsRef<str>],
        cid_manager: Rc<RefCell<dyn ConnectionIdManager>>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        http3_parametars: (u32, u16, u64),
    ) -> Res<Self> {
        Ok(Http3Client::new_with_conn(
            Connection::new_client(server_name, protocols, cid_manager, local_addr, remote_addr)?,
            http3_parametars.0,
            http3_parametars.1,
            http3_parametars.2,
        ))
    }

    pub fn new_with_conn(
        c: Connection,
        max_table_size: u32,
        max_blocked_streams: u16,
        max_concurent_push: u64,
    ) -> Self {
        Http3Client {
            conn: c,
            base_handler: Http3Connection::new(max_table_size, max_blocked_streams),
            events: Http3ClientEvents::default(),
            push_control: PushControl::new(max_concurent_push),
        }
    }

    pub fn role(&self) -> Role {
        self.conn.role()
    }

    pub fn state(&self) -> Http3State {
        self.base_handler.state()
    }

    pub fn tls_info(&self) -> Option<&SecretAgentInfo> {
        self.conn.tls_info()
    }

    /// Get the peer's certificate.
    pub fn peer_certificate(&self) -> Option<CertificateInfo> {
        self.conn.peer_certificate()
    }

    pub fn authenticated(&mut self, status: AuthenticationStatus, now: Instant) {
        self.conn.authenticated(status, now);
    }

    pub fn close(&mut self, now: Instant, error: AppError, msg: &str) {
        qinfo!([self], "Close the connection error={} msg={}.", error, msg);
        if !matches!(self.base_handler.state, Http3State::Closing(_)| Http3State::Closed(_)) {
            self.push_control.clear();
            self.conn.close(now, error, msg);
            self.base_handler.close(error);
            self.events
                .connection_state_change(self.base_handler.state());
        }
    }

    pub fn fetch(
        &mut self,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        headers: &[Header],
    ) -> Res<u64> {
        qinfo!(
            [self],
            "Fetch method={}, scheme={}, host={}, path={}",
            method,
            scheme,
            host,
            path
        );
        let id = self.conn.stream_create(StreamType::BiDi)?;
        self.base_handler.add_transaction(
            id,
            TransactionClient::new(id, method, scheme, host, path, headers, self.events.clone()),
        );
        Ok(id)
    }

    // API: request/response streams

    pub fn stream_reset(&mut self, stream_id: u64, error: AppError) -> Res<()> {
        qinfo!([self], "reset_stream {} error={}.", stream_id, error);
        self.base_handler
            .stream_reset(&mut self.conn, stream_id, error)?;
        self.events.remove_events_for_stream_id(stream_id);
        Ok(())
    }

    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        qinfo!([self], "Close sending side stream={}.", stream_id);
        self.base_handler
            .stream_close_send(&mut self.conn, stream_id)
    }

    pub fn send_request_body(&mut self, stream_id: u64, buf: &[u8]) -> Res<usize> {
        qinfo!(
            [self],
            "send_request_body from stream {} sending {} bytes.",
            stream_id,
            buf.len()
        );
        self.base_handler
            .transactions
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?
            .send_request_body(&mut self.conn, buf)
    }

    pub fn read_response_headers(&mut self, stream_id: u64) -> Res<(Vec<Header>, bool)> {
        qinfo!([self], "read_response_headers from stream {}.", stream_id);
        let transaction = self
            .base_handler
            .transactions
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?;
        match transaction.read_response_headers() {
            Ok((headers, fin)) => {
                if transaction.done() {
                    self.remove_transaction(stream_id)?;
                }
                Ok((headers, fin))
            }
            Err(e) => Err(e),
        }
    }

    pub fn read_response_data(
        &mut self,
        now: Instant,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Res<(usize, bool)> {
        qinfo!([self], "read_data from stream {}.", stream_id);
        let transaction = self
            .base_handler
            .transactions
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?;

        match transaction.read_response_data(&mut self.conn, buf) {
            Ok((amount, fin)) => {
                if fin {
                    self.remove_transaction(stream_id)?;
                } else if amount > 0 {
                    // Directly call receive instead of adding to
                    // streams_are_readable here. This allows the app to
                    // pick up subsequent already-received data frames in
                    // the stream even if no new packets arrive to cause
                    // process_http3() to run.
                    let pushes = transaction
                        .receive(&mut self.conn, &mut self.base_handler.qpack_decoder)?;
                    self.handle_push_infos(pushes, stream_id)?;
                }
                Ok((amount, fin))
            }
            Err(e) => {
                if e == Error::HttpFrameError {
                    self.close(now, e.code(), "");
                }
                Err(e)
            }
        }
    }

    // API: Push streams

    pub fn cancel_push(&mut self, push_id: u64) -> Res<()> {
        self.push_control.cancel(
            push_id,
            &mut self.base_handler,
            &mut self.conn,
            &mut self.events,
        )
    }

    pub fn push_read_headers(&mut self, push_id: u64) -> Res<(Vec<Header>, bool)> {
        if let Some(stream_id) = self.push_control.get_active_stream_id(push_id) {
            self.read_response_headers(stream_id)
        } else {
            Err(Error::InvalidStreamId)
        }
    }

    pub fn push_read_data(
        &mut self,
        now: Instant,
        push_id: u64,
        buf: &mut [u8],
    ) -> Res<(usize, bool)> {
        if let Some(stream_id) = self.push_control.get_active_stream_id(push_id) {
            self.read_response_data(now, stream_id, buf)
        } else {
            Err(Error::InvalidStreamId)
        }
    }

    //API: events

    /// Get all current events. Best used just in debug/testing code, use
    /// next_event() instead.
    pub fn events(&mut self) -> impl Iterator<Item = Http3ClientEvent> {
        self.events.events()
    }

    /// Return true if there are outstanding events.
    pub fn has_events(&self) -> bool {
        self.events.has_events()
    }

    /// Get events that indicate state changes on the connection. This method
    /// correctly handles cases where handling one event can obsolete
    /// previously-queued events, or cause new events to be generated.
    pub fn next_event(&mut self) -> Option<Http3ClientEvent> {
        self.events.next_event()
    }

    pub fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        qtrace!([self], "Process.");
        if let Some(d) = dgram {
            self.process_input(d, now);
        }
        self.process_http3(now);
        self.process_output(now)
    }

    pub fn process_input(&mut self, dgram: Datagram, now: Instant) {
        qtrace!([self], "Process input.");
        self.conn.process_input(dgram, now);
    }

    pub fn process_timer(&mut self, now: Instant) {
        qtrace!([self], "Process timer.");
        self.conn.process_timer(now);
    }

    pub fn conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn process_http3(&mut self, now: Instant) {
        qtrace!([self], "Process http3 internal.");
        match self.base_handler.state() {
            Http3State::Connected | Http3State::GoingAway => {
                let res = self.check_connection_events();
                if self.check_result(now, res) {
                    return;
                }
                let res = self.base_handler.process_sending(&mut self.conn);
                self.check_result(now, res);
            }
            Http3State::Closed { .. } => {}
            _ => {
                let res = self.check_connection_events();
                if self.check_result(now, res) {
                    return;
                }

                // The state may switch to Connected
                if Http3State::Connected == self.base_handler.state() {
                    let res = self.base_handler.process_sending(&mut self.conn);
                    self.check_result(now, res);
                }
            }
        }
    }

    pub fn process_output(&mut self, now: Instant) -> Output {
        qtrace!([self], "Process output.");
        self.conn.process_output(now)
    }

    // This function takes the provided result and check for an error.
    // An error results in closing the connection.
    fn check_result<ERR>(&mut self, now: Instant, res: Res<ERR>) -> bool {
        match &res {
            Err(e) => {
                qinfo!([self], "Connection error: {}.", e);
                self.close(now, e.code(), &format!("{}", e));
                true
            }
            _ => false,
        }
    }

    // If this return an error the connection must be closed.
    fn check_connection_events(&mut self) -> Res<()> {
        qtrace!([self], "Check connection events.");
        while let Some(e) = self.conn.next_event() {
            qdebug!([self], "check_connection_events - event {:?}.", e);
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => match stream_type {
                    StreamType::BiDi => return Err(Error::HttpStreamCreationError),
                    StreamType::UniDi => {
                        if self
                            .base_handler
                            .handle_new_unidi_stream(&mut self.conn, stream_id)?
                        {
                            self.push_control.handle_new_push_stream(stream_id)?;
                        }
                    }
                },
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    if let Some(t) = self.base_handler.transactions.get_mut(&stream_id) {
                        if t.is_state_sending_data() {
                            self.events.data_writable(stream_id);
                        }
                    }
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    self.handle_stream_readable(stream_id)?
                }
                ConnectionEvent::RecvStreamReset {
                    stream_id,
                    app_error,
                } => {
                    if let Some(t) = self.base_handler.handle_stream_reset(
                        &mut self.conn,
                        stream_id,
                        app_error,
                    )? {
                        if let Some(push_id) = t.push_id() {
                            self.push_control.push_stream_reset(
                                push_id,
                                &mut self.base_handler,
                                &mut self.events,
                            )?;
                        } else {
                            // Post the reset event.
                            self.events.reset(stream_id, app_error);
                        }
                    }
                }
                ConnectionEvent::SendStreamStopSending {
                    stream_id,
                    app_error,
                } => self.handle_stream_stop_sending(stream_id, app_error)?,
                ConnectionEvent::SendStreamComplete { .. } => {}
                ConnectionEvent::SendStreamCreatable { stream_type } => {
                    self.events.new_requests_creatable(stream_type)
                }
                ConnectionEvent::AuthenticationNeeded => self.events.authentication_needed(),
                ConnectionEvent::StateChange(state) => {
                    if self
                        .base_handler
                        .handle_state_change(&mut self.conn, &state)?
                    {
                        self.events
                            .connection_state_change(self.base_handler.state());
                        if matches!(self.base_handler.state(), Http3State::Connected) {
                            self.push_control
                                .maybe_send_max_push_id_frame(&mut self.base_handler);
                        }
                    }
                }
                ConnectionEvent::ZeroRttRejected => {
                    // TODO(mt) work out what to do here.
                    // Everything will have to be redone: SETTINGS, qpack streams, and requests.
                }
            }
        }
        Ok(())
    }

    fn handle_stream_readable(&mut self, stream_id: u64) -> Res<()> {
        // See if this is a control, qpack or a new stream
        if let Some(res) = self
            .base_handler
            .handle_stream_readable(&mut self.conn, stream_id)?
        {
            if res.push {
                self.push_control.handle_new_push_stream(stream_id)?;
                // We also need to read from it.
                self.handle_read_stream(stream_id)?;
            } else if !res.control_frames.is_empty() {
                for f in res.control_frames.into_iter() {
                    match f {
                        HFrame::CancelPush { push_id } => self.handle_cancel_push(push_id),
                        HFrame::MaxPushId { .. } => Err(Error::HttpFrameUnexpected),
                        HFrame::Goaway { stream_id } => self.handle_goaway(stream_id),
                        _ => {
                            unreachable!(
                                "we should only put MaxPushId and Goaway into control_frames."
                            );
                        }
                    }?;
                }
            } else {
                for stream_id in res.unblocked_streams {
                    qinfo!([self], "Stream {} is unblocked", stream_id);
                    self.handle_read_stream(stream_id)?;
                }
            }
        } else if !self.handle_read_stream(stream_id)? {
            // For a new stream we receive NewStream event and a
            // RecvStreamReadable event.
            // In most cases we decode a new stream already on the NewStream
            // event and remove it from self.new_streams.
            // Therefore, while processing RecvStreamReadable there will be no
            // entry for the stream in self.new_streams.
            qdebug!("Unknown stream.");
        }
        Ok(())
    }

    fn handle_stream_stop_sending(&mut self, stop_stream_id: u64, app_err: AppError) -> Res<()> {
        qinfo!(
            [self],
            "Handle stream_stop_sending stream_id={} app_err={}",
            stop_stream_id,
            app_err
        );

        if let Some(t) = self.base_handler.transactions.get_mut(&stop_stream_id) {
            // close sending side.
            t.stop_sending();

            // If error is Error::EarlyResponse we will post StopSending event,
            // otherwise post reset.
            if app_err == Error::HttpEarlyResponse.code() && !t.is_sending_closed() {
                self.events.stop_sending(stop_stream_id, app_err);
            }
            // if error is not Error::EarlyResponse we will close receiving part as well.
            if app_err != Error::HttpEarlyResponse.code() {
                self.events.reset(stop_stream_id, app_err);
                // The server may close its sending side as well, but just to be sure
                // we will do it ourselves.
                let _ = self.conn.stream_stop_sending(stop_stream_id, app_err);
                t.reset_receiving_side();
            }
            if t.done() {
                self.remove_transaction(stop_stream_id)?;
            }
        }
        Ok(())
    }

    fn handle_goaway(&mut self, goaway_stream_id: u64) -> Res<()> {
        qinfo!([self], "handle_goaway");

        // Issue reset events for streams >= goaway stream id
        for id in self
            .base_handler
            .transactions
            .iter()
            .filter(|(id, t)| **id >= goaway_stream_id && t.push_id().is_none())
            .map(|(id, _)| *id)
        {
            self.events.reset(id, Error::HttpRequestRejected.code());
        }
        self.events.goaway_received();

        // Actually remove (i.e. don't retain) these streams
        self.base_handler
            .transactions
            .retain(|id, _| *id < goaway_stream_id);

        if self.base_handler.state == Http3State::Connected {
            self.base_handler.state = Http3State::GoingAway;
        }
        Ok(())
    }

    fn handle_push_infos(&mut self, pushes: Vec<PushInfo>, stream_id: u64) -> Res<()> {
        for p in pushes.into_iter() {
            if let Some(push_stream_id) = self.push_control.handle_push_info(
                p,
                stream_id,
                &mut self.events,
                &mut self.base_handler,
            )? {
                self.handle_read_stream(push_stream_id)?;
            }
        }
        Ok(())
    }

    fn handle_cancel_push(&mut self, push_id: u64) -> Res<()> {
        self.push_control.handle_cancel_push(
            push_id,
            &mut self.base_handler,
            &mut self.conn,
            &mut self.events,
        )
    }

    fn handle_read_stream(&mut self, stream_id: u64) -> Res<bool> {
        if let Some(transaction) = &mut self.base_handler.transactions.get_mut(&stream_id) {
            match transaction.receive(&mut self.conn, &mut self.base_handler.qpack_decoder) {
                Err(e) => {
                    qerror!([self], "Error {} ocurred reading stream {}", e, stream_id);
                    return Err(e);
                }
                Ok(pushes) => self.handle_push_infos(pushes, stream_id)?,
            }
            Ok(true)
        } else if let Some(ps) = self.push_control.handle_read_new_push_stream(
            stream_id,
            &mut self.base_handler,
            &mut self.conn,
            &mut self.events,
        )? {
            if ps {
                self.handle_read_stream(stream_id)?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_transaction(&mut self, stream_id: u64) -> Res<()> {
        if let Some(transaction) = self.base_handler.transactions.remove(&stream_id) {
            if let Some(push_id) = transaction.push_id() {
                self.push_control.close(push_id, &mut self.base_handler)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hframe::HFrame;
    use neqo_common::{matches, Encoder};
    use neqo_qpack::encoder::QPackEncoder;
    use neqo_transport::{CloseError, ConnectionEvent, FixedConnectionIdManager, State};
    use test_fixture::*;

    fn assert_closed(hconn: &Http3Client, expected: Error) {
        match hconn.state() {
            Http3State::Closing(err) | Http3State::Closed(err) => {
                assert_eq!(err, CloseError::Application(expected.code()))
            }
            _ => panic!("Wrong state {:?}", hconn.state()),
        };
    }

    /// Create a http3 client with default configuration.
    pub fn default_http3_client() -> Http3Client {
        Http3Client::new(
            DEFAULT_SERVER_NAME,
            DEFAULT_ALPN,
            Rc::new(RefCell::new(FixedConnectionIdManager::new(3))),
            loopback(),
            loopback(),
            (100, 100, 5),
        )
        .expect("create a default client")
    }

    // Start a client/server and check setting frame.
    #[allow(clippy::cognitive_complexity)]
    fn connect_and_receive_settings() -> (Http3Client, Connection) {
        // Create a client and connect it to a server.
        // We will have a http3 client on one side and a neqo_transport
        // connection on the other side so that we can check what the http3
        // side sends and also to simulate an incorrectly behaving http3
        // server.

        fixture_init();
        let mut hconn = default_http3_client();
        let mut neqo_trans_conn = default_server();

        assert_eq!(hconn.state(), Http3State::Initializing);
        let out = hconn.process(None, now());
        assert_eq!(hconn.state(), Http3State::Initializing);
        assert_eq!(*neqo_trans_conn.state(), State::WaitInitial);
        let out = neqo_trans_conn.process(out.dgram(), now());
        assert_eq!(*neqo_trans_conn.state(), State::Handshaking);
        let out = hconn.process(out.dgram(), now());
        let out = neqo_trans_conn.process(out.dgram(), now());
        assert!(out.as_dgram_ref().is_none());

        let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
        assert!(hconn.events().any(authentication_needed));
        hconn.authenticated(AuthenticationStatus::Ok, now());
        let out = hconn.process(out.dgram(), now());

        let connected = |e| matches!(e, Http3ClientEvent::StateChange(Http3State::Connected));
        assert!(hconn.events().any(connected));

        assert_eq!(hconn.state(), Http3State::Connected);
        neqo_trans_conn.process(out.dgram(), now());

        let mut connected = false;
        let mut control_stream_received = false;
        while let Some(e) = neqo_trans_conn.next_event() {
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => {
                    assert!((stream_id == 2) || (stream_id == 6) || (stream_id == 10));
                    assert_eq!(stream_type, StreamType::UniDi);
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    if stream_id == 2 {
                        control_stream_received = true;
                        // the control stream
                        let mut buf = [0u8; 100];
                        let (amount, fin) =
                            neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                        assert_eq!(fin, false);
                        const CONTROL_STREAM_DATA: &[u8] = &[
                            0x0, 0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64, 0xd, 0x1, 0x5,
                        ];
                        assert_eq!(amount, CONTROL_STREAM_DATA.len());
                        assert_eq!(&buf[..12], CONTROL_STREAM_DATA);
                    } else if stream_id == 6 {
                        let mut buf = [0u8; 100];
                        let (amount, fin) =
                            neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                        assert_eq!(fin, false);
                        assert_eq!(amount, 1);
                        assert_eq!(buf[..1], [0x2]);
                    } else if stream_id == 10 {
                        let mut buf = [0u8; 100];
                        let (amount, fin) =
                            neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                        assert_eq!(fin, false);
                        assert_eq!(amount, 1);
                        assert_eq!(buf[..1], [0x3]);
                    } else {
                        panic!("unexpected event");
                    }
                }
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    assert!((stream_id == 2) || (stream_id == 6) || (stream_id == 10));
                }
                ConnectionEvent::StateChange(State::Connected) => connected = true,
                ConnectionEvent::StateChange(_) => (),
                _ => panic!("unexpected event"),
            }
        }
        assert!(connected);
        assert!(control_stream_received);
        (hconn, neqo_trans_conn)
    }

    // Test http3 connection inintialization.
    // The client will open the control and qpack streams and send SETTINGS frame.
    #[test]
    fn test_client_connect() {
        let _ = connect_and_receive_settings();
    }

    struct PeerConnection {
        conn: Connection,
        control_stream_id: u64,
        encoder: QPackEncoder,
    }

    // Connect transport, send and receive settings.
    fn connect() -> (Http3Client, PeerConnection) {
        let (mut hconn, mut neqo_trans_conn) = connect_and_receive_settings();
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        let mut sent = neqo_trans_conn.stream_send(
            control_stream,
            &[0x0, 0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64],
        );
        assert_eq!(sent, Ok(9));
        let mut encoder = QPackEncoder::new(true);
        encoder.add_send_stream(neqo_trans_conn.stream_create(StreamType::UniDi).unwrap());
        encoder.send(&mut neqo_trans_conn).unwrap();
        let decoder_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        sent = neqo_trans_conn.stream_send(decoder_stream, &[0x3]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // assert no error occured.
        assert_eq!(hconn.state(), Http3State::Connected);
        (
            hconn,
            PeerConnection {
                conn: neqo_trans_conn,
                control_stream_id: control_stream,
                encoder,
            },
        )
    }

    // Client: Test receiving a new control stream and a SETTINGS frame.
    #[test]
    fn test_client_receive_control_frame() {
        let _ = connect();
    }

    // Client: Test that the connection will be closed if control stream
    // has been closed.
    #[test]
    fn test_client_close_control_stream() {
        let (mut hconn, mut peer_conn) = connect();
        peer_conn
            .conn
            .stream_close_send(peer_conn.control_stream_id)
            .unwrap();
        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::HttpClosedCriticalStream);
    }

    // Client: test missing SETTINGS frame
    // (the first frame sent is a garbage frame).
    #[test]
    fn test_client_missing_settings() {
        let (mut hconn, mut neqo_trans_conn) = connect_and_receive_settings();
        // Create server control stream.
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        // Send a HEADERS frame instead (which contains garbage).
        let sent = neqo_trans_conn.stream_send(control_stream, &[0x0, 0x1, 0x3, 0x0, 0x1, 0x2]);
        assert_eq!(sent, Ok(6));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::HttpMissingSettings);
    }

    // Client: receiving SETTINGS frame twice causes connection close
    // with error HTTP_UNEXPECTED_FRAME.
    #[test]
    fn test_client_receive_settings_twice() {
        let (mut hconn, mut peer_conn) = connect();
        // send the second SETTINGS frame.
        let sent = peer_conn.conn.stream_send(
            peer_conn.control_stream_id,
            &[0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64],
        );
        assert_eq!(sent, Ok(8));
        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::HttpFrameUnexpected);
    }

    fn test_wrong_frame_on_control_stream(v: &[u8]) {
        let (mut hconn, mut peer_conn) = connect();

        // receive a frame that is not allowed on the control stream.
        let _ = peer_conn.conn.stream_send(peer_conn.control_stream_id, v);

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        assert_closed(&hconn, Error::HttpFrameUnexpected);
    }

    // send DATA frame on a cortrol stream
    #[test]
    fn test_data_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(&[0x0, 0x2, 0x1, 0x2]);
    }

    // send HEADERS frame on a cortrol stream
    #[test]
    fn test_headers_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(&[0x1, 0x2, 0x1, 0x2]);
    }

    // send PUSH_PROMISE frame on a cortrol stream
    #[test]
    fn test_push_promise_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(&[0x5, 0x2, 0x1, 0x2]);
    }

    // send DUPLICATE_PUSH frame on a cortrol stream
    #[test]
    fn test_duplicate_push_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(&[0xe, 0x2, 0x1, 0x2]);
    }

    // Client: receive unkonwn stream type
    // This function also tests getting stream id that does not fit into a single byte.
    #[test]
    fn test_client_received_unknown_stream() {
        let (mut hconn, mut peer_conn) = connect();

        // create a stream with unknown type.
        let new_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        let _ = peer_conn
            .conn
            .stream_send(new_stream_id, &[0x41, 0x19, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
        let out = peer_conn.conn.process(None, now());
        let out = hconn.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // check for stop-sending with Error::HttpStreamCreationError.
        let mut stop_sending_event_found = false;
        while let Some(e) = peer_conn.conn.next_event() {
            if let ConnectionEvent::SendStreamStopSending {
                stream_id,
                app_error,
            } = e
            {
                stop_sending_event_found = true;
                assert_eq!(stream_id, new_stream_id);
                assert_eq!(app_error, Error::HttpStreamCreationError.code());
            }
        }
        assert!(stop_sending_event_found);
        assert_eq!(hconn.state(), Http3State::Connected);
    }

    // Test wrong frame on req/rec stream
    fn test_wrong_frame_on_request_stream(v: &[u8]) {
        let (mut hconn, mut peer_conn) = connect();

        assert_eq!(
            hconn.fetch("GET", "https", "something.com", "/", &[]),
            Ok(0)
        );

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        while let Some(e) = peer_conn.conn.next_event() {
            if let ConnectionEvent::NewStream {
                stream_id,
                stream_type,
            } = e
            {
                assert_eq!(stream_type, StreamType::BiDi);
                let _ = peer_conn.conn.stream_send(stream_id, v);
            }
        }
        // Generate packet with the above bad h3 input
        let out = peer_conn.conn.process(None, now());
        // Process bad input and generate stop sending frame
        let out = hconn.process(out.dgram(), now());
        // Process stop sending frame and generate an event and a reset frame
        let _ = peer_conn.conn.process(out.dgram(), now());

        assert_closed(&hconn, Error::HttpFrameUnexpected);
    }

    #[test]
    fn test_cancel_push_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0x3, 0x1, 0x5]);
    }

    #[test]
    fn test_settings_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0x4, 0x4, 0x6, 0x4, 0x8, 0x4]);
    }

    #[test]
    fn test_goaway_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0x7, 0x1, 0x5]);
    }

    #[test]
    fn test_max_push_id_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0xd, 0x1, 0x5]);
    }

    fn test_wrong_frame_on_push_stream(v: &[u8]) {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 0
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);
        // Create push stream
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();

        // Send push stream type byte, push_id and frame v.
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, &[0x01, 0x0])
            .unwrap();
        let _ = peer_conn.conn.stream_send(push_stream_id, v).unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpFrameUnexpected);
    }

    #[test]
    fn test_cancel_push_frame_on_push_stream() {
        test_wrong_frame_on_push_stream(&[0x3, 0x1, 0x5]);
    }

    #[test]
    fn test_settings_frame_on_push_stream() {
        test_wrong_frame_on_push_stream(&[0x4, 0x4, 0x6, 0x4, 0x8, 0x4]);
    }

    #[test]
    fn test_push_promise_frame_on_push_stream() {
        test_wrong_frame_on_push_stream(&[0x5, 0x2, 0x1, 0x2]);
    }

    #[test]
    fn test_goaway_frame_on_push_stream() {
        test_wrong_frame_on_push_stream(&[0x7, 0x1, 0x5]);
    }

    #[test]
    fn test_max_push_id_frame_on_push_stream() {
        test_wrong_frame_on_push_stream(&[0xd, 0x1, 0x5]);
    }

    #[test]
    fn test_duplicate_push_frame_on_push_stream() {
        test_wrong_frame_on_push_stream(&[0xe, 0x2, 0x1, 0x2]);
    }

    // Test reading of a slowly streamed frame. bytes are received one by one
    #[test]
    fn test_frame_reading() {
        let (mut hconn, mut neqo_trans_conn) = connect_and_receive_settings();

        // create a control stream.
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();

        // send the stream type
        let mut sent = neqo_trans_conn.stream_send(control_stream, &[0x0]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // start sending SETTINGS frame
        sent = neqo_trans_conn.stream_send(control_stream, &[0x4]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x4]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x6]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x0]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x8]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x0]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        assert_eq!(hconn.state(), Http3State::Connected);

        // Now test PushPromise
        sent = neqo_trans_conn.stream_send(control_stream, &[0x5]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x5]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x4]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x61]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x62]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x63]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        sent = neqo_trans_conn.stream_send(control_stream, &[0x64]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // PUSH_PROMISE on a control stream will cause an error
        assert_closed(&hconn, Error::HttpFrameUnexpected);
    }

    // We usually send the same request header. This function check if the request has been
    // receive properly by a peer.
    fn check_header_frame(peer_conn: &mut Connection, stream_id: u64, expected_fin: bool) {
        let mut buf = [0u8; 18];
        let (amount, fin) = peer_conn.stream_recv(stream_id, &mut buf).unwrap();
        const EXPECTED_REQUEST_HEADER_FRAME: &[u8] = &[
            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67, 0x35, 0x53,
            0x2e, 0x43, 0xd3, 0xc1,
        ];
        assert_eq!(fin, expected_fin);
        assert_eq!(amount, EXPECTED_REQUEST_HEADER_FRAME.len());
        assert_eq!(&buf[..], EXPECTED_REQUEST_HEADER_FRAME);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn fetch_basic() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        let events = peer_conn.conn.events().collect::<Vec<_>>();
        assert_eq!(events.len(), 6); // NewStream, RecvStreamReadable, SendStreamWritable x 4
        for e in events {
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(stream_type, StreamType::BiDi);
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    check_header_frame(&mut peer_conn.conn, stream_id, true);

                    // send response - 200  Content-Length: 6
                    // with content: 'abcdef'.
                    // The content will be send in 2 DATA frames.
                    let _ = peer_conn.conn.stream_send(
                        stream_id,
                        &[
                            // headers
                            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                            // the first data frame
                            0x0, 0x3, 0x61, 0x62, 0x63,
                            // the second data frame
                            // the first data frame
                            0x0, 0x3, 0x64, 0x65, 0x66,
                        ],
                    );
                    peer_conn.conn.stream_close_send(stream_id).unwrap();
                }
                _ => {}
            }
        }
        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events().collect::<Vec<_>>();
        assert_eq!(http_events.len(), 2);
        for e in http_events {
            match e {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = hconn
                        .read_response_data(now(), stream_id, &mut buf)
                        .unwrap();
                    assert_eq!(fin, false);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], [0x61, 0x62, 0x63]);
                }
                _ => {}
            }
        }

        hconn.process_http3(now());
        let http_events = hconn.events().collect::<Vec<_>>();
        assert_eq!(http_events.len(), 1);
        for e in http_events {
            match e {
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = hconn
                        .read_response_data(now(), stream_id, &mut buf)
                        .unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], [0x64, 0x65, 0x66]);
                }
                _ => panic!("unexpected event"),
            }
        }

        // after this stream will be removed from hcoon. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    // Helper function
    fn read_response(
        mut hconn: Http3Client,
        mut neqo_trans_conn: Connection,
        request_stream_id: u64,
    ) {
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = hconn
                        .read_response_data(now(), stream_id, &mut buf)
                        .unwrap();
                    assert_eq!(fin, true);
                    const EXPECTED_RESPONSE_BODY: &[u8] = &[0x61, 0x62, 0x63];
                    assert_eq!(amount, EXPECTED_RESPONSE_BODY.len());
                    assert_eq!(&buf[..3], EXPECTED_RESPONSE_BODY);
                }
                _ => {}
            }
        }

        // after this stream will be removed from hconn. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    // Send a request with the request body.
    #[test]
    fn fetch_with_data() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0x64, 0x65, 0x66]);
        assert_eq!(sent, Ok(3));
        let _ = hconn.stream_close_send(request_stream_id);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // find the new request/response stream and send response on it.
        while let Some(e) = peer_conn.conn.next_event() {
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(stream_type, StreamType::BiDi);
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    check_header_frame(&mut peer_conn.conn, stream_id, false);

                    // Read request body.
                    let mut buf = [0u8; 100];
                    let (amount, fin) = peer_conn.conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    const EXPECTED_REQUEST_BODY: &[u8] = &[0x0, 0x3, 0x64, 0x65, 0x66];
                    assert_eq!(amount, EXPECTED_REQUEST_BODY.len());
                    assert_eq!(&buf[..5], EXPECTED_REQUEST_BODY);

                    // send response - 200  Content-Length: 3
                    // with content: 'abc'.
                    let _ = peer_conn.conn.stream_send(
                        stream_id,
                        &[
                            // headers
                            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                            // a data frame
                            0x0, 0x3, 0x61, 0x62, 0x63,
                        ],
                    );
                    peer_conn.conn.stream_close_send(stream_id).unwrap();
                }
                _ => {}
            }
        }

        read_response(hconn, peer_conn.conn, request_stream_id);
    }

    // send a request with request body containing request_body. We expect to receive expected_data_frame_header.
    fn fetch_with_data_length_xbytes(request_body: &[u8], expected_data_frame_header: &[u8]) {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, request_body);
        assert_eq!(sent, Ok(request_body.len()));

        // Close stream.
        let _ = hconn.stream_close_send(request_stream_id);

        // We need to loop a bit until all data has been sent.
        let mut out = hconn.process(None, now());
        for _i in 0..20 {
            out = peer_conn.conn.process(out.dgram(), now());
            out = hconn.process(out.dgram(), now());
        }

        // find the new request/response stream, check received frames and send a response.
        while let Some(e) = peer_conn.conn.next_event() {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                if stream_id == request_stream_id {
                    // Read only the HEADER frame
                    check_header_frame(&mut peer_conn.conn, stream_id, false);

                    // Read the DATA frame.
                    let mut buf = [1u8; 0xffff];
                    let (amount, fin) = peer_conn.conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(
                        amount,
                        request_body.len() + expected_data_frame_header.len()
                    );

                    // Check the DATA frame header
                    assert_eq!(
                        &buf[..expected_data_frame_header.len()],
                        expected_data_frame_header
                    );

                    // Check data.
                    assert_eq!(&buf[expected_data_frame_header.len()..amount], request_body);

                    // send response - 200  Content-Length: 3
                    // with content: 'abc'.
                    let _ = peer_conn.conn.stream_send(
                        stream_id,
                        &[
                            // headers
                            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                            // a data frame
                            0x0, 0x3, 0x61, 0x62, 0x63,
                        ],
                    );
                    peer_conn.conn.stream_close_send(stream_id).unwrap();
                }
            }
        }

        read_response(hconn, peer_conn.conn, request_stream_id);
    }

    // send a request with 63 bytes. The DATA frame length field will still have 1 byte.
    #[test]
    fn fetch_with_data_length_63bytes() {
        fetch_with_data_length_xbytes(&[0u8; 63], &[0x0, 0x3f]);
    }

    // send a request with 64 bytes. The DATA frame length field will need 2 byte.
    #[test]
    fn fetch_with_data_length_64bytes() {
        fetch_with_data_length_xbytes(&[0u8; 64], &[0x0, 0x40, 0x40]);
    }

    // send a request with 16383 bytes. The DATA frame length field will still have 2 byte.
    #[test]
    fn fetch_with_data_length_16383bytes() {
        fetch_with_data_length_xbytes(&[0u8; 16383], &[0x0, 0x7f, 0xff]);
    }

    // send a request with 16384 bytes. The DATA frame length field will need 4 byte.
    #[test]
    fn fetch_with_data_length_16384bytes() {
        fetch_with_data_length_xbytes(&[0u8; 16384], &[0x0, 0x80, 0x0, 0x40, 0x0]);
    }

    // Send 2 data frames so that the second one cannot fit into the send_buf and it is only
    // partialy sent. We check that the sent data is correct.
    fn fetch_with_two_data_frames(
        first_frame: &[u8],
        expected_first_data_frame_header: &[u8],
        expected_second_data_frame_header: &[u8],
        expected_second_data_frame: &[u8],
    ) {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));

        // Send the first frame.
        let sent = hconn.send_request_body(request_stream_id, first_frame);
        assert_eq!(sent, Ok(first_frame.len()));

        // The second frame cannot fit.
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 0xffff]);
        assert_eq!(sent, Ok(expected_second_data_frame.len()));

        // Close stream.
        let _ = hconn.stream_close_send(request_stream_id);

        let mut out = hconn.process(None, now());
        // We need to loop a bit until all data has been sent.
        for _i in 0..55 {
            out = peer_conn.conn.process(out.dgram(), now());
            out = hconn.process(out.dgram(), now());
        }

        // find the new request/response stream, check received frames and send a response.
        while let Some(e) = peer_conn.conn.next_event() {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                if stream_id == request_stream_id {
                    // Read only the HEADER frame
                    check_header_frame(&mut peer_conn.conn, stream_id, false);

                    // Read DATA frames.
                    let mut buf = [1u8; 0xffff];
                    let (amount, fin) = peer_conn.conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(
                        amount,
                        expected_first_data_frame_header.len()
                            + first_frame.len()
                            + expected_second_data_frame_header.len()
                            + expected_second_data_frame.len()
                    );

                    // Check the first DATA frame header
                    let end = expected_first_data_frame_header.len();
                    assert_eq!(&buf[..end], expected_first_data_frame_header);

                    // Check the first frame data.
                    let start = end;
                    let end = end + first_frame.len();
                    assert_eq!(&buf[start..end], first_frame);

                    // Check the second DATA frame header
                    let start = end;
                    let end = end + expected_second_data_frame_header.len();
                    assert_eq!(&buf[start..end], expected_second_data_frame_header);

                    // Check the second frame data.
                    let start = end;
                    let end = end + expected_second_data_frame.len();
                    assert_eq!(&buf[start..end], expected_second_data_frame);

                    // send response - 200  Content-Length: 3
                    // with content: 'abc'.
                    let _ = peer_conn.conn.stream_send(
                        stream_id,
                        &[
                            // headers
                            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                            // a data frame
                            0x0, 0x3, 0x61, 0x62, 0x63,
                        ],
                    );
                    peer_conn.conn.stream_close_send(stream_id).unwrap();
                }
            }
        }

        read_response(hconn, peer_conn.conn, request_stream_id);
    }

    // Send 2 frames. For the second one we can only send 63 bytes.
    // After the first frame there is exactly 63+2 bytes left in the send buffer.
    #[test]
    fn fetch_two_data_frame_second_63bytes() {
        fetch_with_two_data_frames(
            &[0u8; 65447],
            &[0x0, 0x80, 0x0, 0xff, 0x0a7],
            &[0x0, 0x3f],
            &[0u8; 63],
        );
    }

    // Send 2 frames. For the second one we can only send 63 bytes.
    // After the first frame there is exactly 63+3 bytes left in the send buffer,
    // but we can only send 63 bytes.
    #[test]
    fn fetch_two_data_frame_second_63bytes_place_for_66() {
        fetch_with_two_data_frames(
            &[0u8; 65446],
            &[0x0, 0x80, 0x0, 0xff, 0x0a6],
            &[0x0, 0x3f],
            &[0u8; 63],
        );
    }

    // Send 2 frames. For the second one we can only send 64 bytes.
    // After the first frame there is exactly 64+3 bytes left in the send buffer,
    // but we can only send 64 bytes.
    #[test]
    fn fetch_two_data_frame_second_64bytes_place_for_67() {
        fetch_with_two_data_frames(
            &[0u8; 65445],
            &[0x0, 0x80, 0x0, 0xff, 0x0a5],
            &[0x0, 0x40, 0x40],
            &[0u8; 64],
        );
    }

    // Send 2 frames. For the second one we can only send 16383 bytes.
    // After the first frame there is exactly 16383+3 bytes left in the send buffer.
    #[test]
    fn fetch_two_data_frame_second_16383bytes() {
        fetch_with_two_data_frames(
            &[0u8; 49126],
            &[0x0, 0x80, 0x0, 0xbf, 0x0e6],
            &[0x0, 0x7f, 0xff],
            &[0u8; 16383],
        );
    }

    // Send 2 frames. For the second one we can only send 16383 bytes.
    // After the first frame there is exactly 16383+4 bytes left in the send buffer, but we can only send 16383 bytes.
    #[test]
    fn fetch_two_data_frame_second_16383bytes_place_for_16387() {
        fetch_with_two_data_frames(
            &[0u8; 49125],
            &[0x0, 0x80, 0x0, 0xbf, 0x0e5],
            &[0x0, 0x7f, 0xff],
            &[0u8; 16383],
        );
    }

    // Send 2 frames. For the second one we can only send 16383 bytes.
    // After the first frame there is exactly 16383+5 bytes left in the send buffer, but we can only send 16383 bytes.
    #[test]
    fn fetch_two_data_frame_second_16383bytes_place_for_16388() {
        fetch_with_two_data_frames(
            &[0u8; 49124],
            &[0x0, 0x80, 0x0, 0xbf, 0x0e4],
            &[0x0, 0x7f, 0xff],
            &[0u8; 16383],
        );
    }

    // Send 2 frames. For the second one we can send 16384 bytes.
    // After the first frame there is exactly 16384+5 bytes left in the send buffer, but we can send 16384 bytes.
    #[test]
    fn fetch_two_data_frame_second_16384bytes_place_for_16389() {
        fetch_with_two_data_frames(
            &[0u8; 49123],
            &[0x0, 0x80, 0x0, 0xbf, 0x0e3],
            &[0x0, 0x80, 0x0, 0x40, 0x0],
            &[0u8; 16384],
        );
    }

    fn read_request(mut neqo_trans_conn: &mut Connection, request_stream_id: u64) {
        // find the new request/response stream and check request data.
        while let Some(e) = neqo_trans_conn.next_event() {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                if stream_id == request_stream_id {
                    // Read only header frame
                    check_header_frame(&mut neqo_trans_conn, stream_id, false);

                    // Read DATA frames.
                    let mut buf = [1u8; 0xffff];
                    let (_, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, false);
                }
            }
        }
    }

    // Test receiving STOP_SENDING with the EarlyResponse error code.
    #[test]
    fn test_stop_sending_early_response() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = peer_conn.conn.process(out.dgram(), now());

        read_request(&mut peer_conn.conn, request_stream_id);

        // Stop sending with early_response.
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_stop_sending(request_stream_id, Error::HttpEarlyResponse.code())
        );

        // send response - 200  Content-Length: 3
        // with content: 'abc'.
        let _ = peer_conn.conn.stream_send(
            request_stream_id,
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // a data frame
                0x0, 0x3, 0x61, 0x62, 0x63,
            ],
        );
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        let mut response_headers = false;
        let mut response_body = false;
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::StopSending { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::HttpEarlyResponse.code());
                    // assert that we cannot send any more request data.
                    assert_eq!(
                        Err(Error::AlreadyClosed),
                        hconn.send_request_body(request_stream_id, &[0u8; 10])
                    );
                }
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                    response_headers = true;
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = hconn
                        .read_response_data(now(), stream_id, &mut buf)
                        .unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], [0x61, 0x62, 0x63]);
                    response_body = true;
                }
                _ => {}
            }
        }
        assert!(response_headers);
        assert!(response_body);

        // after this stream will be removed from hconn. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    // Server sends stop sending and reset.
    #[test]
    fn test_stop_sending_other_error_with_reset() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = peer_conn.conn.process(out.dgram(), now());

        read_request(&mut peer_conn.conn, request_stream_id);

        // Stop sending with RequestRejected.
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_stop_sending(request_stream_id, Error::HttpRequestRejected.code())
        );
        // also reset with RequestRejested.
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_reset_send(request_stream_id, Error::HttpRequestRejected.code())
        );

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3ClientEvent::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::HttpRequestRejected.code());
                }
                Http3ClientEvent::HeaderReady { .. } | Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not get any headers or data");
                }
                _ => {}
            }
        }

        // after this stream will be removed from hconn. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    // Server sends stop sending with RequestRejected, but it does not send reset.
    // We will reset the stream anyway.
    #[test]
    fn test_stop_sending_other_error_wo_reset() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = peer_conn.conn.process(out.dgram(), now());

        read_request(&mut peer_conn.conn, request_stream_id);

        // Stop sending with RequestRejected.
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_stop_sending(request_stream_id, Error::HttpRequestRejected.code())
        );

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3ClientEvent::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::HttpRequestRejected.code());
                }
                Http3ClientEvent::HeaderReady { .. } | Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not get any headers or data");
                }
                _ => {}
            }
        }

        // after this stream will be removed from hconn. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    // Server sends stop sending and reset. We have some events for that stream already
    // in hconn.events. The events will be removed.
    #[test]
    fn test_stop_sending_and_reset_other_error_with_events() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = peer_conn.conn.process(out.dgram(), now());

        read_request(&mut peer_conn.conn, request_stream_id);

        // send response - 200  Content-Length: 3
        // with content: 'abc'.
        let _ = peer_conn.conn.stream_send(
            request_stream_id,
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // a data frame
                0x0, 0x3, 0x61, 0x62, 0x63,
            ],
        );

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());
        // At this moment we have some new events, i.e. a HeaderReady event

        // Send a stop sending and reset.
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_stop_sending(request_stream_id, Error::HttpRequestCancelled.code())
        );
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_reset_send(request_stream_id, Error::HttpRequestCancelled.code())
        );

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3ClientEvent::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::HttpRequestCancelled.code());
                }
                Http3ClientEvent::HeaderReady { .. } | Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not get any headers or data");
                }
                _ => {}
            }
        }

        // after this stream will be removed from hconn. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    // Server sends stop sending with code that is not EarlyResponse.
    // We have some events for that stream already in the hconn.events.
    // The events will be removed.
    #[test]
    fn test_stop_sending_other_error_with_events() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = peer_conn.conn.process(out.dgram(), now());

        read_request(&mut peer_conn.conn, request_stream_id);

        // send response - 200  Content-Length: 3
        // with content: 'abc'.
        let _ = peer_conn.conn.stream_send(
            request_stream_id,
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // a data frame
                0x0, 0x3, 0x61, 0x62, 0x63,
            ],
        );

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());
        // At this moment we have some new event, i.e. a HeaderReady event

        // Send a stop sending.
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_stop_sending(request_stream_id, Error::HttpRequestCancelled.code())
        );

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3ClientEvent::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::HttpRequestCancelled.code());
                }
                Http3ClientEvent::HeaderReady { .. } | Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not get any headers or data");
                }
                _ => {}
            }
        }

        // after this stream will be removed from hconn. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    // Server sends a reset. We will close sending side as well.
    #[test]
    fn test_reset_wo_stop_sending() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3ClientEvent::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = peer_conn.conn.process(out.dgram(), now());

        read_request(&mut peer_conn.conn, request_stream_id);

        // Send a reset.
        assert_eq!(
            Ok(()),
            peer_conn
                .conn
                .stream_reset_send(request_stream_id, Error::HttpRequestCancelled.code())
        );

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3ClientEvent::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::HttpRequestCancelled.code());
                }
                Http3ClientEvent::HeaderReady { .. } | Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not get any headers or data");
                }
                _ => {}
            }
        }

        // after this stream will be removed from hconn. We will check this by trying to read
        // from the stream and that should fail.
        let mut buf = [0u8; 100];
        let res = hconn.read_response_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

        hconn.close(now(), 0, "");
    }

    fn test_incomplet_frame(res: &[u8], error: Error) {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();

        // send an incomplete response - 200  Content-Length: 3
        // with content: 'abc'.
        let _ = peer_conn.conn.stream_send(request_stream_id, res);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        while let Some(e) = hconn.next_event() {
            if let Http3ClientEvent::DataReadable { stream_id } = e {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let res = hconn.read_response_data(now(), stream_id, &mut buf);
                assert!(res.is_err());
                assert_eq!(res.unwrap_err(), Error::HttpFrameError);
            }
        }
        assert_closed(&hconn, error);
    }

    // Incomplete DATA frame
    #[test]
    fn test_incomplet_data_frame() {
        test_incomplet_frame(
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                // the data frame is incomplete.
                0x0, 0x3, 0x61, 0x62,
            ],
            Error::HttpFrameError,
        );
    }

    // Incomplete HEADERS frame
    #[test]
    fn test_incomplet_headers_frame() {
        test_incomplet_frame(
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01,
            ],
            Error::HttpFrameError,
        );
    }

    #[test]
    fn test_incomplet_unknown_frame() {
        test_incomplet_frame(&[0x21], Error::HttpFrameError);
    }

    // test goaway
    #[test]
    fn test_goaway() {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id_1 = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id_1, 0);
        let request_stream_id_2 = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id_2, 4);
        let request_stream_id_3 = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id_3, 8);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        let _ = peer_conn
            .conn
            .stream_send(peer_conn.control_stream_id, &[0x7, 0x1, 0x8]);

        // find the new request/response stream and send frame v on it.
        while let Some(e) = peer_conn.conn.next_event() {
            match e {
                ConnectionEvent::NewStream { .. } => {}
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    let mut buf = [0u8; 100];
                    let _ = peer_conn.conn.stream_recv(stream_id, &mut buf).unwrap();
                    if stream_id == request_stream_id_1 || stream_id == request_stream_id_2 {
                        // send response - 200  Content-Length: 6
                        // with content: 'abcdef'.
                        // The content will be send in 2 DATA frames.
                        let _ = peer_conn.conn.stream_send(
                            stream_id,
                            &[
                                // headers
                                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                                // the first data frame
                                0x0, 0x3, 0x61, 0x62, 0x63,
                                // the second data frame
                                // the first data frame
                                0x0, 0x3, 0x64, 0x65, 0x66,
                            ],
                        );

                        peer_conn.conn.stream_close_send(stream_id).unwrap();
                    }
                }
                _ => {}
            }
        }
        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        let mut stream_reset = false;
        let mut http_events = hconn.events().collect::<Vec<_>>();
        while !http_events.is_empty() {
            for e in http_events {
                match e {
                    Http3ClientEvent::HeaderReady { stream_id } => {
                        let h = hconn.read_response_headers(stream_id);
                        assert_eq!(
                            h,
                            Ok((
                                vec![
                                    (String::from(":status"), String::from("200")),
                                    (String::from("content-length"), String::from("3"))
                                ],
                                false
                            ))
                        );
                    }
                    Http3ClientEvent::DataReadable { stream_id } => {
                        assert!(
                            stream_id == request_stream_id_1 || stream_id == request_stream_id_2
                        );
                        let mut buf = [0u8; 100];
                        let (amount, _) = hconn
                            .read_response_data(now(), stream_id, &mut buf)
                            .unwrap();
                        assert_eq!(amount, 3);
                    }
                    Http3ClientEvent::Reset { stream_id, error } => {
                        assert!(stream_id == request_stream_id_3);
                        assert_eq!(error, Error::HttpRequestRejected.code());
                        stream_reset = true;
                    }
                    _ => {}
                }
            }
            hconn.process_http3(now());
            http_events = hconn.events().collect::<Vec<_>>();
        }

        assert!(stream_reset);
        assert_eq!(hconn.state(), Http3State::GoingAway);
        hconn.close(now(), 0, "");
    }

    fn connect_and_send_request() -> (Http3Client, PeerConnection, u64) {
        let (mut hconn, mut peer_conn) = connect();
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);

        let out = hconn.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        while let Some(e) = peer_conn.conn.next_event() {
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(stream_type, StreamType::BiDi);
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    check_header_frame(&mut peer_conn.conn, stream_id, true);
                }
                _ => {}
            }
        }

        (hconn, peer_conn, request_stream_id)
    }

    // Close stream before headers.
    #[test]
    fn test_stream_fin_wo_headers() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();
        // send fin before sending any data.
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv HeaderReady wo headers with fin.
        let e = hconn.events().next().unwrap();
        if let Http3ClientEvent::HeaderReady { stream_id } = e {
            assert_eq!(stream_id, request_stream_id);
            let h = hconn.read_response_headers(stream_id);
            assert_eq!(h, Ok((vec![], true)));
        } else {
            panic!("wrong event type");
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    // Close stream imemediately after headers.
    #[test]
    fn test_stream_fin_after_headers() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
        ];
        let _ = peer_conn.conn.stream_send(request_stream_id, data);
        // ok NOW send fin
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv HeaderReady with headers and fin.
        let e = hconn.events().next().unwrap();
        if let Http3ClientEvent::HeaderReady { stream_id } = e {
            assert_eq!(stream_id, request_stream_id);
            let h = hconn.read_response_headers(stream_id);
            assert_eq!(
                h,
                Ok((
                    vec![
                        (String::from(":status"), String::from("200")),
                        (String::from("content-length"), String::from("3"))
                    ],
                    true
                ))
            );
        } else {
            panic!("wrong event type");
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    // Send headers, read headers and than close stream.
    // We should get HeaderReady and a DataReadable
    #[test]
    fn test_stream_fin_after_headers_are_read_wo_data_frame() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
        ];
        let _ = peer_conn.conn.stream_send(request_stream_id, data);

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv headers wo fin
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                }
                Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not receive a DataGeadable event!");
                }
                _ => {}
            };
        }

        // ok NOW send fin
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv DataReadable wo data with fin
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { .. } => {
                    panic!("We should not get another HeaderReady!");
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let res = hconn.read_response_data(now(), stream_id, &mut buf);
                    let (len, fin) = res.expect("should read");
                    assert_eq!(0, len);
                    assert_eq!(fin, true);
                }
                _ => {}
            };
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    // Send headers anf an empy data frame and a close stream.
    // We should only recv HeaderReady event
    #[test]
    fn test_stream_fin_after_headers_and_a_empty_data_frame() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // data
            0x00, 0x00,
        ];
        let _ = peer_conn.conn.stream_send(request_stream_id, data);
        // ok NOW send fin
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv HeaderReady with fin.
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            true
                        ))
                    );
                }
                Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not receive a DataGeadable event!");
                }
                _ => {}
            };
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    // Send headers and an empty data frame. Read headers and then close the stream.
    // We should get a HeaderReady without fin and a DataReadable wo data and with fin.
    #[test]
    fn test_stream_fin_after_headers_an_empty_data_frame_are_read() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // the data frame
            0x0, 0x0,
        ];
        let _ = peer_conn.conn.stream_send(request_stream_id, data);

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv headers wo fin
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                }
                Http3ClientEvent::DataReadable { .. } => {
                    panic!("We should not receive a DataGeadable event!");
                }
                _ => {}
            };
        }

        // ok NOW send fin
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv no data, but do get fin
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { .. } => {
                    panic!("We should not get another HeaderReady!");
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let res = hconn.read_response_data(now(), stream_id, &mut buf);
                    let (len, fin) = res.expect("should read");
                    assert_eq!(0, len);
                    assert_eq!(fin, true);
                }
                _ => {}
            };
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    #[test]
    fn test_stream_fin_after_a_data_frame() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // the data frame is complete
            0x0, 0x3, 0x61, 0x62, 0x63,
        ];
        let _ = peer_conn.conn.stream_send(request_stream_id, data);

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv some good data wo fin
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let res = hconn.read_response_data(now(), stream_id, &mut buf);
                    let (len, fin) = res.expect("should have data");
                    assert_eq!(&buf[..len], &[0x61, 0x62, 0x63]);
                    assert_eq!(fin, false);
                }
                _ => {}
            };
        }

        // ok NOW send fin
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();
        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // fin wo data should generate DataReadable
        let e = hconn.events().next().unwrap();
        if let Http3ClientEvent::DataReadable { stream_id } = e {
            assert_eq!(stream_id, request_stream_id);
            let mut buf = [0u8; 100];
            let res = hconn.read_response_data(now(), stream_id, &mut buf);
            let (len, fin) = res.expect("should read");
            assert_eq!(0, len);
            assert_eq!(fin, true);
        } else {
            panic!("wrong event type");
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    #[test]
    fn test_multiple_data_frames() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send two data frames with fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // 2 complete data frames
            0x0, 0x3, 0x61, 0x62, 0x63, 0x0, 0x3, 0x64, 0x65, 0x66,
        ];
        let _ = peer_conn.conn.stream_send(request_stream_id, data);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Read first frame
        match hconn.events().nth(1).unwrap() {
            Http3ClientEvent::DataReadable { stream_id } => {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let (len, fin) = hconn
                    .read_response_data(now(), stream_id, &mut buf)
                    .unwrap();
                assert_eq!(&buf[..len], &[0x61, 0x62, 0x63]);
                assert_eq!(fin, false);
            }
            x => {
                eprintln!("event {:?}", x);
                panic!()
            }
        }

        // Second frame isn't read in first read_response_data(), but it generates
        // another DataReadable event so that another read_response_data() will happen to
        // pick it up.
        match hconn.events().next().unwrap() {
            Http3ClientEvent::DataReadable { stream_id } => {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let (len, fin) = hconn
                    .read_response_data(now(), stream_id, &mut buf)
                    .unwrap();
                assert_eq!(&buf[..len], &[0x64, 0x65, 0x66]);
                assert_eq!(fin, true);
            }
            x => {
                eprintln!("event {:?}", x);
                panic!()
            }
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    #[test]
    fn test_receive_grease_before_response() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Construct an unknown frame.
        const UNKNOWN_FRAME_LEN: usize = 832;
        let mut enc = Encoder::with_capacity(UNKNOWN_FRAME_LEN + 4);
        enc.encode_varint(1028u64); // Arbitrary type.
        enc.encode_varint(UNKNOWN_FRAME_LEN as u64);
        let mut buf: Vec<_> = enc.into();
        buf.resize(UNKNOWN_FRAME_LEN + buf.len(), 0);
        let _ = peer_conn.conn.stream_send(request_stream_id, &buf).unwrap();

        // Send a headers and a data frame with fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // 1 complete data frames
            0x0, 0x3, 0x61, 0x62, 0x63,
        ];
        let _ = peer_conn.conn.stream_send(request_stream_id, data);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        hconn.process(out.dgram(), now());
        hconn.process(None, now());

        // Read first frame
        match hconn.events().nth(1).unwrap() {
            Http3ClientEvent::DataReadable { stream_id } => {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let (len, fin) = hconn
                    .read_response_data(now(), stream_id, &mut buf)
                    .unwrap();
                assert_eq!(&buf[..len], &[0x61, 0x62, 0x63]);
                assert_eq!(fin, true);
            }
            x => {
                eprintln!("event {:?}", x);
                panic!()
            }
        }
        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_response_data(now(), 0, &mut buf),
            Err(Error::InvalidStreamId)
        );
    }

    #[test]
    fn test_read_frames_header_blocked() {
        let (mut hconn, mut peer_conn, request_stream_id) = connect_and_send_request();

        peer_conn.encoder.set_max_capacity(100).unwrap();
        peer_conn.encoder.set_max_blocked_streams(100).unwrap();

        let headers = vec![
            (String::from(":status"), String::from("200")),
            (String::from("my-header"), String::from("my-header")),
            (String::from("content-length"), String::from("3")),
        ];
        let encoded_headers = peer_conn
            .encoder
            .encode_header_block(&headers, request_stream_id);
        let hframe = HFrame::Headers {
            len: encoded_headers.len() as u64,
        };
        let mut d = Encoder::default();
        hframe.encode(&mut d);
        d.encode(&encoded_headers);
        let d_frame = HFrame::Data { len: 3 };
        d_frame.encode(&mut d);
        d.encode(&[0x61, 0x62, 0x63]);
        let _ = peer_conn.conn.stream_send(request_stream_id, &d[..]);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        // Send response before sending encoder instructions.
        let out = peer_conn.conn.process(None, now());
        let _out = hconn.process(out.dgram(), now());

        let header_ready_event = |e| matches!(e, Http3ClientEvent::HeaderReady { .. });
        assert!(!hconn.events().any(header_ready_event));

        // Send encoder instructions to unblock the stream.
        peer_conn.encoder.send(&mut peer_conn.conn).unwrap();

        let out = peer_conn.conn.process(None, now());
        let _out = hconn.process(out.dgram(), now());
        let _out = hconn.process(None, now());

        let mut recv_header = false;
        let mut recv_data = false;
        // Now the stream is unblocked and both headers and data will be consumed.
        while let Some(e) = hconn.next_event() {
            match e {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    recv_header = true;
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    recv_data = true;
                    assert_eq!(stream_id, request_stream_id);
                }
                x => {
                    eprintln!("event {:?}", x);
                    panic!()
                }
            }
        }
        assert!(recv_header && recv_data);
    }

    const PUSH_PROMISE_DATA: &[u8] = &[
        0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67, 0x35, 0x53, 0x2e, 0x43, 0xd3,
        0xc1,
    ];
    const PUSH_DATA: &[u8] = &[
        // headers
        0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // the data frame.
        0x0, 0x3, 0x61, 0x62, 0x63,
    ];

    const RESPONSE_DATA: &[u8] = &[
        0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x36, // the data frame is incomplete.
        0x0, 0x6, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    ];

    // Send a push promise. (this function can only handle small push_id numbers that fit
    // in a varint of length 1 byte)
    fn send_push_promise(conn: &mut Connection, stream_id: u64, push_id: u8) {
        let _ = conn.stream_send(stream_id, &[0x5, 0x11, push_id]).unwrap();
        let _ = conn.stream_send(stream_id, &PUSH_PROMISE_DATA).unwrap();
    }

    fn send_push_data(conn: &mut Connection, stream_id: u64, push_id: u8) {
        let _ = conn.stream_send(stream_id, &[0x01, push_id]).unwrap();
        let _ = conn.stream_send(stream_id, PUSH_DATA).unwrap();
        let _ = conn.stream_close_send(stream_id).unwrap();
    }

    fn check_conn_events_with_push(
        client: &mut Http3Client,
        pushes: &[(u64, u64)],
        request_stream_id: u64,
    ) {
        let mut num_push = 0;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert!(pushes
                        .iter()
                        .any(|(p, r)| p == &push_id && r == &ref_stream_id));
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    num_push += 1;
                }
                Http3ClientEvent::PushHeaderReady { push_id } => {
                    assert!(pushes.iter().any(|(p, _)| p == &push_id));
                    let h = client.push_read_headers(push_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                }
                Http3ClientEvent::PushDataReadable { push_id } => {
                    assert!(pushes.iter().any(|(p, _)| p == &push_id));
                    let mut buf = [0u8; 100];
                    let (amount, fin) = client.push_read_data(now(), push_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], PUSH_DATA[10..]);
                }
                Http3ClientEvent::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = client.read_response_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("6"))
                            ],
                            false
                        ))
                    );
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = client
                        .read_response_data(now(), stream_id, &mut buf)
                        .unwrap();
                    if amount == 0 {
                        assert_eq!(fin, true);
                    } else {
                        assert_eq!(amount, 6);
                        assert_eq!(buf[..6], RESPONSE_DATA[10..]);
                    }
                }
                _ => {}
            }
        }
        assert_eq!(num_push, pushes.len())
    }

    // Client: receive a push stream
    #[test]
    fn test_client_received_push_stream() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        // create a push stream.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let _ = peer_conn.conn.stream_send(request_stream_id, RESPONSE_DATA);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();
        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);

        assert_eq!(client.state(), Http3State::Connected);

        // Check that push stream is closed. Calling cancel_push should return InvalidStreamId.
        assert_eq!(client.cancel_push(0), Err(Error::InvalidStreamId));
    }

    #[test]
    fn test_client_received_multiple_push_streams() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);
        send_push_promise(&mut peer_conn.conn, request_stream_id, 1);

        // create the first push stream.
        let push_stream_id_0 = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id_0, 0);

        // create the second push stream.
        let push_stream_id_1 = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id_1, 1);

        let _ = peer_conn.conn.stream_send(request_stream_id, RESPONSE_DATA);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();
        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        check_conn_events_with_push(
            &mut client,
            &[(0, request_stream_id), (1, request_stream_id)],
            request_stream_id,
        );

        assert_eq!(client.state(), Http3State::Connected);

        // Check that push streams are closed. Calling cancel_push should return InvalidStreamId.
        assert_eq!(client.cancel_push(0), Err(Error::InvalidStreamId));
        assert_eq!(client.cancel_push(1), Err(Error::InvalidStreamId));
    }

    #[test]
    fn test_client_push_after_stream_headers() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send response headers
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id, &RESPONSE_DATA[..8]);

        // Send a push promise.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        // create a push stream.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        // Send response data
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id, &RESPONSE_DATA[8..]);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();
        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);

        assert_eq!(client.state(), Http3State::Connected);
    }

    #[test]
    fn test_client_push_after_a_stream_data_frame() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send response headers
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id, &RESPONSE_DATA[..8]);
        // Send response data
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id, &RESPONSE_DATA[8..]);

        // Send a push promise.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);
        // create a push stream.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        // Close the request/response stream
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);

        assert_eq!(client.state(), Http3State::Connected);
    }

    #[test]
    fn test_client_receive_push_stream_before_promise() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // create a push stream.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        let any_push_event = |e| matches!(e, Http3ClientEvent::Push{..} |Http3ClientEvent::PushHeaderReady{..} | Http3ClientEvent::PushDataReadable{..});
        assert!(!client.events().any(any_push_event));

        // Now send push_promise
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        // Send response data
        let _ = peer_conn.conn.stream_send(request_stream_id, RESPONSE_DATA);
        peer_conn.conn.stream_close_send(request_stream_id).unwrap();
        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);

        assert_eq!(client.state(), Http3State::Connected);
    }

    // Next tests test max_push_id is enforced in case:
    //  1) duplicate push frame
    //  2) push promise frame
    //  3) push stream
    //  4) cancel push frame
    //  5) calling cancel_push

    #[test]
    fn test_client_receive_duplicate_push_with_push_id_gt_max_push_id() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id, &[0xe, 0x1, 0x6])
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);
    }

    #[test]
    fn test_client_receive_push_promise_with_push_id_gt_max_push_id() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise. max_push_id is set to 5, to trigger an error we send push_id=6.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 6);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);
    }

    #[test]
    fn test_client_receive_push_stream_with_push_id_gt_max_push_id() {
        // Connect and send a request
        let (mut client, mut peer_conn) = connect();

        // Send a push stream. max_push_id is set to 5, to trigger an error we send push_id=6.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 6);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);
    }

    #[test]
    fn test_client_receive_cancel_push_with_push_id_gt_max_push_id() {
        // Connect and send a request
        let (mut client, mut peer_conn, _request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 6);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);
    }

    #[test]
    fn test_client_call_cancel_push_with_push_id_gt_max_push_id() {
        // Connect and send a request
        let (mut client, _, _) = connect_and_send_request();

        assert_eq!(client.cancel_push(6), Err(Error::InvalidStreamId));
        assert_eq!(client.state(), Http3State::Connected);
    }

    #[test]
    fn test_max_push_id_frame_update_is_sent() {
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send 2 push promises.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);
        send_push_promise(&mut peer_conn.conn, request_stream_id, 1);
        send_push_promise(&mut peer_conn.conn, request_stream_id, 2);

        // create 2 push streams.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 1);
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 2);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        check_conn_events_with_push(
            &mut client,
            &[
                (0, request_stream_id),
                (1, request_stream_id),
                (2, request_stream_id),
            ],
            request_stream_id,
        );

        let out = client.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        // Check max_push_id frame has been received
        let control_stream_readable =
            |e| matches!(e, ConnectionEvent::RecvStreamReadable{stream_id: x} if x == 2);
        assert!(peer_conn.conn.events().any(control_stream_readable));
        let mut buf = [0u8; 100];
        let (amount, fin) = peer_conn.conn.stream_recv(2, &mut buf).unwrap();
        assert_eq!(fin, false);
        const MAX_PUSH_ID_FRAME: &[u8] = &[0xd, 0x1, 0x8];
        assert_eq!(amount, MAX_PUSH_ID_FRAME.len());
        assert_eq!(&buf[..3], MAX_PUSH_ID_FRAME);

        // Check that we can send push_id=8 now
        send_push_promise(&mut peer_conn.conn, request_stream_id, 8);
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 8);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_eq!(client.state(), Http3State::Connected);

        check_conn_events_with_push(&mut client, &[(8, request_stream_id)], request_stream_id);

        assert_eq!(client.state(), Http3State::Connected);
    }

    // Test that push_id reuses are caught. A push stream may be in couple of states:
    //  1) PushState::PushPromise
    //  2) PushState::OnlyPushStream
    //  3) PushState::Active
    //  4) PushState::"Closed" (push stream is not in the list any more)
    //  5) PushState::CancelPushAndPushPromise
    //  6) PushState::CancelPushAndPushStream
    //  7) push_promise and push stream are received than cancelled, than push_promise.
    //  8) push_promise and push stream are received than cancelled, than push stream.
    #[test]
    fn test_wrong_push_ids_are_caught() {
        // 1) PushState::PushPromise

        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send it again
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);
        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);

        //  2) PushState::OnlyPushStream
        // Connect and send a request
        let (mut client, mut peer_conn, _) = connect_and_send_request();

        // Start a push stream with push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send it again
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);

        //  3) PushState::Active
        //  send a wrong PUSH_PROMISE frame

        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 0
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);
        // Start a push stream with push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
        // Now the push_stream is in PushState::Active state

        // Send it again
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);

        //  3) PushState::Active
        //  send a wrong push stream

        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 0
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);
        // Start a push stream with push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
        // Now the push_stream is in PushState::Active state

        // Send it again
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);

        //  4) PushState::Closed
        // send a wrong PUSH_PROMISE frame

        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 3.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 3);
        // Start a push stream with push_id 3.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 3);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
        // Now the push_stream is in PushState::Active state

        // We need to read the push stream, to make it change to Closed state.
        check_conn_events_with_push(&mut client, &[(3, request_stream_id)], request_stream_id);

        // Send it again
        send_push_promise(&mut peer_conn.conn, request_stream_id, 3);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);

        //  4) PushState::Closed
        // send a wrong push stream

        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 3.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 3);
        // Start a push stream with push_id 3.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 3);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
        // Now the push_stream is in PushState::Active state

        // We need to read the push stream, to make it change to Closed state.
        check_conn_events_with_push(&mut client, &[(3, request_stream_id)], request_stream_id);

        // Send it again
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 3);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        assert_closed(&client, Error::HttpIdError);

        //  5) PushState::CancelPushAndPushPromise

        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send again PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        assert_closed(&client, Error::HttpIdError);

        //  6) PushState::CancelPushAndPushStream

        let (mut client, mut peer_conn, _) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send again the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        assert_closed(&client, Error::HttpIdError);

        //  7) push_promise and push stream are received than cancelled, than push_promise.

        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send again PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        assert_closed(&client, Error::HttpIdError);

        //  8) push_promise and push stream are received than cancelled, than push stream.

        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send again the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        assert_closed(&client, Error::HttpIdError);
    }

    // 1) Client receives push_promise and push stream for push_id 5, then for push_id 3.
    // 2) Client receives push_promise and push stream for push_id 5, reads the push stream
    //    so that its state changes to Closed. After that the client receives push_promise
    //    and push stream for push_id 3.
    // 3) Client receives push_promise and push stream for push_id 5, then for push_stream 3
    //    and then push_promise.
    // 4) Client receives push_promise and push stream for push_id 5, reads the push stream
    //    so that its state changes to Closed. After that the client receives push stream 3
    //    and then push_promise for push_id 3
    #[test]
    fn test_receiving_out_of_order_push_id() {
        // 1) Client receives push_promise and push stream for push_id 5, then for push_id 3.
        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 5
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 5);
        // Start a push stream with push_id 5.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 5);
        assert_eq!(client.state(), Http3State::Connected);

        // The push stream with push_id 5 will still be in active state.

        // Send a push promise with push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);
        // Start a push stream with push_id 3.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 3);

        assert_eq!(client.state(), Http3State::Connected);

        check_conn_events_with_push(
            &mut client,
            &[(5, request_stream_id), (3, request_stream_id)],
            request_stream_id,
        );
        assert_eq!(client.state(), Http3State::Connected);

        // 2) Client receives push_promise and push stream for push_id 5, reads the push stream
        //    so that its sttate changes to Closed. After that the client receives push_promise
        //    and push stream for push_id 3.

        // Connect and send a request
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 5
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 5);
        // Start a push stream with push_id 5.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 5);
        assert_eq!(client.state(), Http3State::Connected);

        // Read push stream with push_id 5 to make it change to closed state.
        check_conn_events_with_push(&mut client, &[(5, request_stream_id)], request_stream_id);

        // Send a push promise with push_id 3
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);
        // Start a push stream with push_id 3.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 3);

        assert_eq!(client.state(), Http3State::Connected);

        check_conn_events_with_push(&mut client, &[(3, request_stream_id)], request_stream_id);
        assert_eq!(client.state(), Http3State::Connected);

        // 3) Client receives push_promise and push stream for push_id 5, then for
        //    push_stream 3 and then push_promise.

        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 5
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 5);
        // Start a push stream with push_id 5.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 5);
        assert_eq!(client.state(), Http3State::Connected);

        // The push stream with push_id 5 will still be in active state.

        // Start a push stream with push_id 3.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 3);
        // Send a push promise with push_id 3
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        check_conn_events_with_push(
            &mut client,
            &[(5, request_stream_id), (3, request_stream_id)],
            request_stream_id,
        );
        assert_eq!(client.state(), Http3State::Connected);

        // 4) Client receives push_promise and push stream for push_id 5, reads the push stream
        //    so that its state changes to Closed. After that the client receives push stream 3
        //    and then push_promise for push_id 3

        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send a push promise with push_id 5
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 5);
        // Start a push stream with push_id 5.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 5);
        assert_eq!(client.state(), Http3State::Connected);

        // Read push stream with push_id 5 to make it change to closed state.
        check_conn_events_with_push(&mut client, &[(5, request_stream_id)], request_stream_id);

        // Start a push stream with push_id 3.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 3);
        // Send a push promise with push_id 3
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        check_conn_events_with_push(&mut client, &[(3, request_stream_id)], request_stream_id);
        assert_eq!(client.state(), Http3State::Connected);
    }

    const DUP_PUSH_FRAME: &[u8] = &[0xe, 0x1, 0x0];

    fn send_request(client: &mut Http3Client, peer_conn: &mut PeerConnection) -> u64 {
        let request_stream_id = client
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();

        let _ = client.stream_close_send(request_stream_id);

        let out = client.process(None, now());
        peer_conn.conn.process(out.dgram(), now());

        request_stream_id
    }

    // The next couple of tests are for receiving duplicate push frame in diffrent states:
    // 1) A new push stream without a state and push_id is greater than expected next_push_id
    // 2) In state PushState::Init
    // 3) In state PushState::DuplicatePush
    // 4) In state PushState::PushPromise
    // 5) In state PushState::OnlyPushStream
    // 6) In state PushState::Active
    // 7) In state PushState::"Closed" (the stresm is not in the table any more)
    // 8) In state PushState::CancelPush
    // 9) In state PushState::CancelPushAndPushPromise
    // 10) In state PushState::CancelPushAndPushStream

    // 1) A new push stream without a state and push_id is greater than expected next_push_id
    #[test]
    fn test_duplicate_push_first_not_next_push_id() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 3.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, &[0xe, 0x1, 0x3])
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        // We should have Http3ClientEvent::Push and Http3ClientEvent::PushDuplicate.
        let mut push = false;
        let mut dup_push = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 3);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push = true;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 3);
                    assert_eq!(ref_stream_id, request_stream_id_2);
                    dup_push = true;
                }
                _ => {}
            }
        }
        assert!(push);
        assert!(dup_push);
    }

    // 2) In state PushState::Init
    #[test]
    fn test_duplicate_push_in_init_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        // Check that we have Http3ClientEvent::Push.
        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));

        // push with push_id=0 will be in init state.

        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // We should have Http3ClientEvent::Push and Http3ClientEvent::PushDuplicate.
        let mut push = false;
        let mut dup_push = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push = true;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id_2);
                    dup_push = true;
                }
                _ => {}
            }
        }
        assert!(push);
        assert!(dup_push);
    }

    // 3) In state PushState::DuplicatePush
    #[test]
    fn test_duplicate_push_after_duplicate_push() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Make a second request
        let request_stream_id_3 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_3, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // We should have Http3ClientEvent::Push and 2 Http3ClientEvent::PushDuplicate.
        let mut push = 0;
        let mut dup_push = 0;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push += 1;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 0);
                    assert!(
                        ref_stream_id == request_stream_id_2
                            || ref_stream_id == request_stream_id_3
                    );
                    dup_push += 1;
                }
                _ => {}
            }
        }
        assert_eq!(push, 1);
        assert_eq!(dup_push, 2);

        assert_eq!(client.state(), Http3State::Connected);
    }

    // 4) In state PushState::PushPromise
    #[test]
    fn test_duplicate_push_after_push_promise() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we have Http3ClientEvent::Push.
        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we have Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(client.events().any(dup_push_event));

        assert_eq!(client.state(), Http3State::Connected);
    }

    // 5) In state PushState::OnlyPushStream
    #[test]
    fn test_duplicate_push_after_push_stream() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Start a push stream with push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // We should have Http3ClientEvent::Push and Http3ClientEvent::PushDuplicate.
        let mut push = false;
        let mut dup_push = false;
        let mut push_headers = false;
        let mut push_data = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push = true;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id_2);
                    dup_push = true;
                }
                Http3ClientEvent::PushHeaderReady { push_id } => {
                    assert_eq!(push_id, 0);
                    let h = client.push_read_headers(push_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                    push_headers = true;
                }
                Http3ClientEvent::PushDataReadable { push_id } => {
                    assert_eq!(push_id, 0);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = client.push_read_data(now(), push_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], PUSH_DATA[10..]);
                    push_data = true;
                }
                _ => {}
            }
        }
        assert!(push);
        assert!(dup_push);
        assert!(push_headers);
        assert!(push_data);

        assert_eq!(client.state(), Http3State::Connected);
    }

    // 6) In state PushState::Active
    #[test]
    fn test_duplicate_push_after_push_promise_and_push_stream() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        // Start a push stream with push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // We should have Http3ClientEvent::Push and Http3ClientEvent::PushDuplicate.
        let mut push = false;
        let mut dup_push = false;
        let mut push_headers = false;
        let mut push_data = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push = true;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id_2);
                    dup_push = true;
                }
                Http3ClientEvent::PushHeaderReady { push_id } => {
                    assert_eq!(push_id, 0);
                    let h = client.push_read_headers(push_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                    push_headers = true;
                }
                Http3ClientEvent::PushDataReadable { push_id } => {
                    assert_eq!(push_id, 0);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = client.push_read_data(now(), push_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], PUSH_DATA[10..]);
                    push_data = true;
                }
                _ => {}
            }
        }
        assert!(push);
        assert!(dup_push);
        assert!(push_headers);
        assert!(push_data);

        assert_eq!(client.state(), Http3State::Connected);
    }

    // 7) In state PushState::"Closed" (the stresm is not in the table any more)
    #[test]
    fn test_duplicate_push_after_push_stream_has_been_closed() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        // Start a push stream with push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we do not have a Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        assert_eq!(client.state(), Http3State::Connected);
    }

    // 8) In state PushState::CancelPush
    #[test]
    fn test_duplicate_push_in_state_cancel_push() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Check that we do not have Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        assert_eq!(client.state(), Http3State::Connected);
    }

    // 9) In state PushState::CancelPushAndPushPromise
    #[test]
    fn test_duplicate_push_in_state_cancel_push_and_push_promise() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        // Check that we do not have Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        assert_eq!(client.state(), Http3State::Connected);
    }

    // 10) In state PushState::CancelPushAndPushStream
    #[test]
    fn test_duplicate_push_in_state_cancel_push_and_push_stream() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        // Check that we do not have Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        assert_eq!(client.state(), Http3State::Connected);
    }

    #[test]
    fn test_duplicate_push_first_then_push_promise() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // We should have Http3ClientEvent::Push and Http3ClientEvent::PushDuplicate.
        let mut push = false;
        let mut dup_push = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push = true;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id_2);
                    dup_push = true;
                }
                _ => {}
            }
        }
        assert!(push);
        assert!(dup_push);
    }

    #[test]
    fn test_duplicate_push_first_then_push_stream_then_push_promise() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();
        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        // Start a push stream with push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        send_push_data(&mut peer_conn.conn, push_stream_id, 0);

        // Check that we do not have any Http3ClientEvent::PushDuplicate.
        let dup_push_event = |e| matches!(e, Http3ClientEvent::PushDuplicate{ .. });
        assert!(!client.events().any(dup_push_event));

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise(&mut peer_conn.conn, request_stream_id, 0);

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // We should have Http3ClientEvent::Push and Http3ClientEvent::PushDuplicate.
        let mut push = false;
        let mut dup_push = false;
        let mut push_headers = false;
        let mut push_data = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push = true;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id_2);
                    dup_push = true;
                }
                Http3ClientEvent::PushHeaderReady { push_id } => {
                    assert_eq!(push_id, 0);
                    let h = client.push_read_headers(push_id);
                    assert_eq!(
                        h,
                        Ok((
                            vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ],
                            false
                        ))
                    );
                    push_headers = true;
                }
                Http3ClientEvent::PushDataReadable { push_id } => {
                    assert_eq!(push_id, 0);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = client.push_read_data(now(), push_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], PUSH_DATA[10..]);
                    push_data = true;
                }
                _ => {}
            }
        }
        assert!(push);
        assert!(dup_push);
        assert!(push_headers);
        assert!(push_data);

        assert_eq!(client.state(), Http3State::Connected);
    }

    fn send_cancel_push(client: &mut Http3Client, peer_conn: &mut PeerConnection, push_id: u8) {
        peer_conn
            .conn
            .stream_send(peer_conn.control_stream_id, &[0x3, 0x1, push_id])
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
    }

    fn send_push_promise_and_send_packets(
        client: &mut Http3Client,
        peer_conn: &mut PeerConnection,
        stream_id: u64,
        push_id: u8,
    ) {
        let _ = peer_conn
            .conn
            .stream_send(stream_id, &[0x5, 0x11, push_id])
            .unwrap();
        let _ = peer_conn
            .conn
            .stream_send(stream_id, &PUSH_PROMISE_DATA)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
    }

    fn send_push_data_and_send_packets(
        client: &mut Http3Client,
        peer_conn: &mut PeerConnection,
        push_id: u8,
    ) {
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();

        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, &[0x01, push_id])
            .unwrap();
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, PUSH_DATA)
            .unwrap();
        let _ = peer_conn.conn.stream_close_send(push_stream_id).unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
    }

    // The folowing tests have diffrent pattern of frames and streams.
    // The function name list the order. To make it shorter:
    // cp - stands for CANCEL_PUSH frame
    // pp - stands for PUSH_PROMISE frame
    // ps - stands for push stream

    // Test push_promise and push streams in different not-cancelled state:
    //  1) Push promise for a new state greater than next_push_id
    //  2) Push promise in PushState::Init
    //  3) Push promise in PushState::DuplicatePush
    //  4) Push promise in PushState::PushPromise
    //  5) Push promise in PushState::OnlyPushStream
    //  6) Push promise in PushState::Active

    //  7) Push stream for a new state greater than next_push_id
    //  8) Push stream in PushState::Init
    //  9) Push stream in PushState::DuplicatePush
    //  10) Push stream in PushState::PushPromise
    //  11) Push stream in PushState::OnlyPushStream
    //  12) Push stream in PushState::Active

    //  1) Push promise for a new state greater than next_push_id
    #[test]
    fn test_push_promise_new_gt_next_push_id() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  2) Push promise in PushState::Init
    #[test]
    fn test_push_promise_in_init_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));

        // Push 0 is in intint state now
        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        assert!(client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  3) Push promise in PushState::DuplicatePush
    #[test]
    fn test_push_promise_in_dup_push_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();
        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // We should have Http3ClientEvent::Push and Http3ClientEvent::PushDuplicate.
        let mut push = false;
        let mut dup_push = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push {
                    push_id,
                    ref_stream_id,
                    headers,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id);
                    assert_eq!(&headers[..], PUSH_PROMISE_DATA);
                    push = true;
                }
                Http3ClientEvent::PushDuplicate {
                    push_id,
                    ref_stream_id,
                } => {
                    assert_eq!(push_id, 0);
                    assert_eq!(ref_stream_id, request_stream_id_2);
                    dup_push = true;
                }
                _ => {}
            }
        }
        assert!(push);
        assert!(dup_push);
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  4) Push promise in PushState::PushPromise
    #[test]
    fn test_push_promise_in_push_promise_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);

        // Send PUSH_PROMISE again.
        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    //  5) Push promise in PushState::OnlyPushStream
    #[test]
    fn test_push_promise_in_only_push_stream_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);
        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  6) Push promise in PushState::Active
    #[test]
    fn test_push_promise_in_active_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);
        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    //  7) Push stream for a new state greater than next_push_id
    #[test]
    fn test_push_stream_new_gt_next_push_id() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send the push stream for push_id 3.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 3);

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        check_conn_events_with_push(&mut client, &[(3, request_stream_id)], request_stream_id);
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  8) Push stream in PushState::Init
    #[test]
    fn test_push_stream_in_init_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);
        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));

        // Push 0 is in intint state now.
        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  9) Push stream in PushState::DuplicatePush
    #[test]
    fn test_push_stream_in_dup_push_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();
        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  10) Push stream in PushState::PushPromise
    #[test]
    fn test_push_stream_in_push_promise_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  11) Push stream in PushState::OnlyPushStream
    #[test]
    fn test_push_stream_in_only_push_stream_state() {
        let (mut client, mut peer_conn, _) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    //  12) Push stream in PushState::Active
    #[test]
    fn test_push_stream_in_active_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    // Testing push_promise and push streams in different cancelled states
    //  1) Push promise in PushState::CancelPush state.
    //  2) Push promise in PushState::CancelPushAndPushPromise state.
    //  3) Push promise in PushState::CancelPushAndPushStream state.
    //  4) Push promise in PushState::"Closed" state after a stream being cancelled.

    //  5) Push stream in PushState::CancelPush state.
    //  6) Push stream in PushState::CancelPushAndPushPromise state.
    //  7) Push stream in PushState::CancelPushAndPushStream state.
    //  8) Push stream in PushState::"Closed" state after a stream being cancelled.

    //  1) Push promise in PushState::CancelPush state
    #[test]
    fn test_push_cancel_cp_pp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Check that we do not have a Http3ClientEvent::Push.
        let push_event = |e| {
            matches!(e,
                Http3ClientEvent::Push{ .. }
                | Http3ClientEvent::PushHeaderReady{ .. }
                | Http3ClientEvent::PushDataReadable{ .. }
                | Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  2) Push promise in PushState::CancelPushAndPushPromise
    #[test]
    fn test_push_cancel_cp_pp_pp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the second PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    //  3) Push promise in PushState::CancelPushAndPushStream state.
    #[test]
    fn test_push_cancel_cp_ps_pp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  4) Push promise in PushState::"Closed" state after a stream being cancelled.
    #[test]
    fn test_push_cancel_cp_pp_ps_pp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send the second PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    //  5) Push stream in PushState::CancelPush state.
    #[test]
    fn test_push_cancel_cp_ps() {
        let (mut client, mut peer_conn, _request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Check that we do not have any Http3ClientEvent::Push* event.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  6) Push stream in PushState::CancelPushAndPushPromise state.
    #[test]
    fn test_push_cancel_cp_pp_ps() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  7) Push stream in PushState::CancelPushAndPushStream state.
    #[test]
    fn test_push_cancel_cp_ps_ps() {
        let (mut client, mut peer_conn, _request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send the second push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    //  8) Push stream in PushState::"Closed" state after a stream being cancelled
    #[test]
    fn test_push_cancel_cp_pp_ps_ps() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send the second push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // This will cause an error.
        assert_closed(&client, Error::HttpIdError);
    }

    // Test CANCEL_PUSH frame in different push stream states:
    //  1) CANCEL_PUSH for a new stream has been tested above (last couple of tests)
    //  2) CANCEL_PUSH for a new stream that is greater than next_push_id
    //  3) CANCEL_PUSH in state PushState::Init
    //  4) CANCEL_PUSH in state PushState::DuplicatePush
    //  5) CANCEL_PUSH in state PushState::PushPromise
    //  6) CANCEL_PUSH in state PushState::PushPromise but application never sees the push
    //  7) CANCEL_PUSH in state PushState::OnlyPushStream
    //  8) CANCEL_PUSH in state PushState::Active
    //  9) CANCEL_PUSH in state PushState::CancelPush
    //  10) CANCEL_PUSH in state PushState::CancelPushAndPushPromise
    //  11) CANCEL_PUSH in state PushState::CancelPushAndPushStream
    //  12) CANCEL_PUSH in state PushState::"Closed" (the push has been removed from the table)

    //  2) CANCEL_PUSH for a new stream that is greater than next_push_id
    // Send cancel_push for push_id=3 and the next expected push_id is 0
    #[test]
    fn test_push_cancel_cp_not_next_push_id() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 3.
        send_cancel_push(&mut client, &mut peer_conn, 3);

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  3) CANCEL_PUSH in state PushState::Init
    #[test]
    fn test_push_cancel_cp_in_init_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 3.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 3);

        // Check that we have a Http3ClientEvent::Push event.
        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  4) CANCEL_PUSH in state PushState::DuplicatePush
    #[test]
    fn test_push_cancel_dp_cp_pp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Make a second request
        let request_stream_id_2 = send_request(&mut client, &mut peer_conn);

        // Send DUPLICATE_PUSH frame for push_id 0.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id_2, DUP_PUSH_FRAME)
            .unwrap();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  5) CANCEL_PUSH in state PushState::PushPromise
    #[test]
    fn test_push_cancel_pp_cp_ps() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Check that we have a Http3ClientEvent::Push.
        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Check that we do not have only a Http3ClientEvent::PushCancel event.
        let mut push_cancel = false;
        while let Some(e) = client.next_event() {
            match e {
                Http3ClientEvent::Push { .. }
                | Http3ClientEvent::PushHeaderReady { .. }
                | Http3ClientEvent::PushDataReadable { .. } => {
                    assert!(false, "We should not have {:?} event", e);
                }
                Http3ClientEvent::PushCancelled { push_id } => {
                    assert_eq!(push_id, 0);
                    push_cancel = true;
                }
                _ => {}
            }
        }
        assert!(push_cancel);
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  6) CANCEL_PUSH in state PushState::PushPromise but application never sees the push
    #[test]
    fn test_push_cancel_pp_cp_ps_not_reading_events_after_pp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        // We should not have Push event for PushPromise any more.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  7) CANCEL_PUSH in state PushState::OnlyPushStream
    #[test]
    fn test_push_cancel_ps_cp_pp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| matches!(e, Http3ClientEvent::Push{ .. });
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  8) CANCEL_PUSH in state PushState::Active
    #[test]
    fn test_push_cancel_ps_pp_cp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e, Http3ClientEvent::Push{ .. } |
            Http3ClientEvent::PushHeaderReady{ .. } | Http3ClientEvent::PushDataReadable{ .. } |
            Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  9) CANCEL_PUSH in state PushState::CancelPush
    #[test]
    fn test_push_cancel_cp_in_cancel_push_state() {
        let (mut client, mut peer_conn, _) = connect_and_send_request();

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        assert_closed(&client, Error::HttpIdError);
    }

    //  10) CANCEL_PUSH in state PushState::CancelPushAndPushPromise
    #[test]
    fn test_push_cancel_cp_in_cancel_push_and_push_promise_state() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // 1) Server has sent cancel_push

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        assert_closed(&client, Error::HttpIdError);

        // 2) Client has cancelled the push.

        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Cancel push.
        assert_eq!(client.cancel_push(0), Ok(()));

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // assert no error occured.
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  11) CANCEL_PUSH in state PushState::CancelPushAndPushStream
    #[test]
    fn test_push_cancel_cp_in_cancel_push_and_push_stream_state() {
        let (mut client, mut peer_conn, _) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        assert_closed(&client, Error::HttpIdError);
    }

    //  12) CANCEL_PUSH in state PushState::"Closed" (the push has been removed from the table)
    #[test]
    fn test_push_cancel_ps_pp_cp_read_push_before_cp() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send the push stream for push_id 0.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 0);

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        check_conn_events_with_push(&mut client, &[(0, request_stream_id)], request_stream_id);

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e,
                Http3ClientEvent::Push{ .. }
                | Http3ClientEvent::PushHeaderReady{ .. }
                | Http3ClientEvent::PushDataReadable{ .. }
                | Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    // Test push stream has been reset:
    //  1) In state PushState:OnlyPushStream
    //  2) In state PushState:Active
    //  3) In state PushState:CancelPushAndPushStream

    //  1) In state PushState:OnlyPushStream
    #[test]
    fn test_push_cancel_ps_push_stream_reset() {
        let (mut client, mut peer_conn, _) = connect_and_send_request();

        // Send the push stream for push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, &[0x01, 0x0])
            .unwrap();
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, PUSH_DATA)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Reset the push stream
        peer_conn
            .conn
            .stream_reset_send(push_stream_id, Error::HttpRequestCancelled.code())
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        client.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e,
                Http3ClientEvent::Push{ .. }
                | Http3ClientEvent::PushHeaderReady{ .. }
                | Http3ClientEvent::PushDataReadable{ .. }
                | Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  2) In state PushState:Active
    #[test]
    fn test_push_cancel_ps_pp_push_stream_reset() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // Send the push stream for push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, &[0x01, 0x0])
            .unwrap();
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, PUSH_DATA)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send PUSH_PROMISE frame for push_id 0.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 0);

        // Reset the push stream
        peer_conn
            .conn
            .stream_reset_send(push_stream_id, Error::HttpRequestCancelled.code())
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        client.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e,
                Http3ClientEvent::Push{ .. }
                | Http3ClientEvent::PushHeaderReady{ .. }
                | Http3ClientEvent::PushDataReadable{ .. }
                | Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    //  3) In state PushState:CancelPushAndPushStream
    #[test]
    fn test_push_cancel_push_stream_reset_in_cancel_push_and_push_stream_state() {
        let (mut client, mut peer_conn, _) = connect_and_send_request();

        // Send the push stream for push_id 0.
        let push_stream_id = peer_conn.conn.stream_create(StreamType::UniDi).unwrap();
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, &[0x01, 0x0])
            .unwrap();
        let _ = peer_conn
            .conn
            .stream_send(push_stream_id, PUSH_DATA)
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());

        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);

        // Reset the push stream
        peer_conn
            .conn
            .stream_reset_send(push_stream_id, Error::HttpRequestCancelled.code())
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        client.process(out.dgram(), now());

        // Check that we do not have any Http3ClientEvent::Push* events.
        let push_event = |e| {
            matches!(e,
            Http3ClientEvent::Push{ .. }
            | Http3ClientEvent::PushHeaderReady{ .. }
            | Http3ClientEvent::PushDataReadable{ .. }
            | Http3ClientEvent::PushCancelled{ .. })
        };
        assert!(!client.events().any(push_event));
        assert_eq!(client.state(), Http3State::Connected);
    }

    #[test]
    fn test_push_cancel_call_cancel_push() {
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // 1) No stream
        assert_eq!(client.cancel_push(0), Err(Error::InvalidStreamId));

        // 2) No stream, not the next expectted push_id
        assert_eq!(client.cancel_push(3), Err(Error::InvalidStreamId));

        // 3) In state Init
        // Send PUSH_PROMISE frame for push_id 1.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 1);
        assert_eq!(client.cancel_push(0), Err(Error::InvalidStreamId));

        // 4) In state DuplicatePush
        // Send DUPLICATE_PUSH frame for push_id 2.
        let _ = peer_conn
            .conn
            .stream_send(request_stream_id, &[0xe, 0x1, 0x2])
            .unwrap();

        let out = peer_conn.conn.process(None, now());
        let out = client.process(out.dgram(), now());
        peer_conn.conn.process(out.dgram(), now());
        assert_eq!(client.cancel_push(2), Err(Error::InvalidStreamId));

        // 5) In PushPromise state
        // Stream 1 is in PushPromise state
        assert_eq!(client.cancel_push(1), Ok(()));

        // 6) In OnlyPushStream state.
        // Send the push stream for push_id 3.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 3);
        assert_eq!(client.cancel_push(3), Err(Error::InvalidStreamId));

        // 7) In Active state.
        // Send PUSH_PROMISE frame for push_id 4.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 4);
        // Send the push stream for push_id 4.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 4);
        assert_eq!(client.cancel_push(4), Ok(()));

        // Make a new connection we do not have push_id available.
        let (mut client, mut peer_conn, request_stream_id) = connect_and_send_request();

        // 8) In CancelPush state
        // Send CANCEL_PUSH for push_id 0.
        send_cancel_push(&mut client, &mut peer_conn, 0);
        assert_eq!(client.cancel_push(0), Err(Error::InvalidStreamId));

        // 9) In CancelPushAndPushPromise state
        // Send CANCEL_PUSH for push_id 1.
        send_cancel_push(&mut client, &mut peer_conn, 1);
        // Send PUSH_PROMISE frame for push_id 1.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 1);
        assert_eq!(client.cancel_push(1), Ok(()));

        // 10) In CancelPushAndPushPromise state, but canceled by calling cancel_push.
        // Send PUSH_PROMISE frame for push_id 2.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 2);
        assert_eq!(client.cancel_push(2), Ok(()));
        assert_eq!(client.cancel_push(2), Err(Error::InvalidStreamId));

        // 11) In CancelPushAndPushStream state
        // Send the push stream for push_id 3.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 3);
        assert_eq!(client.cancel_push(3), Err(Error::InvalidStreamId));

        // 12) In "Closed" state
        // Send PUSH_PROMISE frame for push_id 4.
        send_push_promise_and_send_packets(&mut client, &mut peer_conn, request_stream_id, 4);
        // Send the push stream for push_id 4.
        send_push_data_and_send_packets(&mut client, &mut peer_conn, 4);
        check_conn_events_with_push(&mut client, &[(4, request_stream_id)], request_stream_id);
        assert_eq!(client.cancel_push(4), Err(Error::InvalidStreamId));
    }
}
