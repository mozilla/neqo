// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::hframe::{HFrame, HFrameReader, HSettingType, H3_FRAME_TYPE_DATA};
use crate::request_stream_client::RequestStreamClient;
use crate::request_stream_server::RequestStreamServer;
use crate::request_stream_server::{Header, RequestHandler};
use neqo_common::{
    qdebug, qerror, qinfo, qwarn, Datagram, Decoder, Encoder, IncrementalDecoder,
    IncrementalDecoderResult,
};
use neqo_crypto::agent::CertificateInfo;
use neqo_crypto::{PRErrorCode, SecretAgentInfo};
use neqo_qpack::decoder::{QPackDecoder, QPACK_UNI_STREAM_TYPE_DECODER};
use neqo_qpack::encoder::{QPackEncoder, QPACK_UNI_STREAM_TYPE_ENCODER};
use neqo_transport::State;
use neqo_transport::{AppError, CloseError, Connection, ConnectionEvent, Output, Role, StreamType};

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::mem;
use std::rc::Rc;
use std::time::Instant;

use crate::{Error, Res};

const HTTP3_UNI_STREAM_TYPE_CONTROL: u64 = 0x0;
const HTTP3_UNI_STREAM_TYPE_PUSH: u64 = 0x1;

const MAX_HEADER_LIST_SIZE_DEFAULT: u64 = u64::max_value();
const NUM_PLACEHOLDERS_DEFAULT: u64 = 0;

// The local control stream, responsible for encoding frames and sending them
#[derive(Default, Debug)]
struct ControlStreamLocal {
    stream_id: Option<u64>,
    buf: Vec<u8>,
}

impl ControlStreamLocal {
    pub fn send_frame(&mut self, f: HFrame) {
        let mut enc = Encoder::default();
        f.encode(&mut enc);
        self.buf.append(&mut enc.into());
    }
    pub fn send(&mut self, conn: &mut Connection) -> Res<()> {
        if let Some(stream_id) = self.stream_id {
            if !self.buf.is_empty() {
                let sent = conn.stream_send(stream_id, &self.buf[..])?;
                if sent == self.buf.len() {
                    self.buf.clear();
                } else {
                    let b = self.buf.split_off(sent);
                    self.buf = b;
                }
            }
            return Ok(());
        }
        Ok(())
    }
}

// The remote control stream is responsible only for reading frames. The frames are handled by Http3Connection
#[derive(Debug)]
struct ControlStreamRemote {
    stream_id: Option<u64>,
    frame_reader: HFrameReader,
    fin: bool,
}

impl ::std::fmt::Display for ControlStreamRemote {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http3 remote control stream {:?}", self.stream_id)
    }
}

impl ControlStreamRemote {
    pub fn new() -> ControlStreamRemote {
        ControlStreamRemote {
            stream_id: None,
            frame_reader: HFrameReader::new(),
            fin: false,
        }
    }

    pub fn add_remote_stream(&mut self, stream_id: u64) -> Res<()> {
        qinfo!([self] "A new control stream {}.", stream_id);
        if self.stream_id.is_some() {
            qdebug!([self] "A control stream already exists");
            return Err(Error::WrongStreamCount);
        }
        self.stream_id = Some(stream_id);
        Ok(())
    }

    pub fn receive_if_this_stream(&mut self, conn: &mut Connection, stream_id: u64) -> Res<bool> {
        if let Some(id) = self.stream_id {
            if id == stream_id {
                self.fin = self.frame_reader.receive(conn, stream_id)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Debug)]
struct NewStreamTypeReader {
    reader: IncrementalDecoder,
    fin: bool,
}

impl NewStreamTypeReader {
    pub fn new() -> NewStreamTypeReader {
        NewStreamTypeReader {
            reader: IncrementalDecoder::decode_varint(),
            fin: false,
        }
    }
    pub fn get_type(&mut self, conn: &mut Connection, stream_id: u64) -> Option<u64> {
        // On any error we will only close this stream!
        loop {
            let to_read = self.reader.min_remaining();
            let mut buf = vec![0; to_read];
            match conn.stream_recv(stream_id, &mut buf[..]) {
                Ok((_, true)) => {
                    self.fin = true;
                    break None;
                }
                Ok((0, false)) => {
                    break None;
                }
                Ok((amount, false)) => {
                    let mut dec = Decoder::from(&buf[..amount]);
                    match self.reader.consume(&mut dec) {
                        IncrementalDecoderResult::Uint(v) => {
                            break Some(v);
                        }
                        IncrementalDecoderResult::InProgress => {}
                        _ => {
                            break None;
                        }
                    }
                }
                Err(e) => {
                    qdebug!([conn] "Error reading stream type for stream {}: {:?}", stream_id, e);
                    self.fin = true;
                    break None;
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub enum Http3State {
    Initializing,
    Connected,
    GoingAway,
    Closing(CloseError),
    Closed(CloseError),
}

pub struct Http3Connection {
    state: Http3State,
    conn: Connection,
    max_header_list_size: u64,
    num_placeholders: u64,
    control_stream_local: ControlStreamLocal,
    control_stream_remote: ControlStreamRemote,
    new_streams: HashMap<u64, NewStreamTypeReader>,
    qpack_encoder: QPackEncoder,
    qpack_decoder: QPackDecoder,
    settings_received: bool,
    streams_are_readable: BTreeSet<u64>,
    streams_have_data_to_send: BTreeSet<u64>,
    // Client only
    events: Http3Events,
    request_streams_client: HashMap<u64, RequestStreamClient>,
    // Server only
    #[allow(clippy::type_complexity)]
    handler: Option<RequestHandler>,
    request_streams_server: HashMap<u64, RequestStreamServer>,
}

impl ::std::fmt::Display for Http3Connection {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http3 connection {:?}", self.role())
    }
}

impl Http3Connection {
    pub fn new(
        c: Connection,
        max_table_size: u32,
        max_blocked_streams: u16,
        handler: Option<RequestHandler>,
    ) -> Http3Connection {
        qinfo!(
            "Create new http connection with max_table_size: {} and max_blocked_streams: {}",
            max_table_size,
            max_blocked_streams
        );
        if max_table_size > (1 << 30) - 1 {
            panic!("Wrong max_table_size");
        }
        Http3Connection {
            state: Http3State::Initializing,
            conn: c,
            max_header_list_size: MAX_HEADER_LIST_SIZE_DEFAULT,
            num_placeholders: NUM_PLACEHOLDERS_DEFAULT,
            control_stream_local: ControlStreamLocal::default(),
            control_stream_remote: ControlStreamRemote::new(),
            qpack_encoder: QPackEncoder::new(true),
            qpack_decoder: QPackDecoder::new(max_table_size, max_blocked_streams),
            new_streams: HashMap::new(),
            request_streams_client: HashMap::new(),
            request_streams_server: HashMap::new(),
            settings_received: false,
            streams_are_readable: BTreeSet::new(),
            streams_have_data_to_send: BTreeSet::new(),
            events: Http3Events::default(),
            handler,
        }
    }

    pub fn tls_info(&self) -> Option<&SecretAgentInfo> {
        self.conn.tls_info()
    }

    /// Get the peer's certificate.
    pub fn peer_certificate(&self) -> Option<CertificateInfo> {
        self.conn.peer_certificate()
    }

    pub fn authenticated(&mut self, error: PRErrorCode, now: Instant) {
        self.conn.authenticated(error, now);
    }

    fn initialize_http3_connection(&mut self) -> Res<()> {
        qdebug!([self] "initialize_http3_connection");
        self.create_control_stream()?;
        self.create_settings();
        self.create_qpack_streams()?;
        Ok(())
    }

    fn create_control_stream(&mut self) -> Res<()> {
        qdebug!([self] "create_control_stream.");
        self.control_stream_local.stream_id = Some(self.conn.stream_create(StreamType::UniDi)?);
        let mut enc = Encoder::default();
        enc.encode_varint(HTTP3_UNI_STREAM_TYPE_CONTROL as u64);
        self.control_stream_local.buf.append(&mut enc.into());
        Ok(())
    }

    fn create_qpack_streams(&mut self) -> Res<()> {
        qdebug!([self] "create_qpack_streams.");
        self.qpack_encoder
            .add_send_stream(self.conn.stream_create(StreamType::UniDi)?);
        self.qpack_decoder
            .add_send_stream(self.conn.stream_create(StreamType::UniDi)?);
        Ok(())
    }

    fn create_settings(&mut self) {
        qdebug!([self] "create_settings.");
        self.control_stream_local.send_frame(HFrame::Settings {
            settings: vec![
                (
                    HSettingType::MaxTableSize,
                    self.qpack_decoder.get_max_table_size().into(),
                ),
                (
                    HSettingType::BlockedStreams,
                    self.qpack_decoder.get_blocked_streams().into(),
                ),
            ],
        });
    }

    // This function takes the provided result and check for an error.
    // An error results in closing the connection.
    fn check_result<T>(&mut self, now: Instant, res: Res<T>) -> bool {
        match &res {
            Err(e) => {
                qinfo!([self] "Connection error: {}.", e);
                self.close(now, e.code(), &format!("{}", e));
                true
            }
            _ => false,
        }
    }

    fn role(&self) -> Role {
        self.conn.role()
    }

    pub fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        qdebug!([self] "Process.");
        if let Some(d) = dgram {
            self.process_input(d, now);
        }
        self.process_http3(now);
        self.process_output(now)
    }

    pub fn process_input(&mut self, dgram: Datagram, now: Instant) {
        qdebug!([self] "Process input.");
        self.conn.process_input(dgram, now);
    }

    pub fn conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn process_http3(&mut self, now: Instant) {
        qdebug!([self] "Process http3 internal.");
        match self.state {
            Http3State::Connected | Http3State::GoingAway => {
                let res = self.check_connection_events();
                if self.check_result(now, res) {
                    return;
                }
                let res = self.process_reading();
                if self.check_result(now, res) {
                    return;
                }
                let res = self.process_sending();
                self.check_result(now, res);
            }
            Http3State::Closed { .. } => {}
            _ => {
                let res = self.check_connection_events();
                let _ = self.check_result(now, res);
            }
        }
    }

    pub fn process_output(&mut self, now: Instant) -> Output {
        qdebug!([self] "Process output.");
        let out = self.conn.process_output(now);
        self.check_state_change(now);
        out
    }

    // If this return an error the connection must be closed.
    fn process_reading(&mut self) -> Res<()> {
        let readable = mem::replace(&mut self.streams_are_readable, BTreeSet::new());
        for stream_id in readable.iter() {
            self.handle_stream_readable(*stream_id)?;
        }
        Ok(())
    }

    fn process_sending(&mut self) -> Res<()> {
        // check if control stream has data to send.
        self.control_stream_local.send(&mut self.conn)?;

        let to_send = mem::replace(&mut self.streams_have_data_to_send, BTreeSet::new());
        if self.role() == Role::Client {
            for stream_id in to_send {
                if let Some(cs) = &mut self.request_streams_client.get_mut(&stream_id) {
                    cs.send(&mut self.conn, &mut self.qpack_encoder)?;
                    if cs.has_data_to_send() {
                        self.streams_have_data_to_send.insert(stream_id);
                    }
                }
            }
        } else {
            for stream_id in to_send {
                let mut remove_stream = false;
                if let Some(cs) = &mut self.request_streams_server.get_mut(&stream_id) {
                    cs.send(&mut self.conn)?;
                    if cs.has_data_to_send() {
                        self.streams_have_data_to_send.insert(stream_id);
                    } else {
                        remove_stream = true;
                    }
                }
                if remove_stream {
                    self.request_streams_server.remove(&stream_id);
                }
            }
        }
        self.qpack_decoder.send(&mut self.conn)?;
        self.qpack_encoder.send(&mut self.conn)?;
        Ok(())
    }

    // Active state means that we still can recv new streams, recv data and send data.
    // This is Connected state and GoingAway (in this state some streams are still active).
    fn state_active(&self) -> bool {
        (self.state == Http3State::Connected) || (self.state == Http3State::GoingAway)
    }

    // If this return an error the connection must be closed.
    fn check_connection_events(&mut self) -> Res<()> {
        qdebug!([self] "check_connection_events");
        let events = self.conn.events();
        for e in events {
            qdebug!([self] "check_connection_events - event {:?}.", e);
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => self.handle_new_stream(stream_id, stream_type)?,
                ConnectionEvent::SendStreamWritable { .. } => {
                    assert!(self.state_active());
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    assert!(self.state_active());
                    self.streams_are_readable.insert(stream_id);
                }
                ConnectionEvent::RecvStreamReset {
                    stream_id,
                    app_error,
                } => self.handle_stream_reset(stream_id, app_error)?,
                ConnectionEvent::SendStreamStopSending {
                    stream_id,
                    app_error,
                } => self.handle_stream_stop_sending(stream_id, app_error)?,
                ConnectionEvent::SendStreamComplete { stream_id } => {
                    self.handle_stream_complete(stream_id)?
                }
                ConnectionEvent::SendStreamCreatable { stream_type } => {
                    self.handle_stream_creatable(stream_type)?
                }
                ConnectionEvent::AuthenticationNeeded => {
                    self.events.borrow_mut().authentication_needed();
                }
                ConnectionEvent::StateChange(state) => {
                    match state {
                        State::Connected => self.handle_connection_connected()?,
                        State::Closing { error, .. } => {
                            self.handle_connection_closing(error.clone().into())?
                        }
                        State::Closed(error) => {
                            self.handle_connection_closed(error.clone().into())?
                        }
                        _ => {}
                    };
                }
                ConnectionEvent::ZeroRttRejected => {
                    // TODO(mt) work out what to do here.
                    // Everything will have to be redone: SETTINGS, qpack streams, and requests.
                }
            }
        }
        Ok(())
    }

    fn handle_new_stream(&mut self, stream_id: u64, stream_type: StreamType) -> Res<()> {
        qdebug!([self] "A new stream: {:?} {}.", stream_type, stream_id);
        assert!(self.state_active());
        match stream_type {
            StreamType::BiDi => match self.role() {
                Role::Server => self.handle_new_client_request(stream_id),
                Role::Client => {
                    qerror!("Client received a new bidirectional stream!");
                    // TODO: passing app error of 0, check if there's a better value
                    self.conn.stream_stop_sending(stream_id, 0)?;
                }
            },
            StreamType::UniDi => {
                let stream_type;
                let fin;
                {
                    let ns = &mut self
                        .new_streams
                        .entry(stream_id)
                        .or_insert_with(NewStreamTypeReader::new);
                    stream_type = ns.get_type(&mut self.conn, stream_id);
                    fin = ns.fin;
                }

                if fin {
                    self.new_streams.remove(&stream_id);
                } else if let Some(t) = stream_type {
                    self.decode_new_stream(t, stream_id)?;
                    self.new_streams.remove(&stream_id);
                }
            }
        };
        Ok(())
    }

    fn handle_stream_readable(&mut self, stream_id: u64) -> Res<()> {
        qdebug!([self] "Readable stream {}.", stream_id);
        assert!(self.state_active());
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        let mut unblocked_streams: Vec<u64> = Vec::new();

        if self.read_stream_client(stream_id, false)? {
            qdebug!([label] "Request/response stream {} read.", stream_id);
        } else if self.read_stream_server(stream_id, false)? {
        } else if self
            .control_stream_remote
            .receive_if_this_stream(&mut self.conn, stream_id)?
        {
            qdebug!(
                [self]
                "The remote control stream ({}) is readable.",
                stream_id
            );
            while self.control_stream_remote.frame_reader.done() || self.control_stream_remote.fin {
                self.handle_control_frame()?;
                self.control_stream_remote
                    .receive_if_this_stream(&mut self.conn, stream_id)?;
            }
        } else if self
            .qpack_encoder
            .recv_if_encoder_stream(&mut self.conn, stream_id)?
        {
            qdebug!(
                [self]
                "The qpack encoder stream ({}) is readable.",
                stream_id
            );
        } else if self.qpack_decoder.is_recv_stream(stream_id) {
            qdebug!(
                [self]
                "The qpack decoder stream ({}) is readable.",
                stream_id
            );
            unblocked_streams = self.qpack_decoder.receive(&mut self.conn, stream_id)?;
        } else if let Some(ns) = self.new_streams.get_mut(&stream_id) {
            let stream_type = ns.get_type(&mut self.conn, stream_id);
            let fin = ns.fin;
            if fin {
                self.new_streams.remove(&stream_id);
            }
            if let Some(t) = stream_type {
                self.decode_new_stream(t, stream_id)?;
                self.new_streams.remove(&stream_id);
            }
        } else {
            // For a new stream we receive NewStream event and a
            // RecvStreamReadable event.
            // In most cases we decode a new stream already on the NewStream
            // event and remove it from self.new_streams.
            // Therefore, while processing RecvStreamReadable there will be no
            // entry for the stream in self.new_streams.
            qdebug!("Unknown stream.");
        }

        for stream_id in unblocked_streams {
            qdebug!([self] "Stream {} is unblocked", stream_id);
            if self.role() == Role::Client {
                self.read_stream_client(stream_id, true)?;
            } else {
                self.read_stream_server(stream_id, true)?;
            }
        }
        Ok(())
    }

    fn handle_stream_reset(&mut self, stream_id: u64, app_err: AppError) -> Res<()> {
        assert!(self.state_active());
        self.events.reset(stream_id, app_err);
        Ok(())
    }

    fn handle_stream_stop_sending(&mut self, _stream_id: u64, _app_err: AppError) -> Res<()> {
        assert!(self.state_active());
        Ok(())
    }

    fn handle_stream_complete(&mut self, _stream_id: u64) -> Res<()> {
        assert!(self.state_active());
        Ok(())
    }

    fn handle_stream_creatable(&mut self, stream_type: StreamType) -> Res<()> {
        assert!(self.state_active());
        if stream_type == StreamType::BiDi {
            self.events.new_requests_creatable();
        }
        Ok(())
    }

    fn handle_connection_connected(&mut self) -> Res<()> {
        assert_eq!(self.state, Http3State::Initializing);
        self.events.connection_state_change(Http3State::Connected);
        self.state = Http3State::Connected;
        self.initialize_http3_connection()
    }

    fn handle_connection_closing(&mut self, error_code: CloseError) -> Res<()> {
        self.events
            .connection_state_change(Http3State::Closing(error_code));
        self.state = Http3State::Closing(error_code);
        Ok(())
    }

    fn handle_connection_closed(&mut self, error_code: CloseError) -> Res<()> {
        self.events
            .connection_state_change(Http3State::Closed(error_code));
        self.state = Http3State::Closed(error_code);
        Ok(())
    }

    fn read_stream_client(&mut self, stream_id: u64, unblocked: bool) -> Res<bool> {
        if self.role() != Role::Client {
            return Ok(false);
        }
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };

        let mut found = false;

        if let Some(request_stream) = &mut self.request_streams_client.get_mut(&stream_id) {
            qdebug!([label] "Request/response stream {} is readable.", stream_id);
            found = true;
            let res = if unblocked {
                request_stream.unblock(&mut self.qpack_decoder)
            } else {
                request_stream.receive(&mut self.conn, &mut self.qpack_decoder)
            };
            if let Err(e) = res {
                qdebug!([label] "Error {} ocurred", e);
                if e.is_stream_error() {
                    self.request_streams_client.remove(&stream_id);
                    self.conn.stream_stop_sending(stream_id, e.code())?;
                } else {
                    return Err(e);
                }
            } else if request_stream.done() {
                self.request_streams_client.remove(&stream_id);
            }
        }
        Ok(found)
    }

    fn read_stream_server(&mut self, stream_id: u64, unblocked: bool) -> Res<bool> {
        if self.role() != Role::Server {
            return Ok(false);
        }
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };

        let mut found = false;

        if let Some(request_stream) = &mut self.request_streams_server.get_mut(&stream_id) {
            qdebug!([label] "Request/response stream {} is readable.", stream_id);
            found = true;
            let res = if unblocked {
                request_stream.unblock(&mut self.qpack_decoder)
            } else {
                request_stream.receive(&mut self.conn, &mut self.qpack_decoder)
            };
            if let Err(e) = res {
                qdebug!([label] "Error {} ocurred", e);
                if e.is_stream_error() {
                    self.request_streams_client.remove(&stream_id);
                    self.conn.stream_stop_sending(stream_id, e.code())?;
                } else {
                    return Err(e);
                }
            }
            if request_stream.done_reading_request() {
                if let Some(ref mut cb) = self.handler {
                    let (headers, data) = (cb)(request_stream.get_request_headers(), false);
                    request_stream.set_response(&headers, data, &mut self.qpack_encoder);
                }
                if request_stream.has_data_to_send() {
                    self.streams_have_data_to_send.insert(stream_id);
                } else {
                    self.request_streams_client.remove(&stream_id);
                }
            }
        }
        Ok(found)
    }

    fn decode_new_stream(&mut self, stream_type: u64, stream_id: u64) -> Res<()> {
        match stream_type {
            HTTP3_UNI_STREAM_TYPE_CONTROL => {
                self.control_stream_remote.add_remote_stream(stream_id)
            }

            HTTP3_UNI_STREAM_TYPE_PUSH => {
                qdebug!([self] "A new push stream {}.", stream_id);
                if self.role() == Role::Server {
                    qdebug!([self] "Error: server receives a push stream!");
                    self.conn
                        .stream_stop_sending(stream_id, Error::WrongStreamDirection.code())?;
                } else {
                    // TODO implement PUSH
                    qdebug!([self] "PUSH is not implemented!");
                    self.conn
                        .stream_stop_sending(stream_id, Error::PushRefused.code())?;
                }
                Ok(())
            }
            QPACK_UNI_STREAM_TYPE_ENCODER => {
                qinfo!([self] "A new remote qpack encoder stream {}", stream_id);
                if self.qpack_decoder.has_recv_stream() {
                    qdebug!([self] "A qpack encoder stream already exists");
                    return Err(Error::WrongStreamCount);
                }
                self.qpack_decoder.add_recv_stream(stream_id);
                self.streams_are_readable.insert(stream_id);
                Ok(())
            }
            QPACK_UNI_STREAM_TYPE_DECODER => {
                qinfo!([self] "A new remote qpack decoder stream {}", stream_id);
                if self.qpack_encoder.has_recv_stream() {
                    qdebug!([self] "A qpack decoder stream already exists");
                    return Err(Error::WrongStreamCount);
                }
                self.qpack_encoder.add_recv_stream(stream_id);
                self.streams_are_readable.insert(stream_id);
                Ok(())
            }
            // TODO reserved stream types
            _ => {
                self.conn
                    .stream_stop_sending(stream_id, Error::UnknownStreamType.code())?;
                Ok(())
            }
        }
    }

    pub fn close(&mut self, now: Instant, error: AppError, msg: &str) {
        qdebug!([self] "Closed.");
        self.state = Http3State::Closing(CloseError::Application(error));
        if (!self.request_streams_client.is_empty() || !self.request_streams_server.is_empty())
            && (error == 0)
        {
            qwarn!("close() called when streams still active");
        }
        self.request_streams_client.clear();
        self.request_streams_server.clear();
        self.conn.close(now, error, msg);
    }

    pub fn fetch(
        &mut self,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        headers: &[Header],
    ) -> Res<u64> {
        qdebug!(
            [self]
            "Fetch method={}, scheme={}, host={}, path={}",
            method,
            scheme,
            host,
            path
        );
        let id = self.conn.stream_create(StreamType::BiDi)?;
        self.request_streams_client.insert(
            id,
            RequestStreamClient::new(id, method, scheme, host, path, headers, self.events.clone()),
        );
        self.streams_have_data_to_send.insert(id);
        Ok(id)
    }

    pub fn stream_reset(&mut self, stream_id: u64, error: AppError) -> Res<()> {
        qdebug!([self] "reset_stream {}.", stream_id);
        match &mut self.request_streams_client.remove(&stream_id) {
            Some(cs) => {
                if cs.has_data_to_send() {
                    self.conn.stream_reset_send(stream_id, error)?;
                    Ok(())
                } else {
                    self.conn.stream_stop_sending(stream_id, error)?;
                    Ok(())
                }
            }
            None => Err(Error::TransportError(
                neqo_transport::Error::InvalidStreamId,
            )),
        }
    }

    pub fn stream_close_send(&mut self, now: Instant, stream_id: u64) -> Res<()> {
        qdebug!([self] "close_stream {}.", stream_id);
        if let Some(cs) = &mut self.request_streams_client.get_mut(&stream_id) {
            match cs.close_send(&mut self.conn) {
                Ok(()) => Ok(()),
                Err(_) => {
                    self.close(now, Error::InternalError.code(), "");
                    Ok(())
                }
            }
        } else {
            return Err(Error::TransportError(
                neqo_transport::Error::InvalidStreamId,
            ));
        }
    }

    fn handle_control_frame(&mut self) -> Res<()> {
        if self.control_stream_remote.fin {
            return Err(Error::ClosedCriticalStream);
        }
        if self.control_stream_remote.frame_reader.done() {
            let f = self.control_stream_remote.frame_reader.get_frame()?;
            qdebug!([self] "Handle a control frame {:?}", f);
            if let HFrame::Settings { .. } = f {
                if self.settings_received {
                    qdebug!([self] "SETTINGS frame already received");
                    return Err(Error::UnexpectedFrame);
                }
                self.settings_received = true;
            } else if !self.settings_received {
                qdebug!([self] "SETTINGS frame not received");
                return Err(Error::MissingSettings);
            }
            return match f {
                HFrame::Settings { settings } => self.handle_settings(&settings),
                HFrame::Priority { .. } => Ok(()),
                HFrame::CancelPush { .. } => Ok(()),
                HFrame::Goaway { stream_id } => self.handle_goaway(stream_id),
                HFrame::MaxPushId { push_id } => self.handle_max_push_id(push_id),
                _ => Err(Error::WrongStream),
            };
        }
        Ok(())
    }

    fn handle_settings(&mut self, s: &[(HSettingType, u64)]) -> Res<()> {
        qdebug!([self] "Handle SETTINGS frame.");
        for (t, v) in s {
            qdebug!([self] " {:?} = {:?}", t, v);
            match t {
                HSettingType::MaxHeaderListSize => {
                    self.max_header_list_size = *v;
                }
                HSettingType::NumPlaceholders => {
                    if self.role() == Role::Server {
                        return Err(Error::WrongStreamDirection);
                    } else {
                        self.num_placeholders = *v;
                    }
                }
                HSettingType::MaxTableSize => self.qpack_encoder.set_max_capacity(*v)?,
                HSettingType::BlockedStreams => self.qpack_encoder.set_max_blocked_streams(*v)?,

                _ => {}
            }
        }
        Ok(())
    }

    fn handle_goaway(&mut self, goaway_stream_id: u64) -> Res<()> {
        qdebug!([self] "handle_goaway");
        if self.role() == Role::Server {
            return Err(Error::UnexpectedFrame);
        } else {
            // Issue reset events for streams >= goaway stream id
            self.request_streams_client
                .iter()
                .filter(|(id, _)| **id >= goaway_stream_id)
                .map(|(id, _)| *id)
                .for_each(|id| self.events.reset(id, Error::RequestRejected.code()));

            // Actually remove (i.e. don't retain) these streams
            self.request_streams_client
                .retain(|id, _| *id < goaway_stream_id);

            // Remove events for any of these streams by creating a new set of
            // filtered events and then swapping with the original set.
            let updated_events = self
                .events
                .events()
                .iter()
                .filter(|evt| match evt {
                    Http3Event::HeaderReady { stream_id }
                    | Http3Event::DataReadable { stream_id }
                    | Http3Event::NewPushStream { stream_id } => *stream_id < goaway_stream_id,
                    Http3Event::Reset { .. }
                    | Http3Event::AuthenticationNeeded
                    | Http3Event::GoawayReceived
                    | Http3Event::StateChange { .. } => true,
                    Http3Event::RequestsCreatable => false,
                })
                .cloned()
                .collect::<BTreeSet<_>>();
            self.events.replace(updated_events);

            self.events.goaway_received();
            if self.state == Http3State::Connected {
                self.state = Http3State::GoingAway;
            }
        }
        Ok(())
    }

    fn handle_max_push_id(&mut self, id: u64) -> Res<()> {
        qdebug!([self] "handle_max_push_id={}.", id);
        if self.role() == Role::Client {
            return Err(Error::UnexpectedFrame);
        } else {
            // TODO
        }
        Ok(())
    }

    pub fn state(&self) -> Http3State {
        self.state.clone()
    }

    // API
    pub fn get_headers(&mut self, stream_id: u64) -> Res<Option<Vec<(String, String)>>> {
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        if let Some(cs) = &mut self.request_streams_client.get_mut(&stream_id) {
            qdebug!([label] "get_header from stream {}.", stream_id);
            Ok(cs.get_header())
        } else {
            Err(Error::TransportError(
                neqo_transport::Error::InvalidStreamId,
            ))
        }
    }

    pub fn read_data(
        &mut self,
        now: Instant,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Res<(usize, bool)> {
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        if let Some(cs) = &mut self.request_streams_client.get_mut(&stream_id) {
            qdebug!([label] "read_data from stream {}.", stream_id);
            match cs.read_data(&mut self.conn, buf) {
                Ok((amount, fin)) => {
                    if fin {
                        self.request_streams_client.remove(&stream_id);
                    } else if amount > 0 {
                        // Directly call receive instead of adding to
                        // streams_are_readable here. This allows the app to
                        // pick up subsequent already-received data frames in
                        // the stream even if no new packets arrive to cause
                        // process_http3() to run.
                        cs.receive(&mut self.conn, &mut self.qpack_decoder)?;
                    }
                    Ok((amount, fin))
                }
                Err(e) => {
                    if e == Error::MalformedFrame(H3_FRAME_TYPE_DATA) {
                        self.close(now, e.code(), "");
                    }
                    return Err(e);
                }
            }
        } else {
            return Err(Error::TransportError(
                neqo_transport::Error::InvalidStreamId,
            ));
        }
    }

    pub fn events(&mut self) -> Vec<Http3Event> {
        // Turn it into a vec for simplicity's sake
        self.events.events().into_iter().collect()
    }

    // SERVER SIDE ONLY FUNCTIONS
    fn handle_new_client_request(&mut self, stream_id: u64) {
        self.request_streams_server
            .insert(stream_id, RequestStreamServer::new(stream_id));
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub enum Http3Event {
    /// Space available in the buffer for an application write to succeed.
    HeaderReady { stream_id: u64 },
    /// New bytes available for reading.
    DataReadable { stream_id: u64 },
    /// Peer reset the stream.
    Reset { stream_id: u64, error: AppError },
    /// A new push stream
    NewPushStream { stream_id: u64 },
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
pub struct Http3Events {
    events: Rc<RefCell<BTreeSet<Http3Event>>>,
}

impl Http3Events {
    pub fn header_ready(&self, stream_id: u64) {
        self.insert(Http3Event::HeaderReady { stream_id });
    }

    pub fn data_readable(&self, stream_id: u64) {
        self.insert(Http3Event::DataReadable { stream_id });
    }

    pub fn reset(&self, stream_id: u64, error: AppError) {
        self.insert(Http3Event::Reset { stream_id, error });
    }

    pub fn new_push_stream(&self, stream_id: u64) {
        self.insert(Http3Event::NewPushStream { stream_id });
    }

    pub fn new_requests_creatable(&self) {
        self.insert(Http3Event::RequestsCreatable);
    }

    pub fn authentication_needed(&mut self) {
        self.events.insert(Http3Event::AuthenticationNeeded);
    }

    pub fn goaway_received(&self) {
        self.insert(Http3Event::GoawayReceived);
    }

    pub fn connection_state_change(&self, state: Http3State) {
        self.insert(Http3Event::StateChange(state));
    }

    pub fn events(&self) -> BTreeSet<Http3Event> {
        self.replace(BTreeSet::new())
    }

    pub fn replace(&self, new_events: BTreeSet<Http3Event>) -> BTreeSet<Http3Event> {
        self.events.replace(new_events)
    }

    fn insert(&self, event: Http3Event) {
        self.events.borrow_mut().insert(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_common::matches;
    use neqo_transport::State;
    use test_fixture::*;

    fn assert_closed(hconn: &Http3Connection, expected: Error) {
        match hconn.state() {
            Http3State::Closing(err) | Http3State::Closed(err) => {
                assert_eq!(err, CloseError::Application(expected.code()))
            }
            _ => panic!("Wrong state {:?}", hconn.state()),
        };
    }

    // Start a client/server and check setting frame.
    #[allow(clippy::cognitive_complexity)]
    fn connect(client: bool) -> (Http3Connection, Connection) {
        // Create a client/server and connect it to a server/client.
        // We will have a http3 server/client on one side and a neqo_transport
        // connection on the other side so that we can check what the http3
        // side sends and also to simulate an incorrectly behaving http3
        // server/client.

        let (mut hconn, mut neqo_trans_conn) = if client {
            (
                Http3Connection::new(default_client(), 100, 100, None),
                default_server(),
            )
        } else {
            (
                Http3Connection::new(default_server(), 100, 100, None),
                default_client(),
            )
        };
        if client {
            assert_eq!(hconn.state(), Http3State::Initializing);
            let out = hconn.process(None, now());
            assert_eq!(hconn.state(), Http3State::Initializing);
            assert_eq!(*neqo_trans_conn.state(), State::WaitInitial);
            let out = neqo_trans_conn.process(out.dgram(), now());
            assert_eq!(*neqo_trans_conn.state(), State::Handshaking);
            let out = hconn.process(out.dgram(), now());
            let out = neqo_trans_conn.process(out.dgram(), now());
            assert!(out.as_dgram_ref().is_none());

            let authentication_needed = |e| matches!(e, Http3Event::AuthenticationNeeded);
            assert!(hconn.events().into_iter().any(authentication_needed));
            hconn.authenticated(0, now());

            let out = hconn.process(out.dgram(), now());
            let connected = |e| matches!(e, Http3Event::ConnectionConnected);
            assert!(hconn.events().into_iter().any(connected));
            let http_events = hconn.events();
            for e in http_events {
                match e {
                    Http3Event::StateChange(..) => (),
                    _ => panic!("events other than connected found"),
                }
            }
            assert_eq!(hconn.state(), Http3State::Connected);
            neqo_trans_conn.process(out.dgram(), now());
        } else {
            assert_eq!(hconn.state(), Http3State::Initializing);
            let out = neqo_trans_conn.process(None, now());
            let out = hconn.process(out.dgram(), now());
            let out = neqo_trans_conn.process(out.dgram(), now());
            let _ = hconn.process(out.dgram(), now());
            let authentication_needed = |e| matches!(e, ConnectionEvent::AuthenticationNeeded);
            assert!(neqo_trans_conn.events().any(authentication_needed));
            neqo_trans_conn.authenticated(0, now());
            let out = neqo_trans_conn.process(None, now());
            let out = hconn.process(out.dgram(), now());
            assert_eq!(hconn.state(), Http3State::Connected);
            neqo_trans_conn.process(out.dgram(), now());
        }

        let events = neqo_trans_conn.events();
        for e in events {
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => {
                    assert!(
                        (client && ((stream_id == 2) || (stream_id == 6) || (stream_id == 10)))
                            || ((stream_id == 3) || (stream_id == 7) || (stream_id == 11))
                    );
                    assert_eq!(stream_type, StreamType::UniDi);
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    if stream_id == 2 || stream_id == 3 {
                        // the control stream
                        let mut buf = [0u8; 100];
                        let (amount, fin) =
                            neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                        assert_eq!(fin, false);
                        assert_eq!(amount, 9);
                        assert_eq!(buf[..9], [0x0, 0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64]);
                    } else if stream_id == 6 || stream_id == 7 {
                        let mut buf = [0u8; 100];
                        let (amount, fin) =
                            neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                        assert_eq!(fin, false);
                        assert_eq!(amount, 1);
                        assert_eq!(buf[..1], [0x2]);
                    } else if stream_id == 10 || stream_id == 11 {
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
                ConnectionEvent::StateChange(..) => {}
                _ => panic!("unexpected event"),
            }
        }
        (hconn, neqo_trans_conn)
    }

    // Test http3 connection inintialization.
    // The client will open the control and qpack streams and send SETTINGS frame.
    #[test]
    fn test_client_connect() {
        let _ = connect(true);
    }

    // Test http3 connection inintialization.
    // The server will open the control and qpack streams and send SETTINGS frame.
    #[test]
    fn test_server_connect() {
        let _ = connect(false);
    }

    fn connect_and_receive_control_stream(client: bool) -> (Http3Connection, Connection, u64) {
        let (mut hconn, mut neqo_trans_conn) = connect(client);
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        let mut sent = neqo_trans_conn.stream_send(
            control_stream,
            &[0x0, 0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64],
        );
        assert_eq!(sent, Ok(9));
        let encoder_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        sent = neqo_trans_conn.stream_send(encoder_stream, &[0x2]);
        assert_eq!(sent, Ok(1));
        let decoder_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        sent = neqo_trans_conn.stream_send(decoder_stream, &[0x3]);
        assert_eq!(sent, Ok(1));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // assert no error occured.
        assert_eq!(hconn.state(), Http3State::Connected);
        (hconn, neqo_trans_conn, control_stream)
    }

    // Client: Test receiving a new control stream and a SETTINGS frame.
    #[test]
    fn test_client_receive_control_frame() {
        let _ = connect_and_receive_control_stream(true);
    }

    // Server: Test receiving a new control stream and a SETTINGS frame.
    #[test]
    fn test_server_receive_control_frame() {
        let _ = connect_and_receive_control_stream(false);
    }

    // Client: Test that the connection will be closed if control stream
    // has been closed.
    #[test]
    fn test_client_close_control_stream() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);
        neqo_trans_conn.stream_close_send(3).unwrap();
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::ClosedCriticalStream);
    }

    // Server: Test that the connection will be closed if control stream
    // has been closed.
    #[test]
    fn test_server_close_control_stream() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(false);
        neqo_trans_conn.stream_close_send(2).unwrap();
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::ClosedCriticalStream);
    }

    // Client: test missing SETTINGS frame
    // (the first frame sent is a PRIORITY frame).
    #[test]
    fn test_client_missing_settings() {
        let (mut hconn, mut neqo_trans_conn) = connect(true);
        // create server control stream.
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        // send a PRIORITY frame.
        let sent =
            neqo_trans_conn.stream_send(control_stream, &[0x0, 0x2, 0x4, 0x0, 0x2, 0x1, 0x3]);
        assert_eq!(sent, Ok(7));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::MissingSettings);
    }

    // Server: test missing SETTINGS frame
    // (the first frame sent is a PRIORITY frame).
    #[test]
    fn test_server_missing_settings() {
        let (mut hconn, mut neqo_trans_conn) = connect(false);
        // create server control stream.
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        // send a PRIORITY frame.
        let sent =
            neqo_trans_conn.stream_send(control_stream, &[0x0, 0x2, 0x4, 0x0, 0x2, 0x1, 0x3]);
        assert_eq!(sent, Ok(7));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::MissingSettings);
    }

    // Client: receiving SETTINGS frame twice causes connection close
    // with error HTTP_UNEXPECTED_FRAME.
    #[test]
    fn test_client_receive_settings_twice() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);
        // send the second SETTINGS frame.
        let sent = neqo_trans_conn.stream_send(3, &[0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64]);
        assert_eq!(sent, Ok(8));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::UnexpectedFrame);
    }

    // Server: receiving SETTINGS frame twice causes connection close
    // with error HTTP_UNEXPECTED_FRAME.
    #[test]
    fn test_server_receive_settings_twice() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(false);
        // send the second SETTINGS frame.
        let sent = neqo_trans_conn.stream_send(2, &[0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64]);
        assert_eq!(sent, Ok(8));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::UnexpectedFrame);
    }

    fn test_wrong_frame_on_control_stream(client: bool, v: &[u8]) {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(client);

        // receive a frame that is not allowed on the control stream.
        if client {
            let _ = neqo_trans_conn.stream_send(3, v);
        } else {
            let _ = neqo_trans_conn.stream_send(2, v);
        }

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        assert_closed(&hconn, Error::WrongStream);
    }

    // send DATA frame on a cortrol stream
    #[test]
    fn test_data_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &[0x0, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &[0x0, 0x2, 0x1, 0x2]);
    }

    // send HEADERS frame on a cortrol stream
    #[test]
    fn test_headers_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &[0x1, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &[0x1, 0x2, 0x1, 0x2]);
    }

    // send PUSH_PROMISE frame on a cortrol stream
    #[test]
    fn test_push_promise_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &[0x5, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &[0x5, 0x2, 0x1, 0x2]);
    }

    // send DUPLICATE_PUSH frame on a cortrol stream
    #[test]
    fn test_duplicate_push_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &[0xe, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &[0xe, 0x2, 0x1, 0x2]);
    }

    // Client: receive unkonwn stream type
    // This function also tests getting stream id that does not fit into a single byte.
    #[test]
    fn test_client_received_unknown_stream() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);

        // create a stream with unknown type.
        let new_stream_id = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        let _ =
            neqo_trans_conn.stream_send(new_stream_id, &[0x41, 0x19, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
        let out = neqo_trans_conn.process(None, now());
        let out = hconn.process(out.dgram(), now());
        neqo_trans_conn.process(out.dgram(), now());

        // check for stop-sending with Error::UnknownStreamType.
        let events = neqo_trans_conn.events();
        let mut stop_sending_event_found = false;
        for e in events {
            if let ConnectionEvent::SendStreamStopSending {
                stream_id,
                app_error,
            } = e
            {
                stop_sending_event_found = true;
                assert_eq!(stream_id, new_stream_id);
                assert_eq!(app_error, Error::UnknownStreamType.code());
            }
        }
        assert!(stop_sending_event_found);
        assert_eq!(hconn.state(), Http3State::Connected);
    }

    // Server: receive unkonwn stream type
    // also test getting stream id that does not fit into a single byte.
    #[test]
    fn test_server_received_unknown_stream() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(false);

        // create a stream with unknown type.
        let new_stream_id = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        let _ =
            neqo_trans_conn.stream_send(new_stream_id, &[0x41, 0x19, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
        let out = neqo_trans_conn.process(None, now());
        let out = hconn.process(out.dgram(), now());
        neqo_trans_conn.process(out.dgram(), now());

        // check for stop-sending with Error::UnknownStreamType.
        let events = neqo_trans_conn.events();
        let mut stop_sending_event_found = false;
        for e in events {
            if let ConnectionEvent::SendStreamStopSending {
                stream_id,
                app_error,
            } = e
            {
                stop_sending_event_found = true;
                assert_eq!(stream_id, new_stream_id);
                assert_eq!(app_error, Error::UnknownStreamType.code());
            }
        }
        assert!(stop_sending_event_found);
        assert_eq!(hconn.state(), Http3State::Connected);
    }

    // Client: receive a push stream
    #[test]
    fn test_client_received_push_stream() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);

        // create a push stream.
        let push_stream_id = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        let _ = neqo_trans_conn.stream_send(push_stream_id, &[0x1]);
        let out = neqo_trans_conn.process(None, now());
        let out = hconn.process(out.dgram(), now());
        neqo_trans_conn.process(out.dgram(), now());

        // check for stop-sending with Error::Error::PushRefused.
        let events = neqo_trans_conn.events();
        let mut stop_sending_event_found = false;
        for e in events {
            if let ConnectionEvent::SendStreamStopSending {
                stream_id,
                app_error,
            } = e
            {
                stop_sending_event_found = true;
                assert_eq!(stream_id, push_stream_id);
                assert_eq!(app_error, Error::PushRefused.code());
            }
        }
        assert!(stop_sending_event_found);
        assert_eq!(hconn.state(), Http3State::Connected);
    }

    // Server: receiving a push stream on a server should cause WrongStreamDirection
    #[test]
    fn test_server_received_push_stream() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(false);

        // create a push stream.
        let push_stream_id = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        let _ = neqo_trans_conn.stream_send(push_stream_id, &[0x1]);
        let out = neqo_trans_conn.process(None, now());
        let out = hconn.process(out.dgram(), now());
        neqo_trans_conn.process(out.dgram(), now());

        // check for stop-sending with Error::WrongStreamDirection.
        let events = neqo_trans_conn.events();
        let mut stop_sending_event_found = false;
        for e in events {
            if let ConnectionEvent::SendStreamStopSending {
                stream_id,
                app_error,
            } = e
            {
                stop_sending_event_found = true;
                assert_eq!(stream_id, push_stream_id);
                assert_eq!(app_error, Error::WrongStreamDirection.code());
            }
        }
        assert!(stop_sending_event_found);
        assert_eq!(hconn.state(), Http3State::Connected);
    }

    // Test wrong frame on req/rec stream
    fn test_wrong_frame_on_request_stream(v: &[u8], err: Error) {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);

        assert_eq!(
            hconn.fetch("GET", "https", "something.com", "/", &[]),
            Ok(0)
        );

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        let events = neqo_trans_conn.events();
        for e in events {
            if let ConnectionEvent::NewStream {
                stream_id,
                stream_type,
            } = e
            {
                assert_eq!(stream_type, StreamType::BiDi);
                let _ = neqo_trans_conn.stream_send(stream_id, v);
            }
        }
        // Generate packet with the above bad h3 input
        let out = neqo_trans_conn.process(None, now());
        // Process bad input and generate stop sending frame
        let out = hconn.process(out.dgram(), now());
        // Process stop sending frame and generate an event and a reset frame
        let out = neqo_trans_conn.process(out.dgram(), now());

        let mut stop_sending_event_found = false;
        for e in neqo_trans_conn.events() {
            if let ConnectionEvent::SendStreamStopSending {
                stream_id,
                app_error,
            } = e
            {
                assert_eq!(stream_id, 0);
                stop_sending_event_found = true;
                assert_eq!(app_error, err.code());
            }
        }
        assert!(stop_sending_event_found);
        assert_eq!(hconn.state(), Http3State::Connected);

        // Process reset frame
        hconn.conn.process(out.dgram(), now());
        let mut reset_event_found = false;
        for e in hconn.conn.events() {
            if let ConnectionEvent::RecvStreamReset { app_error, .. } = e {
                reset_event_found = true;
                assert_eq!(app_error, err.code());
            }
        }
        assert!(reset_event_found);
        assert_eq!(hconn.state(), Http3State::Connected);
    }

    #[test]
    fn test_cancel_push_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0x3, 0x1, 0x5], Error::WrongStream);
    }

    #[test]
    fn test_settings_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0x4, 0x4, 0x6, 0x4, 0x8, 0x4], Error::WrongStream);
    }

    #[test]
    fn test_goaway_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0x7, 0x1, 0x5], Error::WrongStream);
    }

    #[test]
    fn test_max_push_id_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0xd, 0x1, 0x5], Error::WrongStream);
    }

    #[test]
    fn test_priority_frame_on_client_on_request_stream() {
        test_wrong_frame_on_request_stream(&[0x2, 0x4, 0xf, 0x2, 0x1, 0x3], Error::UnexpectedFrame);
    }

    // Test reading of a slowly streamed frame. bytes are received one by one
    #[test]
    fn test_frame_reading() {
        let (mut hconn, mut neqo_trans_conn) = connect(true);

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

        // PUSH_PROMISE on a control stream will cause an error
        assert_closed(&hconn, Error::WrongStream);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn fetch() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        let events = neqo_trans_conn.events();
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
                    let mut buf = [0u8; 100];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 18);
                    assert_eq!(
                        buf[..18],
                        [
                            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                            0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1
                        ]
                    );
                    // send response - 200  Content-Length: 6
                    // with content: 'abcdef'.
                    // The content will be send in 2 DATA frames.
                    let _ = neqo_trans_conn.stream_send(
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
                    neqo_trans_conn.stream_close_send(stream_id).unwrap();
                }
                _ => {}
            }
        }
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let h = hconn.get_headers(stream_id);
                    assert_eq!(
                        h,
                        Ok(Some(vec![
                            (String::from(":status"), String::from("200")),
                            (String::from("content-length"), String::from("3"))
                        ]))
                    );
                }
                Http3Event::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = hconn.read_data(now(), stream_id, &mut buf).unwrap();
                    assert_eq!(fin, false);
                    assert_eq!(amount, 3);
                    assert_eq!(buf[..3], [0x61, 0x62, 0x63]);
                }
                _ => {}
            }
        }

        hconn.process_http3(now());
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::DataReadable { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    let mut buf = [0u8; 100];
                    let (amount, fin) = hconn.read_data(now(), stream_id, &mut buf).unwrap();
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
        let res = hconn.read_data(now(), request_stream_id, &mut buf);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            Error::TransportError(neqo_transport::Error::InvalidStreamId)
        );

        hconn.close(now(), 0, "");
    }

    fn test_incomplet_frame(res: &[u8], error: Error) {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        let events = neqo_trans_conn.events();
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
                    let mut buf = [0u8; 100];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 18);
                    assert_eq!(
                        buf[..18],
                        [
                            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                            0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1
                        ]
                    );
                    // send an incomplete response - 200  Content-Length: 3
                    // with content: 'abc'.
                    let _ = neqo_trans_conn.stream_send(stream_id, res);
                    neqo_trans_conn.stream_close_send(stream_id).unwrap();
                }
                _ => {}
            }
        }
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            if let Http3Event::DataReadable { stream_id } = e {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let res = hconn.read_data(now(), stream_id, &mut buf);
                assert!(res.is_err());
                assert_eq!(res.unwrap_err(), Error::MalformedFrame(H3_FRAME_TYPE_DATA));
            }
        }
        assert_closed(&hconn, error);
    }

    use crate::hframe::H3_FRAME_TYPE_DATA;
    use crate::hframe::H3_FRAME_TYPE_HEADERS;

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
            Error::MalformedFrame(H3_FRAME_TYPE_DATA),
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
            Error::MalformedFrame(H3_FRAME_TYPE_HEADERS),
        );
    }

    #[test]
    fn test_incomplet_unknown_frame() {
        test_incomplet_frame(&[0x21], Error::MalformedFrame(0xff));
    }

    // test goaway
    #[test]
    fn test_goaway() {
        let (mut hconn, mut neqo_trans_conn, _control_stream) =
            connect_and_receive_control_stream(true);
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
        neqo_trans_conn.process(out.dgram(), now());

        let _ = neqo_trans_conn.stream_send(
            3, //control_stream,
            &[0x7, 0x1, 0x8],
        );

        // find the new request/response stream and send frame v on it.
        let events = neqo_trans_conn.events();
        for e in events {
            match e {
                ConnectionEvent::NewStream { .. } => {}
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    let mut buf = [0u8; 100];
                    let _ = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    if stream_id == request_stream_id_1 || stream_id == request_stream_id_2 {
                        // send response - 200  Content-Length: 6
                        // with content: 'abcdef'.
                        // The content will be send in 2 DATA frames.
                        let _ = neqo_trans_conn.stream_send(
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

                        neqo_trans_conn.stream_close_send(stream_id).unwrap();
                    }
                }
                _ => {}
            }
        }
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let mut stream_reset = false;
        let mut http_events = hconn.events();
        while !http_events.is_empty() {
            for e in http_events {
                match e {
                    Http3Event::HeaderReady { stream_id } => {
                        let h = hconn.get_headers(stream_id);
                        assert_eq!(
                            h,
                            Ok(Some(vec![
                                (String::from(":status"), String::from("200")),
                                (String::from("content-length"), String::from("3"))
                            ]))
                        );
                    }
                    Http3Event::DataReadable { stream_id } => {
                        assert!(
                            stream_id == request_stream_id_1 || stream_id == request_stream_id_2
                        );
                        let mut buf = [0u8; 100];
                        let (amount, _) = hconn.read_data(now(), stream_id, &mut buf).unwrap();
                        assert_eq!(amount, 3);
                    }
                    Http3Event::Reset { stream_id, error } => {
                        assert!(stream_id == request_stream_id_3);
                        assert_eq!(error, Error::RequestRejected.code());
                        stream_reset = true;
                    }
                    _ => {}
                }
            }
            hconn.process_http3(now());
            http_events = hconn.events();
        }

        assert!(stream_reset);
        assert_eq!(hconn.state(), Http3State::GoingAway);
        hconn.close(now(), 0, "");
    }

    #[test]
    fn test_stream_fin_wo_data() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        let events = neqo_trans_conn.events();
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
                    let mut buf = [0u8; 100];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 18);
                    assert_eq!(
                        buf[..18],
                        [
                            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                            0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1
                        ]
                    );

                    // Send some good data wo fin
                    let data = &[
                        // headers
                        0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                        // the data frame is complete.
                        0x0, 0x3, 0x61, 0x62, 0x63,
                    ];
                    let _ = neqo_trans_conn.stream_send(stream_id, data);
                }
                _ => {}
            }
        }
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv some good data wo fin
        let http_events = hconn.events();
        for e in http_events {
            if let Http3Event::DataReadable { stream_id } = e {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let res = hconn.read_data(now(), stream_id, &mut buf);
                let (len, fin) = res.expect("should have data");
                assert_eq!(&buf[..len], &[0x61, 0x62, 0x63]);
                assert_eq!(fin, false);
            }
        }

        // ok NOW send fin
        neqo_trans_conn.stream_close_send(0).unwrap();
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // fin wo data should generate DataReadable
        let e = hconn.events().into_iter().next().unwrap();
        if let Http3Event::DataReadable { stream_id } = e {
            assert_eq!(stream_id, request_stream_id);
            let mut buf = [0u8; 100];
            let res = hconn.read_data(now(), stream_id, &mut buf);
            let (len, fin) = res.expect("should read");
            assert_eq!(0, len);
            assert_eq!(fin, true);
        } else {
            panic!("wrong event type");
        }

        // Stream should now be closed and gone
        let mut buf = [0u8; 100];
        assert_eq!(
            hconn.read_data(now(), 0, &mut buf),
            Err(Error::TransportError(
                neqo_transport::Error::InvalidStreamId
            ))
        );
    }

    #[test]
    fn test_multiple_data_frames() {
        let (mut hconn, mut neqo_trans_conn, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch(
                &"GET".to_string(),
                &"https".to_string(),
                &"something.com".to_string(),
                &"/".to_string(),
                &Vec::<(String, String)>::new(),
            )
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        let events = neqo_trans_conn.events();
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
                    let mut buf = [0u8; 100];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, true);
                    assert_eq!(amount, 18);
                    assert_eq!(
                        buf[..18],
                        [
                            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                            0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1
                        ]
                    );

                    // Send two data frames with fin
                    let data = &[
                        // headers
                        0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                        // 2 complete data frames
                        0x0, 0x3, 0x61, 0x62, 0x63, 0x0, 0x3, 0x64, 0x65, 0x66,
                    ];
                    let _ = neqo_trans_conn.stream_send(stream_id, data);
                    neqo_trans_conn.stream_close_send(0).unwrap();
                }
                _ => {}
            }
        }
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Read first frame
        match hconn.events().into_iter().nth(1).unwrap() {
            Http3Event::DataReadable { stream_id } => {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let (len, fin) = hconn.read_data(now(), stream_id, &mut buf).unwrap();
                assert_eq!(&buf[..len], &[0x61, 0x62, 0x63]);
                assert_eq!(fin, false);
            }
            x => {
                eprintln!("event {:?}", x);
                panic!()
            }
        }

        // Second frame isn't read in first read_data(), but it generates
        // another DataReadable event so that another read_data() will happen to
        // pick it up.
        match hconn.events().into_iter().next().unwrap() {
            Http3Event::DataReadable { stream_id } => {
                assert_eq!(stream_id, request_stream_id);
                let mut buf = [0u8; 100];
                let (len, fin) = hconn.read_data(now(), stream_id, &mut buf).unwrap();
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
            hconn.read_data(now(), 0, &mut buf),
            Err(Error::TransportError(
                neqo_transport::Error::InvalidStreamId
            ))
        );
    }
}
