// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use smallvec::SmallVec;

use crate::hframe::{HFrame, HFrameReader, HSettingType, H3_FRAME_TYPE_DATA};
use crate::transaction_client::TransactionClient;
use crate::transaction_server::{RequestHandler, TransactionServer};
use crate::Header;
use neqo_common::{
    qdebug, qerror, qinfo, qwarn, Datagram, Decoder, Encoder, IncrementalDecoder,
    IncrementalDecoderResult,
};
use neqo_crypto::{agent::CertificateInfo, AuthenticationStatus, SecretAgentInfo};
use neqo_qpack::decoder::{QPackDecoder, QPACK_UNI_STREAM_TYPE_DECODER};
use neqo_qpack::encoder::{QPackEncoder, QPACK_UNI_STREAM_TYPE_ENCODER};
use neqo_transport::{
    AppError, CloseError, Connection, ConnectionEvent, Output, Role, State, StreamType,
};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::mem;
use std::rc::Rc;
use std::time::Instant;

use crate::{Error, Res};

const HTTP3_UNI_STREAM_TYPE_CONTROL: u64 = 0x0;
const HTTP3_UNI_STREAM_TYPE_PUSH: u64 = 0x1;

const MAX_HEADER_LIST_SIZE_DEFAULT: u64 = u64::max_value();

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
    transactions_client: HashMap<u64, TransactionClient>,
    // Server only
    #[allow(clippy::type_complexity)]
    handler: Option<RequestHandler>,
    transactions_server: HashMap<u64, TransactionServer>,
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
            control_stream_local: ControlStreamLocal::default(),
            control_stream_remote: ControlStreamRemote::new(),
            qpack_encoder: QPackEncoder::new(true),
            qpack_decoder: QPackDecoder::new(max_table_size, max_blocked_streams),
            new_streams: HashMap::new(),
            transactions_client: HashMap::new(),
            transactions_server: HashMap::new(),
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

    pub fn authenticated(&mut self, status: AuthenticationStatus, now: Instant) {
        self.conn.authenticated(status, now);
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

    pub fn process_timer(&mut self, now: Instant) {
        qdebug!([self] "Process timer.");
        self.conn.process_timer(now);
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
        self.conn.process_output(now)
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
                if let Some(cs) = &mut self.transactions_client.get_mut(&stream_id) {
                    cs.send_request_headers(&mut self.conn, &mut self.qpack_encoder)?;
                    if cs.is_state_sending_headers() {
                        self.streams_have_data_to_send.insert(stream_id);
                    }
                }
            }
        } else {
            for stream_id in to_send {
                let mut remove_stream = false;
                if let Some(cs) = &mut self.transactions_server.get_mut(&stream_id) {
                    cs.send(&mut self.conn)?;
                    if cs.is_state_sending() {
                        self.streams_have_data_to_send.insert(stream_id);
                    } else {
                        remove_stream = true;
                    }
                }
                if remove_stream {
                    self.transactions_server.remove(&stream_id);
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
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    self.handle_send_stream_writable(stream_id)?
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
                    self.events.authentication_needed();
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

    fn handle_send_stream_writable(&mut self, stream_id: u64) -> Res<()> {
        qdebug!([self] "Writable stream {}.", stream_id);
        assert!(self.state_active());

        if let Some(cs) = self.transactions_client.get_mut(&stream_id) {
            if cs.is_state_sending_data() {
                self.events.data_writable(stream_id);
            }
        }
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

        if self.read_stream_client(stream_id)? {
            qdebug!([label] "Request/response stream {} read.", stream_id);
        } else if self.read_stream_server(stream_id)? {
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
                self.read_stream_client(stream_id)?;
            } else {
                self.read_stream_server(stream_id)?;
            }
        }
        Ok(())
    }

    fn handle_stream_reset(&mut self, stream_id: u64, app_err: AppError) -> Res<()> {
        assert!(self.state_active());
        qdebug!([self] "handle_stream_reset stream_id={} app_err={}", stream_id, app_err);
        if let Some(cs) = self.transactions_client.get_mut(&stream_id) {
            // Remove all events for this stream.
            self.events.remove_events_for_stream_id(stream_id);
            // Post the reset event.
            self.events.reset(stream_id, app_err);
            // Close both sides of the transaction_client.
            cs.reset_receiving_side();
            cs.stop_sending();
            // close sending side of the transport stream as well. The server may have done
            // it se well, but just to be sure.
            let _ = self.conn.stream_reset_send(stream_id, app_err);
            // remove the stream
            self.transactions_client.remove(&stream_id);
        }
        Ok(())
    }

    fn handle_stream_stop_sending(&mut self, stop_stream_id: u64, app_err: AppError) -> Res<()> {
        assert!(self.state_active());
        qdebug!([self] "handle_stream_stop_sending stream_id={} app_err={}", stop_stream_id, app_err);

        if let Some(cs) = self.transactions_client.get_mut(&stop_stream_id) {
            // close sending side.
            cs.stop_sending();

            // If error is Error::EarlyResponse we will post StopSending event,
            // otherwise post reset.
            if app_err == Error::EarlyResponse.code() && !cs.is_sending_closed() {
                // Remove DataWritable event if any.
                self.events.remove(&Http3Event::DataWritable {
                    stream_id: stop_stream_id,
                });
                self.events.stop_sending(stop_stream_id, app_err);
            }

            // if error is not Error::EarlyResponse we will close receiving part as well.
            if app_err != Error::EarlyResponse.code() {
                self.events.remove_events_for_stream_id(stop_stream_id);
                self.events.reset(stop_stream_id, app_err);

                // The server may close its sending side as well, but just to be sure
                // we will do it ourselves.
                let _ = self.conn.stream_stop_sending(stop_stream_id, app_err);
                cs.reset_receiving_side();
            }
            if cs.done() {
                self.transactions_client.remove(&stop_stream_id);
            }
        }
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

    fn read_stream_client(&mut self, stream_id: u64) -> Res<bool> {
        if self.role() != Role::Client {
            return Ok(false);
        }
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };

        let mut found = false;

        if let Some(transaction) = &mut self.transactions_client.get_mut(&stream_id) {
            qdebug!([label] "Request/response stream {} is readable.", stream_id);
            found = true;
            let res = transaction.receive(&mut self.conn, &mut self.qpack_decoder);
            if let Err(e) = res {
                qdebug!([label] "Error {} ocurred", e);
                if e.is_stream_error() {
                    self.transactions_client.remove(&stream_id);
                    self.conn.stream_stop_sending(stream_id, e.code())?;
                } else {
                    return Err(e);
                }
            } else if transaction.done() {
                self.transactions_client.remove(&stream_id);
            }
        }
        Ok(found)
    }

    fn read_stream_server(&mut self, stream_id: u64) -> Res<bool> {
        if self.role() != Role::Server {
            return Ok(false);
        }
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };

        let mut found = false;

        if let Some(transaction) = &mut self.transactions_server.get_mut(&stream_id) {
            qdebug!([label] "Request/response stream {} is readable.", stream_id);
            found = true;
            let res = transaction.receive(&mut self.conn, &mut self.qpack_decoder);
            if let Err(e) = res {
                qdebug!([label] "Error {} ocurred", e);
                if e.is_stream_error() {
                    self.transactions_client.remove(&stream_id);
                    self.conn.stream_stop_sending(stream_id, e.code())?;
                } else {
                    return Err(e);
                }
            }
            if transaction.done_reading_request() {
                if let Some(ref mut cb) = self.handler {
                    let (headers, data) = (cb)(transaction.get_request_headers(), false);
                    transaction.set_response(&headers, data, &mut self.qpack_encoder);
                }
                if transaction.is_state_sending() {
                    self.streams_have_data_to_send.insert(stream_id);
                } else {
                    self.transactions_client.remove(&stream_id);
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
        if (!self.transactions_client.is_empty() || !self.transactions_server.is_empty())
            && (error == 0)
        {
            qwarn!("close() called when streams still active");
        }
        self.transactions_client.clear();
        self.transactions_server.clear();
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
        self.transactions_client.insert(
            id,
            TransactionClient::new(id, method, scheme, host, path, headers, self.events.clone()),
        );
        self.streams_have_data_to_send.insert(id);
        Ok(id)
    }

    pub fn stream_reset(&mut self, stream_id: u64, error: AppError) -> Res<()> {
        qdebug!([self] "reset_stream {}.", stream_id);
        let mut cs = self
            .transactions_client
            .remove(&stream_id)
            .ok_or(Error::InvalidStreamId)?;
        cs.stop_sending();
        // Stream maybe already be closed and we may get an error here, but we do not care.
        let _ = self.conn.stream_reset_send(stream_id, error);
        cs.reset_receiving_side();
        // Stream maybe already be closed and we may get an error here, but we do not care.
        self.conn.stream_stop_sending(stream_id, error)?;
        self.events.remove_events_for_stream_id(stream_id);
        Ok(())
    }

    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        qdebug!([self] "close_stream {}.", stream_id);
        let cs = self
            .transactions_client
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?;
        cs.close_send(&mut self.conn)?;
        if cs.done() {
            self.transactions_client.remove(&stream_id);
        }
        Ok(())
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
            for id in self
                .transactions_client
                .iter()
                .filter(|(id, _)| **id >= goaway_stream_id)
                .map(|(id, _)| *id)
            {
                self.events.remove_events_for_stream_id(id);
                self.events.reset(id, Error::RequestRejected.code())
            }
            self.events.remove(&Http3Event::RequestsCreatable);
            self.events.goaway_received();

            // Actually remove (i.e. don't retain) these streams
            self.transactions_client
                .retain(|id, _| *id < goaway_stream_id);

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

    pub fn send_request_body(&mut self, stream_id: u64, buf: &[u8]) -> Res<usize> {
        qdebug!([self] "send_request_body from stream {}.", stream_id);
        self.transactions_client
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?
            .send_request_body(&mut self.conn, buf)
    }

    pub fn read_response_headers(&mut self, stream_id: u64) -> Res<(Vec<Header>, bool)> {
        qdebug!([self] "read_response_headers from stream {}.", stream_id);
        let cs = self
            .transactions_client
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?;
        match cs.read_response_headers() {
            Ok((headers, fin)) => {
                if cs.done() {
                    self.transactions_client.remove(&stream_id);
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
        qdebug!([self] "read_data from stream {}.", stream_id);
        let cs = self
            .transactions_client
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?;

        match cs.read_response_data(&mut self.conn, buf) {
            Ok((amount, fin)) => {
                if fin {
                    self.transactions_client.remove(&stream_id);
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
                Err(e)
            }
        }
    }

    pub fn events(&mut self) -> impl Iterator<Item = Http3Event> {
        self.events.events()
    }

    // SERVER SIDE ONLY FUNCTIONS
    fn handle_new_client_request(&mut self, stream_id: u64) {
        self.transactions_server
            .insert(stream_id, TransactionServer::new(stream_id));
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub enum Http3Event {
    /// Space available in the buffer for an application write to succeed.
    HeaderReady { stream_id: u64 },
    /// A stream can accept new data.
    DataWritable { stream_id: u64 },
    /// New bytes available for reading.
    DataReadable { stream_id: u64 },
    /// Peer reset the stream.
    Reset { stream_id: u64, error: AppError },
    /// Peer has send STOP_SENDING with error code EarlyResponse, other error will post a reset event.
    StopSending { stream_id: u64, error: AppError },
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

    pub fn data_writable(&self, stream_id: u64) {
        self.insert(Http3Event::DataWritable { stream_id });
    }

    pub fn data_readable(&self, stream_id: u64) {
        self.insert(Http3Event::DataReadable { stream_id });
    }

    pub fn reset(&self, stream_id: u64, error: AppError) {
        self.insert(Http3Event::Reset { stream_id, error });
    }

    pub fn stop_sending(&self, stream_id: u64, error: AppError) {
        self.insert(Http3Event::StopSending { stream_id, error });
    }

    pub fn new_push_stream(&self, stream_id: u64) {
        self.insert(Http3Event::NewPushStream { stream_id });
    }

    pub fn new_requests_creatable(&self) {
        self.insert(Http3Event::RequestsCreatable);
    }

    pub fn authentication_needed(&self) {
        self.insert(Http3Event::AuthenticationNeeded);
    }

    pub fn goaway_received(&self) {
        self.insert(Http3Event::GoawayReceived);
    }

    pub fn connection_state_change(&self, state: Http3State) {
        self.insert(Http3Event::StateChange(state));
    }

    pub fn events(&self) -> impl Iterator<Item = Http3Event> {
        self.events.replace(BTreeSet::new()).into_iter()
    }

    fn insert(&self, event: Http3Event) {
        self.events.borrow_mut().insert(event);
    }

    fn remove(&self, event: &Http3Event) -> bool {
        self.events.borrow_mut().remove(event)
    }

    fn remove_events_for_stream_id(&self, remove_stream_id: u64) {
        let events_to_remove = self
            .events
            .borrow()
            .iter()
            .filter(|evt| match evt {
                Http3Event::HeaderReady { stream_id }
                | Http3Event::DataWritable { stream_id }
                | Http3Event::DataReadable { stream_id }
                | Http3Event::NewPushStream { stream_id }
                | Http3Event::Reset { stream_id, .. }
                | Http3Event::StopSending { stream_id, .. } => *stream_id == remove_stream_id,
                _ => false,
            })
            .cloned()
            .collect::<SmallVec<[_; 8]>>();

        for evt in events_to_remove {
            self.remove(&evt);
        }
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
            assert!(hconn.events().any(authentication_needed));
            hconn.authenticated(AuthenticationStatus::Ok, now());

            let out = hconn.process(out.dgram(), now());
            let connected = |e| matches!(e, Http3Event::StateChange(Http3State::Connected));
            assert!(hconn.events().any(connected));

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
            neqo_trans_conn.authenticated(AuthenticationStatus::Ok, now());
            let out = neqo_trans_conn.process(None, now());
            let out = hconn.process(out.dgram(), now());
            assert_eq!(hconn.state(), Http3State::Connected);
            neqo_trans_conn.process(out.dgram(), now());
        }

        let events = neqo_trans_conn.events();
        let mut connected = false;
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
                ConnectionEvent::StateChange(State::Connected) => connected = true,
                ConnectionEvent::StateChange(_) => (),
                _ => panic!("unexpected event"),
            }
        }
        assert!(connected);
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

    fn connect_and_receive_control_stream(
        client: bool,
    ) -> (Http3Connection, Connection, u64, QPackEncoder) {
        let (mut hconn, mut neqo_trans_conn) = connect(client);
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
        (hconn, neqo_trans_conn, control_stream, encoder)
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        neqo_trans_conn.stream_close_send(3).unwrap();
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::ClosedCriticalStream);
    }

    // Server: Test that the connection will be closed if control stream
    // has been closed.
    #[test]
    fn test_server_close_control_stream() {
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(false);
        neqo_trans_conn.stream_close_send(2).unwrap();
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::ClosedCriticalStream);
    }

    // Client: test missing SETTINGS frame
    // (the first frame sent is a garbage frame).
    #[test]
    fn test_client_missing_settings() {
        let (mut hconn, mut neqo_trans_conn) = connect(true);
        // Create server control stream.
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        // Send a HEADERS frame instead (which contains garbage).
        let sent = neqo_trans_conn.stream_send(control_stream, &[0x0, 0x1, 0x3, 0x0, 0x1, 0x2]);
        assert_eq!(sent, Ok(6));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::MissingSettings);
    }

    // Server: test missing SETTINGS frame
    // (the first frame sent is a MAX_PUSH_ID frame).
    #[test]
    fn test_server_missing_settings() {
        let (mut hconn, mut neqo_trans_conn) = connect(false);
        // Create client control stream.
        let control_stream = neqo_trans_conn.stream_create(StreamType::UniDi).unwrap();
        // Send a MAX_PUSH_ID frame instead.
        let sent = neqo_trans_conn.stream_send(control_stream, &[0x0, 0xd, 0x1, 0xf]);
        assert_eq!(sent, Ok(4));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::MissingSettings);
    }

    // Client: receiving SETTINGS frame twice causes connection close
    // with error HTTP_UNEXPECTED_FRAME.
    #[test]
    fn test_client_receive_settings_twice() {
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(false);
        // send the second SETTINGS frame.
        let sent = neqo_trans_conn.stream_send(2, &[0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64]);
        assert_eq!(sent, Ok(8));
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        assert_closed(&hconn, Error::UnexpectedFrame);
    }

    fn test_wrong_frame_on_control_stream(client: bool, v: &[u8]) {
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(client);

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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);

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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(false);

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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);

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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(false);

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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);

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
    fn fetch_basic() {
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // find the new request/response stream and send frame v on it.
        let events = neqo_trans_conn.events().collect::<Vec<_>>();
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

        let http_events = hconn.events().collect::<Vec<_>>();
        assert_eq!(http_events.len(), 2);
        for e in http_events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
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
                Http3Event::DataReadable { stream_id } => {
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
                Http3Event::DataReadable { stream_id } => {
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
        mut hconn: Http3Connection,
        mut neqo_trans_conn: Connection,
        request_stream_id: u64,
    ) {
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
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
                Http3Event::DataReadable { stream_id } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0x64, 0x65, 0x66]);
        assert_eq!(sent, Ok(3));
        let _ = hconn.stream_close_send(request_stream_id);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // find the new request/response stream and send response on it.
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
                    const EXPECTED_RESPONSE_BODY: &[u8] = &[
                        0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                        0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1, 0x0, 0x3, 0x64, 0x65, 0x66,
                    ];
                    assert_eq!(amount, EXPECTED_RESPONSE_BODY.len());
                    assert_eq!(&buf[..23], EXPECTED_RESPONSE_BODY);

                    // send response - 200  Content-Length: 3
                    // with content: 'abc'.
                    let _ = neqo_trans_conn.stream_send(
                        stream_id,
                        &[
                            // headers
                            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                            // a data frame
                            0x0, 0x3, 0x61, 0x62, 0x63,
                        ],
                    );
                    neqo_trans_conn.stream_close_send(stream_id).unwrap();
                }
                _ => {}
            }
        }

        read_response(hconn, neqo_trans_conn, request_stream_id);
    }

    // send a request with request body containing request_body. We expect to receive expected_data_frame_header.
    fn fetch_with_data_length_xbytes(request_body: &[u8], expected_data_frame_header: &[u8]) {
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, request_body);
        assert_eq!(sent, Ok(request_body.len()));

        // Close stream.
        let _ = hconn.stream_close_send(request_stream_id);

        // We need to loop a bit until all data has been sent.
        let mut out = hconn.process(None, now());
        for _i in 0..20 {
            out = neqo_trans_conn.process(out.dgram(), now());
            out = hconn.process(out.dgram(), now());
        }

        // find the new request/response stream, check received frames and send a response.
        let events = neqo_trans_conn.events();
        for e in events {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                if stream_id == request_stream_id {
                    // Read only the HEADER frame
                    let mut buf = [0u8; 18];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, false);
                    assert_eq!(amount, 18);
                    assert_eq!(
                        buf[..18],
                        [
                            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                            0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1,
                        ]
                    );

                    // Read the DATA frame.
                    let mut buf = [1u8; 0xffff];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
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
                    let _ = neqo_trans_conn.stream_send(
                        stream_id,
                        &[
                            // headers
                            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                            // a data frame
                            0x0, 0x3, 0x61, 0x62, 0x63,
                        ],
                    );
                    neqo_trans_conn.stream_close_send(stream_id).unwrap();
                }
            }
        }

        read_response(hconn, neqo_trans_conn, request_stream_id);
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
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
            out = neqo_trans_conn.process(out.dgram(), now());
            out = hconn.process(out.dgram(), now());
        }

        // find the new request/response stream, check received frames and send a response.
        let events = neqo_trans_conn.events();
        for e in events {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                if stream_id == request_stream_id {
                    // Read only the HEADER frame
                    let mut buf = [0u8; 18];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, false);
                    assert_eq!(amount, 18);
                    assert_eq!(
                        buf[..18],
                        [
                            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                            0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1,
                        ]
                    );

                    // Read DATA frames.
                    let mut buf = [1u8; 0xffff];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
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
                    let _ = neqo_trans_conn.stream_send(
                        stream_id,
                        &[
                            // headers
                            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                            // a data frame
                            0x0, 0x3, 0x61, 0x62, 0x63,
                        ],
                    );
                    neqo_trans_conn.stream_close_send(stream_id).unwrap();
                }
            }
        }

        read_response(hconn, neqo_trans_conn, request_stream_id);
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

    fn read_request(neqo_trans_conn: &mut Connection, request_stream_id: u64) {
        // find the new request/response stream and check request data.
        let events = neqo_trans_conn.events();
        for e in events {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                if stream_id == request_stream_id {
                    // Read only header frame
                    let mut buf = [0u8; 18];
                    let (amount, fin) = neqo_trans_conn.stream_recv(stream_id, &mut buf).unwrap();
                    assert_eq!(fin, false);
                    assert_eq!(amount, 18);
                    assert_eq!(
                        buf[..18],
                        [
                            0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67,
                            0x35, 0x53, 0x2e, 0x43, 0xd3, 0xc1,
                        ]
                    );

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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = neqo_trans_conn.process(out.dgram(), now());

        read_request(&mut neqo_trans_conn, request_stream_id);

        // Stop sending with early_response.
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_stop_sending(request_stream_id, Error::EarlyResponse.code())
        );

        // send response - 200  Content-Length: 3
        // with content: 'abc'.
        let _ = neqo_trans_conn.stream_send(
            request_stream_id,
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // a data frame
                0x0, 0x3, 0x61, 0x62, 0x63,
            ],
        );
        neqo_trans_conn
            .stream_close_send(request_stream_id)
            .unwrap();

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let mut response_headers = false;
        let mut response_body = false;
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::StopSending { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::EarlyResponse.code());
                    // assert that we cannot send any more request data.
                    assert_eq!(
                        Err(Error::AlreadyClosed),
                        hconn.send_request_body(request_stream_id, &[0u8; 10])
                    );
                }
                Http3Event::HeaderReady { stream_id } => {
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
                Http3Event::DataReadable { stream_id } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = neqo_trans_conn.process(out.dgram(), now());

        read_request(&mut neqo_trans_conn, request_stream_id);

        // Stop sending with RequestRejected.
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_stop_sending(request_stream_id, Error::RequestRejected.code())
        );
        // also reset with RequestRejested.
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_reset_send(request_stream_id, Error::RequestRejected.code())
        );

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3Event::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::RequestRejected.code());
                }
                Http3Event::HeaderReady { .. } | Http3Event::DataReadable { .. } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = neqo_trans_conn.process(out.dgram(), now());

        read_request(&mut neqo_trans_conn, request_stream_id);

        // Stop sending with RequestRejected.
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_stop_sending(request_stream_id, Error::RequestRejected.code())
        );

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3Event::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::RequestRejected.code());
                }
                Http3Event::HeaderReady { .. } | Http3Event::DataReadable { .. } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = neqo_trans_conn.process(out.dgram(), now());

        read_request(&mut neqo_trans_conn, request_stream_id);

        // send response - 200  Content-Length: 3
        // with content: 'abc'.
        let _ = neqo_trans_conn.stream_send(
            request_stream_id,
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // a data frame
                0x0, 0x3, 0x61, 0x62, 0x63,
            ],
        );

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        // At this moment we have some new events, i.e. a HeadersReady event

        // Send a stop sending and reset.
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_stop_sending(request_stream_id, Error::RequestCancelled.code())
        );
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_reset_send(request_stream_id, Error::RequestCancelled.code())
        );

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3Event::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::RequestCancelled.code());
                }
                Http3Event::HeaderReady { .. } | Http3Event::DataReadable { .. } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = neqo_trans_conn.process(out.dgram(), now());

        read_request(&mut neqo_trans_conn, request_stream_id);

        // send response - 200  Content-Length: 3
        // with content: 'abc'.
        let _ = neqo_trans_conn.stream_send(
            request_stream_id,
            &[
                // headers
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // a data frame
                0x0, 0x3, 0x61, 0x62, 0x63,
            ],
        );

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        // At this moment we have some new event, i.e. a HeadersReady event

        // Send a stop sending.
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_stop_sending(request_stream_id, Error::RequestCancelled.code())
        );

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3Event::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::RequestCancelled.code());
                }
                Http3Event::HeaderReady { .. } | Http3Event::DataReadable { .. } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);

        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        // Get DataWritable for the request stream so that we can write the request body.
        let data_writable = |e| matches!(e, Http3Event::DataWritable { .. });
        assert!(hconn.events().any(data_writable));
        let sent = hconn.send_request_body(request_stream_id, &[0u8; 10000]);
        assert_eq!(sent, Ok(10000));

        let out = hconn.process(None, now());
        let _ = neqo_trans_conn.process(out.dgram(), now());

        read_request(&mut neqo_trans_conn, request_stream_id);

        // Send a reset.
        assert_eq!(
            Ok(()),
            neqo_trans_conn.stream_reset_send(request_stream_id, Error::RequestCancelled.code())
        );

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::StopSending { .. } => {
                    panic!("We should not get StopSending.");
                }
                Http3Event::Reset { stream_id, error } => {
                    assert_eq!(stream_id, request_stream_id);
                    assert_eq!(error, Error::RequestCancelled.code());
                }
                Http3Event::HeaderReady { .. } | Http3Event::DataReadable { .. } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);

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
                let res = hconn.read_response_data(now(), stream_id, &mut buf);
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
        let (mut hconn, mut neqo_trans_conn, _control_stream, _) =
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
        let mut http_events = hconn.events().collect::<Vec<_>>();
        while !http_events.is_empty() {
            for e in http_events {
                match e {
                    Http3Event::HeaderReady { stream_id } => {
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
                    Http3Event::DataReadable { stream_id } => {
                        assert!(
                            stream_id == request_stream_id_1 || stream_id == request_stream_id_2
                        );
                        let mut buf = [0u8; 100];
                        let (amount, _) = hconn
                            .read_response_data(now(), stream_id, &mut buf)
                            .unwrap();
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
            http_events = hconn.events().collect::<Vec<_>>();
        }

        assert!(stream_reset);
        assert_eq!(hconn.state(), Http3State::GoingAway);
        hconn.close(now(), 0, "");
    }

    fn connect_and_send_request() -> (Http3Connection, Connection, u64) {
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &[])
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);

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
                }
                _ => {}
            }
        }
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        (hconn, neqo_trans_conn, request_stream_id)
    }

    // Close stream before headers.
    #[test]
    fn test_stream_fin_wo_headers() {
        let (mut hconn, mut neqo_trans_conn, request_stream_id) = connect_and_send_request();
        // send fin before sending any data.
        neqo_trans_conn.stream_close_send(0).unwrap();

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv HeaderReady wo headers with fin.
        let e = hconn.events().next().unwrap();
        if let Http3Event::HeaderReady { stream_id } = e {
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
        let (mut hconn, mut neqo_trans_conn, request_stream_id) = connect_and_send_request();
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
        ];
        let _ = neqo_trans_conn.stream_send(request_stream_id, data);
        // ok NOW send fin
        neqo_trans_conn.stream_close_send(0).unwrap();

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv HeaderReady with headers and fin.
        let e = hconn.events().next().unwrap();
        if let Http3Event::HeaderReady { stream_id } = e {
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
        let (mut hconn, mut neqo_trans_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
        ];
        let _ = neqo_trans_conn.stream_send(request_stream_id, data);

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv headers wo fin
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
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
                Http3Event::DataReadable { .. } => {
                    panic!("We should not receive a DataGeadable event!");
                }
                _ => {}
            };
        }

        // ok NOW send fin
        neqo_trans_conn.stream_close_send(0).unwrap();

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv DataReadable wo data with fin
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { .. } => {
                    panic!("We should not get another HeaderReady!");
                }
                Http3Event::DataReadable { stream_id } => {
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
    // We should only recv HeadersReady event
    #[test]
    fn test_stream_fin_after_headers_and_a_empty_data_frame() {
        let (mut hconn, mut neqo_trans_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // data
            0x00, 0x00,
        ];
        let _ = neqo_trans_conn.stream_send(request_stream_id, data);
        // ok NOW send fin
        neqo_trans_conn.stream_close_send(0).unwrap();

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv HeaderReady with fin.
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
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
                Http3Event::DataReadable { .. } => {
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
        let (mut hconn, mut neqo_trans_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // the data frame
            0x0, 0x0,
        ];
        let _ = neqo_trans_conn.stream_send(request_stream_id, data);

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv headers wo fin
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
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
                Http3Event::DataReadable { .. } => {
                    panic!("We should not receive a DataGeadable event!");
                }
                _ => {}
            };
        }

        // ok NOW send fin
        neqo_trans_conn.stream_close_send(0).unwrap();

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv no data, but do get fin
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { .. } => {
                    panic!("We should not get another HeaderReady!");
                }
                Http3Event::DataReadable { stream_id } => {
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
        let (mut hconn, mut neqo_trans_conn, request_stream_id) = connect_and_send_request();
        // Send some good data wo fin
        let data = &[
            // headers
            0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // the data frame is complete
            0x0, 0x3, 0x61, 0x62, 0x63,
        ];
        let _ = neqo_trans_conn.stream_send(request_stream_id, data);

        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // Recv some good data wo fin
        let http_events = hconn.events();
        for e in http_events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
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
                Http3Event::DataReadable { stream_id } => {
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
        neqo_trans_conn.stream_close_send(0).unwrap();
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());

        // fin wo data should generate DataReadable
        let e = hconn.events().next().unwrap();
        if let Http3Event::DataReadable { stream_id } = e {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch("GET", "https", "something.com", "/", &Vec::<Header>::new())
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);

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
        match hconn.events().nth(1).unwrap() {
            Http3Event::DataReadable { stream_id } => {
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
            Http3Event::DataReadable { stream_id } => {
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
        let (mut hconn, mut neqo_trans_conn, _, _) = connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch(
                "GET",
                "https",
                "something.com",
                "/",
                &Vec::<(String, String)>::new(),
            )
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);

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

                    // Construct an unknown frame.
                    const UNKNOWN_FRAME_LEN: usize = 832;
                    let mut enc = Encoder::with_capacity(UNKNOWN_FRAME_LEN + 4);
                    enc.encode_varint(1028u64); // Arbitrary type.
                    enc.encode_varint(UNKNOWN_FRAME_LEN as u64);
                    let mut buf: Vec<_> = enc.into();
                    buf.resize(UNKNOWN_FRAME_LEN + buf.len(), 0);
                    let _ = neqo_trans_conn.stream_send(stream_id, &buf).unwrap();

                    // Send a headers and a data frame with fin
                    let data = &[
                        // headers
                        0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33,
                        // 1 complete data frames
                        0x0, 0x3, 0x61, 0x62, 0x63,
                    ];
                    let _ = neqo_trans_conn.stream_send(stream_id, data);
                    neqo_trans_conn.stream_close_send(stream_id).unwrap();
                }
                _ => {}
            }
        }
        let out = neqo_trans_conn.process(None, now());
        hconn.process(out.dgram(), now());
        hconn.process(None, now());

        // Read first frame
        match hconn.events().nth(1).unwrap() {
            Http3Event::DataReadable { stream_id } => {
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
        let (mut hconn, mut neqo_trans_conn, _, mut encoder) =
            connect_and_receive_control_stream(true);
        let request_stream_id = hconn
            .fetch(
                "GET",
                "https",
                "something.com",
                "/",
                &Vec::<(String, String)>::new(),
            )
            .unwrap();
        assert_eq!(request_stream_id, 0);
        let _ = hconn.stream_close_send(request_stream_id);
        let out = hconn.process(None, now());
        neqo_trans_conn.process(out.dgram(), now());

        encoder.set_max_capacity(100).unwrap();
        encoder.set_max_blocked_streams(100).unwrap();

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

                    let headers = vec![
                        (String::from(":status"), String::from("200")),
                        (String::from("my-header"), String::from("my-header")),
                        (String::from("content-length"), String::from("3")),
                    ];
                    let encoded_headers = encoder.encode_header_block(&headers, stream_id);
                    let hframe = HFrame::Headers {
                        len: encoded_headers.len() as u64,
                    };
                    let mut d = Encoder::default();
                    hframe.encode(&mut d);
                    d.encode(&encoded_headers);
                    let d_frame = HFrame::Data { len: 3 };
                    d_frame.encode(&mut d);
                    d.encode(&[0x61, 0x62, 0x63]);
                    let _ = neqo_trans_conn.stream_send(stream_id, &d[..]);
                    neqo_trans_conn.stream_close_send(stream_id).unwrap();
                }
                _ => {}
            }
        }
        // Send response before sending encoder instructions.
        let out = neqo_trans_conn.process(None, now());
        let _out = hconn.process(out.dgram(), now());

        let header_ready_event = |e| matches!(e, Http3Event::HeaderReady { .. });
        assert!(!hconn.events().into_iter().any(header_ready_event));

        // Send encoder instructions to unblock the stream.
        encoder.send(&mut neqo_trans_conn).unwrap();

        let out = neqo_trans_conn.process(None, now());
        let _out = hconn.process(out.dgram(), now());
        let _out = hconn.process(None, now());

        let mut recv_header = false;
        let mut recv_data = false;
        // Now the stream is unblocked and both headers and data will be consumed.
        let events = hconn.events();
        for e in events {
            match e {
                Http3Event::HeaderReady { stream_id } => {
                    assert_eq!(stream_id, request_stream_id);
                    recv_header = true;
                }
                Http3Event::DataReadable { stream_id } => {
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
}
