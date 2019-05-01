// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_variables, dead_code)]

use crate::hframe::{
    ElementDependencyType, HFrame, HFrameReader, HSettingType, PrioritizedElementType,
};
use crate::recvable::RecvableWrapper;
use neqo_common::data::Data;
use neqo_common::readbuf::ReadBuf;
use neqo_common::varint::decode_varint;
use neqo_common::{qdebug, qinfo};
use neqo_qpack::decoder::{QPackDecoder, QPACK_UNI_STREAM_TYPE_DECODER};
use neqo_qpack::encoder::{QPackEncoder, QPACK_UNI_STREAM_TYPE_ENCODER};
use neqo_transport::connection::Role;

use neqo_transport::frame::StreamType;
use neqo_transport::{AppError, ConnectionEvent, Datagram, State};
use std::collections::HashMap;

#[cfg(not(test))]
pub use neqo_transport::connection::Connection;

#[cfg(test)]
use crate::transport::Connection;

use crate::{Error, Res};
use std::mem;

const HTTP3_UNI_STREAM_TYPE_CONTROL: u64 = 0x0;
const HTTP3_UNI_STREAM_TYPE_PUSH: u64 = 0x1;

const MAX_HEADER_LIST_SIZE_DEFAULT: u64 = u64::max_value();
const NUM_PLACEHOLDERS_DEFAULT: u64 = 0;

#[derive(Debug)]
struct Request {
    method: String,
    scheme: String,
    host: String,
    path: String,
    headers: Vec<(String, String)>,
    buf: Option<Data>,
}

impl Request {
    pub fn new(
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Request {
        let mut r = Request {
            method: method.to_owned(),
            scheme: scheme.to_owned(),
            host: host.to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
            buf: None,
        };
        r.headers.push((":method".into(), method.to_owned()));
        r.headers.push((":scheme".into(), r.scheme.clone()));
        r.headers.push((":authority".into(), r.host.clone()));
        r.headers.push((":path".into(), r.path.clone()));
        r.headers.extend_from_slice(headers);
        r
    }

    pub fn encode_request(&mut self, encoder: &mut QPackEncoder, stream_id: u64) {
        qdebug!(self, "Encoding headers for {}/{}", self.host, self.path);
        let mut encoded_headers = encoder.encode_header_block(&self.headers, stream_id);
        let f = HFrame::Headers {
            len: encoded_headers.len() as u64,
        };
        let mut d = Data::default();
        f.encode(&mut d).unwrap();
        d.encode_vec(encoded_headers.as_mut_vec());
        self.buf = Some(d);
    }
}

impl ::std::fmt::Display for Request {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Request {} {}/{}", self.method, self.host, self.path)
    }
}

#[derive(Debug)]
pub struct Response {
    status: u32,
    status_line: Vec<u8>,
    pub headers: Option<Vec<(String, String)>>,
    pub data_len: u64,
    pub trailers: Option<Vec<(String, String)>>,
    fin: bool,
}

impl Response {
    pub fn new(stream_id: u64) -> Response {
        Response {
            status: 0,
            status_line: Vec::new(),
            headers: None,
            data_len: 0,
            trailers: None,
            fin: false,
        }
    }
}

/*
 *  States:
 *    SendingRequest,
 *    WaitingForResponseHeaders : we wait for headers. in this state we can also get PRIORITY frame
 *                                or a PUSH_PROMISE.
 *    ReadingHeaders : we got HEADERS frame headerand now we are reading header block.
 *    WaitingForData : we got HEADERS, we are waiting for one or more data frames. In this state we
 *                    can receive one or more PUSH_PROMIS frames or a HEADERS frame carrying trailers.
 *    ReadingData : we got a DATA frame, now we leting app read payload. From here we will go back to
 *                 WaitingForData state to wait for more data frames or to CLosed state
 *    ReadingTrailers : reading trailers.
 *    Closed : waiting for app to pick up data, after that we can delete the ClientRequest.
 */

#[derive(PartialEq, Debug)]
enum ClientRequestState {
    SendingRequest,
    WaitingForResponseHeaders,
    ReadingHeaders { buf: Vec<u8>, offset: usize },
    BlockedDecodingHeaders { buf: Vec<u8> },
    WaitingForData,
    ReadingData,
    ReadingTrailers,
    Closed,
}

//  This is used for normal request/responses.
struct ClientRequest {
    state: ClientRequestState,
    stream_id: u64,
    request: Request,
    response: Response,
    frame_reader: HFrameReader,
    priority_received: bool,
    done: bool,
}

impl ClientRequest {
    pub fn new(
        stream_id: u64,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> ClientRequest {
        qinfo!("Create a request stream_id={}", stream_id);
        ClientRequest {
            state: ClientRequestState::SendingRequest,
            stream_id,
            request: Request::new(method, scheme, host, path, headers),
            response: Response::new(stream_id),
            frame_reader: HFrameReader::new(),
            priority_received: false,
            done: false,
        }
    }

    // TODO: Currently we cannot send data along with a request
    pub fn send(&mut self, conn: &mut Connection, encoder: &mut QPackEncoder) -> Res<()> {
        let label = match ::log::log_enabled!(::log::Level::Debug) {
            true => format!("{}", self),
            _ => String::new(),
        };
        if self.state == ClientRequestState::SendingRequest {
            if let None = self.request.buf {
                self.request.encode_request(encoder, self.stream_id);
            }
            if let Some(d) = &mut self.request.buf {
                let sent = conn.stream_send(self.stream_id, d.as_mut_vec())?;
                qdebug!(label, "{} bytes sent", sent);
                if sent == d.remaining() {
                    self.request.buf = None;
                    conn.stream_close_send(self.stream_id)?;
                    self.state = ClientRequestState::WaitingForResponseHeaders;
                    qdebug!(label, "done sending request");
                } else {
                    d.read(sent);
                }
            }
        }
        Ok(())
    }

    fn recv_frame(&mut self, conn: &mut Connection) -> Res<()> {
        if self.frame_reader.receive(conn, self.stream_id)? {
            self.state = ClientRequestState::Closed;
        }
        Ok(())
    }

    pub fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        let label = match ::log::log_enabled!(::log::Level::Debug) {
            true => format!("{}", self),
            _ => String::new(),
        };
        qdebug!(label, "state={:?}: receiving data.", self.state);
        loop {
            match self.state {
                ClientRequestState::SendingRequest => {
                    /*TODO if we get response whlie streaming data. We may also get a stop_sending...*/
                    break Ok(());
                }
                ClientRequestState::WaitingForResponseHeaders => {
                    self.recv_frame(conn)?;
                    if !self.frame_reader.done() {
                        break Ok(());
                    }
                    qdebug!(label, "received a frame");
                    match self.frame_reader.get_frame()? {
                        HFrame::Priority {
                            priorized_elem_type,
                            elem_dependensy_type,
                            priority_elem_id,
                            elem_dependency_id,
                            weight,
                        } => break Err(Error::UnexpectedFrame),
                        HFrame::Headers { len } => self.handle_headers_frame(len, conn)?,
                        HFrame::PushPromise { .. } => break Err(Error::UnexpectedFrame),
                        _ => {
                            break { Err(Error::WrongStream) };
                        }
                    };
                }
                ClientRequestState::ReadingHeaders {
                    ref mut buf,
                    ref mut offset,
                } => {
                    let (amount, fin) = conn.stream_recv(self.stream_id, &mut buf[*offset..])?;
                    qdebug!(
                        label,
                        "state=ReadingHeaders: read {} bytes fin={}.",
                        amount,
                        fin
                    );
                    if fin {
                        self.state = ClientRequestState::Closed;
                        break Ok(());
                    }
                    *offset += amount as usize;
                    if *offset < buf.len() {
                        break Ok(());
                    }
                    // we have read the headers.
                    self.response.headers = decoder.decode_header_block(buf, self.stream_id)?;
                    if let None = self.response.headers {
                        qdebug!(label, "decoding header is blocked.");
                        let mut tmp: Vec<u8> = Vec::new();
                        mem::swap(&mut tmp, buf);
                        self.state = ClientRequestState::BlockedDecodingHeaders { buf: tmp };
                    } else {
                        self.state = ClientRequestState::WaitingForData;
                    }
                }
                ClientRequestState::BlockedDecodingHeaders { ref mut buf } => break Ok(()),
                ClientRequestState::WaitingForData => {
                    self.recv_frame(conn)?;
                    if !self.frame_reader.done() {
                        break Ok(());
                    }
                    match self.frame_reader.get_frame()? {
                        HFrame::Data { len } => self.handle_data_frame(len)?,
                        HFrame::PushPromise { .. } => break Err(Error::UnexpectedFrame),
                        HFrame::Headers { .. } => {
                            // TODO implement trailers!
                            break Err(Error::UnexpectedFrame);
                        }
                        _ => break Err(Error::WrongStream),
                    };
                    break Ok(());
                }
                ClientRequestState::ReadingData => break Ok(()),
                ClientRequestState::ReadingTrailers => break Ok(()),
                ClientRequestState::Closed => {
                    panic!("Stream readable after being closed!");
                }
            };
        }
    }

    fn handle_headers_frame(&mut self, len: u64, conn: &mut Connection) -> Res<()> {
        if self.state == ClientRequestState::Closed {
            return Ok(());
        }
        if len == 0 {
            self.state = ClientRequestState::WaitingForData;
        } else {
            self.state = ClientRequestState::ReadingHeaders {
                buf: vec![0; len as usize],
                offset: 0,
            };
        }
        Ok(())
    }

    fn handle_data_frame(&mut self, len: u64) -> Res<()> {
        self.response.data_len = len;
        if self.state != ClientRequestState::Closed {
            if self.response.data_len > 0 {
                self.state = ClientRequestState::ReadingData;
            } else {
                self.state = ClientRequestState::WaitingForData;
            }
        }
        Ok(())
    }

    fn unblock(&mut self, decoder: &mut QPackDecoder) -> Res<()> {
        if let ClientRequestState::BlockedDecodingHeaders { ref mut buf } = self.state {
            self.response.headers = decoder.decode_header_block(buf, self.stream_id)?;
            self.state = ClientRequestState::WaitingForData;
            if let None = self.response.headers {
                panic!("We must not be blocked again!");
            }
        } else {
            panic!("Stream must be in the block state!");
        }
        Ok(())
    }
}

impl ::std::fmt::Display for ClientRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "ClientRequest {}", self.stream_id)
    }
}

#[derive(PartialEq, Debug)]
enum ClientRequestServerState {
    WaitingForRequestHeaders,
    ReadingRequestHeaders { buf: Vec<u8>, offset: usize },
    BlockedDecodingHeaders { buf: Vec<u8> },
    ReadingRequestDone,
    SendingResponse,
    Error,
    Closed,
}

pub struct ClientRequestServer {
    state: ClientRequestServerState,
    stream_id: u64,
    frame_reader: HFrameReader,
    request_headers: Option<Vec<(String, String)>>,
    response_headers: Vec<(String, String)>,
    data: String,
    response_buf: Option<Data>,
    fin: bool,
}

impl ClientRequestServer {
    pub fn new(stream_id: u64) -> ClientRequestServer {
        ClientRequestServer {
            state: ClientRequestServerState::WaitingForRequestHeaders,
            stream_id: stream_id,
            frame_reader: HFrameReader::new(),
            request_headers: None,
            response_headers: Vec::new(),
            data: String::new(),
            response_buf: None,
            fin: false,
        }
    }

    pub fn get_request_headers(&self) -> Vec<(String, String)> {
        if let Some(h) = &self.request_headers {
            h.to_vec()
        } else {
            Vec::new()
        }
    }
    pub fn set_response(&mut self, headers: &Vec<(String, String)>, data: &String) {
        self.response_headers.extend_from_slice(headers);
        self.data = data.to_string();
    }

    pub fn encode_response(&mut self, encoder: &mut QPackEncoder, stream_id: u64) {
        qdebug!(self, "Encoding headers");
        let mut encoded_headers = encoder.encode_header_block(&self.response_headers, stream_id);
        let f = HFrame::Headers {
            len: encoded_headers.len() as u64,
        };
        let mut d = Data::default();
        f.encode(&mut d).unwrap();
        d.encode_vec(encoded_headers.as_mut_vec());
        if self.data.len() > 0 {
            let d_frame = HFrame::Data {
                len: self.data.len() as u64,
            };
            d_frame.encode(&mut d).unwrap();
            d.encode_vec(&self.data.clone().into_bytes());
        }
        self.response_buf = Some(d);
    }

    pub fn send(&mut self, conn: &mut Connection, encoder: &mut QPackEncoder) -> Res<()> {
        let label = match ::log::log_enabled!(::log::Level::Debug) {
            true => format!("{}", self),
            _ => String::new(),
        };
        if self.state == ClientRequestServerState::SendingResponse {
            if let None = self.response_buf {
                self.encode_response(encoder, self.stream_id);
            }
            if let Some(d) = &mut self.response_buf {
                let sent = conn.stream_send(self.stream_id, d.as_mut_vec())?;
                qdebug!(label, "{} bytes sent", sent);
                if sent == d.remaining() {
                    self.response_buf = None;
                    conn.stream_close_send(self.stream_id)?;
                    self.state = ClientRequestServerState::Closed;
                    qdebug!(label, "done sending request");
                } else {
                    d.read(sent);
                }
            }
        }
        Ok(())
    }

    fn recv_frame(&mut self, conn: &mut Connection) -> Res<()> {
        if self.frame_reader.receive(conn, self.stream_id)? {
            self.state = ClientRequestServerState::Closed;
        }
        Ok(())
    }

    pub fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        let label = match ::log::log_enabled!(::log::Level::Debug) {
            true => format!("{}", self),
            _ => String::new(),
        };
        qdebug!(label, "state={:?}: receiving data.", self.state);
        loop {
            match self.state {
                ClientRequestServerState::WaitingForRequestHeaders => {
                    self.recv_frame(conn)?;
                    if !self.frame_reader.done() {
                        break Ok(());
                    }
                    qdebug!(label, "received a frame");
                    match self.frame_reader.get_frame()? {
                        HFrame::Priority {
                            priorized_elem_type,
                            elem_dependensy_type,
                            priority_elem_id,
                            elem_dependency_id,
                            weight,
                        } => self.handle_priority_frame(
                            priorized_elem_type,
                            elem_dependensy_type,
                            priority_elem_id,
                            elem_dependency_id,
                            weight,
                        )?,
                        HFrame::Headers { len } => self.handle_headers_frame(len, conn)?,
                        _ => {
                            break { Err(Error::WrongStream) };
                        }
                    };
                }
                ClientRequestServerState::ReadingRequestHeaders {
                    ref mut buf,
                    ref mut offset,
                } => {
                    let (amount, fin) = conn.stream_recv(self.stream_id, &mut buf[*offset..])?;
                    qdebug!(
                        label,
                        "state=ReadingHeaders: read {} bytes fin={}.",
                        amount,
                        fin
                    );
                    *offset += amount as usize;
                    self.fin = fin;
                    if fin && *offset < buf.len() {
                        self.state = ClientRequestServerState::Error;
                        break Ok(());
                    }
                    if *offset < buf.len() {
                        break Ok(());
                    }
                    // we have read the headers.
                    self.request_headers = decoder.decode_header_block(buf, self.stream_id)?;
                    if let None = self.request_headers {
                        qdebug!(label, "decoding header is blocked.");
                        let mut tmp: Vec<u8> = Vec::new();
                        mem::swap(&mut tmp, buf);
                        self.state = ClientRequestServerState::BlockedDecodingHeaders { buf: tmp };
                    } else {
                        self.state = ClientRequestServerState::ReadingRequestDone;
                    }
                }
                ClientRequestServerState::BlockedDecodingHeaders { ref mut buf } => break Ok(()),
                ClientRequestServerState::ReadingRequestDone => break Ok(()),
                ClientRequestServerState::SendingResponse => break Ok(()),
                ClientRequestServerState::Error => break Ok(()),
                ClientRequestServerState::Closed => {
                    panic!("Stream readable after being closed!");
                }
            };
        }
    }

    fn handle_priority_frame(
        &mut self,
        _priorized_elem_type: PrioritizedElementType,
        _elem_dependensy_type: ElementDependencyType,
        _priority_elem_id: u64,
        _elem_dependency_id: u64,
        _weight: u8,
    ) -> Res<()> {
        // Not implemented
        Ok(())
    }

    fn handle_headers_frame(&mut self, len: u64, conn: &mut Connection) -> Res<()> {
        if self.state == ClientRequestServerState::Closed {
            return Ok(());
        }
        if len == 0 {
            self.state = ClientRequestServerState::Error;
        } else {
            self.state = ClientRequestServerState::ReadingRequestHeaders {
                buf: vec![0; len as usize],
                offset: 0,
            };
        }
        Ok(())
    }

    fn unblock(&mut self, decoder: &mut QPackDecoder) -> Res<()> {
        if let ClientRequestServerState::BlockedDecodingHeaders { ref mut buf } = self.state {
            self.request_headers = decoder.decode_header_block(buf, self.stream_id)?;
            if let None = self.request_headers {
                panic!("We must not be blocked again!");
            }
            self.state = ClientRequestServerState::ReadingRequestDone;
        } else {
            panic!("Stream must be in the block state!");
        }
        Ok(())
    }
}

impl ::std::fmt::Display for ClientRequestServer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "ClientRequestServer {}", self.stream_id)
    }
}

// The local control stream, responsible for encoding frames and sending them
#[derive(Default, Debug)]
struct ControlStreamLocal {
    stream_id: Option<u64>,
    buf: Data,
}

impl ControlStreamLocal {
    pub fn send_frame(&mut self, f: HFrame) {
        f.encode(&mut self.buf).unwrap();
    }
    pub fn send_if_this_stream(&mut self, conn: &mut Connection, stream_id: u64) -> Res<bool> {
        if let Some(id) = self.stream_id {
            if id == stream_id {
                if self.buf.remaining() != 0 {
                    let sent = conn.stream_send(stream_id, self.buf.as_mut_vec())?;
                    if sent == self.buf.remaining() {
                        self.buf.clear();
                    } else {
                        self.buf.read(sent);
                    }
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// The remote control stream is responsible only for reading frames. The frames are handled by HttpConn
#[derive(Debug)]
struct ControlStreamRemote {
    stream_id: Option<u64>,
    frame_reader: HFrameReader,
    fin: bool,
}

impl ControlStreamRemote {
    pub fn new() -> ControlStreamRemote {
        ControlStreamRemote {
            stream_id: None,
            frame_reader: HFrameReader::new(),
            fin: false,
        }
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
    reader: ReadBuf,
    fin: bool,
}

impl NewStreamTypeReader {
    pub fn new() -> NewStreamTypeReader {
        NewStreamTypeReader {
            reader: ReadBuf::new(),
            fin: false,
        }
    }
    pub fn get_type(&mut self, conn: &mut Connection, stream_id: u64) -> Option<u64> {
        // On any error we will only close this stream!
        let mut w = RecvableWrapper::wrap(conn, stream_id);
        loop {
            match self.reader.get_varint(&mut w) {
                Ok((rv, fin)) => {
                    if fin || rv == 0 {
                        self.fin = fin;
                        break None;
                    }

                    if self.reader.done() {
                        match decode_varint(&mut self.reader) {
                            Ok(v) => {
                                self.fin = true;
                                break Some(v);
                            }
                            Err(_) => {
                                self.fin = true;
                                break None;
                            }
                        }
                    }
                }
                Err(_) => {
                    self.fin = true;
                    break None;
                }
            }
        }
    }
}

pub struct HttpConn {
    conn: Connection,
    max_header_list_size: u64,
    num_placeholders: u64,
    control_stream_local: ControlStreamLocal,
    control_stream_remote: ControlStreamRemote,
    new_streams: HashMap<u64, NewStreamTypeReader>,
    qpack_encoder: QPackEncoder,
    qpack_decoder: QPackDecoder,
    client_requests: HashMap<u64, ClientRequest>,
    client_requests_server: HashMap<u64, ClientRequestServer>,
    settings_received: bool,
    new_stream_callback: Option<Box<FnMut(&mut ClientRequestServer, bool)>>,
}

impl ::std::fmt::Display for HttpConn {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http connection {:?}", self.role())
    }
}

impl HttpConn {
    pub fn new(c: Connection, max_table_size: u32, max_blocked_streams: u16) -> HttpConn {
        qinfo!(
            "Create new http connection with max_table_size: {} and max_blocked_streams: {}",
            max_table_size,
            max_blocked_streams
        );
        if max_table_size > (1 << 30) - 1 {
            panic!("Wrong max_table_size");
        }
        HttpConn {
            conn: c,
            max_header_list_size: MAX_HEADER_LIST_SIZE_DEFAULT,
            num_placeholders: NUM_PLACEHOLDERS_DEFAULT,
            control_stream_local: ControlStreamLocal::default(),
            control_stream_remote: ControlStreamRemote::new(),
            qpack_encoder: QPackEncoder::new(true),
            qpack_decoder: QPackDecoder::new(max_table_size, max_blocked_streams),
            new_streams: HashMap::new(),
            client_requests: HashMap::new(),
            client_requests_server: HashMap::new(),
            settings_received: false,
            new_stream_callback: None,
        }
    }

    pub fn set_new_stream_callback<CB: 'static + FnMut(&mut ClientRequestServer, bool)>(
        &mut self,
        c: CB,
    ) {
        self.new_stream_callback = Some(Box::new(c));
    }

    // This function takes the provided result and check for an error.
    // An error results in closing the connection.
    fn check_result<T>(&mut self, res: Res<T>) {
        match &res {
            Err(e) => {
                qinfo!(self, "Connection error: {}.", e);
                self.conn.close(e.code(), format!("{}", e));
            }
            _ => {}
        };
    }

    fn role(&self) -> Role {
        self.conn.role()
    }

    fn process_state_change(&mut self, state: &State) -> Res<()> {
        if *state == State::Connected {
            self.on_connected()?;
        }
        Ok(())
    }

    pub fn process<I>(&mut self, in_dgrams: I, cur_time: u64) -> (Vec<Datagram>, u64)
    where
        I: IntoIterator<Item = Datagram>,
    {
        qdebug!(self, "Process.");
        let state_before = self.state().clone();
        self.conn.process_input(in_dgrams, cur_time);
        let state_after = self.state().clone();
        if state_after != state_before {
            qinfo!(
                self,
                "State has changed from {:?} to {:?}.",
                state_before,
                state_after
            );
            let res = self.process_state_change(&state_after);
            self.check_result(res);
        }
        if let State::Connected = self.state() {
            let res = self.check_connection_events();
            self.check_result(res);
        }
        self.conn.process_output(cur_time)
    }

    fn on_connected(&mut self) -> Res<()> {
        qdebug!(self, "OnConnect.");
        self.create_control_stream()?;
        self.create_settings();
        self.create_qpack_streams()?;
        Ok(())
    }

    fn create_control_stream(&mut self) -> Res<()> {
        qdebug!(self, "create_control_stream.");
        self.control_stream_local.stream_id = Some(self.conn.stream_create(StreamType::UniDi)?);
        self.control_stream_local
            .buf
            .encode_varint(HTTP3_UNI_STREAM_TYPE_CONTROL as u64);
        Ok(())
    }

    fn create_qpack_streams(&mut self) -> Res<()> {
        qdebug!(self, "create_qpack_streams.");
        self.qpack_encoder
            .add_send_stream(self.conn.stream_create(StreamType::UniDi)?);
        self.qpack_decoder
            .add_send_stream(self.conn.stream_create(StreamType::UniDi)?);
        Ok(())
    }

    fn create_settings(&mut self) {
        qdebug!(self, "create_settings.");
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

    // If this return an error the connection must be closed.
    fn check_connection_events(&mut self) -> Res<()> {
        qdebug!(self, "check_connection_events");
        let events = self.conn.events();
        for e in events {
            match e {
                ConnectionEvent::NewStream {
                    stream_id,
                    stream_type,
                } => self.handle_new_stream(stream_id, stream_type)?,
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    self.handle_stream_writable(stream_id)?
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    self.handle_stream_readable(stream_id)?
                }
                ConnectionEvent::RecvStreamReset {
                    stream_id,
                    app_error,
                } => self.handle_stream_reset(stream_id, app_error)?,
                ConnectionEvent::SendStreamComplete { stream_id } => {
                    self.handle_stream_complete(stream_id)?
                }
                ConnectionEvent::SendStreamCreatable { stream_type } => {
                    self.handle_stream_creatable(stream_type)?
                }
            }
        }
        Ok(())
    }

    fn handle_new_stream(&mut self, stream_id: u64, stream_type: StreamType) -> Res<()> {
        qdebug!(self, "A new stream: {:?} {}.", stream_type, stream_id);
        match stream_type {
            StreamType::BiDi => match self.role() {
                Role::Server => self.handle_new_client_request(stream_id),
                Role::Client => assert!(false, "Client received a new bidirectiona stream!"),
            },
            StreamType::UniDi => {
                let stream_type;
                let fin;
                {
                    let ns = &mut self
                        .new_streams
                        .entry(stream_id)
                        .or_insert(NewStreamTypeReader::new());
                    stream_type = ns.get_type(&mut self.conn, stream_id);
                    fin = ns.fin;
                }

                if let Some(t) = stream_type {
                    self.decode_new_stream(t, stream_id)?;
                }
                if fin {
                    self.new_streams.remove(&stream_id);
                }
            }
        };
        Ok(())
    }

    fn handle_stream_writable(&mut self, stream_id: u64) -> Res<()> {
        let label = match ::log::log_enabled!(::log::Level::Debug) {
            true => format!("{}", self),
            _ => String::new(),
        };
        if let Some(cs) = &mut self.client_requests.get_mut(&stream_id) {
            qdebug!(label, "Request/response stream {} is writable.", stream_id);
            cs.send(&mut self.conn, &mut self.qpack_encoder)?;
        } else if let Some(cs) = &mut self.client_requests_server.get_mut(&stream_id) {
            qdebug!(label, "Request/response stream {} is writable.", stream_id);
            cs.send(&mut self.conn, &mut self.qpack_encoder)?;
        } else if self
            .control_stream_local
            .send_if_this_stream(&mut self.conn, stream_id)?
        {
            qdebug!(
                self,
                "The local control stream ({}) is writable.",
                stream_id
            );
        } else if self.qpack_encoder.is_send_stream(stream_id) {
            qdebug!(
                self,
                "The local qpack encoder stream ({}) is writable.",
                stream_id
            );
            match self.conn.get_send_stream_mut(stream_id) {
                None => assert!(false, "Stream must exist"),
                Some(send) => self.qpack_encoder.send(send)?,
            };
        } else if self.qpack_decoder.is_send_stream(stream_id) {
            qdebug!(
                self,
                "The local qpack decoder stream ({}) is writable.",
                stream_id
            );
            match self.conn.get_send_stream_mut(stream_id) {
                None => assert!(false, "Stream must exist"),
                Some(send) => self.qpack_decoder.send(send)?,
            };
        } else {
            assert!(false, "Unexpected - unknown stream {}", stream_id);
        }
        Ok(())
    }

    fn handle_stream_readable(&mut self, stream_id: u64) -> Res<()> {
        qdebug!(self, "Readable stream {}.", stream_id);
        let mut reset_stream_error: Option<Error> = None;
        let mut remove_stream = false;
        let mut unblocked_streams: Vec<u64> = Vec::new();
        let label = match ::log::log_enabled!(::log::Level::Debug) {
            true => format!("{}", self),
            _ => String::new(),
        };
        if let Some(cs) = &mut self.client_requests.get_mut(&stream_id) {
            qdebug!(label, "Request/response stream {} is readable.", stream_id);
            if let Err(e) = cs.receive(&mut self.conn, &mut self.qpack_decoder) {
                qdebug!(label, "Error {} ocurred", e);
                if e.is_stream_error() {
                    reset_stream_error = Some(e);
                } else {
                    return Err(e);
                }
                if cs.done {
                    remove_stream = true;
                }
            }
        } else if let Some(cs) = &mut self.client_requests_server.get_mut(&stream_id) {
            qdebug!(label, "Request/response stream {} is readable.", stream_id);
            if let Err(e) = cs.receive(&mut self.conn, &mut self.qpack_decoder) {
                qdebug!(label, "Error {} ocurred", e);
                if e.is_stream_error() {
                    reset_stream_error = Some(e);
                } else {
                    return Err(e);
                }
            }
            if cs.state == ClientRequestServerState::ReadingRequestDone {
                if let Some(cb) = &mut self.new_stream_callback {
                    (cb)(cs, false);
                }
            }
        } else if self
            .control_stream_remote
            .receive_if_this_stream(&mut self.conn, stream_id)?
        {
            qdebug!(
                self,
                "The remote control stream ({}) is readable.",
                stream_id
            );
            while self.control_stream_remote.frame_reader.done() || self.control_stream_remote.fin {
                self.handle_control_frame()?;
                self.control_stream_remote
                    .receive_if_this_stream(&mut self.conn, stream_id)?;
            }
        } else if self.qpack_encoder.is_recv_stream(stream_id) {
            qdebug!(
                self,
                "The qpack encoder stream ({}) is readable.",
                stream_id
            );
            match self.conn.get_recv_stream_mut(stream_id) {
                None => assert!(false, "Stream must exist"),
                Some(recv) => self.qpack_encoder.receive(recv)?,
            };
        } else if self.qpack_decoder.is_recv_stream(stream_id) {
            qdebug!(
                self,
                "The qpack decoder stream ({}) is readable.",
                stream_id
            );
            match self.conn.get_recv_stream_mut(stream_id) {
                None => assert!(false, "Stream must exist"),
                Some(recv) => {
                    unblocked_streams = self.qpack_decoder.receive(recv)?;
                }
            };
        } else {
            let mut stream_type = None;
            let mut fin = false;
            if let Some(ns) = self.new_streams.get_mut(&stream_id) {
                stream_type = ns.get_type(&mut self.conn, stream_id);
                fin = ns.fin;
            } else {
                // If we receive a stream that we do not know, we will close it,
                // but in the same event list there can be a readable event as well.
                qdebug!("Unknown stream, this is stream that we have closed");
            }
            if let Some(t) = stream_type {
                self.decode_new_stream(t, stream_id)?;
            }
            if fin {
                self.new_streams.remove(&stream_id);
            }
        }

        if let Some(e) = reset_stream_error {
            self.client_requests.remove(&stream_id);
            self.conn.stream_reset(stream_id, e.code())?;
        } else if remove_stream {
            self.client_requests.remove(&stream_id);
        }
        for id in unblocked_streams {
            qdebug!(self, "Stream {} is unblocked", id);
            if let Some(client_request) = &mut self.client_requests.get_mut(&id) {
                if let Err(e) = client_request.unblock(&mut self.qpack_decoder) {
                    if e.is_stream_error() {
                        self.client_requests.remove(&id);
                        self.conn.stream_reset(id, e.code())?;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_stream_reset(&mut self, stream_id: u64, app_err: AppError) -> Res<()> {
        Ok(())
    }

    fn handle_stream_complete(&mut self, stream_id: u64) -> Res<()> {
        Ok(())
    }

    fn handle_stream_creatable(&mut self, stream_type: StreamType) -> Res<()> {
        Ok(())
    }

    fn decode_new_stream(&mut self, stream_type: u64, stream_id: u64) -> Res<()> {
        match stream_type {
            HTTP3_UNI_STREAM_TYPE_CONTROL => {
                qinfo!(self, "A new control stream {}.", stream_id);
                if let Some(_) = self.control_stream_remote.stream_id {
                    qdebug!(self, "A control stream already exists");
                    return Err(Error::WrongStreamCount);
                }
                self.control_stream_remote.stream_id = Some(stream_id);
            }
            HTTP3_UNI_STREAM_TYPE_PUSH => {
                qdebug!(self, "A new push stream {}.", stream_id);
                if self.role() == Role::Server {
                    qdebug!(self, "Error: server receives a push stream!");
                    self.conn
                        .stream_reset(stream_id, Error::WrongStreamDirection.code())?;
                } else {
                    // TODO implement PUSH
                    qdebug!(self, "PUSH is not implemented!");
                    if let Some(recv) = self.conn.get_recv_stream_mut(stream_id) {
                        recv.stop_sending(Error::PushRefused.code());
                    }
                }
            }
            QPACK_UNI_STREAM_TYPE_ENCODER => {
                qinfo!(self, "A new remote qpack encoder stream {}", stream_id);
                if self.qpack_decoder.has_recv_stream() {
                    qdebug!(self, "A qpack encoder stream already exists");
                    return Err(Error::WrongStreamCount);
                }
                self.qpack_decoder.add_recv_stream(stream_id);
            }
            QPACK_UNI_STREAM_TYPE_DECODER => {
                qinfo!(self, "A new remore qpack decoder stream {}", stream_id);
                if self.qpack_encoder.has_recv_stream() {
                    qdebug!(self, "A qpack decoder stream already exists");
                    return Err(Error::WrongStreamCount);
                }
                self.qpack_encoder.add_recv_stream(stream_id);
            }
            // TODO reserved stream types
            _ => {
                if let Some(recv) = self.conn.get_recv_stream_mut(stream_id) {
                    recv.stop_sending(Error::UnknownStreamType.code());
                }
            }
        };
        Ok(())
    }

    fn close(&mut self) {
        qdebug!(self, "Closed.");
        self.conn.close(0, "");
    }

    pub fn fetch(
        &mut self,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Res<()> {
        qdebug!(
            self,
            "Fetch method={}, scheme={}, host={}, path={}",
            method,
            scheme,
            host,
            path
        );
        let id = self.conn.stream_create(StreamType::BiDi)?;
        self.client_requests.insert(
            id,
            ClientRequest::new(id, method, scheme, host, path, headers),
        );
        Ok(())
    }

    fn handle_control_frame(&mut self) -> Res<()> {
        if self.control_stream_remote.fin {
            return Err(Error::ClosedCriticalStream);
        }
        if self.control_stream_remote.frame_reader.done() {
            let f = self.control_stream_remote.frame_reader.get_frame()?;
            qdebug!(self, "Handle a control frame {:?}", f);
            if let HFrame::Settings { .. } = f {
                if self.settings_received {
                    qdebug!(self, "SETTINGS frame already received");
                    return Err(Error::UnexpectedFrame);
                }
                self.settings_received = true;
            } else {
                if !self.settings_received {
                    qdebug!(self, "SETTINGS frame not received");
                    return Err(Error::MissingSettings);
                }
            }
            return match f {
                HFrame::Settings { settings } => self.handle_settings(&settings),
                HFrame::Priority { .. } => Ok(()),
                HFrame::CancelPush { .. } => Ok(()),
                HFrame::Goaway { stream_id } => self.handle_goaway(stream_id),
                HFrame::MaxPushId { .. } => Ok(()),
                _ => Err(Error::WrongStream),
            };
        }
        Ok(())
    }

    fn handle_settings(&mut self, s: &Vec<(HSettingType, u64)>) -> Res<()> {
        qdebug!(self, "Handle SETTINGS frame.");
        for (t, v) in s {
            qdebug!(self, " {:?} = {:?}", t, v);
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
                HSettingType::BlockedStreams => self.qpack_encoder.set_blocked_streams(*v)?,

                _ => {}
            }
        }
        Ok(())
    }

    fn handle_goaway(&mut self, _id: u64) -> Res<()> {
        qdebug!(self, "handle_goaway");
        if self.role() == Role::Server {
            return Err(Error::UnexpectedFrame);
        } else {
            // TODO
        }
        Ok(())
    }

    fn handle_max_push_id(&mut self, id: u64) -> Res<()> {
        qdebug!(self, "handle_max_push_id={}.", id);
        if self.role() == Role::Client {
            return Err(Error::UnexpectedFrame);
        } else {
            // TODO
        }
        Ok(())
    }

    pub fn state(&self) -> &State {
        self.conn.state()
    }

    // SERVER SIDE ONLY FUNCTIONS
    fn handle_new_client_request(&mut self, stream_id: u64) {
        self.client_requests_server
            .insert(stream_id, ClientRequestServer::new(stream_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_transport::recv_stream::Recvable;

    fn check_return_value(r: (Vec<Datagram>, u64)) {
        assert_eq!(r.0, Vec::new());
    }

    fn assert_closed(hconn: &HttpConn, expected: Error) {
        match hconn.state() {
            State::Closing(err, ..) | State::Closed(err) => {
                assert_eq!(err.app_code(), Some(expected.code()))
            }
            _ => panic!("Wrong state {:?}", hconn.state()),
        };
    }

    // Start a client/server and check setting frame.
    fn connect(client: bool) -> HttpConn {
        // create connection.
        let mut hconn;
        if client {
            hconn = HttpConn::new(Connection::new_client(), 100, 100);
        } else {
            hconn = HttpConn::new(Connection::new_server(), 100, 100);
        }
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        if let Some(s) = hconn.conn.streams.get(&0) {
            assert_eq!(
                s.send_buf,
                vec![0x0, 0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64]
            );
        }
        hconn
    }

    // Test http3 connection inintialization.
    // The client will open a control stream and send SETTINGS frame.
    #[test]
    fn test_client_connect() {
        let hconn = connect(true);
    }

    // Test http3 connection inintialization.
    // The server will a control stream and send SETTINGS frame.
    #[test]
    fn test_server_connect() {
        let hconn = connect(false);
    }

    fn connect_and_receive_control_stream(client: bool) -> (HttpConn, u64) {
        let mut hconn = connect(client);
        let remote_control_stream_id;
        if client {
            // create server control stream.
            remote_control_stream_id = hconn
                .conn
                .stream_create_net(Role::Server, StreamType::UniDi)
                .unwrap();
            // send server settings.
            hconn.conn.stream_recv_net(
                remote_control_stream_id,
                &vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0],
            );
        } else {
            // create client control stream.
            remote_control_stream_id = hconn
                .conn
                .stream_create_net(Role::Client, StreamType::UniDi)
                .unwrap();
            // send client settings.
            hconn
                .conn
                .stream_recv_net(remote_control_stream_id, &vec![0x0, 0x4, 0x2, 0x6, 0x0]);
        }

        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        (hconn, remote_control_stream_id)
    }

    // Client: Test receiving a new control stream and a SETTINGS frame.
    #[test]
    fn test_client_receive_control_frame() {
        let hconn = connect_and_receive_control_stream(true);
    }

    // Server: Test receiving a new control stream and a SETTINGS frame.
    #[test]
    fn test_server_receive_control_frame() {
        let hconn = connect_and_receive_control_stream(false);
    }

    // Client: Test that the connection will be closed if control stream
    // has been closed.
    #[test]
    fn test_client_close_control_stream() {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(true);
        hconn.conn.close_receive_side(remote_control_stream_id);
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::ClosedCriticalStream);
    }

    // Server: Test that the connection will be closed if control stream
    // has been closed.
    #[test]
    fn test_server_close_control_stream() {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(true);
        hconn.conn.close_receive_side(remote_control_stream_id);
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::ClosedCriticalStream);
    }

    // Client: test missing SETTINGS frame
    // (the first frame sent is a PRIORITY frame).
    #[test]
    fn test_client_missing_settings() {
        let mut hconn = connect(true);
        // create server control stream.
        let remote_control_stream_id = hconn
            .conn
            .stream_create_net(Role::Server, StreamType::UniDi)
            .unwrap();
        // send a PRIORITY frame.
        hconn.conn.stream_recv_net(
            remote_control_stream_id,
            &vec![0x0, 0x2, 0x4, 0x0, 0x2, 0x1, 0x3],
        );
        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::MissingSettings);
    }

    // Server: test missing SETTINGS frame
    // (the first frame sent is a PRIORITY frame).
    #[test]
    fn test_server_missing_settings() {
        let mut hconn = connect(false);
        // create server control stream.
        let remote_control_stream_id = hconn
            .conn
            .stream_create_net(Role::Client, StreamType::UniDi)
            .unwrap();
        // send a PRIORITY frame.
        hconn.conn.stream_recv_net(
            remote_control_stream_id,
            &vec![0x0, 0x2, 0x4, 0x0, 0x2, 0x1, 0x3],
        );
        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::MissingSettings);
    }

    // Client: receiving SETTINGS frame twice causes connection close
    // with error HTTP_UNEXPECTED_FRAME.
    #[test]
    fn test_client_receive_settings_twice() {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(true);

        // receive the second SETTINGS frame.
        hconn.conn.stream_recv_net(
            remote_control_stream_id,
            &vec![0x4, 0x4, 0x6, 0x0, 0x8, 0x0],
        );

        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::UnexpectedFrame);
    }

    // Server: receiving SETTINGS frame twice causes connection close
    // with error HTTP_UNEXPECTED_FRAME.
    #[test]
    fn test_server_receive_settings_twice() {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(true);

        // receive the second SETTINGS frame.
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x4, 0x2, 0x6, 0x0]);

        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::UnexpectedFrame);
    }

    fn test_wrong_frame_on_control_stream(client: bool, v: &[u8]) {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(client);

        // receive a frame that is not allowed on the control stream.
        hconn.conn.stream_recv_net(remote_control_stream_id, v);

        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::WrongStream);
    }

    // send DATA frame on a cortrol stream
    #[test]
    fn test_data_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &vec![0x0, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &vec![0x0, 0x2, 0x1, 0x2]);
    }

    // send HEADERS frame on a cortrol stream
    #[test]
    fn test_headers_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &vec![0x1, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &vec![0x1, 0x2, 0x1, 0x2]);
    }

    // send PUSH_PROMISE frame on a cortrol stream
    #[test]
    fn test_push_promise_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &vec![0x5, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &vec![0x5, 0x2, 0x1, 0x2]);
    }

    // send DUPLICATE_PUSH frame on a cortrol stream
    #[test]
    fn test_duplicate_push_frame_on_control_stream() {
        test_wrong_frame_on_control_stream(true, &vec![0xe, 0x2, 0x1, 0x2]);
        test_wrong_frame_on_control_stream(false, &vec![0xe, 0x2, 0x1, 0x2]);
    }

    // Client: receive unkonwn stream type
    // also test getting stream id that does not fit into a single byte.
    #[test]
    fn test_client_received_unknown_stream() {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(true);

        // create a stream with unknown type.
        let new_stream = hconn
            .conn
            .stream_create_net(Role::Server, StreamType::UniDi)
            .unwrap();
        hconn
            .conn
            .stream_recv_net(new_stream, &vec![0x41, 0x19, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);

        match hconn.conn.streams.get_mut(&new_stream) {
            Some(s) => {
                assert_eq!(s.stop_sending_error, Some(Error::UnknownStreamType.code()));
            }
            None => {
                assert!(false);
            }
        }
        assert_eq!(*hconn.state(), State::Connected);
    }

    // Server: receive unkonwn stream type
    // also test getting stream id that does not fit into a single byte.
    #[test]
    fn test_server_received_unknown_stream() {
        let mut hconn = connect(false);

        // create a stream with unknown type.
        let new_stream = hconn
            .conn
            .stream_create_net(Role::Client, StreamType::UniDi)
            .unwrap();
        hconn
            .conn
            .stream_recv_net(new_stream, &vec![0x41, 0x19, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);

        match hconn.conn.streams.get_mut(&new_stream) {
            Some(s) => {
                assert_eq!(s.stop_sending_error, Some(Error::UnknownStreamType.code()));
            }
            None => {
                assert!(false);
            }
        }
        assert_eq!(*hconn.state(), State::Connected);
    }

    // Client: receive a push stream
    #[test]
    fn test_client_received_push_stream() {
        let mut hconn = connect(true);

        let push_stream_id = hconn
            .conn
            .stream_create_net(Role::Server, StreamType::UniDi)
            .unwrap();
        hconn.conn.stream_recv_net(push_stream_id, &vec![0x1]);
        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        match hconn.conn.streams.get_mut(&push_stream_id) {
            Some(s) => {
                assert_eq!(s.stop_sending_error, Some(Error::PushRefused.code()));
            }
            None => {
                assert!(false);
            }
        }
        assert_eq!(*hconn.state(), State::Connected);
    }

    // Server: receiving a push stream on a server should cause WrongStreamDirection
    #[test]
    fn test_server_received_push_stream() {
        let mut hconn = connect(false);

        let push_stream_id = hconn
            .conn
            .stream_create_net(Role::Client, StreamType::UniDi)
            .unwrap();
        hconn.conn.stream_recv_net(push_stream_id, &vec![0x1]);
        let r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        match hconn.conn.streams.get_mut(&push_stream_id) {
            Some(s) => {
                assert_eq!(s.error, Some(Error::WrongStreamDirection.code()));
            }
            None => {
                assert!(false);
            }
        }
        assert_eq!(*hconn.state(), State::Connected);
    }

    // Test wrong frame on req/rec stream
    fn test_wrong_frame_on_request_stream(v: &[u8], err: Error) {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(true);

        assert_eq!(
            hconn.fetch(
                &"GET".to_string(),
                &"https".to_string(),
                &"something.com".to_string(),
                &"/".to_string(),
                &Vec::<(String, String)>::new()
            ),
            Ok(())
        );

        let mut r = hconn.process(Vec::new(), 0);
        check_return_value(r);

        hconn.conn.stream_recv_net(4, v);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);

        match hconn.conn.streams.get_mut(&4) {
            Some(s) => {
                assert_eq!(s.error, Some(err.code()));
            }
            None => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_cancel_push_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&vec![0x3, 0x1, 0x5], Error::WrongStream);
    }

    #[test]
    fn test_settings_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&vec![0x4, 0x4, 0x6, 0x4, 0x8, 0x4], Error::WrongStream);
    }

    #[test]
    fn test_goaway_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&vec![0x7, 0x1, 0x5], Error::WrongStream);
    }

    #[test]
    fn test_max_push_id_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&vec![0xd, 0x1, 0x5], Error::WrongStream);
    }

    #[test]
    fn test_priority_frame_on_client_on_request_stream() {
        test_wrong_frame_on_request_stream(
            &vec![0x2, 0x4, 0xf, 0x2, 0x1, 0x3],
            Error::UnexpectedFrame,
        );
    }

    // Test reading of a slowly streamed frame. bytes are received one by one
    #[test]
    fn test_frame_reading() {
        let mut hconn = connect(true);
        let remote_control_stream_id = hconn
            .conn
            .stream_create_net(Role::Server, StreamType::UniDi)
            .unwrap();
        // send stream type
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x0]);
        let mut r = hconn.process(Vec::new(), 0);
        check_return_value(r);

        // start sending SETTINGS frame
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x4]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x4]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x6]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x0]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x8]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x0]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        match hconn.conn.streams.get_mut(&remote_control_stream_id) {
            Some(s) => {
                assert!(!s.data_ready());
            }
            None => {
                assert!(false);
            }
        }

        // Now test PushPromise
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x5]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x5]);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);
        hconn
            .conn
            .stream_recv_net(remote_control_stream_id, &vec![0x4]);

        // PUSH_PROMISE on a control stream will cause an error
        let _ = hconn.process(Vec::new(), 0);
        assert_closed(&hconn, Error::WrongStream);
        match hconn.conn.streams.get_mut(&remote_control_stream_id) {
            Some(s) => {
                assert!(!s.data_ready());
            }
            None => {
                assert!(false);
            }
        }
    }

    #[test]
    fn fetch() {
        let (mut hconn, remote_control_stream_id) = connect_and_receive_control_stream(true);
        assert_eq!(
            hconn.fetch(
                &"GET".to_string(),
                &"https".to_string(),
                &"something.com".to_string(),
                &"/".to_string(),
                &Vec::<(String, String)>::new()
            ),
            Ok(())
        );
        let mut r = hconn.process(Vec::new(), 0);
        check_return_value(r);

        if let Some(s) = hconn.conn.streams.get(&4) {
            assert_eq!(
                s.send_buf,
                vec![
                    0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67, 0x35,
                    0x53, 0x2e, 0x43, 0xd3, 0xc1,
                ]
            );
            assert!(s.send_side_closed);
        }

        // send response.
        hconn.conn.stream_recv_net(
            4,
            &vec![
                0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // data frame
                0x0, 0x3, 0x61, 0x62, 0x63,
            ],
        ); // 200  Content-Length: 3  abc
        hconn.conn.close_receive_side(4);
        r = hconn.process(Vec::new(), 0);
        check_return_value(r);

        match hconn.conn.streams.get_mut(&2) {
            Some(s) => {
                assert!(!s.data_ready());
            }
            None => {
                assert!(false);
            }
        }
        match hconn.conn.streams.get_mut(&4) {
            Some(s) => {
                assert_eq!(s.recv_data_ready_amount(), 3);
            }
            None => {
                assert!(false);
            }
        }
    }
}
