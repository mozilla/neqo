#![allow(unused_variables, dead_code)]

use neqo_common::data::Data;
use neqo_common::readbuf::ReadBuf;
use neqo_common::varint::decode_varint;
use neqo_qpack::decoder::{QPackDecoder, QPACK_UNI_STREAM_TYPE_DECODER};
use neqo_qpack::encoder::{QPackEncoder, QPACK_UNI_STREAM_TYPE_ENCODER};
use neqo_transport::connection::Role;
use neqo_transport::frame::StreamType;
use neqo_transport::stream::{Recvable, Sendable};
use neqo_transport::{Datagram, State};
use std::collections::HashMap;

use crate::hframe::{
    ElementDependencyType, HFrame, HFrameReader, HSettingType, PrioritizedElementType,
};
use crate::recvable::RecvableWrapper;
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
        method: &String,
        scheme: &String,
        host: &String,
        path: &String,
        headers: &Vec<(String, String)>,
    ) -> Request {
        let mut r = Request {
            method: method.clone(),
            scheme: scheme.clone(),
            host: host.clone(),
            path: path.clone(),
            headers: Vec::new(),
            buf: None,
        };
        r.headers.push((String::from(":method"), method.clone()));
        r.headers.push((String::from(":scheme"), r.scheme.clone()));
        r.headers.push((String::from(":authority"), r.host.clone()));
        r.headers.push((String::from(":path"), r.path.clone()));
        r.headers.extend_from_slice(&headers);
        r
    }

    // TODO(dragana) this will be encoded by QPACK
    pub fn encode_request(&mut self, encoder: &mut QPackEncoder, stream_id: u64) {
        log!(
            Level::Debug,
            "Encoding headers for {}{}",
            self.host,
            self.path
        );
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

#[derive(Debug)]
struct Response {
    status: u32,
    status_line: Vec<u8>,
    pub headers: Option<Vec<(String, String)>>,
    pub data_len: u64,
    pub trailers: Option<Vec<(String, String)>>,
}

impl Response {
    pub fn new() -> Response {
        Response {
            status: 0,
            status_line: Vec::new(),
            headers: None,
            data_len: 0,
            trailers: None,
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
#[derive(Debug)]
struct ClientRequest {
    role: Role,
    state: ClientRequestState,
    stream_id: u64,
    request: Request,
    response: Response,
    frame_reader: HFrameReader,
    priority_received: bool,
}

impl ClientRequest {
    pub fn new(
        role: Role,
        id: u64,
        method: &String,
        scheme: &String,
        host: &String,
        path: &String,
        headers: &Vec<(String, String)>,
    ) -> ClientRequest {
        log!(Level::Debug, "Create a request stream_id={}", id);
        ClientRequest {
            role: role,
            state: ClientRequestState::SendingRequest,
            stream_id: id,
            request: Request::new(method, scheme, host, path, headers),
            response: Response::new(),
            frame_reader: HFrameReader::new(),
            priority_received: false,
        }
    }

    // TODO: Currently we cannot send data along with a request
    pub fn send(&mut self, s: &mut Sendable, encoder: &mut QPackEncoder) -> Res<()> {
        if self.state == ClientRequestState::SendingRequest {
            if let None = self.request.buf {
                self.request.encode_request(encoder, self.stream_id);
            }
            if let Some(d) = &mut self.request.buf {
                let sent = s.send(d.as_mut_vec())?;
                log!(
                    Level::Debug,
                    "Request stream_id={}: {} bytes sent.",
                    self.stream_id,
                    sent
                );
                if sent == d.remaining() {
                    self.request.buf = None;
                    s.close();
                    self.state = ClientRequestState::WaitingForResponseHeaders;
                    log!(
                        Level::Debug,
                        "Request stream_id={}: done sending request.",
                        self.stream_id
                    );
                } else {
                    d.read(sent);
                }
            }
        }
        Ok(())
    }

    fn recv_frame(&mut self, s: &mut Recvable) -> Res<()> {
        if self.frame_reader.receive(s)? {
            self.state = ClientRequestState::Closed;
        }
        Ok(())
    }

    pub fn receive(&mut self, s: &mut Recvable, decoder: &mut QPackDecoder) -> Res<()> {
        log!(
            Level::Debug,
            "Request stream_id={} state={:?}: receiving data.",
            self.stream_id,
            self.state
        );
        loop {
            match self.state {
                ClientRequestState::SendingRequest => {
                    /*TODO if we get response whlie streaming data. We may also get a stop_sending...*/
                    break Ok(());
                }
                ClientRequestState::WaitingForResponseHeaders => {
                    self.recv_frame(s)?;
                    if !self.frame_reader.done() {
                        break Ok(());
                    }
                    log!(
                        Level::Debug,
                        "Request stream_id={}: received a frame.",
                        self.stream_id
                    );
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
                        HFrame::Headers { len } => self.handle_headers_frame(len, s)?,
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
                    let (amount, fin) = s.read(&mut buf[*offset..])?;
                    log!(
                        Level::Debug,
                        "Request stream_id={} state=ReadingHeaders: read {} bytes fin={}.",
                        self.stream_id,
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
                        log!(
                            Level::Debug,
                            "Request stream_id={} decoding header is blocked.",
                            self.stream_id
                        );
                        let mut tmp: Vec<u8> = Vec::new();
                        mem::swap(&mut tmp, buf);
                        self.state = ClientRequestState::BlockedDecodingHeaders { buf: tmp };
                    } else {
                        self.state = ClientRequestState::WaitingForData;
                    }
                }
                ClientRequestState::BlockedDecodingHeaders { ref mut buf } => break Ok(()),
                ClientRequestState::WaitingForData => {
                    self.recv_frame(s)?;
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

    fn handle_priority_frame(
        &mut self,
        _priorized_elem_type: PrioritizedElementType,
        _elem_dependensy_type: ElementDependencyType,
        _priority_elem_id: u64,
        _elem_dependency_id: u64,
        _weight: u8,
    ) -> Res<()> {
        if self.role == Role::Client {
            Err(Error::UnexpectedFrame)
        } else if self.priority_received {
            Err(Error::UnexpectedFrame)
        } else {
            self.priority_received = true;
            //TODO
            Ok(())
        }
    }

    fn handle_headers_frame(&mut self, len: u64, s: &mut Recvable) -> Res<()> {
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

// The local control stream, responsible for encoding frames and sending them
#[derive(Default)]
struct ControlStreamLocal {
    stream_id: Option<u64>,
    buf: Data,
}

impl ControlStreamLocal {
    pub fn send_frame(&mut self, f: HFrame) {
        f.encode(&mut self.buf).unwrap();
    }
    pub fn send(&mut self, s: &mut Sendable) -> Res<()> {
        if self.buf.remaining() != 0 {
            let sent = s.send(self.buf.as_mut_vec())?;
            if sent == self.buf.remaining() {
                self.buf.clear();
            } else {
                self.buf.read(sent);
            }
        }
        Ok(())
    }

    pub fn is_control_stream(&self, stream_id: u64) -> bool {
        match self.stream_id {
            Some(id) => id == stream_id,
            None => false,
        }
    }
}

// The remote control stream is responsible only for reading frames. The frames are handled by HttpConn
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

    pub fn is_control_stream(&self, stream_id: u64) -> bool {
        match self.stream_id {
            Some(id) => id == stream_id,
            None => false,
        }
    }

    pub fn receive(&mut self, s: &mut Recvable) -> Res<()> {
        self.fin = self.frame_reader.receive(s)?;
        Ok(())
    }
}

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
    pub fn get_type(&mut self, s: &mut Recvable) -> Option<u64> {
        // On any error we will only close this stream!
        let mut w = RecvableWrapper::wrap(s);
        loop {
            match self.reader.get_varint(&mut w) {
                Ok((rv, fin)) => {
                    if fin || rv == 0 {
                        self.fin = fin;
                        break None;
                    }

                    if self.reader.done() {
                        match decode_varint(&mut self.reader) {
                            Ok(v) => break Some(v),
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

struct HttpConn {
    // TODO(mt): This is redundant with the role on the transport.
    role: Role,
    conn: Connection,
    max_header_list_size: u64,
    num_placeholders: u64,
    control_stream_local: ControlStreamLocal,
    control_stream_remote: ControlStreamRemote,
    new_streams: HashMap<u64, NewStreamTypeReader>,
    qpack_encoder: QPackEncoder,
    qpack_decoder: QPackDecoder,
    client_requests: HashMap<u64, ClientRequest>,
    settings_received: bool,
}

impl HttpConn {
    pub fn new(c: Connection, max_table_size: u32, nax_blocked_streams: u16) -> HttpConn {
        if max_table_size > (1 << 30) - 1 {
            panic!("Wrong max_table_size");
        }
        HttpConn {
            role: c.role(),
            conn: c,
            max_header_list_size: MAX_HEADER_LIST_SIZE_DEFAULT,
            num_placeholders: NUM_PLACEHOLDERS_DEFAULT,
            control_stream_local: ControlStreamLocal::default(),
            control_stream_remote: ControlStreamRemote::new(),
            qpack_encoder: QPackEncoder::new(true),
            qpack_decoder: QPackDecoder::new(max_table_size, nax_blocked_streams),
            new_streams: HashMap::new(),
            client_requests: HashMap::new(),
            settings_received: false,
        }
    }

    // This function takes the provided result and check for an error.
    // An error results in closing the connection.
    fn check_result<T>(&mut self, res: Res<T>) {
        match &res {
            Err(e) => {
                self.conn.close(e.code(), format!("{}", e));
            }
            _ => {}
        };
    }

    fn process_state_change(&mut self, state: &State) -> Res<()> {
        if *state == State::Connected {
            self.on_connected()?;
        }
        Ok(())
    }

    pub fn process(&mut self, d: Vec<Datagram>) -> Vec<Datagram> {
        let state_before = self.state().clone();
        let out = self.conn.process(d);
        let state_after = self.state().clone();
        if state_after != state_before {
            let res = self.process_state_change(&state_after);
            self.check_result(res);
        }
        if let State::Connected = self.state() {
            let res = self.check_streams();
            self.check_result(res);
        }
        out
    }

    fn on_connected(&mut self) -> Res<()> {
        self.create_control_stream()?;
        self.create_qpack_streams()?;
        self.create_settings();
        Ok(())
    }

    fn create_control_stream(&mut self) -> Res<()> {
        self.control_stream_local.stream_id = Some(self.conn.stream_create(StreamType::UniDi)?);
        self.control_stream_local
            .buf
            .encode_varint(HTTP3_UNI_STREAM_TYPE_CONTROL as u64);
        Ok(())
    }

    fn create_qpack_streams(&mut self) -> Res<()> {
        self.qpack_encoder
            .add_send_stream(self.conn.stream_create(StreamType::UniDi)?);
        self.qpack_decoder
            .add_send_stream(self.conn.stream_create(StreamType::UniDi)?);
        Ok(())
    }

    fn create_settings(&mut self) {
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
    fn check_streams(&mut self) -> Res<()> {
        let mut unblocked_streams: Vec<u64> = Vec::new();
        let lw = self.conn.get_sendable_streams();
        for (id, ws) in lw {
            if let Some(cs) = &mut self.client_requests.get_mut(&id) {
                cs.send(ws, &mut self.qpack_encoder)?;
            } else if self.control_stream_local.is_control_stream(id) {
                self.control_stream_local.send(ws)?;
            } else if self.qpack_encoder.is_send_stream(id) {
                self.qpack_encoder.send(ws)?;
            } else if self.qpack_decoder.is_send_stream(id) {
                self.qpack_encoder.send(ws)?;
            }
        }

        // TODO see if we can do this better (with better solution I am getting cannot borrow `*self` as mutable more than once at a time)
        let mut stream_errors: Vec<(u64, Error)> = Vec::new();
        for (id, rs) in self.conn.get_recvable_streams() {
            if let Some(cs) = &mut self.client_requests.get_mut(&id) {
                if let Err(e) = cs.receive(rs, &mut self.qpack_decoder) {
                    if e.is_stream_error() {
                        stream_errors.push((id, e));
                    } else {
                        return Err(e);
                    }
                }
            } else if self.control_stream_remote.is_control_stream(id) {
                if let Err(_) = self.control_stream_remote.receive(rs) {
                    //TODO handle error
                }
            } else if self.qpack_encoder.is_recv_stream(id) {
                self.qpack_encoder.receive(rs)?;
            } else if self.qpack_decoder.is_recv_stream(id) {
                unblocked_streams = self.qpack_decoder.receive(rs)?;

            // new stream we need to decode stream id.
            } else {
                let ns = &mut self
                    .new_streams
                    .entry(id)
                    .or_insert(NewStreamTypeReader::new());
                if let Some(t) = ns.get_type(rs) {
                    match t {
                        HTTP3_UNI_STREAM_TYPE_CONTROL => {
                            if let Some(_) = self.control_stream_remote.stream_id {
                                return Err(Error::WrongStreamCount);
                            }
                            self.control_stream_remote.stream_id = Some(id);
                        }
                        HTTP3_UNI_STREAM_TYPE_PUSH => {
                            if self.role == Role::Server {
                                rs.stop_sending(Error::WrongStreamDirection.code());
                            } else {
                                // TODO implement PUSH
                                rs.stop_sending(Error::PushRefused.code());
                            }
                        }
                        QPACK_UNI_STREAM_TYPE_ENCODER => {
                            if self.qpack_decoder.has_recv_stream() {
                                return Err(Error::WrongStreamCount);
                            }
                            self.qpack_decoder.add_recv_stream(id);
                        }
                        QPACK_UNI_STREAM_TYPE_DECODER => {
                            if self.qpack_encoder.has_recv_stream() {
                                return Err(Error::WrongStreamCount);
                            }
                            self.qpack_encoder.add_recv_stream(id);
                        }
                        // TODO reserved stream types
                        _ => {
                            rs.stop_sending(Error::UnknownStreamType.code());
                        }
                    };
                }
            }
        }

        // Handle control frame if we have one.
        self.handle_control_frame()?;

        // Handle stream errors.
        for (id, e) in stream_errors {
            // TODO(dragana) we need to inform app about any failed requests.
            self.client_requests.remove(&id);
            self.conn.stream_reset(id, e.code())?;
        }

        self.new_streams.retain(|_, v| !v.fin);

        for id in unblocked_streams {
            if let Some(client_request) = &mut self.client_requests.get_mut(&id) {
                if let Err(e) = client_request.unblock(&mut self.qpack_decoder) {
                    self.client_requests.remove(&id);
                    self.conn.stream_reset(id, e.code())?;
                }
            }
        }
        Ok(())
    }

    fn close(&mut self) {
        self.conn.close(0, "");
    }

    pub fn fetch(
        &mut self,
        method: &String,
        scheme: &String,
        host: &String,
        path: &String,
        headers: &Vec<(String, String)>,
    ) -> Res<()> {
        let id = self.conn.stream_create(StreamType::BiDi)?;
        self.client_requests.insert(
            id,
            ClientRequest::new(self.role, id, method, scheme, host, path, headers),
        );
        Ok(())
    }

    fn handle_control_frame(&mut self) -> Res<()> {
        if self.control_stream_remote.fin {
            return Err(Error::ClosedCriticalStream);
        }
        if self.control_stream_remote.frame_reader.done() {
            let f = self.control_stream_remote.frame_reader.get_frame()?;
            if let HFrame::Settings { .. } = f {
                if self.settings_received {
                    return Err(Error::UnexpectedFrame);
                }
                self.settings_received = true;
            } else {
                if !self.settings_received {
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
        for (t, v) in s {
            match t {
                HSettingType::MaxHeaderListSize => {
                    self.max_header_list_size = *v;
                }
                HSettingType::NumPlaceholders => {
                    if self.role == Role::Server {
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
        if self.role == Role::Server {
            return Err(Error::UnexpectedFrame);
        } else {
            // TODO
        }
        Ok(())
    }

    fn handle_max_push_id(&mut self, _id: u64) -> Res<()> {
        if self.role == Role::Client {
            return Err(Error::UnexpectedFrame);
        } else {
            // TODO
        }
        Ok(())
    }

    pub fn state(&self) -> &State {
        self.conn.state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_return_value(r: Vec<Datagram>) {
        assert_eq!(r, Vec::new());
    }

    fn assert_closed(hconn: &HttpConn, expected: Error) {
        match hconn.state() {
            State::Closing(err, ..) | State::Closed(err) => {
                assert_eq!(err.app_code(), Some(expected.code()))
            }
            _ => panic!("Wrong state {:?}", hconn.state()),
        };
    }

    #[test]
    fn test_connect() {
        let mut hconn = HttpConn::new(Connection::new_client(), 100, 100);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);
        if let Some(s) = hconn.conn.streams.get(&0) {
            assert_eq!(
                s.send_buf,
                vec![0x0, 0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64]
            );
        }
    }

    #[test]
    fn fetch() {
        let mut hconn = HttpConn::new(Connection::new_client(), 100, 100);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get(&0) {
            Some(s) => {
                assert_eq!(
                    s.send_buf,
                    vec![0x0, 0x4, 0x6, 0x1, 0x40, 0x64, 0x7, 0x40, 0x64]
                );
            }
            None => {
                assert!(false);
            }
        }
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
        r = hconn.process(Vec::new());
        check_return_value(r);

        if let Some(s) = hconn.conn.streams.get(&3) {
            assert_eq!(
                s.send_buf,
                vec![
                    0x01, 0x10, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x89, 0x41, 0xe9, 0x2a, 0x67, 0x35,
                    0x53, 0x2e, 0x43, 0xd3, 0xc1,
                ]
            );
            assert!(s.send_side_closed);
        }

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send server settings.
        match hconn.conn.streams.get_mut(&2) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }

        // send response.
        match hconn.conn.streams.get_mut(&3) {
            Some(s) => {
                s.recv_buf.extend(vec![
                    0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x33, // data frame
                    0x0, 0x3, 0x61, 0x62, 0x63,
                ]); // 200  Content-Length: 3  abc
                s.receive_side_closed = true;
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        r = hconn.process(Vec::new());
        check_return_value(r);
        r = hconn.process(Vec::new());
        check_return_value(r);
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&2) {
            Some(s) => {
                assert!(!s.recv_data_ready());
            }
            None => {
                assert!(false);
            }
        }
        match hconn.conn.streams.get_mut(&3) {
            Some(s) => {
                assert_eq!(s.recv_data_ready_amount(), 3);
            }
            None => {
                assert!(false);
            }
        }
    }

    // Test reading of a slowly streamed frame. bytes are received one by one
    #[test]
    fn test_frame_reading() {
        let mut hconn = HttpConn::new(Connection::new_client(), 100, 100);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);

        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send stream type
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        // start sending SETTINGS frame
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x4]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x4]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x6]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x8]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
            }
            None => {
                assert!(false);
            }
        }

        // Now test PushPromise
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x5]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x5]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
                s.recv_buf.extend(vec![0x4]);
            }
            None => {
                assert!(false);
            }
        }

        // PUSH_PROMISE on a control stream will cause an error
        let _ = hconn.process(Vec::new());
        assert_closed(&hconn, Error::WrongStream);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert!(!s.recv_data_ready());
            }
            None => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_close_cotrol_stream() {
        let mut hconn = HttpConn::new(Connection::new_client(), 100, 100);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        hconn.conn.close_receive_side(1);
        let _ = hconn.process(Vec::new());
        assert_closed(&hconn, Error::ClosedCriticalStream);
    }

    #[test]
    fn test_missing_settings() {
        let mut hconn = HttpConn::new(Connection::new_client(), 100, 100);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x2, 0x4, 0x0, 0x2, 0x1, 0x3]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        let _ = hconn.process(Vec::new());
        assert_closed(&hconn, Error::MissingSettings);
    }

    #[test]
    fn test_receive_settings_twice() {
        let mut hconn = HttpConn::new(Connection::new_client(), 100, 100);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        let _ = hconn.process(Vec::new());
        assert_closed(&hconn, Error::UnexpectedFrame);
    }

    fn test_wrong_frame_on_control_stream(v: &Vec<u8>) {
        let mut hconn = HttpConn::new(Connection::new_client(), 100, 100);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(v);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);
        let _ = hconn.process(Vec::new());
        assert_closed(&hconn, Error::WrongStream);
    }

    // send DATA frame on a cortrol stream
    #[test]
    fn test_data_frame_on_cotrol_stream() {
        test_wrong_frame_on_control_stream(&vec![0x0, 0x2, 0x1, 0x2]);
    }

    // send HEADERS frame on a cortrol stream
    #[test]
    fn test_headers_frame_on_cotrol_stream() {
        test_wrong_frame_on_control_stream(&vec![0x1, 0x2, 0x1, 0x2]);
    }

    // send PUSH_PROMISE frame on a cortrol stream
    #[test]
    fn test_push_promise_frame_on_cotrol_stream() {
        test_wrong_frame_on_control_stream(&vec![0x5, 0x2, 0x1, 0x2]);
    }

    // send DUPLICATE_PUSH frame on a cortrol stream
    #[test]
    fn test_duplicate_push_frame_on_cotrol_stream() {
        test_wrong_frame_on_control_stream(&vec![0xe, 0x2, 0x1, 0x2]);
    }

    // receive unkonwn stream type
    // also test getting stream id that does not fit into a single byte.
    #[test]
    fn test_received_unknown_stream() {
        let mut hconn = HttpConn::new(Connection::new_client(), 200, 200);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf
                    .extend(vec![0x41, 0x19, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);

        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert_eq!(s.stop_sending_error, Some(Error::UnknownStreamType.code()));
            }
            None => {
                assert!(false);
            }
        }
        assert_eq!(*hconn.state(), State::Connected);
    }

    // receive a push stream
    #[test]
    fn test_received_push_stream() {
        let mut hconn = HttpConn::new(Connection::new_client(), 200, 200);
        assert_eq!(*hconn.state(), State::Init);
        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);
        r = hconn.process(Vec::new());
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi).unwrap();
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x1, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(Vec::new());
        check_return_value(r);

        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert_eq!(s.stop_sending_error, Some(Error::PushRefused.code()));
            }
            None => {
                assert!(false);
            }
        }
        assert_eq!(*hconn.state(), State::Connected);
    }

    // Test wrong frame on req/rec stream
    fn test_wrong_frame_on_request_stream(v: &Vec<u8>, err: Error) {
        let mut hconn = HttpConn::new(Connection::new_client(), 200, 200);
        assert_eq!(*hconn.state(), State::Init);

        let mut r = hconn.process(Vec::new());
        check_return_value(r);
        assert_eq!(*hconn.state(), State::Connected);

        r = hconn.process(Vec::new());
        check_return_value(r);

        match hconn.conn.streams.get(&0) {
            Some(s) => {
                assert_eq!(
                    s.send_buf,
                    vec![0x0, 0x4, 0x6, 0x1, 0x40, 0xc8, 0x7, 0x40, 0xc8]
                );
            }
            None => {
                assert!(false);
            }
        }

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

        r = hconn.process(Vec::new());
        check_return_value(r);

        match hconn.conn.streams.get_mut(&3) {
            Some(s) => {
                s.recv_buf.extend(v);
            }
            None => {
                assert!(false);
            }
        }

        r = hconn.process(Vec::new());
        check_return_value(r);

        match hconn.conn.streams.get_mut(&3) {
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
}
