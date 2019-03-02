#![allow(unused_variables, dead_code)]

use crate::connection::{Agent, Connection};
use crate::hframe::{
    ElementDependencyType, HFrame, HFrameReader, HSettingType, PrioritizedElementType, ReadBuf,
};
use neqo_transport::connection::{ConnState, Datagram, Role};
use neqo_transport::data::Data;
use neqo_transport::frame::StreamType;
use neqo_transport::stream::{Recvable, Sendable};
use neqo_transport::varint::decode_varint;
use neqo_transport::{CError, HError, Res};
use std::collections::HashMap;

const HTTP3_UNI_STREAM_TYPE_CONTROL: u64 = 0x0;
const HTTP3_UNI_STREAM_TYPE_PUSH: u64 = 0x1;

const MAX_HEADER_LIST_SIZE_DEFAULT: u64 = u64::max_value();
const NUM_PLACEHOLDERS_DEFAULT: u64 = 0;

// TODO this will need to make a list out of a header stream provided by necko.
struct HeaderList {
    headers: Vec<(String, String)>,
}

struct Request {
    method: String,
    target: String,
    headers: HeaderList,
    buf: Option<Data>,
}

impl Request {
    pub fn new(method: String, target: String, headers: HeaderList) -> Request {
        Request {
            method: method,
            target: target,
            headers: headers,
            buf: None,
        }
    }

    // TODO this will be encoded by QPACK
    pub fn encode_request(&mut self) {
        let mut len = self.method.as_bytes().len()
            + 1
            + self.target.as_bytes().len()
            + " HTTP/1.1".as_bytes().len()
            + 2;
        for i in self.headers.headers.iter() {
            len += i.0.as_bytes().len() + 2 + i.1.as_bytes().len() + 2;
        }
        let f = HFrame::Headers { len: len as u64 };
        let mut d = Data::default();
        f.encode(&mut d).unwrap();
        d.encode_vec(self.method.as_bytes());
        d.encode_vec(" ".as_bytes());
        d.encode_vec(self.target.as_bytes());
        d.encode_vec(" HTTP/1.1".as_bytes());
        d.encode_vec("\r\n".as_bytes());
        for i in self.headers.headers.iter() {
            d.encode_vec(i.0.as_bytes());
            d.encode_vec(": ".as_bytes());
            d.encode_vec(i.1.as_bytes());
            d.encode_vec("\r\n".as_bytes());
        }
        d.encode_vec("\r\n".as_bytes());
        self.buf = Some(d);
    }
}

struct Response {
    status: u32,
    status_line: Vec<u8>,
    pub headers: ReadBuf,
    pub data_len: u64,
    pub trailers: ReadBuf,
}

impl Response {
    pub fn new() -> Response {
        Response {
            status: 0,
            status_line: Vec::new(),
            headers: ReadBuf::new(),
            data_len: 0,
            trailers: ReadBuf::new(),
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

#[derive(PartialEq, Debug, Copy, Clone)]
enum ClientRequestState {
    SendingRequest,
    WaitingForResponseHeaders,
    ReadingHeaders,
    WaitingForData,
    ReadingData,
    ReadingTrailers,
    Closed,
}

//  This is used for normal request/responses.
struct ClientRequest {
    role: Role,
    state: ClientRequestState,
    request: Request,
    response: Option<Response>,
    frame_reader: HFrameReader,
    priority_received: bool,
}

impl ClientRequest {
    pub fn new(role: Role, method: String, target: String, headers: HeaderList) -> ClientRequest {
        ClientRequest {
            role: role,
            state: ClientRequestState::SendingRequest,
            request: Request::new(method, target, headers),
            response: None,
            frame_reader: HFrameReader::new(),
            priority_received: false,
        }
    }

    // TODO: Currently we cannot send data with a request
    pub fn send(&mut self, s: &mut Sendable) {
        if self.state == ClientRequestState::SendingRequest {
            if let None = self.request.buf {
                self.request.encode_request();
            }
            if let Some(d) = &mut self.request.buf {
                let sent = s.send(d.as_mut_vec());
                if sent == d.remaining() as u64 {
                    self.request.buf = None;
                    s.close();
                    self.state = ClientRequestState::WaitingForResponseHeaders;
                } else {
                    d.read(sent as usize);
                }
            }
        }
    }

    fn get_frame(&mut self, s: &mut Recvable) -> Result<(), CError> {
        if self.frame_reader.receive(s)? {
            self.state = ClientRequestState::Closed;
        }
        Ok(())
    }

    pub fn receive(&mut self, s: &mut Recvable) -> Result<(), CError> {
        return match self.state {
            ClientRequestState::SendingRequest => {
                /*TODO if we get response whlie streaming data. We may also get a stop_sending...*/
                Ok(())
            }
            ClientRequestState::WaitingForResponseHeaders => {
                self.get_frame(s)?;
                if self.frame_reader.done() {
                    return match self.frame_reader.get_frame()? {
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
                        ),
                        HFrame::Headers { len } => self.handle_headers_frame(len, s),
                        HFrame::PushPromise { .. } => {
                            Err(CError::HError(HError::ErrHttpUnexpectedFrame))
                        }
                        _ => Err(CError::HError(HError::ErrHttpWrongStream)),
                    };
                }
                Ok(())
            }
            ClientRequestState::ReadingHeaders => {
                if let Some(r) = &mut self.response {
                    let (_, fin) = r.headers.get(s)?;
                    if fin {
                        self.state = ClientRequestState::Closed;
                    } else if r.headers.done() {
                        self.state = ClientRequestState::WaitingForData;
                    }
                    Ok(())
                } else {
                    panic!("We must have responce here!");
                }
            }
            ClientRequestState::WaitingForData => {
                self.get_frame(s)?;
                if self.frame_reader.done() {
                    return match self.frame_reader.get_frame()? {
                        HFrame::Data { len } => self.handle_data_frame(len),
                        HFrame::PushPromise { .. } => {
                            Err(CError::HError(HError::ErrHttpUnexpectedFrame))
                        }
                        HFrame::Headers { .. } => {
                            // TODO implement trailers!
                            Err(CError::HError(HError::ErrHttpUnexpectedFrame))
                        }
                        _ => Err(CError::HError(HError::ErrHttpWrongStream)),
                    };
                }
                Ok(())
            }
            ClientRequestState::ReadingData => Ok(()),
            ClientRequestState::ReadingTrailers => Ok(()),
            ClientRequestState::Closed => {
                panic!("Stream readable after being closed!");
            }
        };
    }

    fn handle_priority_frame(
        &mut self,
        _priorized_elem_type: PrioritizedElementType,
        _elem_dependensy_type: ElementDependencyType,
        _priority_elem_id: u64,
        _elem_dependency_id: u64,
        _weight: u8,
    ) -> Result<(), CError> {
        if self.role == Role::Client {
            Err(CError::HError(HError::ErrHttpUnexpectedFrame))
        } else if self.priority_received {
            Err(CError::HError(HError::ErrHttpUnexpectedFrame))
        } else {
            self.priority_received = true;
            //TODO
            Ok(())
        }
    }

    fn handle_headers_frame(&mut self, len: u64, s: &mut Recvable) -> Result<(), CError> {
        if self.state == ClientRequestState::Closed {
            return Ok(());
        }

        if let Some(_) = &self.response {
            panic!("We sould not have a responce here!");
        }
        self.response = Some(Response::new());

        if let Some(r) = &mut self.response {
            if len == 0 {
                self.state = ClientRequestState::WaitingForData;
            } else {
                r.headers.get_len(len);
                let (_, fin) = r.headers.get(s)?;
                if fin {
                    self.state = ClientRequestState::Closed;
                } else if r.headers.done() {
                    self.state = ClientRequestState::WaitingForData;
                }
            }
        }
        Ok(())
    }

    fn handle_data_frame(&mut self, len: u64) -> Result<(), CError> {
        if let Some(r) = &mut self.response {
            r.data_len = len;
            if self.state != ClientRequestState::Closed {
                if r.data_len > 0 {
                    self.state = ClientRequestState::ReadingData;
                } else {
                    self.state = ClientRequestState::WaitingForData;
                }
            }
            Ok(())
        } else {
            panic!("We must have a responce here!");
        }
    }
}

// The local control stream, responsible for encoding frames and sending them
struct ControlStreamLocal {
    stream_id: u64,
    buf: Data,
}

impl ControlStreamLocal {
    pub fn send_frame(&mut self, f: HFrame) {
        f.encode(&mut self.buf).unwrap();
    }
    pub fn send(&mut self, s: &mut Sendable) {
        if self.buf.remaining() != 0 {
            let sent = s.send(self.buf.as_mut_vec());
            if sent == self.buf.remaining() as u64 {
                self.buf.clear();
            } else {
                self.buf.read(sent as usize);
            }
        }
    }
}

// The remote control stream is responsible only for reading frames. The frames are handled by HttpConn
struct ControlStreamRemote {
    stream_id: u64,
    frame_reader: HFrameReader,
    fin: bool,
}

impl ControlStreamRemote {
    pub fn new(id: u64) -> ControlStreamRemote {
        ControlStreamRemote {
            stream_id: id,
            frame_reader: HFrameReader::new(),
            fin: false,
        }
    }
    pub fn receive(&mut self, s: &mut Recvable) -> Result<(), CError> {
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
        loop {
            match self.reader.get_varint(s) {
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

#[derive(PartialEq, Debug)]
enum HState {
    Connecting,
    Connected,
    Closed,
}

struct HttpConn {
    role: Role,
    state: HState,
    conn: Connection,
    max_header_list_size: u64,
    num_placeholders: u64,
    control_stream_local: Option<ControlStreamLocal>,
    control_stream_remote: Option<ControlStreamRemote>,
    new_streams: HashMap<u64, NewStreamTypeReader>,
    //  qpack: QPack,Stream
    client_requests: HashMap<u64, ClientRequest>,
    settings_received: bool,
    error: CError,
}

impl HttpConn {
    pub fn new(r: Role, agent: Agent) -> HttpConn {
        HttpConn {
            role: r,
            state: HState::Connecting,
            conn: Connection::new(r, agent),
            max_header_list_size: MAX_HEADER_LIST_SIZE_DEFAULT,
            num_placeholders: NUM_PLACEHOLDERS_DEFAULT,
            control_stream_local: None,
            control_stream_remote: None,
            new_streams: HashMap::new(),
            client_requests: HashMap::new(),
            settings_received: false,
            error: CError::HError(HError::ErrHttpNoError),
        }
    }

    pub fn process(
        &mut self,
        d: Option<Datagram>,
        now: u64,
    ) -> Result<(Option<Datagram>, u64), CError> {
        match self.conn.process(d, now) {
            Err(e) => Err(CError::Error(e)),
            Ok(r) => {
                let s = self.conn.get_state();
                if s.connected {
                    match self.state {
                        HState::Connecting => {
                            self.on_connected();
                        }
                        HState::Connected => {
                            if let Err(e) = self.check_streams() {
                                self.close(e);
                                return Err(e);
                            }
                        }
                        HState::Closed => {}
                    }
                } else if s.closed {
                    self.close(s.error);
                }
                Ok(r)
            }
        }
    }

    fn on_connected(&mut self) {
        self.state = HState::Connected;
        self.create_control_stream();
        self.create_settings();
    }

    fn create_control_stream(&mut self) {
        let id = self.conn.stream_create(StreamType::UniDi);
        let mut cs = ControlStreamLocal {
            stream_id: id,
            buf: Data::default(),
        };
        cs.buf.encode_varint(HTTP3_UNI_STREAM_TYPE_CONTROL as u64);
        self.control_stream_local = Some(cs);
    }

    fn create_settings(&mut self) {
        if let Some(cs) = &mut self.control_stream_local {
            cs.send_frame(HFrame::Settings {
                settings: vec![
                    (HSettingType::MaxHeaderListSize, 0),
                    (HSettingType::NumPlaceholders, 0),
                ],
            });
        }
    }

    // If this return an error the connection must be closed.
    fn check_streams(&mut self) -> Result<(), CError> {
        let lw = self.conn.get_writable_streams();
        for (id, ws) in lw {
            if let Some(cs) = &mut self.client_requests.get_mut(&id) {
                cs.send(ws);
            } else if let Some(s) = &mut self.control_stream_local {
                if id == s.stream_id {
                    s.send(ws);
                }
            }
        }

        // TODO see if we can do this better (with better solution I am getting cannot borrow `*self` as mutable more than once at a time)
        let mut s_err: Vec<(u64, HError)> = Vec::new();
        for (id, rs) in self.conn.get_readable_streams() {
            if let Some(cs) = &mut self.client_requests.get_mut(&id) {
                if let Err(e) = cs.receive(rs) {
                    match e {
                        CError::Error(te) => return Err(CError::Error(te)),
                        CError::HError(he) => {
                            if is_stream_error(he) {
                                s_err.push((id, he));
                            } else {
                                return Err(CError::HError(he));
                            }
                        }
                    }
                }
            } else if let Some(s) = &mut self.control_stream_remote {
                if id == s.stream_id {
                    if let Err(_) = s.receive(rs) {
                        //TODO handle error
                    }
                }
            // new stream we need to decode stream id.
            } else {
                let ns = &mut self
                    .new_streams
                    .entry(id)
                    .or_insert(NewStreamTypeReader::new()); //{
                if let Some(t) = ns.get_type(rs) {
                    match t {
                        HTTP3_UNI_STREAM_TYPE_CONTROL => {
                            if let Some(_) = &mut self.control_stream_remote {
                                return Err(CError::HError(HError::ErrHttpWrongStreamCount));
                            }
                            self.control_stream_remote = Some(ControlStreamRemote::new(id));
                        }
                        HTTP3_UNI_STREAM_TYPE_PUSH => {
                            if self.role == Role::Server {
                                rs.stop_sending(HError::ErrHttpWrongStreamDirection);
                            } else {
                                // TODO implement PUSH
                                rs.stop_sending(HError::ErrHttpPushRefused);
                            }
                        }
                        // TODO reserved stream types
                        _ => {
                            rs.stop_sending(HError::ErrHttpUnknownStreamType);
                        }
                    };
                }
            }
        }

        // Handle control frame if we have one.
        self.handle_control_frame()?;

        // handle stream errors
        for (id, e) in s_err.iter() {
            // TODO we need to infprm app about this reset.
            self.client_requests.remove(&id);
            self.conn.reset_stream(*id, *e);
        }

        self.new_streams.retain(|_, v| !v.fin);
        Ok(())
    }

    fn close(&mut self, err: CError) {
        self.state = HState::Closed;
        self.error = err;
        if let CError::HError(e) = err {
            self.conn.close(e);
        }
    }

    pub fn fetch(&mut self, method: String, target: String, headers: HeaderList) -> Res<()> {
        let id = self.conn.stream_create(StreamType::BiDi);
        self.client_requests
            .insert(id, ClientRequest::new(self.role, method, target, headers));
        Ok(())
    }

    fn handle_control_frame(&mut self) -> Result<(), HError> {
        if let Some(cs) = &mut self.control_stream_remote {
            if cs.fin {
                return Err(HError::ErrHttpClosedCriticalStream);
            }
            if cs.frame_reader.done() {
                let f = cs.frame_reader.get_frame()?;
                if let HFrame::Settings { .. } = f {
                    if self.settings_received {
                        return Err(HError::ErrHttpUnexpectedFrame);
                    }
                    self.settings_received = true;
                } else {
                    if !self.settings_received {
                        return Err(HError::ErrHttpMissingSettings);
                    }
                }
                return match f {
                    HFrame::Settings { settings } => self.handle_settings(&settings),
                    HFrame::Priority { .. } => Ok(()),
                    HFrame::CancelPush { .. } => Ok(()),
                    HFrame::Goaway { stream_id } => self.handle_goaway(stream_id),
                    HFrame::MaxPushId { .. } => Ok(()),
                    _ => Err(HError::ErrHttpWrongStream),
                };
            }
        }
        Ok(())
    }

    fn handle_settings(&mut self, s: &Vec<(HSettingType, u64)>) -> Result<(), HError> {
        for (t, v) in s {
            match t {
                HSettingType::MaxHeaderListSize => {
                    self.max_header_list_size = *v;
                }
                HSettingType::NumPlaceholders => {
                    if self.role == Role::Server {
                        return Err(HError::ErrHttpWrongStreamDirection);
                    } else {
                        self.num_placeholders = *v;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn handle_goaway(&mut self, _id: u64) -> Result<(), HError> {
        if self.role == Role::Server {
            return Err(HError::ErrHttpUnexpectedFrame);
        } else {
            // TODO
        }
        Ok(())
    }

    fn handle_max_push_id(&mut self, _id: u64) -> Result<(), HError> {
        if self.role == Role::Client {
            return Err(HError::ErrHttpUnexpectedFrame);
        } else {
            // TODO
        }
        Ok(())
    }

    pub fn get_state(&self) -> ConnState {
        ConnState {
            connected: self.state == HState::Connected,
            error: self.error,
            closed: self.state == HState::Closed,
        }
    }
}

fn is_stream_error(e: HError) -> bool {
    if e == HError::ErrHttpUnexpectedFrame
        || e == HError::ErrHttpWrongStreamDirection
        || e == HError::ErrHttpWrongStream
    {
        return true;
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_return_value(r: Result<(Option<Datagram>, u64), CError>) {
        if let Ok(v) = r {
            assert_eq!(v, (None, 0));
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_connect() {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);
        if let Some(s) = hconn.conn.streams.get(&0) {
            assert_eq!(s.send_buf, vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
        }
    }

    #[test]
    fn fetch() {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);
        match hconn.conn.streams.get(&0) {
            Some(s) => {
                assert_eq!(s.send_buf, vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        let headers = HeaderList {
            headers: Vec::new(),
        };
        assert_eq!(
            hconn.fetch("GET".to_string(), "something.com".to_string(), headers),
            Ok(())
        );
        r = hconn.process(None, 0);
        check_return_value(r);

        if let Some(s) = hconn.conn.streams.get(&1) {
            assert_eq!(
                s.send_buf,
                vec![
                    0x1, 0x1c, 0x47, 0x45, 0x54, 0x20, 0x73, 0x6f, 0x6d, 0x65, 0x74, 0x68, 0x69,
                    0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
                    0x2e, 0x31, 0xd, 0xa, 0xd, 0xa
                ]
            );
            assert!(s.send_side_closed);
        }

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi);
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
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![
                    0x1, 0x1f, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30,
                    0x30, 0x20, 0x4f, 0x4b, 0xd, 0xa, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
                    0x3a, 0x20, 0x33, 0xd, 0xa, 0xd, 0xa, // data frame
                    0x0, 0x3, 0x61, 0x62, 0x63,
                ]); //HTTP/1.1 200 OK  Content-Length: 3  abc
                s.receive_side_closed = true;
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        r = hconn.process(None, 0);
        check_return_value(r);
        r = hconn.process(None, 0);
        check_return_value(r);
        r = hconn.process(None, 0);
        check_return_value(r);
        match hconn.conn.streams.get_mut(&2) {
            Some(s) => {
                assert!(!s.recv_data_ready());
            }
            None => {
                assert!(false);
            }
        }
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert_eq!(s.recv_data_ready_amount(), 3);
            }
            None => {
                assert!(false);
            }
        }
    }

    // Test reading of a slow streamed frame. bytes are received one by one
    #[test]
    fn test_frame_reading() {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);

        hconn.conn.stream_create(StreamType::UniDi);
        // send stream type
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
        check_return_value(r);
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
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
        r = hconn.process(None, 0);
        if let Err(e) = r {
            assert_eq!(e, CError::HError(HError::ErrHttpWrongStream));
        }
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
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi);
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        hconn.conn.close_receive_side(1);
        r = hconn.process(None, 0);
        if let Err(e) = r {
            assert_eq!(e, CError::HError(HError::ErrHttpClosedCriticalStream));
        }
        let state = hconn.get_state();
        assert_eq!(state.closed, true);
        assert_eq!(
            state.error,
            CError::HError(HError::ErrHttpClosedCriticalStream)
        );
    }

    #[test]
    fn test_missing_settings() {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi);
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x2, 0x4, 0x0, 0x2, 0x1, 0x3]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        r = hconn.process(None, 0);
        if let Err(e) = r {
            assert_eq!(e, CError::HError(HError::ErrHttpMissingSettings));
        }
        let state = hconn.get_state();
        assert_eq!(state.closed, true);
        assert_eq!(state.error, CError::HError(HError::ErrHttpMissingSettings));
    }

    #[test]
    fn test_receive_settings_twice() {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi);
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        r = hconn.process(None, 0);
        if let Err(e) = r {
            assert_eq!(e, CError::HError(HError::ErrHttpUnexpectedFrame));
        }
        let state = hconn.get_state();
        assert_eq!(state.closed, true);
        assert_eq!(state.error, CError::HError(HError::ErrHttpUnexpectedFrame));
    }

    fn test_wrong_frame_on_control_stream(v: &Vec<u8>) {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi);
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(v);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        r = hconn.process(None, 0);
        if let Err(e) = r {
            assert_eq!(e, CError::HError(HError::ErrHttpWrongStream));
        }
        let state = hconn.get_state();
        assert_eq!(state.closed, true);
        assert_eq!(state.error, CError::HError(HError::ErrHttpWrongStream));
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
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi);
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x41, 0x19, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);

        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert_eq!(s.stop_sending_error, Some(HError::ErrHttpUnknownStreamType));
            }
            None => {
                assert!(false);
            }
        }
        let state = hconn.get_state();
        assert_eq!(state.closed, false);
    }

    // receive a push stream
    #[test]
    fn test_received_push_stream() {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);

        // create server control stream
        hconn.conn.stream_create(StreamType::UniDi);
        // send server settings.
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(vec![0x1, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);

        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert_eq!(s.stop_sending_error, Some(HError::ErrHttpPushRefused));
            }
            None => {
                assert!(false);
            }
        }
        let state = hconn.get_state();
        assert_eq!(state.closed, false);
    }

    // Test wrong frame on req/rec stream
    fn test_wrong_frame_on_request_stream(v: &Vec<u8>, err: HError) {
        let mut hconn = HttpConn::new(Role::Client, Agent {});
        assert_eq!(hconn.state, HState::Connecting);
        let mut r = hconn.process(None, 0);
        check_return_value(r);
        assert_eq!(hconn.state, HState::Connected);
        r = hconn.process(None, 0);
        check_return_value(r);
        match hconn.conn.streams.get(&0) {
            Some(s) => {
                assert_eq!(s.send_buf, vec![0x0, 0x4, 0x4, 0x6, 0x0, 0x8, 0x0]);
            }
            None => {
                assert!(false);
            }
        }
        let headers = HeaderList {
            headers: Vec::new(),
        };
        assert_eq!(
            hconn.fetch("GET".to_string(), "something.com".to_string(), headers),
            Ok(())
        );
        r = hconn.process(None, 0);
        check_return_value(r);

        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                s.recv_buf.extend(v);
            }
            None => {
                assert!(false);
            }
        }
        r = hconn.process(None, 0);
        check_return_value(r);
        match hconn.conn.streams.get_mut(&1) {
            Some(s) => {
                assert_eq!(s.error, Some(err));
            }
            None => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_cancel_push_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&vec![0x3, 0x1, 0x5], HError::ErrHttpWrongStream);
    }

    #[test]
    fn test_settings_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(
            &vec![0x4, 0x4, 0x6, 0x4, 0x8, 0x4],
            HError::ErrHttpWrongStream,
        );
    }

    #[test]
    fn test_goaway_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&vec![0x7, 0x1, 0x5], HError::ErrHttpWrongStream);
    }

    #[test]
    fn test_max_push_id_frame_on_request_stream() {
        test_wrong_frame_on_request_stream(&vec![0xd, 0x1, 0x5], HError::ErrHttpWrongStream);
    }

    #[test]
    fn test_priority_frame_on_client_on_request_stream() {
        test_wrong_frame_on_request_stream(
            &vec![0x2, 0x4, 0xf, 0x2, 0x1, 0x3],
            HError::ErrHttpUnexpectedFrame,
        );
    }
}
