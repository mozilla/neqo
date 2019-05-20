// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::hframe::{ElementDependencyType, HFrame, HFrameReader, PrioritizedElementType};
use crate::{Error, Res};
use neqo_common::data::Data;
use neqo_common::qdebug;
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::connection::Connection;
use std::mem;

#[derive(PartialEq, Debug)]
enum RequestStreamServerState {
    WaitingForRequestHeaders,
    ReadingRequestHeaders { buf: Vec<u8>, offset: usize },
    BlockedDecodingHeaders { buf: Vec<u8> },
    ReadingRequestDone,
    SendingResponse,
    Error,
    Closed,
}

pub struct RequestStreamServer {
    state: RequestStreamServerState,
    stream_id: u64,
    frame_reader: HFrameReader,
    request_headers: Option<Vec<(String, String)>>,
    response_headers: Vec<(String, String)>,
    data: String,
    response_buf: Option<Data>,
    fin: bool,
}

impl RequestStreamServer {
    pub fn new(stream_id: u64) -> RequestStreamServer {
        RequestStreamServer {
            state: RequestStreamServerState::WaitingForRequestHeaders,
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
        self.data = data.clone();
        self.state = RequestStreamServerState::SendingResponse;
    }

    fn encode_response(&mut self, encoder: &mut QPackEncoder, stream_id: u64) {
        qdebug!([self] "Encoding headers");
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
        if self.state == RequestStreamServerState::SendingResponse {
            if let None = self.response_buf {
                self.encode_response(encoder, self.stream_id);
            }
            if let Some(d) = &mut self.response_buf {
                let sent = conn.stream_send(self.stream_id, d.as_mut_vec())?;
                qdebug!([label] "{} bytes sent", sent);
                if sent == d.remaining() {
                    self.response_buf = None;
                    conn.stream_close_send(self.stream_id)?;
                    self.state = RequestStreamServerState::Closed;
                    qdebug!([label] "done sending request");
                } else {
                    d.read(sent);
                }
            }
        }
        Ok(())
    }

    fn recv_frame(&mut self, conn: &mut Connection) -> Res<()> {
        if self.frame_reader.receive(conn, self.stream_id)? {
            self.state = RequestStreamServerState::Closed;
        }
        Ok(())
    }

    pub fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        let label = match ::log::log_enabled!(::log::Level::Debug) {
            true => format!("{}", self),
            _ => String::new(),
        };
        qdebug!([label] "state={:?}: receiving data.", self.state);
        loop {
            match self.state {
                RequestStreamServerState::WaitingForRequestHeaders => {
                    self.recv_frame(conn)?;
                    if !self.frame_reader.done() {
                        break Ok(());
                    }
                    qdebug!([label] "received a frame");
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
                        HFrame::Headers { len } => self.handle_headers_frame(len)?,
                        _ => {
                            break { Err(Error::WrongStream) };
                        }
                    };
                }
                RequestStreamServerState::ReadingRequestHeaders {
                    ref mut buf,
                    ref mut offset,
                } => {
                    let (amount, fin) = conn.stream_recv(self.stream_id, &mut buf[*offset..])?;
                    qdebug!(
                        [label]
                        "state=ReadingHeaders: read {} bytes fin={}.",
                        amount,
                        fin
                    );
                    *offset += amount as usize;
                    self.fin = fin;
                    if fin && *offset < buf.len() {
                        self.state = RequestStreamServerState::Error;
                        break Ok(());
                    }
                    if *offset < buf.len() {
                        break Ok(());
                    }
                    // we have read the headers.
                    self.request_headers = decoder.decode_header_block(buf, self.stream_id)?;
                    if let None = self.request_headers {
                        qdebug!([label] "decoding header is blocked.");
                        let mut tmp: Vec<u8> = Vec::new();
                        mem::swap(&mut tmp, buf);
                        self.state = RequestStreamServerState::BlockedDecodingHeaders { buf: tmp };
                    } else {
                        self.state = RequestStreamServerState::ReadingRequestDone;
                    }
                }
                RequestStreamServerState::BlockedDecodingHeaders { .. } => break Ok(()),
                RequestStreamServerState::ReadingRequestDone => break Ok(()),
                RequestStreamServerState::SendingResponse => break Ok(()),
                RequestStreamServerState::Error => break Ok(()),
                RequestStreamServerState::Closed => {
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

    fn handle_headers_frame(&mut self, len: u64) -> Res<()> {
        if self.state == RequestStreamServerState::Closed {
            return Ok(());
        }
        if len == 0 {
            self.state = RequestStreamServerState::Error;
        } else {
            self.state = RequestStreamServerState::ReadingRequestHeaders {
                buf: vec![0; len as usize],
                offset: 0,
            };
        }
        Ok(())
    }

    pub fn unblock(&mut self, decoder: &mut QPackDecoder) -> Res<()> {
        if let RequestStreamServerState::BlockedDecodingHeaders { ref mut buf } = self.state {
            self.request_headers = decoder.decode_header_block(buf, self.stream_id)?;
            if let None = self.request_headers {
                panic!("We must not be blocked again!");
            }
            self.state = RequestStreamServerState::ReadingRequestDone;
        } else {
            panic!("Stream must be in the block state!");
        }
        Ok(())
    }

    pub fn done_reading_request(&self) -> bool {
        self.state == RequestStreamServerState::ReadingRequestDone
    }
    pub fn has_data_to_send(&self) -> bool {
        self.state == RequestStreamServerState::SendingResponse
    }
}

impl ::std::fmt::Display for RequestStreamServer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "RequestStreamServer {}", self.stream_id)
    }
}
