// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::hframe::{HFrame, HFrameReader, H3_FRAME_TYPE_DATA, H3_FRAME_TYPE_HEADERS};

use crate::connection::Http3Events;
use crate::Header;
use neqo_common::{qdebug, qinfo, qtrace, Encoder};
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::Connection;

use crate::{Error, Res};
use std::mem;

#[derive(Debug)]
struct Request {
    method: String,
    scheme: String,
    host: String,
    path: String,
    headers: Vec<Header>,
    buf: Option<Vec<u8>>,
}

impl Request {
    pub fn new(method: &str, scheme: &str, host: &str, path: &str, headers: &[Header]) -> Request {
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
        qdebug!([self] "Encoding headers for {}/{}", self.host, self.path);
        let encoded_headers = encoder.encode_header_block(&self.headers, stream_id);
        let f = HFrame::Headers {
            len: encoded_headers.len() as u64,
        };
        let mut d = Encoder::default();
        f.encode(&mut d);
        d.encode(&encoded_headers[..]);
        self.buf = Some(d.into());
    }
}

impl ::std::fmt::Display for Request {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Request {} {}/{}", self.method, self.host, self.path)
    }
}

/*
 *  Transaction send states:
 *    SendingHeaders : sending headers. From here we may switch to SendingData
 *                     or Closed (if the app does not want to send data and
 *                     has alreadyclosed the send stream).
 *    SendingData : We are sending request data until the app closes stream.
 *    Closed
 */

#[derive(PartialEq, Debug)]
enum TransactionSendState {
    SendingHeaders,
    SendingData,
    Closed,
}

/*
 * Transaction receive state:
 *    WaitingForResponseHeaders : we wait for headers. in this state we can
 *                                also get a PUSH_PROMISE frame.
 *    ReadingHeaders : we have HEADERS frame and now we are reading header
 *                     block. This may block on encoder instructions. In this
 *                     state we do no read from the stream.
 *    BlockedDecodingHeaders : Decoding headers is blocked on encoder
 *                             instructions.
 *    WaitingForData : we got HEADERS, we are waiting for one or more data
 *                     frames. In this state we can receive one or more
 *                     PUSH_PROMIS frames or a HEADERS frame carrying trailers.
 *    ReadingData : we got a DATA frame, now we letting the app read payload.
 *                  From here we will go back to WaitingForData state to wait
 *                  for more data frames or to CLosed state
 *    ReadingTrailers : reading trailers.
 *    ClosePending : waiting for app to pick up data, after that we can delete
 * the TransactionClient.
 *    Closed
 */
#[derive(PartialEq, Debug)]
enum TransactionRecvState {
    WaitingForResponseHeaders,
    ReadingHeaders { buf: Vec<u8>, offset: usize },
    BlockedDecodingHeaders { buf: Vec<u8>, fin: bool },
    WaitingForData,
    ReadingData { remaining_data_len: usize },
    //    ReadingTrailers,
    ClosePending, // Close must first be read by application
    Closed,
}

#[derive(Debug, PartialEq)]
enum ResponseHeadersState {
    NoHeaders,
    Ready(Option<Vec<Header>>),
    Read,
}

//  This is used for normal request/responses.
pub struct TransactionClient {
    send_state: TransactionSendState,
    recv_state: TransactionRecvState,
    stream_id: u64,
    request: Request,
    frame_reader: HFrameReader,
    response_headers_state: ResponseHeadersState,
    conn_events: Http3Events,
}

impl TransactionClient {
    pub fn new(
        stream_id: u64,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        headers: &[Header],
        conn_events: Http3Events,
    ) -> TransactionClient {
        qinfo!("Create a request stream_id={}", stream_id);
        TransactionClient {
            send_state: TransactionSendState::SendingHeaders,
            recv_state: TransactionRecvState::WaitingForResponseHeaders,
            stream_id,
            request: Request::new(method, scheme, host, path, headers),
            response_headers_state: ResponseHeadersState::NoHeaders,
            frame_reader: HFrameReader::new(),
            conn_events,
        }
    }

    // TODO: Currently we cannot send data along with a request
    pub fn send(&mut self, conn: &mut Connection, encoder: &mut QPackEncoder) -> Res<()> {
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        if self.send_state == TransactionSendState::SendingHeaders {
            if self.request.buf.is_none() {
                self.request.encode_request(encoder, self.stream_id);
            }
            if let Some(d) = &mut self.request.buf {
                let sent = conn.stream_send(self.stream_id, &d[..])?;
                qdebug!([label] "{} bytes sent", sent);
                if sent == d.len() {
                    self.request.buf = None;
                    conn.stream_close_send(self.stream_id)?;
                    self.send_state = TransactionSendState::Closed;
                    qdebug!([label] "done sending request");
                } else {
                    let b = d.split_off(sent);
                    self.request.buf = Some(b);
                }
            }
        }
        Ok(())
    }

    pub fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        loop {
            qdebug!([label] "send_state={:?} recv_state={:?}.", self.send_state, self.recv_state);
            match self.recv_state {
                TransactionRecvState::WaitingForResponseHeaders => {
                    match self.recv_frame_header(conn)? {
                        None => break Ok(()),
                        Some((f, fin)) => {
                            self.handle_frame_in_state_waiting_for_headers(f, fin)?;
                            if fin {
                                self.set_state_to_close_pending();
                                break Ok(());
                            }
                        }
                    };
                }
                TransactionRecvState::ReadingHeaders { .. } => {
                    if self.read_headers_frame_body(conn, decoder)? {
                        break Ok(());
                    }
                }
                TransactionRecvState::BlockedDecodingHeaders { .. } => break Ok(()),
                TransactionRecvState::WaitingForData => {
                    match self.recv_frame_header(conn)? {
                        None => break Ok(()),
                        Some((f, fin)) => {
                            self.handle_frame_in_state_waiting_for_data(f, fin)?;
                            if fin {
                                self.set_state_to_close_pending();
                                break Ok(());
                            }
                        }
                    };
                }
                TransactionRecvState::ReadingData { .. } => {
                    self.conn_events.data_readable(self.stream_id);
                    break Ok(());
                }
                // TransactionRecvState::ReadingTrailers => break Ok(()),
                TransactionRecvState::ClosePending => {
                    panic!("Stream readable after being closed!");
                }
                TransactionRecvState::Closed => {
                    panic!("Stream readable after being closed!");
                }
            };
        }
    }

    fn handle_frame_in_state_waiting_for_headers(&mut self, frame: HFrame, fin: bool) -> Res<()> {
        qdebug!([self] "A new frame has been received: {:?}", frame);
        match frame {
            HFrame::Headers { len } => self.handle_headers_frame(len, fin),
            HFrame::PushPromise { .. } => Err(Error::UnexpectedFrame),
            _ => Err(Error::WrongStream),
        }
    }

    fn handle_headers_frame(&mut self, len: u64, fin: bool) -> Res<()> {
        if len == 0 {
            self.add_headers(None)
        } else {
            if fin {
                return Err(Error::MalformedFrame(H3_FRAME_TYPE_HEADERS));
            }
            self.recv_state = TransactionRecvState::ReadingHeaders {
                buf: vec![0; len as usize],
                offset: 0,
            };
            Ok(())
        }
    }

    fn handle_frame_in_state_waiting_for_data(&mut self, frame: HFrame, fin: bool) -> Res<()> {
        match frame {
            HFrame::Data { len } => self.handle_data_frame(len, fin),
            HFrame::PushPromise { .. } => Err(Error::UnexpectedFrame),
            HFrame::Headers { .. } => {
                // TODO implement trailers!
                Err(Error::UnexpectedFrame)
            }
            _ => Err(Error::WrongStream),
        }
    }

    fn handle_data_frame(&mut self, len: u64, fin: bool) -> Res<()> {
        if len > 0 {
            if fin {
                return Err(Error::MalformedFrame(H3_FRAME_TYPE_HEADERS));
            }
            self.recv_state = TransactionRecvState::ReadingData {
                remaining_data_len: len as usize,
            };
        }
        Ok(())
    }

    fn add_headers(&mut self, headers: Option<Vec<Header>>) -> Res<()> {
        if self.response_headers_state != ResponseHeadersState::NoHeaders {
            return Err(Error::InternalError);
        }
        self.response_headers_state = ResponseHeadersState::Ready(headers);
        self.conn_events.header_ready(self.stream_id);
        self.recv_state = TransactionRecvState::WaitingForData;
        Ok(())
    }

    fn set_state_to_close_pending(&mut self) {
        // Stream has received fin. Depending on headers state set header_ready
        // or data_readable event so that app can pick up the fin.
        qdebug!([self] "set_state_to_close_pending:  response_headers_state={:?}", self.response_headers_state);
        match self.response_headers_state {
            ResponseHeadersState::NoHeaders => {
                self.conn_events.header_ready(self.stream_id);
                self.response_headers_state = ResponseHeadersState::Ready(None);
            }
            // In Ready state we are already waiting for app to pick up headers
            // it can also pick up fin, so we do not need a new event.
            ResponseHeadersState::Ready(..) => {}
            ResponseHeadersState::Read => self.conn_events.data_readable(self.stream_id),
        }
        self.recv_state = TransactionRecvState::ClosePending;
    }

    fn recv_frame_header(&mut self, conn: &mut Connection) -> Res<Option<(HFrame, bool)>> {
        qtrace!([self] "receiving frame header");
        let fin = self.frame_reader.receive(conn, self.stream_id)?;
        if !self.frame_reader.done() {
            if fin {
                //we have received stream fin while waiting for a frame.
                // !self.frame_reader.done() means that we do not have a new
                // frame at all. Set state to ClosePending and waith for app
                // to pick up fin.
                self.set_state_to_close_pending();
            }
            Ok(None)
        } else {
            qdebug!([self] "A new frame has been received.");
            Ok(Some((self.frame_reader.get_frame()?, fin)))
        }
    }

    fn read_headers_frame_body(
        &mut self,
        conn: &mut Connection,
        decoder: &mut QPackDecoder,
    ) -> Res<bool> {
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        if let TransactionRecvState::ReadingHeaders {
            ref mut buf,
            ref mut offset,
        } = self.recv_state
        {
            let (amount, fin) = conn.stream_recv(self.stream_id, &mut buf[*offset..])?;
            qdebug!([label] "read_headers: read {} bytes fin={}.", amount, fin);
            *offset += amount as usize;
            if *offset < buf.len() {
                if fin {
                    // Malformated frame
                    return Err(Error::MalformedFrame(H3_FRAME_TYPE_HEADERS));
                }
                return Ok(true);
            }

            // we have read the headers, try decoding them.
            qdebug!([label] "read_headers: read all headers, try decoding them.");
            match decoder.decode_header_block(buf, self.stream_id)? {
                Some(headers) => {
                    self.add_headers(Some(headers))?;
                    if fin {
                        self.set_state_to_close_pending();
                        return Ok(true);
                    }
                }
                None => {
                    qdebug!([label] "decoding header is blocked.");
                    let mut tmp: Vec<u8> = Vec::new();
                    mem::swap(&mut tmp, buf);
                    self.recv_state =
                        TransactionRecvState::BlockedDecodingHeaders { buf: tmp, fin };
                    return Ok(true);
                }
            };
            Ok(false)
        } else {
            panic!("This is only called when recv_state is ReadingHeaders.");
        }
    }

    pub fn unblock(&mut self, decoder: &mut QPackDecoder) -> Res<()> {
        if let TransactionRecvState::BlockedDecodingHeaders { ref mut buf, fin } = self.recv_state {
            match decoder.decode_header_block(buf, self.stream_id)? {
                Some(headers) => {
                    self.add_headers(Some(headers))?;
                    if fin {
                        self.set_state_to_close_pending();
                    }
                }
                None => panic!("We must not be blocked again!"),
            };
        } else {
            panic!("Stream must be in the block state!");
        }
        Ok(())
    }

    pub fn close_send(&mut self, conn: &mut Connection) -> Res<()> {
        self.send_state = TransactionSendState::Closed;
        conn.stream_close_send(self.stream_id)?;
        Ok(())
    }

    pub fn done(&self) -> bool {
        self.send_state == TransactionSendState::Closed
            && self.recv_state == TransactionRecvState::Closed
    }

    pub fn has_data_to_send(&self) -> bool {
        self.send_state == TransactionSendState::SendingHeaders
            || self.send_state == TransactionSendState::SendingData
    }

    pub fn read_response_headers(&mut self) -> Res<(Vec<Header>, bool)> {
        if let ResponseHeadersState::Ready(ref mut headers) = self.response_headers_state {
            let mut tmp = Vec::new();
            if let Some(ref mut hdrs) = headers {
                mem::swap(&mut tmp, hdrs);
            }
            self.response_headers_state = ResponseHeadersState::Read;
            let mut fin = false;
            if self.recv_state == TransactionRecvState::ClosePending {
                fin = true;
                self.recv_state = TransactionRecvState::Closed;
            }
            Ok((tmp, fin))
        } else {
            Err(Error::Unavailable)
        }
    }

    pub fn read_response_data(
        &mut self,
        conn: &mut Connection,
        buf: &mut [u8],
    ) -> Res<(usize, bool)> {
        match self.recv_state {
            TransactionRecvState::ReadingData {
                ref mut remaining_data_len,
            } => {
                let to_read = if *remaining_data_len > buf.len() {
                    buf.len()
                } else {
                    *remaining_data_len
                };
                let (amount, fin) = conn.stream_recv(self.stream_id, &mut buf[..to_read])?;
                assert!(amount <= to_read);
                *remaining_data_len -= amount;

                if fin {
                    if *remaining_data_len > 0 {
                        return Err(Error::MalformedFrame(H3_FRAME_TYPE_DATA));
                    }
                    self.recv_state = TransactionRecvState::Closed;
                } else if *remaining_data_len == 0 {
                    self.recv_state = TransactionRecvState::WaitingForData;
                }

                Ok((amount, fin))
            }
            TransactionRecvState::ClosePending => {
                self.recv_state = TransactionRecvState::Closed;
                Ok((0, true))
            }
            _ => Ok((0, false)),
        }
    }
}

impl ::std::fmt::Display for TransactionClient {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "TransactionClient {}", self.stream_id)
    }
}
