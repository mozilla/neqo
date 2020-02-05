// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::client_events::Http3ClientEvents;
use crate::hframe::{HFrame, HFrameReader};
use crate::{Error, Header, Res};
use neqo_common::{qdebug, qinfo, qtrace};
use neqo_qpack::decoder::QPackDecoder;
use neqo_transport::Connection;
use std::mem;

/*
 * Response stream state:
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
enum ResponseStreamState {
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

#[derive(Debug)]
pub(crate) struct ResponseStream {
    state: ResponseStreamState,
    frame_reader: HFrameReader,
    response_headers_state: ResponseHeadersState,
    conn_events: Http3ClientEvents,
    stream_id: u64,
}

impl ::std::fmt::Display for ResponseStream {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "ResponseStream stream_id:{}",
            self.stream_id
        )
    }
}

impl ResponseStream {
    pub fn new(stream_id: u64, conn_events: Http3ClientEvents) -> Self {
        ResponseStream {
            state: ResponseStreamState::WaitingForResponseHeaders,
            frame_reader: HFrameReader::new(),
            response_headers_state: ResponseHeadersState::NoHeaders,
            conn_events,
            stream_id,
        }
    }

    fn handle_frame_in_state_waiting_for_headers(&mut self, frame: HFrame, fin: bool) -> Res<()> {
        qinfo!(
            [self],
            "A new frame has been received: {:?}; state={:?}",
            frame,
            self.state
        );
        match frame {
            HFrame::Headers { len } => self.handle_headers_frame(len, fin),
            HFrame::PushPromise { .. } => Err(Error::HttpIdError),
            _ => Err(Error::HttpFrameUnexpected),
        }
    }

    fn handle_frame_in_state_waiting_for_data(&mut self, frame: HFrame, fin: bool) -> Res<()> {
        qinfo!(
            [self],
            "A new frame has been received: {:?}; state={:?}",
            frame,
            self.state
        );
        match frame {
            HFrame::Data { len } => self.handle_data_frame(len, fin),
            HFrame::PushPromise { .. } => Err(Error::HttpIdError),
            HFrame::Headers { .. } => {
                // TODO implement trailers!
                Err(Error::HttpFrameUnexpected)
            }
            _ => Err(Error::HttpFrameUnexpected),
        }
    }

    fn handle_headers_frame(&mut self, len: u64, fin: bool) -> Res<()> {
        if len == 0 {
            self.add_headers(None)
        } else {
            if fin {
                return Err(Error::HttpFrameError);
            }
            self.state = ResponseStreamState::ReadingHeaders {
                buf: vec![0; len as usize],
                offset: 0,
            };
            Ok(())
        }
    }

    fn handle_data_frame(&mut self, len: u64, fin: bool) -> Res<()> {
        if len > 0 {
            if fin {
                return Err(Error::HttpFrameError);
            }
            self.state = ResponseStreamState::ReadingData {
                remaining_data_len: len as usize,
            };
        }
        Ok(())
    }

    fn add_headers(&mut self, headers: Option<Vec<Header>>) -> Res<()> {
        if self.response_headers_state != ResponseHeadersState::NoHeaders {
            return Err(Error::HttpInternalError);
        }
        self.response_headers_state = ResponseHeadersState::Ready(headers);
        self.conn_events.header_ready(self.stream_id);
        self.state = ResponseStreamState::WaitingForData;
        Ok(())
    }

    fn set_state_to_close_pending(&mut self) {
        // Stream has received fin. Depending on headers state set header_ready
        // or data_readable event so that app can pick up the fin.
        qdebug!(
            [self],
            "set_state_to_close_pending:  response_headers_state={:?}",
            self.response_headers_state
        );
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
        self.state = ResponseStreamState::ClosePending;
    }

    fn recv_frame_header(&mut self, conn: &mut Connection) -> Res<Option<(HFrame, bool)>> {
        qtrace!([self], "receiving frame header");
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
            qdebug!([self], "A new frame has been received.");
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
        if let ResponseStreamState::ReadingHeaders {
            ref mut buf,
            ref mut offset,
        } = self.state
        {
            let (amount, fin) = conn.stream_recv(self.stream_id, &mut buf[*offset..])?;
            qdebug!([label], "read_headers: read {} bytes fin={}.", amount, fin);
            *offset += amount as usize;
            if *offset < buf.len() {
                if fin {
                    // Malformated frame
                    return Err(Error::HttpFrameError);
                }
                return Ok(true);
            }

            // we have read the headers, try decoding them.
            qinfo!(
                [label],
                "read_headers: read all headers, try decoding them."
            );
            match decoder.decode_header_block(buf, self.stream_id)? {
                Some(headers) => {
                    self.add_headers(Some(headers))?;
                    if fin {
                        self.set_state_to_close_pending();
                    }
                    Ok(fin)
                }
                None => {
                    let mut tmp: Vec<u8> = Vec::new();
                    mem::swap(&mut tmp, buf);
                    self.state =
                        ResponseStreamState::BlockedDecodingHeaders { buf: tmp, fin };
                    Ok(true)
                }
            }
        } else {
            panic!("This is only called when state is ReadingHeaders.");
        }
    }

    pub fn read_response_headers(&mut self) -> Res<(Vec<Header>, bool)> {
        if let ResponseHeadersState::Ready(ref mut headers) = self.response_headers_state {
            let mut tmp = Vec::new();
            if let Some(ref mut hdrs) = headers {
                mem::swap(&mut tmp, hdrs);
            }
            self.response_headers_state = ResponseHeadersState::Read;
            let mut fin = false;
            if self.state == ResponseStreamState::ClosePending {
                fin = true;
                self.state = ResponseStreamState::Closed;
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
        match self.state {
            ResponseStreamState::ReadingData {
                ref mut remaining_data_len,
            } => {
                let to_read = if *remaining_data_len > buf.len() {
                    buf.len()
                } else {
                    *remaining_data_len
                };
                let (amount, fin) = conn.stream_recv(self.stream_id, &mut buf[..to_read])?;
                debug_assert!(amount <= to_read);
                *remaining_data_len -= amount;

                if fin {
                    if *remaining_data_len > 0 {
                        return Err(Error::HttpFrameError);
                    }
                    self.state = ResponseStreamState::Closed;
                } else if *remaining_data_len == 0 {
                    self.state = ResponseStreamState::WaitingForData;
                }

                Ok((amount, fin))
            }
            ResponseStreamState::ClosePending => {
                self.state = ResponseStreamState::Closed;
                Ok((0, true))
            }
            _ => Ok((0, false)),
        }
    }

    pub fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        loop {
            qdebug!(
                [label],
                "state={:?}.",
                self.state
            );
            match self.state {
                ResponseStreamState::WaitingForResponseHeaders => {
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
                ResponseStreamState::ReadingHeaders { .. } => {
                    if self.read_headers_frame_body(conn, decoder)? {
                        break Ok(());
                    }
                }
                ResponseStreamState::BlockedDecodingHeaders { ref buf, fin } => {
                    match decoder.decode_header_block(buf, self.stream_id)? {
                        Some(headers) => {
                            self.add_headers(Some(headers))?;
                            if fin {
                                self.set_state_to_close_pending();
                                break Ok(());
                            }
                        }
                        None => {
                            qinfo!([self], "decoding header is blocked.");
                            break Ok(());
                        }
                    }
                }
                ResponseStreamState::WaitingForData => {
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
                ResponseStreamState::ReadingData { .. } => {
                    self.conn_events.data_readable(self.stream_id);
                    break Ok(());
                }
                // ResponseStreamState::ReadingTrailers => break Ok(()),
                ResponseStreamState::ClosePending => {
                    panic!("Stream readable after being closed!");
                }
                ResponseStreamState::Closed => {
                    panic!("Stream readable after being closed!");
                }
            };
        }
    }

    pub fn is_closed(&self) -> bool {
        self.state == ResponseStreamState::Closed
    }

    pub fn close(&mut self) {
        self.state = ResponseStreamState::Closed;
    }
}
