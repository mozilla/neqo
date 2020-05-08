// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::Http3Transaction;
use crate::hframe::{HFrame, HFrameReader};
use crate::server_connection_events::Http3ServerConnEvents;
use crate::Header;
use crate::{Error, Res};
use neqo_common::{matches, qdebug, qinfo, qtrace, Encoder};
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::Connection;
use std::cmp::min;
use std::convert::TryFrom;
use std::mem;

const MAX_EVENT_DATA_SIZE: usize = 1024;

#[derive(PartialEq, Debug)]
enum TransactionRecvState {
    WaitingForHeaders,
    DecodingHeaders { header_block: Vec<u8>, fin: bool },
    WaitingForData,
    ReadingData { remaining_data_len: usize },
    Closed,
}

#[derive(PartialEq, Debug)]
enum TransactionSendState {
    Initial,
    ResponseInitiated { headers: Vec<Header>, data: Vec<u8> },
    SendingResponse { buf: Vec<u8> },
    Closed,
}

#[derive(Debug)]
pub struct TransactionServer {
    recv_state: TransactionRecvState,
    send_state: TransactionSendState,
    stream_id: u64,
    frame_reader: HFrameReader,
    conn_events: Http3ServerConnEvents,
}

impl TransactionServer {
    #[must_use]
    pub(crate) fn new(stream_id: u64, conn_events: Http3ServerConnEvents) -> Self {
        qinfo!("Create a request stream_id={}", stream_id);
        Self {
            recv_state: TransactionRecvState::WaitingForHeaders,
            send_state: TransactionSendState::Initial,
            stream_id,
            frame_reader: HFrameReader::new(),
            conn_events,
        }
    }

    pub fn set_response(&mut self, headers: &[Header], data: &[u8]) {
        self.send_state = TransactionSendState::ResponseInitiated {
            headers: headers.to_vec(),
            data: data.to_vec(),
        };
    }

    fn ensure_response_encoded(
        &mut self,
        conn: &mut Connection,
        encoder: &mut QPackEncoder,
    ) -> Res<()> {
        if let TransactionSendState::ResponseInitiated { headers, data } = &self.send_state {
            qdebug!([self], "Encoding headers");
            let header_block = encoder.encode_header_block(conn, &headers, self.stream_id)?;
            let hframe = HFrame::Headers {
                header_block: header_block.to_vec(),
            };
            let mut d = Encoder::default();
            hframe.encode(&mut d);
            if !data.is_empty() {
                qdebug!([self], "Encoding data");
                let d_frame = HFrame::Data {
                    len: data.len() as u64,
                };
                d_frame.encode(&mut d);
                d.encode(&data);
            }

            self.send_state = TransactionSendState::SendingResponse { buf: d.into() };
        }
        Ok(())
    }

    fn recv_frame(&mut self, conn: &mut Connection) -> Res<(Option<HFrame>, bool)> {
        qtrace!([self], "receiving a frame");
        let fin = self.frame_reader.receive(conn, self.stream_id)?;
        if self.frame_reader.done() {
            qinfo!([self], "A new frame has been received.");
            Ok((Some(self.frame_reader.get_frame()?), fin))
        } else {
            Ok((None, fin))
        }
    }

    fn handle_data_frame(&mut self, len: u64, fin: bool) -> Res<()> {
        qinfo!([self], "A new data frame len={} fin={}", len, fin);
        if len > 0 {
            if fin {
                return Err(Error::HttpFrame);
            }
            self.recv_state = TransactionRecvState::ReadingData {
                remaining_data_len: usize::try_from(len).or(Err(Error::HttpFrame))?,
            };
        } else if fin {
            self.conn_events.data(self.stream_id, Vec::new(), true);
            self.recv_state = TransactionRecvState::Closed;
        }
        Ok(())
    }
}

impl ::std::fmt::Display for TransactionServer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "TransactionServer {}", self.stream_id)
    }
}

impl Http3Transaction for TransactionServer {
    fn send(&mut self, conn: &mut Connection, encoder: &mut QPackEncoder) -> Res<()> {
        self.ensure_response_encoded(conn, encoder)?;
        qtrace!([self], "Sending response.");
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };
        if let TransactionSendState::SendingResponse { ref mut buf } = self.send_state {
            let sent = conn.stream_send(self.stream_id, &buf[..])?;
            qinfo!([label], "{} bytes sent", sent);
            if sent == buf.len() {
                conn.stream_close_send(self.stream_id)?;
                self.send_state = TransactionSendState::Closed;
                qinfo!([label], "done sending request");
            } else {
                let mut b = buf.split_off(sent);
                mem::swap(buf, &mut b);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };

        loop {
            qtrace!(
                [label],
                "[recv_state={:?}] receiving data.",
                self.recv_state
            );
            match self.recv_state {
                TransactionRecvState::WaitingForHeaders => {
                    match self.recv_frame(conn)? {
                        (None, true) => {
                            // Stream has been closed without any data, just ignore it.
                            self.recv_state = TransactionRecvState::Closed;
                            return Ok(());
                        }
                        (None, false) => {
                            // We do not have a complete frame.
                            return Ok(());
                        }
                        (Some(HFrame::Headers { header_block }), fin) => {
                            if header_block.is_empty() {
                                self.conn_events.headers(self.stream_id, Vec::new(), fin);
                                if fin {
                                    self.recv_state = TransactionRecvState::Closed;
                                    return Ok(());
                                } else {
                                    self.recv_state = TransactionRecvState::WaitingForData;
                                }
                            } else {
                                // Next step decoding headers.
                                self.recv_state =
                                    TransactionRecvState::DecodingHeaders { header_block, fin };
                            }
                        }
                        // server can only receive a Header frame at this point.
                        _ => {
                            return Err(Error::HttpFrameUnexpected);
                        }
                    }
                }
                TransactionRecvState::DecodingHeaders {
                    ref mut header_block,
                    fin,
                } => {
                    if let Some(headers) =
                        decoder.decode_header_block(header_block, self.stream_id)?
                    {
                        self.conn_events.headers(self.stream_id, headers, fin);
                        if fin {
                            self.recv_state = TransactionRecvState::Closed;
                            return Ok(());
                        } else {
                            self.recv_state = TransactionRecvState::WaitingForData;
                        }
                    } else {
                        qinfo!([self], "decoding header is blocked.");
                        return Ok(());
                    }
                }
                TransactionRecvState::WaitingForData => {
                    match self.recv_frame(conn)? {
                        (None, true) => {
                            // Inform the app tthat tthe stream is done.
                            self.conn_events.data(self.stream_id, Vec::new(), true);
                            self.recv_state = TransactionRecvState::Closed;
                            return Ok(());
                        }
                        (None, false) => {
                            // Still reading a frame.
                            return Ok(());
                        }
                        (Some(HFrame::Data { len }), fin) => {
                            self.handle_data_frame(len, fin)?;
                            if fin {
                                return Ok(());
                            }
                        }
                        _ => {
                            return Err(Error::HttpFrameUnexpected);
                        }
                    };
                }
                TransactionRecvState::ReadingData {
                    ref mut remaining_data_len,
                } => {
                    // TODO add available(stream_id) to neqo_transport.
                    assert!(*remaining_data_len > 0);
                    while *remaining_data_len != 0 {
                        let mut data = vec![0x0; min(*remaining_data_len, MAX_EVENT_DATA_SIZE)];
                        let (amount, fin) = conn.stream_recv(self.stream_id, &mut data)?;
                        if amount > 0 {
                            data.truncate(amount);
                            self.conn_events.data(self.stream_id, data, fin);
                            *remaining_data_len -= amount;
                        }

                        if fin {
                            if *remaining_data_len > 0 {
                                return Err(Error::HttpFrame);
                            } else {
                                self.recv_state = TransactionRecvState::Closed;
                                return Ok(());
                            }
                        } else if *remaining_data_len == 0 {
                            self.recv_state = TransactionRecvState::WaitingForData;
                            break;
                        } else if amount == 0 {
                            return Ok(());
                        }
                    }
                }
                TransactionRecvState::Closed => {
                    panic!("Stream readable after being closed!");
                }
            };
        }
    }

    fn has_data_to_send(&self) -> bool {
        matches!(self.send_state, TransactionSendState::SendingResponse { .. })
    }

    fn reset_receiving_side(&mut self) {
        self.recv_state = TransactionRecvState::Closed;
    }

    fn stop_sending(&mut self) {}

    fn done(&self) -> bool {
        self.send_state == TransactionSendState::Closed
            && self.recv_state == TransactionRecvState::Closed
    }

    fn close_send(&mut self, _conn: &mut Connection) -> Res<()> {
        Ok(())
    }
}
