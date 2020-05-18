// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::client_events::Http3ClientEvents;
use crate::hframe::HFrame;
use crate::Header;
use crate::{Error, Res};
use neqo_common::{matches, qdebug, qinfo, qtrace, Encoder};
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::Connection;
use std::cmp::min;
use std::convert::TryFrom;

const MAX_DATA_HEADER_SIZE_2: usize = (1 << 6) - 1; // Maximal amount of data with DATA frame header size 2
const MAX_DATA_HEADER_SIZE_2_LIMIT: usize = MAX_DATA_HEADER_SIZE_2 + 3; // 63 + 3 (size of the next buffer data frame header)
const MAX_DATA_HEADER_SIZE_3: usize = (1 << 14) - 1; // Maximal amount of data with DATA frame header size 3
const MAX_DATA_HEADER_SIZE_3_LIMIT: usize = MAX_DATA_HEADER_SIZE_3 + 5; // 16383 + 5 (size of the next buffer data frame header)
const MAX_DATA_HEADER_SIZE_5: usize = (1 << 30) - 1; // Maximal amount of data with DATA frame header size 3
const MAX_DATA_HEADER_SIZE_5_LIMIT: usize = MAX_DATA_HEADER_SIZE_5 + 9; // 1073741823 + 9 (size of the next buffer data frame header)

/*
 *  Transaction send states:
 *    HeaderInitialized : Headers are present but still nott encoded.
 *    SendingInitialMessage : sending headers. From here we may switch to SendingData
 *                     or Closed (if the app does not want to send data and
 *                     has already closed the send stream).
 *    SendingData : We are sending request data until the app closes the stream.
 *    Closed
 */

#[derive(PartialEq, Debug)]
enum SendMessageState {
    Initialized {
        headers: Vec<Header>,
        data: Option<Vec<u8>>,
        fin: bool,
    },
    SendingInitialMessage {
        buf: Vec<u8>,
        fin: bool,
    },
    SendingData,
    Closed,
}

#[derive(Debug)]
pub(crate) struct SendMessage {
    state: SendMessageState,
    stream_id: u64,
    conn_events: Http3ClientEvents,
}

impl SendMessage {
    pub fn new(stream_id: u64, headers: Vec<Header>, conn_events: Http3ClientEvents) -> Self {
        qinfo!("Create a request stream_id={}", stream_id);
        Self {
            state: SendMessageState::Initialized {
                headers,
                data: None,
                fin: false,
            },
            stream_id,
            conn_events,
        }
    }

    pub fn send_body(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        qinfo!(
            [self],
            "send_request_body: state={:?} len={}",
            self.state,
            buf.len()
        );
        match self.state {
            SendMessageState::Initialized { .. }
            | SendMessageState::SendingInitialMessage { .. } => Ok(0),
            SendMessageState::SendingData => {
                let available = usize::try_from(conn.stream_avail_send_space(self.stream_id)?)
                    .unwrap_or(usize::max_value());
                if available <= 2 {
                    return Ok(0);
                }
                let to_send;
                if available <= MAX_DATA_HEADER_SIZE_2_LIMIT {
                    // 63 + 3
                    to_send = min(min(buf.len(), available - 2), MAX_DATA_HEADER_SIZE_2);
                } else if available <= MAX_DATA_HEADER_SIZE_3_LIMIT {
                    // 16383 + 5
                    to_send = min(min(buf.len(), available - 3), MAX_DATA_HEADER_SIZE_3);
                } else if available <= MAX_DATA_HEADER_SIZE_5 {
                    // 1073741823 + 9
                    to_send = min(min(buf.len(), available - 5), MAX_DATA_HEADER_SIZE_5_LIMIT);
                } else {
                    to_send = min(buf.len(), available - 9);
                }

                qinfo!(
                    [self],
                    "send_request_body: available={} to_send={}.",
                    available,
                    to_send
                );

                let data_frame = HFrame::Data {
                    len: to_send as u64,
                };
                let mut enc = Encoder::default();
                data_frame.encode(&mut enc);
                match conn.stream_send(self.stream_id, &enc) {
                    Ok(sent) => {
                        debug_assert_eq!(sent, enc.len());
                    }
                    Err(e) => return Err(Error::TransportError(e)),
                }
                match conn.stream_send(self.stream_id, &buf[..to_send]) {
                    Ok(sent) => Ok(sent),
                    Err(e) => Err(Error::TransportError(e)),
                }
            }
            SendMessageState::Closed => Err(Error::AlreadyClosed),
        }
    }

    pub fn is_sending_closed(&self) -> bool {
        match self.state {
            SendMessageState::Initialized { fin, .. }
            | SendMessageState::SendingInitialMessage { fin, .. } => fin,
            SendMessageState::SendingData => false,
            _ => true,
        }
    }

    pub fn done(&self) -> bool {
        matches!(self.state, SendMessageState::Closed)
    }

    pub fn is_state_sending_data(&self) -> bool {
        matches!(self.state, SendMessageState::SendingData)
    }

    fn ensure_response_encoded(
        &mut self,
        conn: &mut Connection,
        encoder: &mut QPackEncoder,
    ) -> Res<()> {
        if let SendMessageState::Initialized { headers, data, fin } = &self.state {
            qdebug!([self], "Encoding headers");
            let header_block = encoder.encode_header_block(conn, &headers, self.stream_id)?;
            let hframe = HFrame::Headers {
                header_block: header_block.to_vec(),
            };
            let mut d = Encoder::default();
            hframe.encode(&mut d);
            if let Some(buf) = data {
                qdebug!([self], "Encoding data");
                let d_frame = HFrame::Data {
                    len: buf.len() as u64,
                };
                d_frame.encode(&mut d);
                d.encode(&buf);
            }

            self.state = SendMessageState::SendingInitialMessage {
                buf: d.into(),
                fin: *fin,
            };
        }
        Ok(())
    }

    pub fn send(&mut self, conn: &mut Connection, encoder: &mut QPackEncoder) -> Res<()> {
        self.ensure_response_encoded(conn, encoder)?;

        let label = if ::log::log_enabled!(::log::Level::Debug) {
            format!("{}", self)
        } else {
            String::new()
        };

        if let SendMessageState::SendingInitialMessage { ref mut buf, fin } = self.state {
            let sent = conn.stream_send(self.stream_id, &buf)?;
            qtrace!([label], "{} bytes sent", sent);

            if sent == buf.len() {
                if fin {
                    conn.stream_close_send(self.stream_id)?;
                    self.state = SendMessageState::Closed;
                    qtrace!([label], "done sending request");
                } else {
                    self.state = SendMessageState::SendingData;
                    self.conn_events.data_writable(self.stream_id);
                    qtrace!([label], "change to state SendingData");
                }
            } else {
                let b = buf.split_off(sent);
                *buf = b;
            }
        }
        Ok(())
    }

    // TransactionClient owns headers and sends them. This method returns if
    // they're still being sent. Request body (if any) is sent by http client
    // afterwards using `send_request_body` after receiving DataWritable event.
    pub fn has_data_to_send(&self) -> bool {
        matches!(self.state, SendMessageState::Initialized {..} | SendMessageState::SendingInitialMessage { .. } )
    }

    pub fn stop_sending(&mut self) {
        self.state = SendMessageState::Closed;
    }

    pub fn close_send(&mut self, conn: &mut Connection) -> Res<()> {
        match self.state {
            SendMessageState::SendingInitialMessage { ref mut fin, .. }
            | SendMessageState::Initialized { ref mut fin, .. } => {
                *fin = true;
            }
            _ => {
                self.state = SendMessageState::Closed;
                conn.stream_close_send(self.stream_id)?;
            }
        }
        Ok(())
    }
}

impl ::std::fmt::Display for SendMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "SendMesage {}", self.stream_id)
    }
}
