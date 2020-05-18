// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::Http3Transaction;
use crate::hframe::HFrame;
use crate::recv_message::RecvMessage;
use crate::server_connection_events::Http3ServerConnEvents;
use crate::Header;
use crate::Res;
use neqo_common::{matches, qdebug, qinfo, qtrace, Encoder};
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::Connection;
use std::mem;

#[derive(PartialEq, Debug)]
enum TransactionSendState {
    Initial,
    ResponseInitiated { headers: Vec<Header>, data: Vec<u8> },
    SendingResponse { buf: Vec<u8> },
    Closed,
}

#[derive(Debug)]
pub struct TransactionServer {
    request: RecvMessage,
    send_state: TransactionSendState,
    stream_id: u64,
    conn_events: Http3ServerConnEvents,
}

impl TransactionServer {
    #[must_use]
    pub(crate) fn new(stream_id: u64, conn_events: Http3ServerConnEvents) -> Self {
        qinfo!("Create a request stream_id={}", stream_id);
        Self {
            request: RecvMessage::new(stream_id, Box::new(conn_events.clone()), None),
            send_state: TransactionSendState::Initial,
            stream_id,
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

    pub fn read_request_data(
        &mut self,
        conn: &mut Connection,
        decoder: &mut QPackDecoder,
        buf: &mut [u8],
    ) -> Res<(usize, bool)> {
        self.request.read_data(conn, decoder, buf)
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
        self.request.receive(conn, decoder, true)
    }

    fn has_data_to_send(&self) -> bool {
        matches!(self.send_state, TransactionSendState::SendingResponse { .. })
    }

    fn reset_receiving_side(&mut self) {
        self.request.close()
    }

    fn stop_sending(&mut self) {}

    fn done(&self) -> bool {
        self.send_state == TransactionSendState::Closed && self.request.is_closed()
    }

    fn close_send(&mut self, _conn: &mut Connection) -> Res<()> {
        Ok(())
    }
}
