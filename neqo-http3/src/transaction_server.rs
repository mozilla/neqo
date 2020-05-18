// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::connection::Http3Transaction;
use crate::recv_message::RecvMessage;
use crate::send_message::SendMessage;
use crate::server_connection_events::Http3ServerConnEvents;
use crate::Header;
use crate::{Error, Res};
use neqo_common::qinfo;
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::Connection;

#[derive(Debug)]
pub struct TransactionServer {
    request: RecvMessage,
    response: Option<SendMessage>,
    stream_id: u64,
    conn_events: Http3ServerConnEvents,
}

impl TransactionServer {
    #[must_use]
    pub(crate) fn new(stream_id: u64, conn_events: Http3ServerConnEvents) -> Self {
        qinfo!("Create a request stream_id={}", stream_id);
        Self {
            request: RecvMessage::new(stream_id, Box::new(conn_events.clone()), None),
            response: None,
            stream_id,
            conn_events,
        }
    }

    pub fn set_response(
        &mut self,
        conn: &mut Connection,
        headers: &[Header],
        data: &[u8],
    ) -> Res<()> {
        if self.response.is_some() {
            return Err(Error::AlreadyInitialized);
        }
        self.response = Some(SendMessage::new(
            self.stream_id,
            headers.to_vec(),
            Some(data.to_vec()),
            Box::new(self.conn_events.clone()),
        ));
        self.close_send(conn)
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
        if let Some(response) = &mut self.response {
            response.send(conn, encoder)
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_lines)]
    fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        self.request.receive(conn, decoder, true)
    }

    fn has_data_to_send(&self) -> bool {
        if let Some(response) = &self.response {
            response.has_data_to_send()
        } else {
            false
        }
    }

    fn reset_receiving_side(&mut self) {
        self.request.close()
    }

    fn stop_sending(&mut self) {}

    fn done(&self) -> bool {
        if let Some(response) = &self.response {
            response.done()
        } else {
            false
        }
    }

    fn close_send(&mut self, conn: &mut Connection) -> Res<()> {
        if let Some(response) = &mut self.response {
            response.close(conn)
        } else {
            Err(Error::Unexpected)
        }
    }
}
