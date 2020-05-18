// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::client_events::Http3ClientEvents;
use crate::connection::Http3Transaction;
use crate::push_controller::PushController;
use crate::recv_message::RecvMessage;
use crate::send_message::SendMessage;
use crate::Header;
use neqo_common::qinfo;
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::Connection;

use crate::Res;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug)]
pub(crate) struct TransactionClient {
    request: SendMessage,
    response: RecvMessage,
}

impl TransactionClient {
    pub fn new(
        stream_id: u64,
        headers: Vec<Header>,
        conn_events: Http3ClientEvents,
        push_handler: Rc<RefCell<PushController>>,
    ) -> Self {
        qinfo!("Create a request stream_id={}", stream_id);
        Self {
            request: SendMessage::new(stream_id, headers, conn_events.clone()),
            response: RecvMessage::new(stream_id, Box::new(conn_events), Some(push_handler)),
        }
    }

    pub fn send_request_body(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        self.request.send_body(conn, buf)
    }

    pub fn is_sending_closed(&self) -> bool {
        self.request.is_sending_closed()
    }

    pub fn read_response_data(
        &mut self,
        conn: &mut Connection,
        decoder: &mut QPackDecoder,
        buf: &mut [u8],
    ) -> Res<(usize, bool)> {
        self.response.read_data(conn, decoder, buf)
    }

    pub fn is_state_sending_data(&self) -> bool {
        self.request.is_state_sending_data()
    }
}

impl ::std::fmt::Display for TransactionClient {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "TransactionClient {} {}", self.request, self.response)
    }
}

impl Http3Transaction for TransactionClient {
    fn send(&mut self, conn: &mut Connection, encoder: &mut QPackEncoder) -> Res<()> {
        self.request.send(conn, encoder)
    }

    fn receive(&mut self, conn: &mut Connection, decoder: &mut QPackDecoder) -> Res<()> {
        self.response.receive(conn, decoder, true)
    }

    // TransactionClient owns headers and sends them. This method returns if
    // they're still being sent. Request body (if any) is sent by http client
    // afterwards using `send_request_body` after receiving DataWritable event.
    fn has_data_to_send(&self) -> bool {
        self.request.has_data_to_send()
    }

    fn reset_receiving_side(&mut self) {
        self.response.close();
    }

    fn stop_sending(&mut self) {
        self.request.stop_sending()
    }

    fn done(&self) -> bool {
        self.request.done() && self.response.is_closed()
    }

    fn close_send(&mut self, conn: &mut Connection) -> Res<()> {
        self.request.close_send(conn)
    }
}
