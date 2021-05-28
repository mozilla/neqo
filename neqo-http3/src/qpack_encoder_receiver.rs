// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{AppError, Error, Http3StreamType, ReceiveOutput, RecvStream, Res, ResetType};
use neqo_qpack::QPackEncoder;
use neqo_transport::Connection;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug)]
pub struct EncoderRecvStream {
    stream_id: u64,
    encoder: Rc<RefCell<QPackEncoder>>,
}

impl EncoderRecvStream {
    pub fn new(stream_id: u64, encoder: Rc<RefCell<QPackEncoder>>) -> Self {
        Self { stream_id, encoder }
    }
}

impl RecvStream for EncoderRecvStream {
    fn stream_reset(&self, _error: AppError, _reset_type: ResetType) -> Res<()> {
        Err(Error::HttpClosedCriticalStream)
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<ReceiveOutput> {
        self.encoder.borrow_mut().receive(conn, self.stream_id)?;
        Ok(ReceiveOutput::NoOutput)
    }

    fn header_unblocked(&mut self, _conn: &mut Connection) -> Res<()> {
        Err(Error::HttpInternal(6))
    }

    fn done(&self) -> bool {
        false
    }

    fn read_data(&mut self, _conn: &mut Connection, _buf: &mut [u8]) -> Res<(usize, bool)> {
        Err(Error::HttpInternal(7))
    }

    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::Encoder
    }
}
