// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{AppError, Error, Http3StreamType, ReceiveOutput, RecvStream, Res, ResetType};
use neqo_qpack::QPackDecoder;
use neqo_transport::Connection;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug)]
pub struct DecoderRecvStream {
    stream_id: u64,
    decoder: Rc<RefCell<QPackDecoder>>,
}

impl DecoderRecvStream {
    pub fn new(stream_id: u64, decoder: Rc<RefCell<QPackDecoder>>) -> Self {
        Self { stream_id, decoder }
    }
}

impl RecvStream for DecoderRecvStream {
    fn stream_reset(&self, _error: AppError, _reset_type: ResetType) -> Res<()> {
        Err(Error::HttpClosedCriticalStream)
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<ReceiveOutput> {
        let unblocked_streams = self.decoder.borrow_mut().receive(conn, self.stream_id)?;
        if unblocked_streams.is_empty() {
            Ok(ReceiveOutput::NoOutput)
        } else {
            Ok(ReceiveOutput::UnblockedStreams(unblocked_streams))
        }
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
        Http3StreamType::Decoder
    }
}
