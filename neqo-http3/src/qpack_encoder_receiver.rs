// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, rc::Rc, time::Instant};

use neqo_qpack as qpack;
use neqo_transport::{Connection, StreamId};

use crate::{CloseType, Error, Http3StreamType, ReceiveOutput, RecvStream, Res, Stream};

#[derive(Debug)]
pub struct EncoderRecvStream {
    encoder: Rc<RefCell<qpack::Encoder>>,
}

impl EncoderRecvStream {
    pub fn new(stream_id: StreamId, encoder: Rc<RefCell<qpack::Encoder>>) -> Res<Self> {
        encoder.borrow_mut().add_recv_stream(stream_id)?;
        Ok(Self { encoder })
    }
}

impl Stream for EncoderRecvStream {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::Encoder
    }
}

impl RecvStream for EncoderRecvStream {
    fn reset(&mut self, _close_type: CloseType) -> Res<()> {
        Err(Error::HttpClosedCriticalStream)
    }

    fn receive(&mut self, conn: &mut Connection, now: Instant) -> Res<(ReceiveOutput, bool)> {
        self.encoder.borrow_mut().receive(conn, now)?;
        Ok((ReceiveOutput::NoOutput, false))
    }
}
