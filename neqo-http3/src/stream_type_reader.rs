// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use crate::{AppError, Http3StreamType, HttpRecvStream, ReceiveOutput, RecvStream, Res, ResetType};
use neqo_common::{qdebug, Decoder, IncrementalDecoderUint};
use neqo_transport::Connection;

#[derive(Debug)]
pub(crate) struct NewStreamTypeReader {
    stream_id: u64,
    reader: IncrementalDecoderUint,
    fin: bool,
}

impl NewStreamTypeReader {
    pub fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            reader: IncrementalDecoderUint::default(),
            fin: false,
        }
    }
    pub fn get_type(&mut self, conn: &mut Connection, stream_id: u64) -> Option<u64> {
        // On any error we will only close this stream!
        loop {
            let to_read = self.reader.min_remaining();
            let mut buf = vec![0; to_read];
            match conn.stream_recv(stream_id, &mut buf[..]) {
                Ok((_, true)) => {
                    self.fin = true;
                    return None;
                }
                Ok((0, false)) => {
                    return None;
                }
                Ok((amount, false)) => {
                    let res = self.reader.consume(&mut Decoder::from(&buf[..amount]));
                    if res.is_some() {
                        return res;
                    }
                }
                Err(e) => {
                    qdebug!(
                        [conn],
                        "Error reading stream type for stream {}: {:?}",
                        stream_id,
                        e
                    );
                    self.fin = true;
                    return None;
                }
            }
        }
    }

    pub fn fin(&self) -> bool {
        self.fin
    }
}

impl RecvStream for NewStreamTypeReader {
    fn stream_reset(&self, _error: AppError, _reset_type: ResetType) -> Res<()> {
        Ok(())
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<ReceiveOutput> {
        let stream_type = self.get_type(conn, self.stream_id);
        if let Some(t) = stream_type {
            Ok(ReceiveOutput::NewStream(t))
        } else {
            Ok(ReceiveOutput::NoOutput)
        }
    }

    fn done(&self) -> bool {
        self.fin
    }

    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::NewStream
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        None
    }
}
