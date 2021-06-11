// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use crate::{AppError, Http3StreamType, HttpRecvStream, ReceiveOutput, RecvStream, Res, ResetType};
use neqo_common::{Decoder, IncrementalDecoderUint};
use neqo_transport::Connection;

#[derive(Debug, PartialEq)]
pub enum NewStreamTypeReader {
    Read {
        reader: IncrementalDecoderUint,
        stream_id: u64,
    },
    Done,
}

impl NewStreamTypeReader {
    pub fn new(stream_id: u64) -> Self {
        Self::Read {
            reader: IncrementalDecoderUint::default(),
            stream_id,
        }
    }

    pub fn get_type(&mut self, conn: &mut Connection) -> Option<Http3StreamType> {
        // On any error we will only close this stream!
        loop {
            match self {
                NewStreamTypeReader::Read {
                    ref mut reader,
                    stream_id,
                } => {
                    let to_read = reader.min_remaining();
                    let mut buf = vec![0; to_read];
                    match conn.stream_recv(*stream_id, &mut buf[..]) {
                        Ok((0, false)) => {
                            return None;
                        }
                        Ok((amount, false)) => {
                            if let Some(res) = reader.consume(&mut Decoder::from(&buf[..amount])) {
                                *self = NewStreamTypeReader::Done;
                                return Some(res.into());
                            }
                        }
                        Ok((_, true)) | Err(_) => {
                            *self = NewStreamTypeReader::Done;
                            return None;
                        }
                    }
                }
                NewStreamTypeReader::Done => return None,
            }
        }
    }
}

impl RecvStream for NewStreamTypeReader {
    fn stream_reset(&self, _error: AppError, _reset_type: ResetType) -> Res<()> {
        Ok(())
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<ReceiveOutput> {
        Ok(self
            .get_type(conn)
            .map_or(ReceiveOutput::NoOutput, |t| ReceiveOutput::NewStream(t)))
    }

    fn done(&self) -> bool {
        *self == NewStreamTypeReader::Done
    }

    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::NewStream
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        None
    }
}
