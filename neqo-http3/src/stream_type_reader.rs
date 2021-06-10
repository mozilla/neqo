// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use neqo_common::{qdebug, Decoder, IncrementalDecoderUint};
use neqo_transport::Connection;
use std::collections::HashMap;

#[derive(Debug)]
pub(crate) struct NewStreamTypeReader {
    reader: IncrementalDecoderUint,
    fin: bool,
}

impl NewStreamTypeReader {
    pub fn new() -> Self {
        Self {
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

#[derive(Debug, Default)]
pub struct NewStreamsDecoder {
    streams: HashMap<u64, NewStreamTypeReader>,
}

impl NewStreamsDecoder {
    /// Returns true if a new stream has been decoded.
    pub fn handle_new_stream(&mut self, conn: &mut Connection, stream_id: u64) -> Option<u64> {
        let stream_type;
        let fin;
        {
            let ns = self
                .streams
                .entry(stream_id)
                .or_insert_with(NewStreamTypeReader::new);
            stream_type = ns.get_type(conn, stream_id);
            fin = ns.fin();
        }

        if fin || stream_type.is_some() {
            self.streams.remove(&stream_id);
        }
        if fin {
            None
        } else {
            stream_type
        }
    }

    pub fn is_new_stream(&self, stream_id: u64) -> bool {
        self.streams.contains_key(&stream_id)
    }

    pub fn clear(&mut self) {
        self.streams.clear();
    }
}
