// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::Res;
use neqo_common::qtrace;
use neqo_transport::{Connection, StreamId};

#[derive(Debug, PartialEq)]
pub enum BufferedStream {
    Uninitialized,
    Initialized { stream_id: StreamId, buf: Vec<u8> },
}

impl Default for BufferedStream {
    fn default() -> Self {
        Self::Uninitialized
    }
}

impl ::std::fmt::Display for BufferedStream {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "BufferedStream {:?}", self.stream_id())
    }
}

impl BufferedStream {
    #[must_use]
    pub fn new(stream_id: StreamId) -> Self {
        Self::Initialized {
            stream_id,
            buf: Vec::new(),
        }
    }

    /// # Panics
    /// If the `BufferedStream` is initialized more than one it will panic.
    pub fn init(&mut self, stream_id: StreamId) {
        match self {
            Self::Initialized { .. } => panic!("Adding multiple streams"),
            Self::Uninitialized => {
                *self = Self::Initialized {
                    stream_id,
                    buf: Vec::new(),
                };
            }
        }
    }

    /// # Panics
    /// This functon cannot be called before the `BufferedStream` is initialized.
    pub fn buffer(&mut self, to_buf: &[u8]) {
        match self {
            Self::Uninitialized => panic!("Do not buffer date before the stream is initialized"),
            Self::Initialized { buf, .. } => buf.extend_from_slice(to_buf),
        }
    }

    /// # Errors
    /// Returns `neqo_transport` errors.
    pub fn send_buffer(&mut self, conn: &mut Connection) -> Res<usize> {
        let label = ::neqo_common::log_subject!(::log::Level::Debug, self);
        let mut sent = 0;
        if let Self::Initialized { stream_id, buf } = self {
            if !buf.is_empty() {
                qtrace!([label], "sending data.");
                sent = conn.stream_send(stream_id.as_u64(), &buf[..])?;
                if sent == buf.len() {
                    buf.clear();
                } else {
                    let b = buf.split_off(sent);
                    *buf = b;
                }
            }
        }
        Ok(sent)
    }

    /// # Errors
    /// Returns `neqo_transport` errors.
    pub fn send_atomic(&mut self, conn: &mut Connection, to_send: &[u8]) -> Res<bool> {
        // First try to send anything that is in the buffer.
        self.send_buffer(conn)?;
        match &self {
            Self::Uninitialized => Ok(false),
            Self::Initialized { stream_id, buf } => {
                if buf.is_empty() {
                    let res = conn.stream_send_atomic(stream_id.as_u64(), to_send)?;
                    Ok(res)
                } else {
                    Ok(false)
                }
            }
        }
    }

    #[must_use]
    pub fn stream_id(&self) -> Option<u64> {
        match self {
            Self::Uninitialized => None,
            Self::Initialized { stream_id, .. } => Some(stream_id.as_u64()),
        }
    }
}
