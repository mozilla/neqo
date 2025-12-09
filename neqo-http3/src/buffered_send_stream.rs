// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Instant;

use neqo_common::Encoder;
use neqo_transport::{Connection, StreamId};

use crate::{qlog, Res};

#[derive(Debug, PartialEq, Eq, Default)]
pub enum BufferedStream {
    #[default]
    Uninitialized,
    Initialized {
        stream_id: StreamId,
        buf: Vec<u8>,
    },
}

impl BufferedStream {
    #[must_use]
    pub const fn new(stream_id: StreamId) -> Self {
        Self::Initialized {
            stream_id,
            buf: Vec::new(),
        }
    }

    /// # Panics
    ///
    /// If the `BufferedStream` is initialized more than once, it will panic.
    pub fn init(&mut self, stream_id: StreamId) {
        debug_assert!(&Self::Uninitialized == self);
        *self = Self::Initialized {
            stream_id,
            buf: Vec::new(),
        };
    }

    pub fn encode_with<F: FnOnce(&mut Encoder<&mut Vec<u8>>)>(&mut self, f: F) {
        if let Self::Initialized { buf, .. } = self {
            f(&mut Encoder::new_borrowed_vec(buf));
        } else {
            debug_assert!(false, "Do not encode data before the stream is initialized");
        }
    }

    /// # Panics
    ///
    /// This function cannot be called before the `BufferedStream` is initialized.
    pub fn buffer(&mut self, to_buf: &[u8]) {
        if let Self::Initialized { buf, .. } = self {
            buf.extend_from_slice(to_buf);
        } else {
            debug_assert!(false, "Do not buffer data before the stream is initialized");
        }
    }

    /// # Errors
    ///
    /// Returns `neqo_transport` errors.
    pub fn send_buffer(&mut self, conn: &mut Connection, now: Instant) -> Res<usize> {
        let Self::Initialized { stream_id, buf } = self else {
            return Ok(0);
        };
        if buf.is_empty() {
            return Ok(0);
        }
        let sent = conn.stream_send(*stream_id, &buf[..])?;
        if sent == 0 {
            return Ok(0);
        } else if sent == buf.len() {
            buf.clear();
        } else {
            let b = buf.split_off(sent);
            *buf = b;
        }
        qlog::h3_data_moved_down(conn.qlog_mut(), *stream_id, sent, now);
        Ok(sent)
    }

    /// Flush the buffer and return the stream ID and buffer if ready to send atomically.
    fn prepare_atomic_send(
        &mut self,
        conn: &mut Connection,
        now: Instant,
    ) -> Res<Option<(StreamId, &mut Vec<u8>)>> {
        self.send_buffer(conn, now)?;
        let Self::Initialized { stream_id, buf } = self else {
            return Ok(None);
        };
        if !buf.is_empty() {
            return Ok(None);
        }
        Ok(Some((*stream_id, buf)))
    }

    /// # Errors
    ///
    /// Returns `neqo_transport` errors.
    pub fn send_atomic(
        &mut self,
        conn: &mut Connection,
        to_send: &[u8],
        now: Instant,
    ) -> Res<bool> {
        let Some((stream_id, _)) = self.prepare_atomic_send(conn, now)? else {
            return Ok(false);
        };
        let sent = conn.stream_send_atomic(stream_id, to_send)?;
        if sent {
            qlog::h3_data_moved_down(conn.qlog_mut(), stream_id, to_send.len(), now);
        }
        Ok(sent)
    }

    /// Encode data using the provided closure and send it atomically.
    ///
    /// This avoids allocating a temporary encoder at the call site by reusing
    /// the stream's internal buffer as scratch space.
    ///
    /// # Errors
    ///
    /// Returns `neqo_transport` errors.
    pub fn send_atomic_with<F: FnOnce(&mut Encoder<&mut Vec<u8>>)>(
        &mut self,
        conn: &mut Connection,
        f: F,
        now: Instant,
    ) -> Res<bool> {
        let Some((stream_id, buf)) = self.prepare_atomic_send(conn, now)? else {
            return Ok(false);
        };
        f(&mut Encoder::new_borrowed_vec(buf));
        let len = buf.len();
        let res = conn.stream_send_atomic(stream_id, buf);
        buf.clear();
        let sent = res?;
        if sent {
            qlog::h3_data_moved_down(conn.qlog_mut(), stream_id, len, now);
        }
        Ok(sent)
    }

    #[must_use]
    pub const fn has_buffered_data(&self) -> bool {
        if let Self::Initialized { buf, .. } = self {
            !buf.is_empty()
        } else {
            false
        }
    }
}

impl From<&BufferedStream> for Option<StreamId> {
    fn from(stream: &BufferedStream) -> Self {
        if let BufferedStream::Initialized { stream_id, .. } = stream {
            Some(*stream_id)
        } else {
            None
        }
    }
}
