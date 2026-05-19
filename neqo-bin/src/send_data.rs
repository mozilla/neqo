// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{borrow::Cow, cmp::min};

use crate::STREAM_IO_BUFFER_SIZE;

#[derive(Debug, Default)]
pub struct SendData {
    data: Cow<'static, [u8]>,
    offset: usize,
    remaining: usize,
    total: usize,
}

impl From<&[u8]> for SendData {
    fn from(data: &[u8]) -> Self {
        Self::from(data.to_vec())
    }
}

impl From<Vec<u8>> for SendData {
    fn from(data: Vec<u8>) -> Self {
        let remaining = data.len();
        Self {
            total: data.len(),
            data: Cow::Owned(data),
            offset: 0,
            remaining,
        }
    }
}

impl From<&str> for SendData {
    fn from(data: &str) -> Self {
        Self::from(data.as_bytes())
    }
}

impl SendData {
    pub const fn zeroes(total: usize) -> Self {
        const MESSAGE: &[u8] = &[0; STREAM_IO_BUFFER_SIZE];
        Self {
            data: Cow::Borrowed(MESSAGE),
            offset: 0,
            remaining: total,
            total,
        }
    }

    fn slice(&self) -> &[u8] {
        let end = min(self.data.len(), self.offset + self.remaining);
        &self.data[self.offset..end]
    }

    /// Send data using a fallible send function, handling stream closure gracefully.
    /// Returns `SendResult::Done` if all data was sent, `SendResult::MoreData` if
    /// more data remains, or `SendResult::StreamClosed` if the stream was closed
    /// (e.g., by `STOP_SENDING`).
    pub fn send<F, E>(&mut self, mut f: F) -> SendResult
    where
        F: FnMut(&[u8]) -> Result<usize, E>,
    {
        while self.remaining > 0 {
            match f(self.slice()) {
                Err(_) => return SendResult::StreamClosed,
                Ok(0) => return SendResult::MoreData,
                Ok(sent) => {
                    self.remaining -= sent;
                    self.offset = (self.offset + sent) % self.data.len();
                }
            }
        }
        SendResult::Done
    }

    pub const fn len(&self) -> usize {
        self.total
    }
}

/// Result of a graceful send operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    /// All data was sent successfully.
    Done,
    /// More data remains to be sent (stream buffer full).
    MoreData,
    /// Stream was closed by peer (e.g., `STOP_SENDING` received).
    StreamClosed,
}
