// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::qinfo;
use neqo_common::readbuf::Reader;

#[cfg(test)]
use crate::transport::Connection;

#[cfg(not(test))]
use neqo_transport::Connection;

// A simple wrapper that wraps a Recvable so that it can be used with ReadBuf.
#[derive(Debug)]
pub struct RecvableWrapper<'a>(&'a mut Connection, u64);

impl<'a> RecvableWrapper<'a> {
    pub fn wrap(conn: &'a mut Connection, stream_id: u64) -> RecvableWrapper<'a> {
        RecvableWrapper(conn, stream_id)
    }
}

impl<'a> Reader for RecvableWrapper<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), ::neqo_common::Error> {
        match self.0.stream_recv(self.1, buf) {
            Ok((amount, end)) => Ok((amount as usize, end)),
            Err(e) => {
                qinfo!("Read error {}", e); // TODO(mt): provide context.
                Err(::neqo_common::Error::ReadError)
            }
        }
    }
}
