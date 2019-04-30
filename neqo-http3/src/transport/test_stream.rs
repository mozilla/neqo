// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_variables, dead_code)]

use neqo_transport::connection::{Role, TxMode};
use neqo_transport::frame::StreamType;
use neqo_transport::{AppError, Res};
use neqo_transport::{Recvable, Sendable};
use std::collections::VecDeque;

impl Sendable for Stream {
    /// Enqueue some bytes to send
    fn send(&mut self, buf: &[u8]) -> Res<usize> {
        self.send_buf.extend(buf);
        Ok(buf.len())
    }

    fn reset(&mut self, err: AppError) {}

    fn send_data_ready(&self) -> bool {
        self.send_buf.len() > 0
    }

    fn close(&mut self) {
        self.send_side_closed = true;
    }
}

impl Recvable for Stream {
    fn data_ready(&self) -> bool {
        self.recv_buf.len() > 0
    }

    /// caller has been told data is available on a stream, and they want to
    /// retrieve it.
    fn read(&mut self, buf: &mut [u8]) -> Res<(u64, bool)> {
        let ret_bytes = std::cmp::min(buf.len(), self.recv_buf.len());
        let remaining = self.recv_buf.split_off(ret_bytes);
        buf[..ret_bytes].copy_from_slice(&*self.recv_buf);
        self.recv_buf = remaining;
        let mut fin = false;
        if self.receive_side_closed && self.recv_buf.len() == 0 {
            fin = true;
        }
        Ok((ret_bytes as u64, fin))
    }

    fn stop_sending(&mut self, err: AppError) {
        self.stop_sending_error = Some(err);
    }
}

#[derive(Debug)]
pub struct Stream {
    pub send_side_closed: bool,
    pub send_side_stop_sending: bool,
    pub receive_side_closed: bool,
    pub role: Role,
    pub stream_type: StreamType,
    send_buf_tmp: VecDeque<u8>,
    pub send_buf: Vec<u8>,
    pub recv_buf: Vec<u8>,
    pub stop_sending_error: Option<AppError>,
    pub error: Option<AppError>,
}

impl Stream {
    pub fn new(role: Role, st: StreamType) -> Stream {
        Stream {
            send_side_closed: false,
            send_side_stop_sending: false,
            receive_side_closed: false,
            role: role,
            stream_type: st,
            send_buf_tmp: VecDeque::new(),
            send_buf: Vec::new(),
            recv_buf: Vec::new(),
            stop_sending_error: None,
            error: None,
        }
    }

    pub fn receive_close(&mut self) {
        self.receive_side_closed = true;
    }

    pub fn reset(&mut self, err: AppError) {
        self.error = Some(err);
    }

    pub fn recv_data_ready_amount(&self) -> usize {
        self.recv_buf.len()
    }

    fn next_bytes(&mut self, mode: TxMode) -> Option<(u64, &[u8])> {
        let len = self.send_buf.len() as u64;
        if len > 0 {
            Some((len, &self.send_buf))
        } else {
            None
        }
    }

    fn final_size(&self) -> Option<u64> {
        None
    }
}
