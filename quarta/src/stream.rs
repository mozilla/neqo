use std::cmp::max;
use std::collections::VecDeque;

use crate::data::Data;
use crate::Res;

#[derive(Debug, Default, PartialEq)]
pub struct Stream {
    // TX
    next_tx_offset: u64, // how many bytes have been enqueued for this stream
    tx_queue: VecDeque<u8>,
    bytes_retired: u64,

    // RX
    rx_offset: u64,             // bytes already received and pushed up
    ooo_data: Vec<(u64, Data)>, // (offset, data)
    final_offset: u64,
    ready_to_go: VecDeque<u8>,
}

// TODO, this is a tx/rx stream for now
impl Stream {
    pub fn new() -> Stream {
        Stream::default()
    }

    // TX

    /// Enqueue some bytes to send
    pub fn send(&mut self, buf: &[u8]) {
        self.tx_queue.extend(buf)
    }

    pub fn next_tx_offset(&self) -> u64 {
        self.next_tx_offset
    }

    pub fn add_to_tx_offset(&mut self, add_to_offset: u64) {
        self.next_tx_offset += add_to_offset
    }

    // RX
    pub fn next_rx_offset(&self) -> u64 {
        self.rx_offset
    }

    /// caller has been told data is available on a stream, and they want to
    /// retrieve it.
    pub fn get_received_data(&mut self, buf: &mut [u8]) -> Res<u64> {
        let ret_bytes = max(self.ready_to_go.len(), buf.len());

        let remaining = self.ready_to_go.split_off(ret_bytes);

        let (slc1, slc2) = self.ready_to_go.as_slices();
        buf.copy_from_slice(slc1);
        buf.copy_from_slice(slc2);
        self.ready_to_go = remaining;

        Ok(ret_bytes as u64)
    }

    pub fn data_ready(&mut self, buf: &[u8]) {
        self.ready_to_go.extend(buf);
    }
}
