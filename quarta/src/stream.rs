use crate::data::Data;

#[derive(Debug, Default, PartialEq)]
pub struct Stream {
    // TX
    next_tx_offset: u64, // how many bytes have been enqueued for this stream

    // RX
    rx_offset: u64,             // bytes already received and pushed up
    ooo_data: Vec<(u64, Data)>, // (offset, data)
    final_offset: u64,
}

// TODO, this is a tx/rx stream for now
impl Stream {
    pub fn new() -> Stream {
        Stream::default()
    }

    // TX
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
}
