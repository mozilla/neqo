use std::cmp::{max, min};
use std::collections::{BTreeMap, VecDeque};

use crate::Res;

pub trait RxStream {
    fn read(&mut self, buf: &mut [u8]) -> Res<u64>;
    fn rx_data_ready(&self) -> bool;
    fn inbound_stream_frame(&mut self, fin: bool, offset: u64, data: Vec<u8>) -> Res<u64>;
}

pub trait TxStream {
    fn send(&mut self, buf: &[u8]);
    fn tx_data_ready(&self) -> bool;
    fn tx_buffer(&mut self) -> &mut VecDeque<u8>;
}

#[derive(Debug, Default, PartialEq)]
pub struct RxStreamOrderer {
    rx_offset: u64,                          // bytes already received and ready
    ooo_data: BTreeMap<(u64, u64), Vec<u8>>, // ((start_offset, end_offset), data)
    ready_to_go: VecDeque<u8>,
    data_ready: bool,
}

impl RxStreamOrderer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an incoming stream frame off the wire. This may result in more
    /// data being available to upper layers (if frame is not out of order
    /// (ooo) or if the frame fills a gap.
    /// Returns bytes that are now retired, since this is relevant for flow
    /// control.
    pub fn inbound_frame(&mut self, offset: u64, data: Vec<u8>) -> Res<u64> {
        self.ooo_data
            .insert((offset, offset + data.len() as u64), data);

        let orig_rx_offset = self.rx_offset;

        // See if maybe we have some contig data now
        for ((start_offset, end_offset), data) in &self.ooo_data {
            if self.rx_offset >= *end_offset {
                // Slready got all these bytes, do nothing
            } else if self.rx_offset > *start_offset {
                // Frame data has some new contig bytes after some old bytes

                // Convert to offset into data vec and move past bytes we
                // already have
                let copy_offset = max(*start_offset, self.rx_offset) - start_offset;
                let copy_slc = &data[copy_offset as usize..];
                self.ready_to_go.extend(copy_slc);
                self.rx_offset += copy_slc.len() as u64;
            } else if self.rx_offset == *start_offset {
                // In-order, woot
                self.ready_to_go.extend(data);
                self.rx_offset += data.len() as u64;
            } else {
                // self.rx_offset < start_offset
                // Start offset later than rx offset, we have a gap. Since
                // BTreeMap is ordered no other ooo frames will fill the gap.
                break;
            }
        }

        // Remove map items that are consumed
        let to_remove = self
            .ooo_data
            .keys()
            .filter(|(_, end)| self.rx_offset >= *end)
            .cloned()
            .collect::<Vec<_>>();
        for key in to_remove {
            self.ooo_data.remove(&key);
        }

        // Tell client we got some new in-order data for them
        let new_bytes_available = self.rx_offset - orig_rx_offset;
        if new_bytes_available != 0 {
            self.data_ready = true;
        }

        Ok(new_bytes_available)
    }

    pub fn data_ready(&self) -> bool {
        self.data_ready
    }

    /// Caller has been told data is available on a stream, and they want to
    /// retrieve it.
    pub fn read(&mut self, buf: &mut [u8]) -> Res<u64> {
        let ret_bytes = min(self.ready_to_go.len(), buf.len());

        let remaining = self.ready_to_go.split_off(ret_bytes);

        let (slc1, slc2) = self.ready_to_go.as_slices();
        let slc1_len = slc1.len();
        let slc2_len = ret_bytes - slc1_len;
        buf[..slc1.len()].copy_from_slice(slc1);
        buf[slc1_len..slc1_len + slc2_len].copy_from_slice(slc2);
        self.ready_to_go = remaining;

        if self.ready_to_go.len() == 0 {
            self.data_ready = false
        }

        Ok(ret_bytes as u64)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct BidiStream {
    // TX
    next_tx_offset: u64, // how many bytes have been enqueued for this stream
    tx_queue: VecDeque<u8>,
    bytes_acked: u64,

    // RX
    final_offset: Option<u64>,
    rx: RxStreamOrderer,
}

impl BidiStream {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TxStream for BidiStream {
    /// Enqueue some bytes to send
    fn send(&mut self, buf: &[u8]) {
        self.tx_queue.extend(buf)
    }

    fn tx_data_ready(&self) -> bool {
        self.tx_queue.len() != 0
    }

    fn tx_buffer(&mut self) -> &mut VecDeque<u8> {
        &mut self.tx_queue
    }
}

impl RxStream for BidiStream {
    fn rx_data_ready(&self) -> bool {
        self.rx.data_ready()
    }

    /// caller has been told data is available on a stream, and they want to
    /// retrieve it.
    fn read(&mut self, buf: &mut [u8]) -> Res<u64> {
        self.rx.read(buf)
    }

    fn inbound_stream_frame(&mut self, fin: bool, offset: u64, data: Vec<u8>) -> Res<u64> {
        if fin {
            // TODO(agrover@mozilla.com): handle fin better
            self.final_offset = Some(offset + data.len() as u64)
        }

        self.rx.inbound_frame(offset, data)
    }
}

mod test {

    use super::*;

    #[test]
    fn test_stream_rx() {
        let frame1 = vec![0; 10];
        let frame2 = vec![0; 12];
        let frame3 = vec![0; 8];
        let frame4 = vec![0; 6];

        let mut s = BidiStream::new();

        // test receiving a contig frame and reading it works
        s.inbound_stream_frame(false, 0, frame1).unwrap();
        assert_eq!(s.rx_data_ready(), true);
        let mut buf = vec![0u8; 100];
        assert_eq!(s.read(&mut buf).unwrap(), 10);
        assert_eq!(s.rx.rx_offset, 10);
        assert_eq!(s.rx.ready_to_go.len(), 0);

        // test receiving a noncontig frame
        s.inbound_stream_frame(false, 12, frame2).unwrap();
        assert_eq!(s.rx_data_ready(), false);
        assert_eq!(s.read(&mut buf).unwrap(), 0);

        // another frame that overlaps the first
        s.inbound_stream_frame(false, 14, frame3).unwrap();
        assert_eq!(s.rx_data_ready(), false);

        // fill in the gap
        s.inbound_stream_frame(false, 10, frame4).unwrap();
        assert_eq!(s.rx_data_ready(), true);
        assert_eq!(s.read(&mut buf).unwrap(), 14);
    }
}
