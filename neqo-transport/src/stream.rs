use crate::connection::TxMode;
use crate::Res;
use std::cmp::{max, min};
use std::collections::{BTreeMap, LinkedList, VecDeque};
use std::fmt::Debug;

use crate::frame::Frame;
use crate::Error;
use crate::Res;

const RX_STREAM_DATA_WINDOW: u64 = 0xFFFF; // 64 KiB

#[allow(dead_code)]
enum PostStreamAction {
    Ok,
    EndConnection,
    SendFrame(Frame),
}

pub trait Recvable: Debug {
    /// Read buffered data from stream. bool says whether is final data on
    /// stream.
    fn read(&mut self, buf: &mut [u8]) -> Res<(u64, bool)>;

    /// The number of bytes that can be read from the stream.
    fn recv_data_ready(&self) -> u64;

    /// Handle a received stream data frame.
    fn inbound_stream_frame(&mut self, fin: bool, offset: u64, data: Vec<u8>) -> Res<()>;

    fn needs_flowc_update(&mut self) -> Option<u64>;
}

pub trait Sendable: Debug {
    /// Send data on the stream.
    fn send(&mut self, buf: &[u8]);

    /// Number of bytes that is queued for sending.
    fn send_data_ready(&self) -> u64;

    /// Access the bytes that are ready to be sent.
    fn send_buffer(&mut self) -> &mut VecDeque<u8>;
}

#[derive(Debug, PartialEq)]
enum TxChunkState {
    Unsent,
    Sent(u64),
    Lost,
}

#[derive(Debug)]
struct TxChunk {
    offset: u64,
    data: Vec<u8>,
    state: TxChunkState,
}

#[derive(Default, Debug)]
pub struct TxBuffer {
    offset: u64,
    chunks: LinkedList<TxChunk>,
}

impl TxBuffer {
    pub fn send(&mut self, buf: &[u8]) {
        self.chunks.push_back(TxChunk {
            offset: self.offset,
            data: Vec::from(buf),
            state: TxChunkState::Unsent,
        })
    }

    fn find_first_chunk_by_state(&self, state: TxChunkState) -> Option<&TxChunk> {
        for c in &self.chunks {
            if c.state == state {
                return Some(c);
            }
        }
        None
    }

    pub fn next_bytes(&self, _mode: TxMode, l: usize) -> Option<(u64, &[u8])> {
        // TODO(ekr@rtfm.com): Send a slice that fits in |l|.
        // First try to find some unsent stuff.
        if let Some(c) = self.find_first_chunk_by_state(TxChunkState::Unsent) {
            Some((c.offset, &c.data))
        }
        // How about some lost stuff.
        else if let Some(c) = self.find_first_chunk_by_state(TxChunkState::Lost) {
            Some((c.offset, &c.data))
        } else {
            None
        }
    }

    fn sent_bytes(&mut self, now: u64, offset: usize, l: usize) -> Res<()> {
        unimplemented!();
    }

    fn lost_bytes(&mut self, now: u64, offset: usize, l: usize) -> Res<()> {
        unimplemented!();
    }

    fn acked_bytes(&mut self, now: u64, offset: usize, l: usize) -> Res<()> {
        unimplemented!();
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct RxStreamOrderer {
    rx_offset: u64,                          // bytes already received and ready
    ooo_data: BTreeMap<(u64, u64), Vec<u8>>, // ((start_offset, end_offset), data)
    ready_to_go: VecDeque<u8>,
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
    pub fn inbound_frame(&mut self, offset: u64, data: Vec<u8>) -> Res<()> {
        // TODO(agrover@mozilla.com): limit ooo data, and possibly cull
        // duplicate ranges
        self.ooo_data
            .insert((offset, offset + data.len() as u64), data);

        let orig_rx_offset = self.rx_offset;

        // See if maybe we have some contig data now
        for ((start_offset, end_offset), data) in &self.ooo_data {
            if self.rx_offset >= *end_offset {
                // Already got all these bytes, do nothing
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
            .take_while(|(_, end)| self.rx_offset >= *end)
            .cloned()
            .collect::<Vec<_>>();
        for key in to_remove {
            self.ooo_data.remove(&key);
        }

        // Tell client we got some new in-order data for them
        let new_bytes_available = self.rx_offset - orig_rx_offset;
        if new_bytes_available != 0 {
            // poke somebody?
        }

        Ok(())
    }

    pub fn data_ready(&self) -> u64 {
        self.ready_to_go.len() as u64
    }

    pub fn rx_offset(&self) -> u64 {
        self.rx_offset
    }

    /// Caller has been told data is available on a stream, and they want to
    /// retrieve it.
    /// Returns bytes copied and if this was final bytes.
    pub fn read(&mut self, buf: &mut [u8]) -> Res<u64> {
        let ret_bytes = min(self.ready_to_go.len(), buf.len());

        let remaining = self.ready_to_go.split_off(ret_bytes);

        let (slc1, slc2) = self.ready_to_go.as_slices();
        let slc1_len = slc1.len();
        let slc2_len = ret_bytes - slc1_len;
        buf[..slc1.len()].copy_from_slice(slc1);
        buf[slc1_len..slc1_len + slc2_len].copy_from_slice(slc2);
        self.ready_to_go = remaining;

        Ok(ret_bytes as u64)
    }

    pub fn highest_seen_offset(&self) -> u64 {
        let maybe_ooo_last = self.ooo_data.keys().next_back().map(|(_, end)| *end);
        maybe_ooo_last.unwrap_or(self.rx_offset)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct BidiStream {
    tx: SendStream,
    rx: RecvStream,
}

impl BidiStream {
    pub fn new() -> BidiStream {
        BidiStream {
            tx: SendStream::new(),
            rx: RecvStream::new(),
        }
    }
}

impl Recvable for BidiStream {
    fn read(&mut self, buf: &mut [u8]) -> Res<(u64, bool)> {
        self.rx.read(buf)
    }

    fn recv_data_ready(&self) -> u64 {
        self.rx.recv_data_ready()
    }

    fn inbound_stream_frame(&mut self, fin: bool, offset: u64, data: Vec<u8>) -> Res<()> {
        self.rx.inbound_stream_frame(fin, offset, data)
    }

    fn needs_flowc_update(&mut self) -> Option<u64> {
        self.rx.needs_flowc_update()
    }
}

impl Sendable for BidiStream {
    fn send(&mut self, buf: &[u8]) {
        self.tx.send(buf)
    }

    fn send_data_ready(&self) -> u64 {
        self.tx.send_data_ready()
    }

    fn send_buffer(&mut self) -> &mut VecDeque<u8> {
        self.tx.send_buffer()
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct SendStream {
    next_tx_offset: u64, // how many bytes have been enqueued for this stream
    tx_queue: VecDeque<u8>,
    bytes_acked: u64,
}

impl SendStream {
    pub fn new() -> SendStream {
        SendStream {
            next_tx_offset: 0,
            tx_queue: VecDeque::new(),
            bytes_acked: 0,
        }
    }
}

impl Sendable for SendStream {
    /// Enqueue some bytes to send
    fn send(&mut self, buf: &[u8]) {
        self.tx_queue.extend(buf)
    }

    fn send_data_ready(&self) -> u64 {
        self.tx_queue.len() as u64
    }

    fn send_buffer(&mut self) -> &mut VecDeque<u8> {
        &mut self.tx_queue
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct RecvStream {
    final_size: Option<u64>,
    rx_done: u64,
    rx_window: u64,
    rx_orderer: RxStreamOrderer,
}

impl RecvStream {
    pub fn new() -> RecvStream {
        RecvStream {
            final_size: None,
            rx_done: 0,
            rx_window: RX_STREAM_DATA_WINDOW,
            rx_orderer: RxStreamOrderer::new(),
        }
    }
}

impl Recvable for RecvStream {
    fn recv_data_ready(&self) -> u64 {
        self.rx_orderer.data_ready()
    }

    /// caller has been told data is available on a stream, and they want to
    /// retrieve it.
    fn read(&mut self, buf: &mut [u8]) -> Res<(u64, bool)> {
        let read_bytes = self.rx_orderer.read(buf)?;
        self.rx_done += read_bytes;

        let fin = if let Some(final_size) = self.final_size {
            if dbg!(final_size) == dbg!(self.rx_done) {
                true
            } else {
                false
            }
        } else {
            false
        };

        Ok((read_bytes, fin))
    }

    fn inbound_stream_frame(&mut self, fin: bool, offset: u64, data: Vec<u8>) -> Res<()> {
        if let Some(final_size) = self.final_size {
            if offset + data.len() as u64 > final_size
                || (fin && offset + data.len() as u64 != final_size)
            {
                return Err(Error::ErrFinalSizeError);
            }
        }

        if fin && self.final_size == None {
            let final_size = offset + data.len() as u64;
            if final_size < self.rx_orderer.highest_seen_offset() {
                return Err(Error::ErrFinalSizeError);
            }
            self.final_size = Some(offset + data.len() as u64);
        }

        self.rx_orderer.inbound_frame(offset, data)
    }

    /// If we should tell the sender they have more credit, return an offset
    fn needs_flowc_update(&mut self) -> Option<u64> {
        let lowater = RX_STREAM_DATA_WINDOW / 2;
        let new_window = self.rx_done + RX_STREAM_DATA_WINDOW;
        if self.final_size.is_none() && new_window > lowater + self.rx_window {
            self.rx_window = new_window;
            Some(new_window)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    // #[test]
    fn test_stream_rx() {
        let frame1 = vec![0; 10];
        let frame2 = vec![0; 12];
        let frame3 = vec![0; 8];
        let frame4 = vec![0; 6];
        let frame5 = vec![0; 10];
        let frame6 = vec![0; 18];

        let mut s = BidiStream::new();

        // test receiving a contig frame and reading it works
        s.inbound_stream_frame(false, 0, frame1).unwrap();
        assert_eq!(s.recv_data_ready(), 10);
        let mut buf = vec![0u8; 100];
        assert_eq!(s.read(&mut buf).unwrap(), (10, false));
        assert_eq!(s.rx.rx_orderer.rx_offset(), 10);
        assert_eq!(s.rx.rx_orderer.ready_to_go.len(), 0);

        // test receiving a noncontig frame
        s.inbound_stream_frame(false, 12, frame2).unwrap();
        assert_eq!(s.recv_data_ready(), 0);
        assert_eq!(s.read(&mut buf).unwrap(), (0, false));

        // another frame that overlaps the first
        s.inbound_stream_frame(false, 14, frame3).unwrap();
        assert_eq!(s.recv_data_ready(), 0);

        // fill in the with a FIN
        s.inbound_stream_frame(true, 10, frame4).unwrap_err();
        assert_eq!(s.recv_data_ready(), 0);
        assert_eq!(s.read(&mut buf).unwrap(), (0, false));

        // fill in the gap
        s.inbound_stream_frame(false, 10, frame5).unwrap();
        dbg!(s.rx.rx_orderer.rx_offset());

        // a legit FIN
        s.inbound_stream_frame(true, 24, frame6).unwrap();
        assert_eq!(s.recv_data_ready(), 32);
        assert_eq!(s.read(&mut buf).unwrap(), (32, true));
        assert_eq!(s.read(&mut buf).unwrap(), (0, true));
    }

    #[test]
    fn test_stream_flowc_update() {
        let frame1 = vec![0; RX_STREAM_DATA_WINDOW as usize];

        let mut s = BidiStream::new();

        let mut buf = vec![0u8; RX_STREAM_DATA_WINDOW as usize * 4]; // Make it overlarge

        assert_eq!(s.needs_flowc_update(), None);
        s.inbound_stream_frame(false, 0, frame1).unwrap();
        assert_eq!(s.needs_flowc_update(), None);
        assert_eq!(s.read(&mut buf).unwrap(), (RX_STREAM_DATA_WINDOW, false));
        assert_eq!(s.recv_data_ready(), 0);
        assert_eq!(s.needs_flowc_update(), Some(RX_STREAM_DATA_WINDOW * 2));
        assert_eq!(s.needs_flowc_update(), None);
    }
}
