use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::mem;
use std::rc::Rc;

use slice_deque::SliceDeque;

use crate::connection::{FlowMgr, TxMode};

use crate::{AppError, Error, Res};

const TX_STREAM_DATA_WINDOW: usize = 0xFFFF; // 64 KiB

pub trait Sendable: Debug {
    /// Enqueue data to send on the stream. Returns bytes enqueued.
    fn send(&mut self, buf: &[u8]) -> Res<usize>;

    /// If enqueueing some data with send will return nonzero.
    fn send_data_ready(&self) -> bool;

    /// Close the stream. Enqueued data will be sent.
    fn close(&mut self) {}

    /// Abandon transmission of in-flight and future stream data.
    fn reset(&mut self, err: AppError) -> Res<()>;
}

#[derive(Debug, Default, PartialEq)]
pub struct TxBuffer {
    acked_offset: u64,                  // contig acked bytes, no longer in buffer
    next_send_offset: u64,              // differentiates bytes buffered from bytes sent
    send_buf: SliceDeque<u8>,           // buffer of not-acked bytes
    acked_ranges: BTreeMap<u64, usize>, // non-contig ranges in buffer that have been acked
}

impl TxBuffer {
    pub fn new() -> TxBuffer {
        TxBuffer {
            send_buf: SliceDeque::with_capacity(TX_STREAM_DATA_WINDOW),
            ..TxBuffer::default()
        }
    }

    pub fn send(&mut self, buf: &[u8]) -> usize {
        let can_send = min(TX_STREAM_DATA_WINDOW - self.buffered(), buf.len());
        if can_send > 0 {
            self.send_buf.extend(&buf[..can_send]);
            assert!(self.send_buf.len() <= TX_STREAM_DATA_WINDOW);
        }
        can_send
    }

    pub fn next_bytes(&mut self, _mode: TxMode) -> Option<(u64, &[u8])> {
        let buffered_bytes_sent_not_acked = self.next_send_offset - self.acked_offset;
        let buffered_bytes_not_sent = self.send_buf.len() as u64 - buffered_bytes_sent_not_acked;

        if buffered_bytes_not_sent == 0 {
            None
        } else {
            // Present all bytes for sending, but frame generator may or may
            // not take all of them (how much indicated by calling
            // mark_as_sent())
            Some((
                self.acked_offset + buffered_bytes_sent_not_acked,
                &self.send_buf[buffered_bytes_sent_not_acked as usize..],
            ))
        }
    }

    pub fn next_retrans_bytes(&mut self, _mode: TxMode) -> Option<(u64, &[u8])> {
        unimplemented!();
    }

    pub fn mark_as_sent(&mut self, new_sent_offset: u64, len: usize) {
        assert!(new_sent_offset == self.next_send_offset);
        self.next_send_offset = new_sent_offset + len as u64;
    }

    pub fn mark_as_acked(&mut self, offset: u64, len: usize) {
        // TODO(agrover@mozilla.com): handle nontrivial ACK scenarios
        if self.acked_offset == offset {
            self.acked_offset += len as u64;
            let origlen = self.send_buf.len();
            assert!(origlen >= len);
            self.send_buf.truncate_front(origlen - len);
        }
    }

    // pub fn mark_as_ackedTODO(&mut self, offset: u64, len: usize) {
    //     let end_off = offset + len as u64;
    //     let (prev_sent_start, prev_len) = self
    //         .sent_ranges
    //         .range_mut(..offset + 1)
    //         .next_back()
    //         .expect("must exist");
    //     let prev_sent_end: u64 = prev_sent_start + *prev_len as u64;
    //     match prev_sent_end.cmp(&offset) {
    //         Ordering::Less => *prev_len = max(prev_sent_end as usize, end_off as usize),
    //         Ordering::Equal => {
    //             *prev_len = max(prev_sent_end as usize, end_off as usize);
    //         }
    //         Ordering::Greater => {
    //             panic!("should never happen, why are we sending out of order?");
    //         }
    //     }
    // }

    fn data_limit(&self) -> u64 {
        self.buffered() as u64 + self.acked_offset
    }

    fn sent_not_acked_bytes(&self) -> usize {
        self.next_send_offset as usize - self.acked_offset as usize
    }

    fn data_ready(&self) -> bool {
        self.send_buf.len() != self.sent_not_acked_bytes()
    }

    fn buffered(&self) -> usize {
        self.send_buf.len()
    }
}

#[derive(Debug, PartialEq)]
enum SendStreamState {
    Ready,
    Send(TxBuffer),
    DataSent(TxBuffer, u64),
    DataRecvd(u64),
    ResetSent,
    #[allow(dead_code)]
    ResetRecvd,
}

impl SendStreamState {
    fn tx_buf_mut(&mut self) -> Option<&mut TxBuffer> {
        match self {
            SendStreamState::Send(buf) => Some(buf),
            SendStreamState::DataSent(buf, _) => Some(buf),
            SendStreamState::Ready
            | SendStreamState::DataRecvd(_)
            | SendStreamState::ResetSent
            | SendStreamState::ResetRecvd => None,
        }
    }

    fn tx_buf(&self) -> Option<&TxBuffer> {
        match self {
            SendStreamState::Send(buf) => Some(buf),
            SendStreamState::DataSent(buf, _) => Some(buf),
            SendStreamState::Ready
            | SendStreamState::DataRecvd(_)
            | SendStreamState::ResetSent
            | SendStreamState::ResetRecvd => None,
        }
    }

    fn final_size(&self) -> Option<u64> {
        match self {
            SendStreamState::DataSent(_, size) => Some(*size),
            SendStreamState::DataRecvd(size) => Some(*size),
            SendStreamState::Ready
            | SendStreamState::Send(_)
            | SendStreamState::ResetSent
            | SendStreamState::ResetRecvd => None,
        }
    }

    fn name(&self) -> &str {
        match self {
            SendStreamState::Ready => "Ready",
            SendStreamState::Send(_) => "Send",
            SendStreamState::DataSent(_, _) => "DataSent",
            SendStreamState::DataRecvd(_) => "DataRecvd",
            SendStreamState::ResetSent => "ResetSent",
            SendStreamState::ResetRecvd => "ResetRecvd",
        }
    }

    fn transition(&mut self, new_state: SendStreamState) {
        qtrace!("SendStream state {} -> {}", self.name(), new_state.name());
        *self = new_state;
    }
}

#[derive(Debug)]
pub struct SendStream {
    max_stream_data: u64,
    state: SendStreamState,
    stream_id: u64,
    flow_mgr: Rc<RefCell<FlowMgr>>,
}

impl SendStream {
    pub fn new(stream_id: u64, max_stream_data: u64, flow_mgr: Rc<RefCell<FlowMgr>>) -> SendStream {
        SendStream {
            max_stream_data,
            state: SendStreamState::Ready,
            stream_id,
            flow_mgr,
        }
    }

    pub fn next_bytes(&mut self, mode: TxMode) -> Option<(u64, &[u8])> {
        self.state.tx_buf_mut().and_then(|buf| buf.next_bytes(mode))
    }

    pub fn mark_as_sent(&mut self, offset: u64, len: usize) {
        self.state
            .tx_buf_mut()
            .map(|buf| buf.mark_as_sent(offset, len));
    }

    pub fn mark_as_acked(&mut self, offset: u64, len: usize) {
        self.state
            .tx_buf_mut()
            .map(|buf| buf.mark_as_acked(offset, len));
    }

    pub fn final_size(&self) -> Option<u64> {
        self.state.final_size()
    }

    pub fn max_stream_data(&mut self, value: u64) {
        self.max_stream_data = max(self.max_stream_data, value)
    }

    #[allow(dead_code)]
    fn reset_acked(&mut self) {
        match self.state {
            SendStreamState::Ready
            | SendStreamState::Send(_)
            | SendStreamState::DataSent(_, _)
            | SendStreamState::DataRecvd(_) => {
                qtrace!("Reset acked while in {} state?", self.state.name())
            }
            SendStreamState::ResetSent => self.state.transition(SendStreamState::ResetRecvd),
            SendStreamState::ResetRecvd => qtrace!("already in ResetRecvd state"),
        };
    }
}

impl Sendable for SendStream {
    fn send(&mut self, buf: &[u8]) -> Res<usize> {
        //let flowc_space = self.max_stream_data;

        let (sent, data_limit) = match self.state {
            SendStreamState::Ready => {
                let mut tx_buf = TxBuffer::new();
                let sent = tx_buf.send(buf);
                let data_limit = tx_buf.data_limit();
                self.state.transition(SendStreamState::Send(tx_buf));
                (sent, data_limit)
            }
            SendStreamState::Send(ref mut tx_buf) => (tx_buf.send(buf), tx_buf.data_limit()),
            SendStreamState::DataSent(_, _) => return Err(Error::FinalSizeError),
            SendStreamState::DataRecvd(_) => return Err(Error::FinalSizeError),
            SendStreamState::ResetSent => return Err(Error::FinalSizeError),
            SendStreamState::ResetRecvd => return Err(Error::FinalSizeError),
        };

        // TODO(agrover@mozilla.com): tx buffer being full is not the same as
        // being out of stream flow credits.
        if sent != buf.len() {
            self.flow_mgr
                .borrow_mut()
                .stream_data_blocked(self.stream_id, data_limit)
        }

        Ok(sent)
    }

    fn send_data_ready(&self) -> bool {
        self.state
            .tx_buf()
            .map(|buf| buf.data_ready())
            .unwrap_or(false)
    }

    fn close(&mut self) {
        match self.state {
            SendStreamState::Ready => {
                self.state.transition(SendStreamState::DataRecvd(0));
            }
            SendStreamState::Send(ref mut tx_buf) => {
                let final_size = tx_buf.acked_offset + tx_buf.buffered() as u64;
                let owned_buf = mem::replace(tx_buf, TxBuffer::new());
                self.state
                    .transition(SendStreamState::DataSent(owned_buf, final_size));
            }
            SendStreamState::DataSent(_, _) => qtrace!("already in DataSent state"),
            SendStreamState::DataRecvd(_) => qtrace!("already in DataRecvd state"),
            SendStreamState::ResetSent => qtrace!("already in ResetSent state"),
            SendStreamState::ResetRecvd => qtrace!("already in ResetRecvd state"),
        }
    }

    fn reset(&mut self, _err: AppError) -> Res<()> {
        match self.state {
            SendStreamState::Ready | SendStreamState::Send(_) | SendStreamState::DataSent(_, _) => {
                // TODO(agrover@mozilla.com): send RESET_STREAM
                self.state.transition(SendStreamState::ResetSent);
            }
            SendStreamState::DataRecvd(_) => qtrace!("already in DataRecvd state"),
            SendStreamState::ResetSent => qtrace!("already in ResetSent state"),
            SendStreamState::ResetRecvd => qtrace!("already in ResetRecvd state"),
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_tx() {
        let flow_mgr = Rc::new(RefCell::new(FlowMgr::default()));
        let mut s = SendStream::new(4, 1024, flow_mgr.clone());

        let res = s.send(&vec![4; 100]).unwrap();
        assert_eq!(res, 100);
        s.mark_as_sent(0, 50);
        assert_eq!(s.state.tx_buf().unwrap().data_limit(), 100);

        // Should cause send() to indicate data blocked
        let res = s.send(&vec![4; TX_STREAM_DATA_WINDOW]).unwrap();
        assert_eq!(res, TX_STREAM_DATA_WINDOW - 100);
        assert!(flow_mgr.borrow_mut().next().is_some());

        s.mark_as_acked(0, 40);
    }

    #[test]
    fn test_tx_buffer_acks() {
        let mut tx = TxBuffer::new();
        assert_eq!(tx.send(&vec![4; 100]), 100);
        let res = tx.next_bytes(TxMode::Normal).unwrap();
        assert_eq!(res.0, 0);
        assert_eq!(res.1.len(), 100);
        tx.mark_as_sent(0, 100);
        let res = tx.next_bytes(TxMode::Normal);
        assert_eq!(res, None);

        tx.mark_as_acked(0, 100);
        let res = tx.next_bytes(TxMode::Normal);
        assert_eq!(res, None);
    }

}
