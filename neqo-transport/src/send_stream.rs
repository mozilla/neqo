// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::mem;
use std::rc::Rc;

use neqo_common::{qtrace, qwarn};
use slice_deque::SliceDeque;

use crate::connection::{ConnectionEvents, FlowMgr, StreamId, TxMode};

use crate::{AppError, Error, Res};

const TX_STREAM_BUFFER: usize = 0xFFFF; // 64 KiB

pub trait Sendable: Debug {
    /// Enqueue data to send on the stream. Returns bytes enqueued.
    fn send(&mut self, buf: &[u8]) -> Res<usize>;

    /// If attempting to enqueue some data with send() will return nonzero.
    fn send_data_ready(&self) -> bool;

    /// Close the stream. Enqueued data will be sent.
    fn close(&mut self);

    /// Abandon transmission of in-flight and future stream data.
    fn reset(&mut self, err: AppError);
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum RangeState {
    Sent,
    Acked,
}

/// Track ranges in the stream as sent or acked. Acked implies sent. Not in a
/// range implies needing-to-be-sent, either initially or as a retransmission.
#[derive(Debug, Default, PartialEq)]
struct RangeTracker {
    // offset, (len, RangeState). Use u64 for len because ranges can exceed 32bits.
    used: BTreeMap<u64, (u64, RangeState)>,
}

impl RangeTracker {
    fn highest_offset(&self) -> u64 {
        self.used
            .range(..)
            .next_back()
            .map(|(k, (v, _))| *k + *v)
            .unwrap_or(0)
    }

    fn acked_from_zero(&self) -> u64 {
        self.used
            .get(&0)
            .filter(|(_, state)| *state == RangeState::Acked)
            .map(|(v, _)| *v)
            .unwrap_or(0)
    }

    /// Find the first unmarked range. If all are contiguous, this will return
    /// (highest_offset(), None).
    fn first_unmarked_range(&self) -> (u64, Option<u64>) {
        let mut prev_end = 0;

        for (cur_off, (cur_len, _)) in &self.used {
            if prev_end == *cur_off {
                prev_end = cur_off + cur_len;
            } else {
                return (prev_end, Some(cur_off - prev_end));
            }
        }
        (prev_end, None)
    }

    /// Turn one range into a list of subranges that align with existing
    /// ranges.
    /// Check impermissible overlaps in subregions: Sent cannot overwrite Acked.
    //
    // e.g. given N is new and ABC are existing:
    //             NNNNNNNNNNNNNNNN
    //               AAAAA   BBBCCCCC  ...then we want 5 chunks:
    //             1122222333444555
    //
    // but also if we have this:
    //             NNNNNNNNNNNNNNNN
    //           AAAAAAAAAA      BBBB  ...then break existing A and B ranges up:
    //
    //             1111111122222233
    //           aaAAAAAAAA      BBbb
    //
    // Doing all this work up front should make handling each chunk much
    // easier.
    fn chunk_range_on_edges(
        &mut self,
        new_off: u64,
        new_len: u64,
        new_state: RangeState,
    ) -> Vec<(u64, u64, RangeState)> {
        let mut tmp_off = new_off;
        let mut tmp_len = new_len;
        let mut v = Vec::new();

        // cut previous overlapping range if needed
        let prev = self.used.range_mut(..tmp_off).next_back();
        if let Some((prev_off, (prev_len, prev_state))) = prev {
            let prev_state = *prev_state;
            let overlap = (*prev_off + *prev_len).saturating_sub(new_off);
            *prev_len -= overlap;
            if overlap > 0 {
                self.used.insert(new_off, (overlap, prev_state));
            }
        }

        let mut last_existing_remaining = None;
        for (off, (len, state)) in self.used.range(tmp_off..tmp_off + tmp_len) {
            // Create chunk for "overhang" before an existing range
            if tmp_off < *off {
                let sub_len = off - tmp_off;
                v.push((tmp_off, sub_len, new_state));
                tmp_off += sub_len;
                tmp_len -= sub_len;
            }

            // Create chunk to match existing range
            let sub_len = min(*len, tmp_len);
            let remaining_len = len - sub_len;
            if new_state == RangeState::Sent && *state == RangeState::Acked {
                qwarn!(
                    "Attempted to downgrade overlapping range Acked range {}-{} with Sent {}-{}",
                    off,
                    len,
                    new_off,
                    new_len
                );
            } else {
                v.push((tmp_off, sub_len, new_state));
            }
            tmp_off += sub_len;
            tmp_len -= sub_len;

            if remaining_len > 0 {
                last_existing_remaining = Some((*off, sub_len, remaining_len, *state));
            }
        }

        // Maybe break last existing range in two so that a final chunk will
        // have the same length as an existing range entry
        if let Some((off, sub_len, remaining_len, state)) = last_existing_remaining {
            *self.used.get_mut(&off).expect("must be there") = (sub_len, state);
            self.used.insert(off + sub_len, (remaining_len, state));
        }

        // Create final chunk if anything remains of the new range
        if tmp_len > 0 {
            v.push((tmp_off, tmp_len, new_state))
        }

        v
    }

    /// Merge contiguous Acked ranges into the first entry (0). This range may
    /// be dropped from the send buffer.
    fn coalesce_acked_from_zero(&mut self) {
        let acked_range_from_zero = self
            .used
            .get_mut(&0)
            .filter(|(_, state)| *state == RangeState::Acked)
            .map(|(len, _)| *len);

        if let Some(len_from_zero) = acked_range_from_zero {
            let mut to_remove = Vec::new();

            let mut new_len_from_zero = len_from_zero;

            // See if there's another Acked range entry contiguous to this one
            while let Some((next_len, _)) = self
                .used
                .get(&new_len_from_zero)
                .filter(|(_, state)| *state == RangeState::Acked)
            {
                to_remove.push(new_len_from_zero);
                new_len_from_zero += *next_len;
            }

            if len_from_zero != new_len_from_zero {
                self.used.get_mut(&0).expect("must be there").0 = new_len_from_zero;
            }

            for val in to_remove {
                self.used.remove(&val);
            }
        }
    }

    fn mark_range(&mut self, off: u64, len: usize, state: RangeState) {
        let subranges = self.chunk_range_on_edges(off, len as u64, state);

        for (sub_off, sub_len, sub_state) in subranges {
            self.used.insert(sub_off, (sub_len, sub_state));
        }

        self.coalesce_acked_from_zero()
    }

    fn unmark_range(&mut self, off: u64, len: usize) {
        let len = len as u64;
        let end_off = off + len;

        let mut to_remove = Vec::new();
        let mut to_add = None;

        // Walk backwards through possibly affected existing ranges
        for (cur_off, (cur_len, cur_state)) in self.used.range_mut(..off + len).rev() {
            // Maybe fixup range preceding the removed range
            if *cur_off < off {
                // Check for overlap
                if *cur_off + *cur_len > off {
                    if *cur_state == RangeState::Acked {
                        qwarn!(
                            "Attempted to unmark Acked range {}-{} with unmark_range {}-{}",
                            cur_off,
                            cur_len,
                            off,
                            len
                        );
                    } else {
                        *cur_len = off - cur_off;
                    }
                }
                break;
            }

            if *cur_state == RangeState::Acked {
                qwarn!(
                    "Attempted to unmark Acked range {}-{} with unmark_range {}-{}",
                    cur_off,
                    cur_len,
                    off,
                    len
                );
                continue;
            }

            // Add a new range for old subrange extending beyond
            // to-be-unmarked range
            let cur_end_off = cur_off + *cur_len;
            if cur_end_off > end_off {
                let new_cur_off = off + len;
                let new_cur_len = cur_end_off - end_off;
                assert_eq!(to_add, None);
                to_add = Some((new_cur_off, new_cur_len, *cur_state));
            }

            to_remove.push(*cur_off);
        }

        for remove_off in to_remove {
            self.used.remove(&remove_off);
        }

        if let Some((new_cur_off, new_cur_len, cur_state)) = to_add {
            self.used.insert(new_cur_off, (new_cur_len, cur_state));
        }
    }
}

/// Buffer to contain queued bytes and track their state.
#[derive(Debug, Default, PartialEq)]
pub struct TxBuffer {
    retired: u64,             // contig acked bytes, no longer in buffer
    send_buf: SliceDeque<u8>, // buffer of not-acked bytes
    ranges: RangeTracker,     // ranges in buffer that have been sent or acked
}

impl TxBuffer {
    pub fn new() -> TxBuffer {
        TxBuffer {
            send_buf: SliceDeque::with_capacity(TX_STREAM_BUFFER),
            ..TxBuffer::default()
        }
    }

    /// Attempt to add some or all of the passed-in buffer to the TxBuffer.
    pub fn send(&mut self, buf: &[u8]) -> usize {
        let can_buffer = min(TX_STREAM_BUFFER - self.buffered(), buf.len());
        if can_buffer > 0 {
            self.send_buf.extend(&buf[..can_buffer]);
            assert!(self.send_buf.len() <= TX_STREAM_BUFFER);
        }
        can_buffer
    }

    pub fn next_bytes(&mut self, _mode: TxMode) -> Option<(u64, &[u8])> {
        let (start, maybe_len) = self.ranges.first_unmarked_range();

        if start == self.retired + self.buffered() as u64 {
            return None;
        }

        let buff_off = (start - self.retired) as usize;
        match maybe_len {
            Some(len) => Some((start, &self.send_buf[buff_off..buff_off + len as usize])),
            None => Some((start, &self.send_buf[buff_off..])),
        }
    }

    pub fn mark_as_sent(&mut self, offset: u64, len: usize) {
        self.ranges.mark_range(offset, len, RangeState::Sent)
    }

    pub fn mark_as_acked(&mut self, offset: u64, len: usize) {
        assert!(self.ranges.highest_offset() >= offset + len as u64);

        self.ranges.mark_range(offset, len, RangeState::Acked);

        // We can drop contig acked range from the buffer
        let new_retirable = self.ranges.acked_from_zero() - self.retired;
        if new_retirable > 0 {
            let keep_len = self.buffered() - new_retirable as usize;
            self.send_buf.truncate_front(keep_len);
            self.retired += new_retirable;
        }
    }

    pub fn mark_as_lost(&mut self, offset: u64, len: usize) {
        assert!(self.ranges.highest_offset() > offset + len as u64);
        assert!(offset >= self.retired);

        // Make eligible for sending again
        self.ranges.unmark_range(offset, len)
    }

    fn data_limit(&self) -> u64 {
        self.buffered() as u64 + self.retired
    }

    fn data_ready(&self) -> bool {
        self.ranges.first_unmarked_range().0 != self.retired + self.buffered() as u64
    }

    fn buffered(&self) -> usize {
        self.send_buf.len()
    }

    fn highest_sent(&self) -> u64 {
        self.ranges.highest_offset()
    }
}

/// QUIC sending stream states, based on -transport 3.1.
#[derive(Debug, PartialEq)]
enum SendStreamState {
    Ready,
    Send { send_buf: TxBuffer },
    DataSent { send_buf: TxBuffer, final_size: u64 },
    DataRecvd { final_size: u64 },
    ResetSent,
    ResetRecvd,
}

impl SendStreamState {
    fn tx_buf(&self) -> Option<&TxBuffer> {
        match self {
            SendStreamState::Send { send_buf } => Some(send_buf),
            SendStreamState::DataSent { send_buf, .. } => Some(send_buf),
            SendStreamState::Ready
            | SendStreamState::DataRecvd { .. }
            | SendStreamState::ResetSent
            | SendStreamState::ResetRecvd => None,
        }
    }

    fn tx_buf_mut(&mut self) -> Option<&mut TxBuffer> {
        match self {
            SendStreamState::Send { send_buf } => Some(send_buf),
            SendStreamState::DataSent { send_buf, .. } => Some(send_buf),
            SendStreamState::Ready
            | SendStreamState::DataRecvd { .. }
            | SendStreamState::ResetSent
            | SendStreamState::ResetRecvd => None,
        }
    }

    fn final_size(&self) -> Option<u64> {
        match self {
            SendStreamState::DataSent { final_size, .. } => Some(*final_size),
            SendStreamState::DataRecvd { final_size } => Some(*final_size),
            SendStreamState::Ready
            | SendStreamState::Send { .. }
            | SendStreamState::ResetSent
            | SendStreamState::ResetRecvd => None,
        }
    }

    fn name(&self) -> &str {
        match self {
            SendStreamState::Ready => "Ready",
            SendStreamState::Send { .. } => "Send",
            SendStreamState::DataSent { .. } => "DataSent",
            SendStreamState::DataRecvd { .. } => "DataRecvd",
            SendStreamState::ResetSent => "ResetSent",
            SendStreamState::ResetRecvd => "ResetRecvd",
        }
    }

    fn transition(&mut self, new_state: SendStreamState) {
        qtrace!("SendStream state {} -> {}", self.name(), new_state.name());
        *self = new_state;
    }
}

/// Implement a QUIC send stream.
#[derive(Debug)]
pub struct SendStream {
    stream_id: StreamId,
    max_stream_data: u64,
    state: SendStreamState,
    flow_mgr: Rc<RefCell<FlowMgr>>,
    conn_events: Rc<RefCell<ConnectionEvents>>,
}

impl SendStream {
    pub fn new(
        stream_id: StreamId,
        max_stream_data: u64,
        flow_mgr: Rc<RefCell<FlowMgr>>,
        conn_events: Rc<RefCell<ConnectionEvents>>,
    ) -> SendStream {
        if max_stream_data > 0 {
            conn_events.borrow_mut().send_stream_writable(stream_id);
        }
        SendStream {
            stream_id,
            max_stream_data,
            state: SendStreamState::Ready,
            flow_mgr,
            conn_events,
        }
    }

    /// Return the next range to be sent, if any.
    pub fn next_bytes(&mut self, mode: TxMode) -> Option<(u64, &[u8])> {
        let stream_credit_avail = self.credit_avail();
        let conn_credit_avail = self.flow_mgr.borrow().conn_credit_avail();
        let credit_avail = min(stream_credit_avail, conn_credit_avail);
        if let Some(tx_buf) = self.state.tx_buf_mut() {
            qtrace!(
                "next_bytes max_stream_data {}, data_limit {}, credit_avail {}",
                self.max_stream_data,
                tx_buf.data_limit(),
                credit_avail
            );
            if let Some((offset, data)) = tx_buf.next_bytes(mode) {
                // Restrict slice of data offered for sending by remaining
                // flow control credits
                let data = &data[..min(credit_avail as usize, data.len())];
                qtrace!("next_bytes after flowc: {} {}", offset, data.len());

                if data.len() == 0 {
                    // We had some bytes to send but were blocked by flow
                    // control.
                    assert!(stream_credit_avail == 0 || conn_credit_avail == 0);
                    if stream_credit_avail == 0 {
                        self.flow_mgr
                            .borrow_mut()
                            .stream_data_blocked(self.stream_id, self.max_stream_data);
                    }
                    if conn_credit_avail == 0 {
                        self.flow_mgr.borrow_mut().data_blocked();
                    }
                    return None;
                } else {
                    return Some((offset, data));
                }
            }
        }

        None
    }

    pub fn mark_as_sent(&mut self, offset: u64, len: usize) {
        self.state
            .tx_buf_mut()
            .map(|buf| buf.mark_as_sent(offset, len));
        self.flow_mgr
            .borrow_mut()
            .conn_increase_credit_used(len as u64);
    }

    pub fn mark_as_acked(&mut self, offset: u64, len: usize) {
        match self.state {
            SendStreamState::Send { ref mut send_buf } => {
                send_buf.mark_as_acked(offset, len);
                if send_buf.buffered() < TX_STREAM_BUFFER {
                    self.conn_events
                        .borrow_mut()
                        .send_stream_writable(self.stream_id)
                }
            }
            SendStreamState::DataSent {
                ref mut send_buf,
                final_size,
            } => {
                send_buf.mark_as_acked(offset, len);
                if send_buf.buffered() == 0 {
                    self.conn_events
                        .borrow_mut()
                        .send_stream_complete(self.stream_id);
                    self.state.transition(SendStreamState::DataRecvd {
                        final_size: final_size,
                    });
                }
            }
            _ => qtrace!("mark_as_acked called from state {}", self.state.name()),
        }
    }

    pub fn mark_as_lost(&mut self, offset: u64, len: usize) {
        self.state
            .tx_buf_mut()
            .map(|buf| buf.mark_as_lost(offset, len));
    }

    pub fn final_size(&self) -> Option<u64> {
        self.state.final_size()
    }

    pub fn credit_avail(&self) -> u64 {
        if let Some(tx_buf) = self.state.tx_buf() {
            self.max_stream_data - tx_buf.data_limit()
        } else {
            0
        }
    }

    pub fn max_stream_data(&self) -> u64 {
        self.max_stream_data
    }

    pub fn set_max_stream_data(&mut self, value: u64) {
        self.max_stream_data = max(self.max_stream_data, value)
    }

    pub fn reset_acked(&mut self) {
        match self.state {
            SendStreamState::Ready
            | SendStreamState::Send { .. }
            | SendStreamState::DataSent { .. }
            | SendStreamState::DataRecvd { .. } => {
                qtrace!("Reset acked while in {} state?", self.state.name())
            }
            SendStreamState::ResetSent => self.state.transition(SendStreamState::ResetRecvd),
            SendStreamState::ResetRecvd => qtrace!("already in ResetRecvd state"),
        };
    }

    pub fn is_terminal(&self) -> bool {
        match self.state {
            SendStreamState::DataRecvd { .. } | SendStreamState::ResetRecvd => true,
            _ => false,
        }
    }
}

impl Sendable for SendStream {
    fn send(&mut self, buf: &[u8]) -> Res<usize> {
        let sent = match self.state {
            SendStreamState::Ready => {
                let mut send_buf = TxBuffer::new();
                let sent = send_buf.send(buf);
                self.state.transition(SendStreamState::Send { send_buf });
                sent
            }
            SendStreamState::Send { ref mut send_buf } => send_buf.send(buf),
            SendStreamState::DataSent { .. } => return Err(Error::FinalSizeError),
            SendStreamState::DataRecvd { .. } => return Err(Error::FinalSizeError),
            SendStreamState::ResetSent => return Err(Error::FinalSizeError),
            SendStreamState::ResetRecvd => return Err(Error::FinalSizeError),
        };

        Ok(sent)
    }

    fn send_data_ready(&self) -> bool {
        match self.state {
            SendStreamState::Ready => true,
            SendStreamState::Send { ref send_buf } => send_buf.data_ready(),
            _ => false,
        }
    }

    fn close(&mut self) {
        match self.state {
            SendStreamState::Ready => {
                self.state
                    .transition(SendStreamState::DataRecvd { final_size: 0 });
            }
            SendStreamState::Send { ref mut send_buf } => {
                let final_size = send_buf.retired + send_buf.buffered() as u64;
                let owned_buf = mem::replace(send_buf, TxBuffer::new());
                self.state.transition(SendStreamState::DataSent {
                    send_buf: owned_buf,
                    final_size,
                });
            }
            SendStreamState::DataSent { .. } => qtrace!("already in DataSent state"),
            SendStreamState::DataRecvd { .. } => qtrace!("already in DataRecvd state"),
            SendStreamState::ResetSent => qtrace!("already in ResetSent state"),
            SendStreamState::ResetRecvd => qtrace!("already in ResetRecvd state"),
        }
    }

    fn reset(&mut self, err: AppError) {
        match &self.state {
            SendStreamState::Ready => {
                self.flow_mgr
                    .borrow_mut()
                    .stream_reset(self.stream_id, err, 0);

                self.state.transition(SendStreamState::ResetSent);
            }
            SendStreamState::Send { send_buf } => {
                self.flow_mgr.borrow_mut().stream_reset(
                    self.stream_id,
                    err,
                    send_buf.highest_sent(),
                );

                self.state.transition(SendStreamState::ResetSent);
            }
            SendStreamState::DataSent { final_size, .. } => {
                self.flow_mgr
                    .borrow_mut()
                    .stream_reset(self.stream_id, err, *final_size);

                self.state.transition(SendStreamState::ResetSent);
            }
            SendStreamState::DataRecvd { .. } => qtrace!("already in DataRecvd state"),
            SendStreamState::ResetSent => qtrace!("already in ResetSent state"),
            SendStreamState::ResetRecvd => qtrace!("already in ResetRecvd state"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mark_range() {
        let mut rt = RangeTracker::default();

        // ranges can go from nothing->Sent if queued for retrans and then
        // acks arrive
        rt.mark_range(5, 5, RangeState::Acked);
        assert_eq!(rt.highest_offset(), 10);
        assert_eq!(rt.acked_from_zero(), 0);
        rt.mark_range(10, 4, RangeState::Acked);
        assert_eq!(rt.highest_offset(), 14);
        assert_eq!(rt.acked_from_zero(), 0);

        rt.mark_range(0, 5, RangeState::Sent);
        assert_eq!(rt.highest_offset(), 14);
        assert_eq!(rt.acked_from_zero(), 0);
        rt.mark_range(0, 5, RangeState::Acked);
        assert_eq!(rt.highest_offset(), 14);
        assert_eq!(rt.acked_from_zero(), 14);

        rt.mark_range(12, 20, RangeState::Acked);
        assert_eq!(rt.highest_offset(), 32);
        assert_eq!(rt.acked_from_zero(), 32);

        // ack the lot
        rt.mark_range(0, 400, RangeState::Acked);
        assert_eq!(rt.highest_offset(), 400);
        assert_eq!(rt.acked_from_zero(), 400);

        // acked trumps sent
        rt.mark_range(0, 200, RangeState::Sent);
        assert_eq!(rt.highest_offset(), 400);
        assert_eq!(rt.acked_from_zero(), 400);
    }

    #[test]
    fn test_unmark_range() {
        let mut rt = RangeTracker::default();

        rt.mark_range(5, 5, RangeState::Acked);
        rt.mark_range(10, 5, RangeState::Sent);

        // Should unmark sent but not acked range
        rt.unmark_range(7, 6);

        let res = rt.first_unmarked_range();
        assert_eq!(res, (0, Some(5)));
        rt.mark_range(0, 5, RangeState::Sent);

        let res = rt.first_unmarked_range();
        assert_eq!(res, (10, Some(3)));
        rt.mark_range(10, 3, RangeState::Sent);

        let res = rt.first_unmarked_range();
        assert_eq!(res, (15, None));
    }

    #[test]
    fn test_stream_tx() {
        let flow_mgr = Rc::new(RefCell::new(FlowMgr::default()));
        flow_mgr.borrow_mut().conn_increase_max_credit(4096);
        let conn_events = Rc::new(RefCell::new(ConnectionEvents::default()));

        let mut s = SendStream::new(4.into(), 1024, flow_mgr.clone(), conn_events.clone());

        let res = s.send(&vec![4; 100]).unwrap();
        assert_eq!(res, 100);
        s.mark_as_sent(0, 50);
        assert_eq!(s.state.tx_buf().unwrap().data_limit(), 100);

        // Should fill up send buffer
        let res = s.send(&vec![4; TX_STREAM_BUFFER]).unwrap();
        assert_eq!(res, TX_STREAM_BUFFER - 100);

        // TODO(agrover@mozilla.com): test flow control somehow
        // TODO(agrover@mozilla.com): test ooo acks somehow
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
