use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::fmt::Debug;

use crate::{AppError, Error, Res};

const RX_STREAM_DATA_WINDOW: u64 = 0xFFFF; // 64 KiB

pub trait Recvable: Debug {
    /// Read buffered data from stream. bool says whether is final data on
    /// stream.
    fn read(&mut self, buf: &mut [u8]) -> Res<(u64, bool)>;

    /// Read with defined amount.
    fn read_with_amount(&mut self, buf: &mut [u8], amount: u64) -> Res<(u64, bool)>;

    /// Application is no longer interested in this stream.
    fn stop_sending(&mut self, err: AppError);

    /// Close the stream.
    fn close(&mut self);

    /// Bytes can be read from the stream.
    fn data_ready(&self) -> bool;
}

#[derive(Debug, Default, PartialEq)]
pub struct RxStreamOrderer {
    data_ranges: BTreeMap<u64, Vec<u8>>, // (start_offset, data)
    retired: u64,                        // Number of bytes the application has read
}

impl RxStreamOrderer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an incoming stream frame off the wire. This may result in data
    /// being available to upper layers if frame is not out of order (ooo) or
    /// if the frame fills a gap.
    pub fn inbound_frame(&mut self, new_start: u64, mut new_data: Vec<u8>) -> Res<()> {
        qtrace!("Inbound data offset={} len={}", new_start, new_data.len());

        // Get entry before where new entry would go, so we can see if we already
        // have the new bytes.
        // Avoid copies and duplicated data.
        let new_end = new_start + new_data.len() as u64;

        if new_end <= self.retired {
            // Range already read by application, this frame is very late and unneeded.
            return Ok(());
        }

        let (insert_new, remove_prev) = if let Some((&prev_start, prev_vec)) =
            self.data_ranges.range_mut(..new_start + 1).next_back()
        {
            let prev_end = prev_start + prev_vec.len() as u64;
            match (new_start > prev_start, new_end > prev_end) {
                (true, true) => {
                    // PPPPPP    ->  PP
                    //   NNNNNN        NNNNNN
                    // Truncate prev if overlap. Insert new.
                    // (In-order frames will take this path, with no overlap)
                    let overlap = prev_end.saturating_sub(new_start);
                    if overlap != 0 {
                        let truncate_to = new_data.len() - overlap as usize;
                        prev_vec.truncate(truncate_to)
                    }
                    qtrace!(
                        "New frame {}-{} received, overlap: {}",
                        new_start,
                        new_end,
                        overlap
                    );
                    (true, None)
                }
                (true, false) => {
                    // PPPPPP    ->  PPPPPP
                    //   NNNN
                    // Do nothing
                    qtrace!(
                        "Dropping frame with already-received range {}-{}",
                        new_start,
                        new_end
                    );
                    (false, None)
                }
                (false, true) => {
                    // PPPP      ->  NNNNNN
                    // NNNNNN
                    // Drop Prev, Insert New
                    qtrace!(
                        "New frame with {}-{} replaces existing {}-{}",
                        new_start,
                        new_end,
                        prev_start,
                        prev_end
                    );
                    (true, Some(prev_start))
                }
                (false, false) => {
                    // PPPPPP    ->  PPPPPP
                    // NNNN
                    // Do nothing
                    qtrace!(
                        "Dropping frame with already-received range {}-{}",
                        new_start,
                        new_end
                    );
                    (false, None)
                }
            }
        } else {
            qtrace!("New frame {}-{} received", new_start, new_end);
            (true, None) // Nothing previous
        };

        if let Some(remove_prev) = &remove_prev {
            self.data_ranges.remove(remove_prev);
        }

        if insert_new {
            // Now handle possible overlap with next entries
            let mut to_remove = Vec::new(); // TODO(agrover@mozilla.com): use smallvec?
            for (&next_start, next_data) in self.data_ranges.range_mut(new_start..) {
                let next_end = next_start + next_data.len() as u64;
                let overlap = new_end.saturating_sub(next_start);
                if overlap == 0 {
                    break;
                } else {
                    if next_end > new_end {
                        let truncate_to = new_data.len() - overlap as usize;
                        new_data.truncate(truncate_to);
                        qtrace!(
                            "New frame {}-{} overlaps with next frame by {}, truncating",
                            new_start,
                            new_end,
                            overlap
                        );
                        break;
                    } else {
                        qtrace!(
                            "New frame {}-{} spans entire next frame {}-{}, replacing",
                            new_start,
                            new_end,
                            next_start,
                            next_end
                        );
                        to_remove.push(next_start);
                    }
                }
            }

            for start in to_remove {
                self.data_ranges.remove(&start);
            }

            self.data_ranges.insert(new_start, new_data);
        };

        Ok(())
    }

    /// Are any bytes readable?
    pub fn data_ready(&self) -> bool {
        self.data_ranges
            .keys()
            .next()
            .map(|&start| start <= self.retired)
            .unwrap_or(false)
    }

    /// how many bytes are readable?
    fn bytes_ready(&self) -> usize {
        let mut prev_end = self.retired;
        self.data_ranges
            .iter()
            .map(|(start_offset, data)| {
                // All ranges don't overlap but we could have partially
                // retired some of the first entry's data.
                let data_len = data.len() as u64 - self.retired.saturating_sub(*start_offset);
                (start_offset, data_len)
            })
            .take_while(|(start_offset, data_len)| {
                if **start_offset <= prev_end {
                    prev_end += data_len;
                    true
                } else {
                    false
                }
            })
            .map(|(_, data_len)| data_len as usize)
            .sum()
    }

    /// Bytes read by the application.
    pub fn retired(&self) -> u64 {
        self.retired
    }

    /// Data bytes buffered. Could be more than bytes_readable if there are
    /// ranges missing.
    pub fn buffered(&self) -> u64 {
        self.data_ranges
            .iter()
            .map(|(&start, data)| data.len() as u64 - (self.retired.saturating_sub(start)))
            .sum()
    }

    /// Caller has been told data is available on a stream, and they want to
    /// retrieve it.
    /// Returns bytes copied.
    pub fn read(&mut self, buf: &mut [u8]) -> Res<u64> {
        self.read_with_amount(buf, buf.len() as u64)
    }

    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Res<u64> {
        let orig_len = buf.len();
        buf.resize(orig_len + self.bytes_ready(), 0);
        self.read(&mut buf[orig_len..])
    }

    /// Caller has been told data is available on a stream, and they want to
    /// retrieve it.
    fn read_with_amount(&mut self, buf: &mut [u8], amount: u64) -> Res<u64> {
        assert!(buf.len() >= amount as usize);
        qtrace!("Reading {} bytes, {} available", amount, self.buffered());
        let mut buf_remaining = amount as usize;
        let mut copied = 0;

        for (&range_start, range_data) in &mut self.data_ranges {
            if self.retired >= range_start {
                // Frame data has some new contig bytes after some old bytes

                // Convert to offset into data vec and move past bytes we
                // already have
                let copy_offset = (max(range_start, self.retired) - range_start) as usize;
                let copy_bytes = min(range_data.len() - copy_offset as usize, buf_remaining);
                let copy_slc = &mut range_data[copy_offset as usize..copy_offset + copy_bytes];
                buf[copied..copied + copy_bytes].copy_from_slice(copy_slc);
                copied += copy_bytes;
                buf_remaining -= copy_bytes;
                self.retired += copy_bytes as u64;
            } else {
                break; // we're missing bytes
            }
        }

        // Remove map items that are consumed
        let to_remove = self
            .data_ranges
            .iter()
            .take_while(|(start, data)| self.retired >= *start + data.len() as u64)
            .map(|(k, _)| *k)
            .collect::<Vec<_>>();
        for key in to_remove {
            self.data_ranges.remove(&key);
        }

        Ok(copied as u64)
    }

    pub fn highest_seen_offset(&self) -> u64 {
        let maybe_ooo_last = self
            .data_ranges
            .iter()
            .next_back()
            .map(|(start, data)| *start + data.len() as u64);
        maybe_ooo_last.unwrap_or(self.retired)
    }
}

#[derive(Debug, PartialEq)]
enum RecvStreamState {
    Open {
        rx_window: u64,
        rx_orderer: RxStreamOrderer,
    },
    Closed,
}

impl RecvStreamState {
    fn new() -> RecvStreamState {
        RecvStreamState::Open {
            rx_window: RX_STREAM_DATA_WINDOW,
            rx_orderer: RxStreamOrderer::new(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct RecvStream {
    final_size: Option<u64>,
    state: RecvStreamState,
}

impl RecvStream {
    pub fn new() -> RecvStream {
        RecvStream {
            final_size: None,
            state: RecvStreamState::new(),
        }
    }

    #[cfg(test)]
    pub fn orderer(&self) -> Option<&RxStreamOrderer> {
        match &self.state {
            RecvStreamState::Open {
                rx_window: _,
                rx_orderer,
            } => Some(&rx_orderer),
            RecvStreamState::Closed => None,
        }
    }

    pub fn inbound_stream_frame(&mut self, fin: bool, offset: u64, data: Vec<u8>) -> Res<()> {
        let new_end = offset + data.len() as u64;

        // Send final size errors even if stream is closed
        if let Some(final_size) = self.final_size {
            if new_end > final_size || (fin && new_end != final_size) {
                return Err(Error::FinalSizeError);
            }
        }

        match &mut self.state {
            RecvStreamState::Closed => {
                Err(Error::TooMuchData) // send STOP_SENDING
            }
            RecvStreamState::Open {
                rx_window,
                rx_orderer,
            } => {
                if fin && self.final_size == None {
                    let final_size = offset + data.len() as u64;
                    if final_size < rx_orderer.highest_seen_offset() {
                        return Err(Error::FinalSizeError);
                    }
                    self.final_size = Some(offset + data.len() as u64);
                }

                if new_end > *rx_window {
                    qtrace!("Stream RX window {} exceeded: {}", rx_window, new_end);
                    return Err(Error::FlowControlError);
                }

                rx_orderer.inbound_frame(offset, data)
            }
        }
    }

    /// If we should tell the sender they have more credit, return an offset
    pub fn needs_flowc_update(&mut self) -> Option<u64> {
        match &mut self.state {
            RecvStreamState::Closed => None,
            RecvStreamState::Open {
                rx_window,
                rx_orderer,
            } => {
                let lowater = RX_STREAM_DATA_WINDOW / 2;
                let new_window = rx_orderer.retired() + RX_STREAM_DATA_WINDOW;
                if self.final_size.is_none() && new_window > lowater + *rx_window {
                    *rx_window = new_window;
                    Some(new_window)
                } else {
                    None
                }
            }
        }
    }

    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }
}

impl Recvable for RecvStream {
    fn data_ready(&self) -> bool {
        match &self.state {
            RecvStreamState::Open {
                rx_window: _,
                rx_orderer,
            } => rx_orderer.data_ready(),
            RecvStreamState::Closed => false,
        }
    }

    /// caller has been told data is available on a stream, and they want to
    /// retrieve it.
    fn read(&mut self, buf: &mut [u8]) -> Res<(u64, bool)> {
        self.read_with_amount(buf, buf.len() as u64)
    }

    fn read_with_amount(&mut self, buf: &mut [u8], amount: u64) -> Res<(u64, bool)> {
        assert!(buf.len() >= amount as usize);

        match &mut self.state {
            RecvStreamState::Closed => return Err(Error::NoMoreData),
            RecvStreamState::Open {
                rx_window: _,
                rx_orderer,
            } => {
                let read_bytes = rx_orderer.read_with_amount(buf, amount)?;

                let fin = if let Some(final_size) = self.final_size {
                    if final_size == rx_orderer.retired() {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                Ok((read_bytes, fin))
            }
        }
    }

    fn close(&mut self) {
        self.state = RecvStreamState::Closed
    }

    #[allow(dead_code, unused_variables)]
    fn stop_sending(&mut self, err: AppError) {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_rx() {
        let mut s = RecvStream::new();

        // test receiving a contig frame and reading it works
        s.inbound_stream_frame(false, 0, vec![1; 10]).unwrap();
        assert_eq!(s.data_ready(), true);
        let mut buf = vec![0u8; 100];
        assert_eq!(s.read(&mut buf).unwrap(), (10, false));
        assert_eq!(s.orderer().unwrap().retired(), 10);
        assert_eq!(s.orderer().unwrap().buffered(), 0);

        // test receiving a noncontig frame
        s.inbound_stream_frame(false, 12, vec![2; 12]).unwrap();
        assert_eq!(s.data_ready(), false);
        assert_eq!(s.read(&mut buf).unwrap(), (0, false));
        assert_eq!(s.orderer().unwrap().retired(), 10);
        assert_eq!(s.orderer().unwrap().buffered(), 12);

        // another frame that overlaps the first
        s.inbound_stream_frame(false, 14, vec![3; 8]).unwrap();
        assert_eq!(s.data_ready(), false);
        assert_eq!(s.orderer().unwrap().retired(), 10);
        assert_eq!(s.orderer().unwrap().buffered(), 12);

        // fill in the gap, but with a FIN
        s.inbound_stream_frame(true, 10, vec![4; 6]).unwrap_err();
        assert_eq!(s.data_ready(), false);
        assert_eq!(s.read(&mut buf).unwrap(), (0, false));
        assert_eq!(s.orderer().unwrap().retired(), 10);
        assert_eq!(s.orderer().unwrap().buffered(), 12);

        // fill in the gap
        s.inbound_stream_frame(false, 10, vec![5; 10]).unwrap();
        assert_eq!(s.data_ready(), true);
        assert_eq!(s.orderer().unwrap().retired(), 10);
        assert_eq!(s.orderer().unwrap().buffered(), 14);

        // a legit FIN
        s.inbound_stream_frame(true, 24, vec![6; 18]).unwrap();
        assert_eq!(s.orderer().unwrap().retired(), 10);
        assert_eq!(s.orderer().unwrap().buffered(), 32);
        assert_eq!(s.data_ready(), true);
        assert_eq!(s.read(&mut buf).unwrap(), (32, true));
        assert_eq!(s.read(&mut buf).unwrap(), (0, true));
    }

    #[test]
    fn test_stream_rx_dedupe() {
        let mut s = RecvStream::new();

        let mut buf = vec![0u8; 100];

        // test receiving a contig frame and reading it works
        s.inbound_stream_frame(false, 0, vec![1; 6]).unwrap();

        // See inbound_frame(). Test (true, true) case
        s.inbound_stream_frame(false, 2, vec![2; 6]).unwrap();
        {
            let mut i = s.orderer().unwrap().data_ranges.iter();
            let item = i.next().unwrap();
            assert_eq!(*item.0, 0);
            assert_eq!(item.1.len(), 2);
            let item = i.next().unwrap();
            assert_eq!(*item.0, 2);
            assert_eq!(item.1.len(), 6);
        }

        // Test (true, false) case
        s.inbound_stream_frame(false, 4, vec![3; 4]).unwrap();
        {
            let mut i = s.orderer().unwrap().data_ranges.iter();
            let item = i.next().unwrap();
            assert_eq!(*item.0, 0);
            assert_eq!(item.1.len(), 2);
            let item = i.next().unwrap();
            assert_eq!(*item.0, 2);
            assert_eq!(item.1.len(), 6);
        }

        // Test (false, true) case
        s.inbound_stream_frame(false, 2, vec![4; 8]).unwrap();
        {
            let mut i = s.orderer().unwrap().data_ranges.iter();
            let item = i.next().unwrap();
            assert_eq!(*item.0, 0);
            assert_eq!(item.1.len(), 2);
            let item = i.next().unwrap();
            assert_eq!(*item.0, 2);
            assert_eq!(item.1.len(), 8);
        }

        // Test (false, false) case
        s.inbound_stream_frame(false, 2, vec![5; 2]).unwrap();
        {
            let mut i = s.orderer().unwrap().data_ranges.iter();
            let item = i.next().unwrap();
            assert_eq!(*item.0, 0);
            assert_eq!(item.1.len(), 2);
            let item = i.next().unwrap();
            assert_eq!(*item.0, 2);
            assert_eq!(item.1.len(), 8);
        }

        assert_eq!(s.read(&mut buf).unwrap(), (10, false));
        assert_eq!(buf[..10], [1, 1, 4, 4, 4, 4, 4, 4, 4, 4]);

        // Test truncation/span-drop on insert
        s.inbound_stream_frame(false, 100, vec![6; 6]).unwrap();
        // a. insert where new frame gets truncated
        s.inbound_stream_frame(false, 99, vec![7; 6]).unwrap();
        {
            let mut i = s.orderer().unwrap().data_ranges.iter();
            let item = i.next().unwrap();
            assert_eq!(*item.0, 99);
            assert_eq!(item.1.len(), 1);
            let item = i.next().unwrap();
            assert_eq!(*item.0, 100);
            assert_eq!(item.1.len(), 6);
            assert_eq!(i.next(), None);
        }

        // b. insert where new frame spans next frame
        s.inbound_stream_frame(false, 98, vec![8; 10]).unwrap();
        {
            let mut i = s.orderer().unwrap().data_ranges.iter();
            let item = i.next().unwrap();
            assert_eq!(*item.0, 98);
            assert_eq!(item.1.len(), 10);
            assert_eq!(i.next(), None);
        }
    }

    #[test]
    fn test_stream_flowc_update() {
        let frame1 = vec![0; RX_STREAM_DATA_WINDOW as usize];

        let mut s = RecvStream::new();

        let mut buf = vec![0u8; RX_STREAM_DATA_WINDOW as usize * 4]; // Make it overlarge

        assert_eq!(s.needs_flowc_update(), None);
        s.inbound_stream_frame(false, 0, frame1).unwrap();
        assert_eq!(s.needs_flowc_update(), None);
        assert_eq!(s.read(&mut buf).unwrap(), (RX_STREAM_DATA_WINDOW, false));
        assert_eq!(s.data_ready(), false);
        assert_eq!(s.needs_flowc_update(), Some(RX_STREAM_DATA_WINDOW * 2));
        assert_eq!(s.needs_flowc_update(), None);
    }

    #[test]
    fn test_stream_rx_window() {
        let frame1 = vec![0; RX_STREAM_DATA_WINDOW as usize];

        let mut s = RecvStream::new();

        assert_eq!(s.needs_flowc_update(), None);
        s.inbound_stream_frame(false, 0, frame1).unwrap();
        s.inbound_stream_frame(false, RX_STREAM_DATA_WINDOW, vec![1; 1])
            .unwrap_err();
    }

    #[test]
    fn test_stream_orderer_bytes_ready() {
        let mut rx_ord = RxStreamOrderer::new();

        let mut buf = vec![0u8; 100];

        rx_ord.inbound_frame(0, vec![1; 6]).unwrap();
        assert_eq!(rx_ord.bytes_ready(), 6);
        assert_eq!(rx_ord.buffered(), 6);
        assert_eq!(rx_ord.retired(), 0);
        // read some so there's an offset into the first frame
        rx_ord.read(&mut buf[..2]).unwrap();
        assert_eq!(rx_ord.bytes_ready(), 4);
        assert_eq!(rx_ord.buffered(), 4);
        assert_eq!(rx_ord.retired(), 2);
        // an overlapping frame
        rx_ord.inbound_frame(5, vec![2; 6]).unwrap();
        assert_eq!(rx_ord.bytes_ready(), 9);
        assert_eq!(rx_ord.buffered(), 9);
        assert_eq!(rx_ord.retired(), 2);
        // a noncontig frame
        rx_ord.inbound_frame(20, vec![3; 6]).unwrap();
        assert_eq!(rx_ord.bytes_ready(), 9);
        assert_eq!(rx_ord.buffered(), 15);
        assert_eq!(rx_ord.retired(), 2);
        // an old frame
        rx_ord.inbound_frame(0, vec![4; 2]).unwrap();
        assert_eq!(rx_ord.bytes_ready(), 9);
        assert_eq!(rx_ord.buffered(), 15);
        assert_eq!(rx_ord.retired(), 2);
    }

}
