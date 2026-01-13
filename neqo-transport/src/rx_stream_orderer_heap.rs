// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Improved BinaryHeap-based `RxStreamOrderer`.
//!
//! This version doesn't eagerly merge overlapping frames. Instead, it stores
//! all frames in the heap and handles deduplication lazily during reads.
//! This provides O(log n) insertion while deferring the complexity to read time.

use std::{cmp::Ordering, collections::BinaryHeap};

use neqo_common::qtrace;

/// A buffer of received stream data at a specific offset.
#[derive(Debug)]
struct StreamBuffer {
    offset: u64,
    data: Vec<u8>,
    seq: u64, // Insertion order for "first data wins" semantics
}

impl StreamBuffer {
    fn end(&self) -> u64 {
        self.offset + self.data.len() as u64
    }
}

// Implement ordering to create a min-heap (smallest offset first).
impl Ord for StreamBuffer {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse to get min-heap (smallest offset first).
        // For same offset, prefer earlier insertion (smaller seq = earlier).
        // Both comparisons are reversed for min-heap behavior.
        other
            .offset
            .cmp(&self.offset)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

impl PartialOrd for StreamBuffer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for StreamBuffer {}

impl PartialEq for StreamBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset
    }
}

/// Stream data reassembly buffer using a binary heap with lazy merging.
#[derive(Debug, Default)]
pub struct RxStreamOrderer {
    /// Binary heap storing stream buffers, ordered by offset (smallest first).
    data: BinaryHeap<StreamBuffer>,
    /// Number of bytes the application has read.
    retired: u64,
    /// The total number of bytes received (including retired).
    received: u64,
    /// Insertion sequence number for "first data wins" semantics.
    next_seq: u64,
}

impl RxStreamOrderer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an incoming stream frame off the wire. This may result in data
    /// being available to upper layers if frame is not out of order (ooo) or
    /// if the frame fills a gap.
    ///
    /// # Panics
    /// Only when `u64` values cannot be converted to `usize`, which only
    /// happens on 32-bit machines that hold far too much data at the same time.
    pub fn inbound_frame(&mut self, mut new_start: u64, mut new_data: &[u8]) {
        qtrace!("Inbound data offset={new_start} len={}", new_data.len());

        let new_end = new_start + u64::try_from(new_data.len()).expect("usize fits in u64");

        if new_end <= self.retired {
            // Range already read by application, discard.
            return;
        }

        if new_start < self.retired {
            // Trim already-retired portion.
            new_data =
                &new_data[usize::try_from(self.retired - new_start).expect("u64 fits in usize")..];
            new_start = self.retired;
        }

        if new_data.is_empty() {
            return;
        }

        // Simply add the frame to the heap. Overlaps will be handled during read.
        qtrace!("Inserting frame {new_start}-{new_end}");
        self.received = self.received.max(new_end);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.data.push(StreamBuffer {
            offset: new_start,
            data: new_data.to_vec(),
            seq,
        });
    }

    /// Are any bytes readable?
    #[must_use]
    pub fn data_ready(&self) -> bool {
        self.data
            .peek()
            .is_some_and(|buf| buf.offset <= self.retired)
    }

    /// How many bytes are readable?
    #[must_use]
    pub fn bytes_ready(&self) -> usize {
        let mut bytes: usize = 0;
        let mut next_expected = self.retired;

        // Create a temporary sorted vec to iterate without consuming the heap.
        let mut buffers: Vec<_> = self.data.iter().collect();
        buffers.sort_by_key(|b| b.offset);

        for buf in buffers {
            if buf.offset <= next_expected {
                let start_in_buf = next_expected.saturating_sub(buf.offset);
                let available = (buf.data.len() as u64).saturating_sub(start_in_buf);
                if available > 0 {
                    bytes = bytes.saturating_add(usize::try_from(available).unwrap_or(usize::MAX));
                    next_expected = buf.end();
                }
            } else {
                // Gap found.
                break;
            }
        }

        bytes
    }

    /// Bytes read by the application.
    #[must_use]
    pub const fn retired(&self) -> u64 {
        self.retired
    }

    /// Total bytes received.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// Data bytes buffered.
    #[must_use]
    pub fn buffered(&self) -> u64 {
        // Sum all buffer sizes (may include overlaps).
        self.data.iter().map(|b| b.data.len() as u64).sum()
    }

    /// Copy received data (if any) into the buffer. Returns bytes copied.
    ///
    /// # Panics
    /// Only when `u64` values cannot be converted to `usize`, which only
    /// happens on 32-bit machines that hold far too much data at the same time.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        qtrace!("Reading {} bytes, {} available", buf.len(), self.buffered());
        let mut copied = 0;

        while let Some(stream_buf) = self.data.peek() {
            if stream_buf.offset > self.retired {
                // Gap in data.
                break;
            }

            let mut stream_buf = self.data.pop().expect("peek succeeded");

            // Calculate what portion of this buffer is new.
            if stream_buf.end() <= self.retired {
                // Entire buffer is stale, discard.
                continue;
            }

            let copy_offset = if stream_buf.offset < self.retired {
                usize::try_from(self.retired - stream_buf.offset).expect("u64 fits in usize")
            } else {
                0
            };

            let available = stream_buf.data.len() - copy_offset;
            let space = buf.len() - copied;
            let copy_bytes = available.min(space);

            if copy_bytes > 0 {
                let copy_slc = &stream_buf.data[copy_offset..copy_offset + copy_bytes];
                buf[copied..copied + copy_bytes].copy_from_slice(copy_slc);
                copied += copy_bytes;
                self.retired += u64::try_from(copy_bytes).expect("usize fits in u64");
            }

            if available > copy_bytes {
                // Still data left, put back the remainder.
                stream_buf.data.drain(..copy_offset + copy_bytes);
                stream_buf.offset = self.retired;
                self.data.push(stream_buf);
                break;
            }

            if copied >= buf.len() {
                break;
            }
        }

        copied
    }

    /// Extend the given Vector with any available data.
    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> usize {
        let orig_len = buf.len();
        buf.resize(orig_len + self.bytes_ready(), 0);
        self.read(&mut buf[orig_len..])
    }
}

// Add a public `data_ranges` field for test compatibility
#[cfg(test)]
impl RxStreamOrderer {
    /// Returns a BTreeMap-compatible view for test compatibility.
    /// This creates a snapshot of the current buffered ranges.
    pub fn data_ranges(&self) -> std::collections::BTreeMap<u64, Vec<u8>> {
        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        for buf in &self.data {
            map.insert(buf.offset, buf.data.clone());
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order() {
        let mut orderer = RxStreamOrderer::new();
        orderer.inbound_frame(0, b"hello");
        assert!(orderer.data_ready());
        assert_eq!(orderer.bytes_ready(), 5);

        let mut buf = vec![0; 10];
        let n = orderer.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(orderer.retired(), 5);
    }

    #[test]
    fn out_of_order() {
        let mut orderer = RxStreamOrderer::new();
        orderer.inbound_frame(5, b"world");
        assert!(!orderer.data_ready());
        assert_eq!(orderer.bytes_ready(), 0);

        orderer.inbound_frame(0, b"hello");
        assert!(orderer.data_ready());
        assert_eq!(orderer.bytes_ready(), 10);

        let mut buf = vec![0; 20];
        let n = orderer.read(&mut buf);
        assert_eq!(n, 10);
        assert_eq!(&buf[..10], b"helloworld");
    }

    #[test]
    fn overlapping() {
        let mut orderer = RxStreamOrderer::new();
        orderer.inbound_frame(0, b"hello");
        orderer.inbound_frame(3, b"lo world");
        assert!(orderer.data_ready());

        let mut buf = vec![0; 20];
        let n = orderer.read(&mut buf);
        assert_eq!(n, 11);
        assert_eq!(&buf[..11], b"hello world");
    }

    #[test]
    fn duplicate() {
        let mut orderer = RxStreamOrderer::new();
        orderer.inbound_frame(0, b"hello");
        orderer.inbound_frame(0, b"hello");
        assert_eq!(orderer.bytes_ready(), 5);

        let mut buf = vec![0; 10];
        let n = orderer.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn late_frame() {
        let mut orderer = RxStreamOrderer::new();
        orderer.inbound_frame(0, b"hello world");

        let mut buf = vec![0; 5];
        orderer.read(&mut buf);
        assert_eq!(&buf, b"hello");

        // This frame is already retired.
        orderer.inbound_frame(0, b"hello");
        assert_eq!(orderer.bytes_ready(), 6);
    }

    #[test]
    fn first_data_wins() {
        let mut orderer = RxStreamOrderer::new();
        // Insert frame with [1] at offset 0
        orderer.inbound_frame(0, &[1; 6]);
        // Insert overlapping frame with [2] at offset 0 (should be ignored for overlap)
        orderer.inbound_frame(0, &[2; 3]);

        let mut buf = vec![0; 10];
        let n = orderer.read(&mut buf);
        println!("Read {} bytes: {:?}", n, &buf[..n]);
        assert_eq!(n, 6);
        // Should get data from first frame, not second
        assert_eq!(&buf[..6], &[1, 1, 1, 1, 1, 1]);
    }
}
