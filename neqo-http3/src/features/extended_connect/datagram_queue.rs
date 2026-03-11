// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use neqo_common::{Bytes, qdebug, qtrace};

const DEFAULT_HARD_LIMIT: usize = 1000;
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(u64::MAX);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOutcome {
    Sent,
    DroppedTooOld,
    DroppedQueueFull,
}

#[derive(Debug)]
pub struct QueuedDatagram {
    pub data: Bytes,
    pub id: u64,
    /// Length of the original payload before framing (varint session ID + protocol prefix).
    pub payload_len: usize,
    pub timestamp: Instant,
}

impl QueuedDatagram {
    pub fn new(data: Bytes, id: u64, payload_len: usize, now: Instant) -> Self {
        Self {
            data,
            id,
            payload_len,
            timestamp: now,
        }
    }

    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.timestamp)
    }
}

/// Per-session outgoing datagram queue with high water mark and max-age support.
///
/// Datagrams are enqueued here by [`WebtransportDatagramQueue::send_datagram()`] and drained into the QUIC
/// layer by `process_queue()`, which is called during `process_http3()` as part
/// of `process_output()`. The caller must call `process_output()` after enqueuing
/// to ensure datagrams are actually transmitted. In Gecko, this happens via
/// `StreamHasDataToWrite()` -> `ForceSend()`, which asynchronously dispatches
/// `SendData()` -> `ProcessOutput()` on the next event loop cycle.
#[derive(Debug)]
pub struct WebTransportDatagramQueue {
    queue: VecDeque<QueuedDatagram>,
    hard_limit: usize,
    high_water_mark: Option<f64>,
    max_age: Duration,
}

impl WebTransportDatagramQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            hard_limit: DEFAULT_HARD_LIMIT,
            high_water_mark: None,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    pub fn set_high_water_mark(&mut self, mark: f64) {
        qtrace!("Setting high water mark to {}", mark);
        self.high_water_mark = if mark.is_infinite() || mark.is_nan() {
            None
        } else {
            Some(mark.max(0.0))
        };
    }

    pub fn set_max_age(&mut self, age_ms: f64, now: Instant) -> Vec<(u64, DatagramOutcome)> {
        qtrace!("Setting max age to {} ms", age_ms);
        self.max_age = if age_ms.is_infinite() || age_ms.is_nan() {
            DEFAULT_MAX_AGE
        } else {
            Duration::from_millis(age_ms.max(0.0) as u64)
        };
        self.expire_old_datagrams(now)
            .into_iter()
            .map(|id| (id, DatagramOutcome::DroppedTooOld))
            .collect()
    }

    fn expire_old_datagrams(&mut self, now: Instant) -> Vec<u64> {
        let split = self.queue.partition_point(|d| d.age(now) > self.max_age);
        if split == 0 {
            return Vec::new();
        }
        let kept = self.queue.split_off(split);
        let old = std::mem::replace(&mut self.queue, kept);
        old.into_iter().map(|d| d.id).collect()
    }

    pub fn enqueue(
        &mut self,
        data: Bytes,
        id: u64,
        payload_len: usize,
        now: Instant,
    ) -> (bool, Option<(u64, DatagramOutcome)>) {
        let dropped = if self.queue.len() >= self.hard_limit {
            if let Some(oldest) = self.queue.pop_front() {
                qdebug!(
                    "Queue at hard limit ({}), dropping oldest datagram {}",
                    self.hard_limit,
                    oldest.id
                );
                Some((oldest.id, DatagramOutcome::DroppedQueueFull))
            } else {
                None
            }
        } else {
            None
        };

        let datagram = QueuedDatagram::new(data, id, payload_len, now);
        self.queue.push_back(datagram);

        let below_watermark = self
            .high_water_mark
            .map_or(true, |mark| (self.queue.len() as f64) < mark);
        qtrace!(
            "Enqueued datagram {}, queue size: {}, below watermark: {}",
            id,
            self.queue.len(),
            below_watermark
        );

        (below_watermark, dropped)
    }

    /// Drain the queue, expiring old datagrams and returning ready-to-send ones.
    ///
    /// Returns `(expired_outcomes, datagrams_to_send)`. The caller is responsible
    /// for passing each returned [`QueuedDatagram`] to
    /// [`Connection::send_datagram`][neqo_transport::Connection::send_datagram],
    /// which enqueues it in the QUIC layer's own outgoing queue. Congestion
    /// control and MTU checks happen later at packet creation time, not during
    /// [`Connection::send_datagram`][neqo_transport::Connection::send_datagram],
    /// so the only error that call can produce is
    /// [`neqo_transport::Error::TooMuchData`] (datagram exceeds the peer's
    /// `max_datagram_frame_size` transport parameter). Since
    /// [`ExtendedConnectSession::send_datagram`][super::session::ExtendedConnectSession::send_datagram]
    /// already validates size before calling [`Self::enqueue`], this error should
    /// not occur in practice.
    pub fn drain(&mut self, now: Instant) -> (Vec<(u64, DatagramOutcome)>, Vec<QueuedDatagram>) {
        let mut expired = Vec::new();

        for id in self.expire_old_datagrams(now) {
            expired.push((id, DatagramOutcome::DroppedTooOld));
        }

        let mut to_send = Vec::new();
        while let Some(dgram) = self.queue.pop_front() {
            if dgram.age(now) > self.max_age {
                qdebug!("Datagram {} expired during processing", dgram.id);
                expired.push((dgram.id, DatagramOutcome::DroppedTooOld));
                continue;
            }
            to_send.push(dgram);
        }

        (expired, to_send)
    }

    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for WebTransportDatagramQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn test_queue_basic() {
        let mut queue = WebTransportDatagramQueue::new();
        let now = Instant::now();

        let (below_watermark, _) = queue.enqueue(Bytes::from(vec![1, 2, 3]), 1, 3, now);
        assert!(below_watermark);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_high_water_mark() {
        let mut queue = WebTransportDatagramQueue::new();
        let now = Instant::now();
        queue.set_high_water_mark(2.0);

        assert!(queue.enqueue(Bytes::from(vec![1]), 1, 1, now).0);
        assert!(!queue.enqueue(Bytes::from(vec![2]), 2, 1, now).0);
        assert!(!queue.enqueue(Bytes::from(vec![3]), 3, 1, now).0);

        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_hard_limit() {
        let mut queue = WebTransportDatagramQueue::new();
        let now = Instant::now();
        queue.hard_limit = 3;

        queue.enqueue(Bytes::from(vec![1]), 1, 1, now);
        queue.enqueue(Bytes::from(vec![2]), 2, 1, now);
        queue.enqueue(Bytes::from(vec![3]), 3, 1, now);
        queue.enqueue(Bytes::from(vec![4]), 4, 1, now);

        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_max_age_expiration() {
        let mut queue = WebTransportDatagramQueue::new();
        let t0 = Instant::now();
        queue.set_max_age(100.0, t0);

        queue.enqueue(Bytes::from(vec![1]), 1, 1, t0);
        // Advance time by 150 ms without sleeping.
        let t1 = t0 + Duration::from_millis(150);

        let expired = queue.expire_old_datagrams(t1);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_drain() {
        let mut queue = WebTransportDatagramQueue::new();
        let now = Instant::now();

        queue.enqueue(Bytes::from(vec![0, 1]), 1, 1, now);
        queue.enqueue(Bytes::from(vec![0, 2]), 2, 1, now);

        let (expired, to_send) = queue.drain(now);

        assert!(expired.is_empty());
        assert_eq!(to_send.len(), 2);
        assert_eq!(to_send[0].id, 1);
        assert_eq!(to_send[1].id, 2);
        assert!(queue.is_empty());
    }
}
