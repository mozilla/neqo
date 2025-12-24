// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use neqo_common::{qdebug, qtrace, Bytes};

const DEFAULT_HARD_LIMIT: usize = 1000;
const DEFAULT_HIGH_WATER_MARK: f64 = f64::INFINITY;
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(u64::MAX / 1000);

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
    pub timestamp: Instant,
}

impl QueuedDatagram {
    pub fn new(data: Bytes, id: u64) -> Self {
        Self {
            data,
            id,
            timestamp: Instant::now(),
        }
    }

    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }
}

#[derive(Debug)]
pub struct WebTransportDatagramQueue {
    queue: VecDeque<QueuedDatagram>,
    hard_limit: usize,
    high_water_mark: f64,
    max_age: Duration,
}

impl WebTransportDatagramQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            hard_limit: DEFAULT_HARD_LIMIT,
            high_water_mark: DEFAULT_HIGH_WATER_MARK,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    pub fn set_high_water_mark(&mut self, mark: f64) {
        qtrace!("Setting high water mark to {}", mark);
        self.high_water_mark = if mark.is_infinite() {
            f64::INFINITY
        } else {
            mark.max(0.0)
        };
    }

    pub fn set_max_age(&mut self, age_ms: f64) {
        qtrace!("Setting max age to {} ms", age_ms);
        self.max_age = if age_ms.is_infinite() {
            DEFAULT_MAX_AGE
        } else {
            Duration::from_millis(age_ms.max(0.0) as u64)
        };
        self.expire_old_datagrams();
    }

    fn expire_old_datagrams(&mut self) -> Vec<u64> {
        let mut expired = Vec::new();

        while let Some(dgram) = self.queue.front() {
            if dgram.age() > self.max_age {
                let dgram = self.queue.pop_front().unwrap();
                qdebug!("Datagram {} expired (age: {:?})", dgram.id, dgram.age());
                expired.push(dgram.id);
            } else {
                break;
            }
        }

        expired
    }

    pub fn enqueue(&mut self, data: Bytes, id: u64) -> (bool, Option<(u64, DatagramOutcome)>) {
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

        let datagram = QueuedDatagram::new(data, id);
        self.queue.push_back(datagram);

        let below_watermark = (self.queue.len() as f64) < self.high_water_mark;
        qtrace!(
            "Enqueued datagram {}, queue size: {}, below watermark: {}",
            id,
            self.queue.len(),
            below_watermark
        );

        (below_watermark, dropped)
    }

    pub fn process_queue(&mut self, send_fn: &mut dyn FnMut(&[u8], u64) -> Result<(), ()>) -> Vec<(u64, DatagramOutcome)> {
        let mut outcomes = Vec::new();

        let expired = self.expire_old_datagrams();
        for id in expired {
            outcomes.push((id, DatagramOutcome::DroppedTooOld));
        }

        while let Some(dgram) = self.queue.front() {
            if dgram.age() > self.max_age {
                let dgram = self.queue.pop_front().unwrap();
                qdebug!("Datagram {} expired during processing", dgram.id);
                outcomes.push((dgram.id, DatagramOutcome::DroppedTooOld));
                continue;
            }

            match send_fn(dgram.data.as_ref(), dgram.id) {
                Ok(()) => {
                    let dgram = self.queue.pop_front().unwrap();
                    qtrace!("Datagram {} sent successfully", dgram.id);
                    outcomes.push((dgram.id, DatagramOutcome::Sent));
                }
                Err(()) => {
                    break;
                }
            }
        }

        outcomes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

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

    #[test]
    fn test_queue_basic() {
        let mut queue = WebTransportDatagramQueue::new();

        let (below_watermark, _) = queue.enqueue(Bytes::from(vec![1, 2, 3]), 1);
        assert!(below_watermark);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_high_water_mark() {
        let mut queue = WebTransportDatagramQueue::new();
        queue.set_high_water_mark(2.0);

        assert!(queue.enqueue(Bytes::from(vec![1]), 1).0);
        assert!(!queue.enqueue(Bytes::from(vec![2]), 2).0);
        assert!(!queue.enqueue(Bytes::from(vec![3]), 3).0);

        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_hard_limit() {
        let mut queue = WebTransportDatagramQueue::new();
        queue.hard_limit = 3;

        queue.enqueue(Bytes::from(vec![1]), 1);
        queue.enqueue(Bytes::from(vec![2]), 2);
        queue.enqueue(Bytes::from(vec![3]), 3);
        queue.enqueue(Bytes::from(vec![4]), 4);

        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_max_age_expiration() {
        let mut queue = WebTransportDatagramQueue::new();
        queue.set_max_age(100.0);

        queue.enqueue(Bytes::from(vec![1]), 1);

        std::thread::sleep(Duration::from_millis(150));

        let expired = queue.expire_old_datagrams();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_process_queue() {
        let mut queue = WebTransportDatagramQueue::new();

        queue.enqueue(Bytes::from(vec![1]), 1);
        queue.enqueue(Bytes::from(vec![2]), 2);

        let outcomes = queue.process_queue(&mut |_data, _id| Ok(()));

        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0], (1, DatagramOutcome::Sent));
        assert_eq!(outcomes[1], (2, DatagramOutcome::Sent));
        assert!(queue.is_empty());
    }
}
