// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use neqo_common::{qdebug, qtrace};

pub const DEFAULT_HARD_LIMIT: usize = 1000;
const DEFAULT_MAX_AGE: Duration = Duration::MAX;

/// Caller-supplied identifier used to report the fate of a tracked datagram.
pub type DatagramId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOutcome {
    /// Handed to the QUIC layer's outgoing queue. Not a delivery or even a
    /// transmission guarantee; the transport reports the eventual fate
    /// separately via `ConnectionEvent::OutgoingDatagramOutcome`.
    Sent(DatagramId),
    Expired(DatagramId),
    /// Discarded without being sent: either the QUIC layer refused it when it
    /// was finally handed over, or the session closed while it was still queued.
    Dropped(DatagramId),
}

impl DatagramOutcome {
    #[must_use]
    pub const fn id(&self) -> DatagramId {
        match *self {
            Self::Sent(id) | Self::Expired(id) | Self::Dropped(id) => id,
        }
    }
}

/// The state of the queue after accepting a datagram, which is what the
/// application needs in order to apply backpressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramQueueOutcome {
    /// The queue was below the high water mark.
    Ok,
    /// The queue had space, but it was at or above the high water mark.
    AboveWatermark,
    /// The queue was full, so the oldest datagram was dropped to make room.
    /// If it was tracked, a [`DatagramOutcome::Dropped`] event is reported
    /// for it separately; the tracking ID isn't carried here too, to avoid
    /// reporting the same eviction twice.
    Overflowed,
}

#[derive(Debug)]
pub struct QueuedDatagram {
    pub data: Vec<u8>,
    /// Caller-supplied tracking ID, or `None` if the caller sent the datagram
    /// untracked (in which case no [`DatagramOutcome`] is ever reported for it).
    pub id: Option<DatagramId>,
    pub timestamp: Instant,
}

impl QueuedDatagram {
    pub const fn new(data: Vec<u8>, id: Option<DatagramId>, now: Instant) -> Self {
        Self {
            data,
            id,
            timestamp: now,
        }
    }

    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.timestamp)
    }
}

/// Per-session outgoing datagram queue with high water mark and max-age support.
///
/// Datagrams are enqueued here by [`Self::enqueue`] and drained into
/// the QUIC layer by [`Self::drain`], which is called during `process_http3()` as part
/// of `process_output()`. The caller must call `process_output()` after enqueuing
/// to ensure datagrams are actually transmitted. In Gecko, this happens via
/// `StreamHasDataToWrite()` -> `ForceSend()`, which asynchronously dispatches
/// `SendData()` -> `ProcessOutput()` on the next event loop cycle.
#[derive(Debug)]
pub struct WebTransportDatagramQueue {
    queue: VecDeque<QueuedDatagram>,
    hard_limit: usize,
    high_water_mark: Option<usize>,
    max_age: Duration,
}

impl WebTransportDatagramQueue {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            hard_limit: DEFAULT_HARD_LIMIT,
            high_water_mark: None,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    /// Clamped to [`Self::hard_limit`]: a watermark above it would never be
    /// reached, since the queue never grows past the hard limit, leaving
    /// [`DatagramQueueOutcome::AboveWatermark`] permanently unreachable and
    /// the caller with no warning before [`DatagramQueueOutcome::Overflowed`].
    pub fn set_high_water_mark(&mut self, mark: Option<usize>) {
        let clamped = mark.map(|m| m.min(self.hard_limit));
        qtrace!("Setting high water mark to {mark:?} (clamped: {clamped:?})");
        self.high_water_mark = clamped;
    }

    /// Returns one entry per expired datagram, `Some(id)` for tracked ones.
    /// The caller reports outcomes for the tracked ones and counts them all.
    pub fn set_max_age(&mut self, max_age: Duration, now: Instant) -> Vec<Option<DatagramId>> {
        qtrace!("Setting max age to {max_age:?}");
        self.max_age = max_age;
        self.expire_old_datagrams(now)
    }

    fn expire_old_datagrams(&mut self, now: Instant) -> Vec<Option<DatagramId>> {
        let mut expired = Vec::new();
        while self
            .queue
            .front()
            .is_some_and(|d| d.age(now) > self.max_age)
        {
            expired.extend(self.queue.pop_front().map(|d| d.id));
        }
        expired
    }

    /// Returns the outcome for the caller to apply backpressure with, and,
    /// on [`DatagramQueueOutcome::Overflowed`], the tracking ID of the
    /// evicted datagram (`None` if it was untracked) for the caller to
    /// report a [`DatagramOutcome::Dropped`] event for separately.
    pub fn enqueue(
        &mut self,
        data: Vec<u8>,
        id: Option<DatagramId>,
        now: Instant,
    ) -> (DatagramQueueOutcome, Option<DatagramId>) {
        // `hard_limit` is a fixed constant today, always > 0, so
        // `pop_front` always finds something to evict here. But nothing
        // enforces that invariant, so degrade to no eviction if it were
        // ever violated (e.g. `hard_limit` made configurable down to 0)
        // rather than panic on an empty queue.
        let evicted = (self.queue.len() >= self.hard_limit)
            .then(|| self.queue.pop_front())
            .flatten();
        if let Some(oldest) = &evicted {
            qdebug!(
                "Queue at hard limit ({}), dropping oldest datagram {:?}",
                self.hard_limit,
                oldest.id
            );
        }

        self.queue.push_back(QueuedDatagram::new(data, id, now));

        let below_watermark = self
            .high_water_mark
            .is_none_or(|mark| self.queue.len() < mark);
        // An overflowing queue is full, so backpressure applies regardless of where
        // the high water mark sits.
        let (outcome, dropped) = match (evicted, below_watermark) {
            (Some(oldest), _) => (DatagramQueueOutcome::Overflowed, oldest.id),
            (None, true) => (DatagramQueueOutcome::Ok, None),
            (None, false) => (DatagramQueueOutcome::AboveWatermark, None),
        };
        qtrace!(
            "Enqueued datagram {id:?}, queue size: {}, outcome: {outcome:?}",
            self.queue.len()
        );

        (outcome, dropped)
    }

    /// Drain up to `budget` datagrams, expiring old ones first and returning
    /// ready-to-send ones.
    ///
    /// `budget` is how many datagrams the QUIC layer can currently accept, i.e.
    /// [`Connection::remaining_datagram_queue_capacity`][neqo_transport::Connection::remaining_datagram_queue_capacity].
    /// Whatever exceeds it stays queued here, subject to this queue's own
    /// max-age/hard-limit policy, rather than being handed to the QUIC layer's
    /// fixed-size queue only to be head-dropped there with no signal back to
    /// the application.
    ///
    /// Returns `(expired, datagrams_to_send)`, where `expired` has one entry per
    /// expired datagram (`Some(id)` for tracked ones). The caller is responsible
    /// for passing each returned [`QueuedDatagram`] to
    /// [`Connection::send_datagram`][neqo_transport::Connection::send_datagram],
    /// which enqueues it in the QUIC layer's own outgoing queue. Congestion
    /// control and MTU checks happen later at packet creation time, not during
    /// [`Connection::send_datagram`][neqo_transport::Connection::send_datagram],
    /// so the only error that call can produce is
    /// [`neqo_transport::Error::TooMuchData`] (datagram exceeds the peer's
    /// `max_datagram_frame_size` transport parameter). Since
    /// [`Session::send_datagram`][super::session::Session::send_datagram]
    /// already validates size before calling [`Self::enqueue`], this error should
    /// not occur in practice.
    pub fn drain(
        &mut self,
        now: Instant,
        budget: usize,
    ) -> (Vec<Option<DatagramId>>, Vec<QueuedDatagram>) {
        // Expiry is not a send, so it must not be gated on `budget`: otherwise
        // stale datagrams pile up while the QUIC layer's queue is full.
        let expired = self.expire_old_datagrams(now);
        let count = budget.min(self.queue.len());
        let to_send = self.queue.drain(..count).collect();
        (expired, to_send)
    }

    /// Every remaining queued datagram, regardless of age. Used when the
    /// session is closing and nothing will call [`Self::drain`] again.
    pub fn take_all(&mut self) -> Vec<QueuedDatagram> {
        self.queue.drain(..).collect()
    }

    /// The instant at which the oldest queued datagram crosses `max_age`, if
    /// any datagram is queued. The caller uses this to schedule a wakeup so
    /// that expiry is not left to whichever unrelated timer happens to fire
    /// next (see `Http3Connection::next_datagram_expiry`).
    ///
    /// Datagrams are served/expired oldest-first, so the front of the queue
    /// is always the next one to expire. `None` if the queue is empty, or if
    /// `max_age` is `DEFAULT_MAX_AGE` (no expiry has ever been requested).
    #[must_use]
    pub fn next_expiry(&self) -> Option<Instant> {
        self.queue.front()?.timestamp.checked_add(self.max_age)
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
    use test_fixture::now;

    use super::*;

    #[test]
    fn queue_basic() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();

        let (outcome, dropped) = queue.enqueue(vec![1, 2, 3], Some(1), t);
        assert_eq!(outcome, DatagramQueueOutcome::Ok);
        assert_eq!(dropped, None);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn high_water_mark() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        queue.set_high_water_mark(Some(2));

        assert_eq!(
            queue.enqueue(vec![1], Some(1), t),
            (DatagramQueueOutcome::Ok, None)
        );
        assert_eq!(
            queue.enqueue(vec![2], Some(2), t),
            (DatagramQueueOutcome::AboveWatermark, None)
        );
        assert_eq!(
            queue.enqueue(vec![3], Some(3), t),
            (DatagramQueueOutcome::AboveWatermark, None)
        );

        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn high_water_mark_above_hard_limit_is_clamped() {
        let mut queue = WebTransportDatagramQueue::new();
        queue.hard_limit = 3;
        queue.set_high_water_mark(Some(10));
        let t = now();

        queue.enqueue(vec![1], Some(1), t);
        queue.enqueue(vec![2], Some(2), t);
        assert_eq!(
            queue.enqueue(vec![3], Some(3), t),
            (DatagramQueueOutcome::AboveWatermark, None),
            "a watermark above hard_limit must not be silently unreachable"
        );
    }

    #[test]
    fn hard_limit() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        queue.hard_limit = 3;

        queue.enqueue(vec![1], Some(1), t);
        queue.enqueue(vec![2], Some(2), t);
        queue.enqueue(vec![3], Some(3), t);
        assert_eq!(
            queue.enqueue(vec![4], Some(4), t),
            (DatagramQueueOutcome::Overflowed, Some(1))
        );

        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn hard_limit_untracked_datagram_drops_silently() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        queue.hard_limit = 1;

        queue.enqueue(vec![1], None, t);

        assert_eq!(
            queue.enqueue(vec![2], Some(2), t),
            (DatagramQueueOutcome::Overflowed, None),
            "an untracked datagram must not be reported with an ID"
        );
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn hard_limit_zero_does_not_panic() {
        let mut queue = WebTransportDatagramQueue::new();
        queue.hard_limit = 0;
        let t = now();

        // Nothing queued yet to evict, so the first datagram is accepted
        // for free rather than panicking on an empty pop_front.
        assert_eq!(
            queue.enqueue(vec![1], Some(1), t),
            (DatagramQueueOutcome::Ok, None)
        );
        assert_eq!(
            queue.enqueue(vec![2], Some(2), t),
            (DatagramQueueOutcome::Overflowed, Some(1))
        );
    }

    #[test]
    fn max_age_expiration() {
        let mut queue = WebTransportDatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Duration::from_millis(100), t0);

        queue.enqueue(vec![1], Some(1), t0);

        // Advance time by 150 ms without sleeping.
        let t1 = t0 + Duration::from_millis(150);

        let expired = queue.expire_old_datagrams(t1);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], Some(1));
        assert!(queue.is_empty());
    }

    #[test]
    fn max_age_expiration_untracked_datagram_reports_nothing() {
        let mut queue = WebTransportDatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Duration::from_millis(100), t0);

        queue.enqueue(vec![1], None, t0);

        let t1 = t0 + Duration::from_millis(150);
        let expired = queue.expire_old_datagrams(t1);
        assert_eq!(expired, vec![None]);
        assert!(queue.is_empty());
    }

    #[test]
    fn next_expiry_is_none_when_empty() {
        let queue = WebTransportDatagramQueue::new();
        assert_eq!(queue.next_expiry(), None);
    }

    #[test]
    fn next_expiry_is_none_without_a_max_age() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        queue.enqueue(vec![1], Some(1), t);
        assert_eq!(queue.next_expiry(), None);
    }

    #[test]
    fn next_expiry_tracks_the_oldest_datagram() {
        let mut queue = WebTransportDatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Duration::from_millis(50), t0);

        queue.enqueue(vec![1], Some(1), t0);
        let t1 = t0 + Duration::from_millis(10);
        queue.enqueue(vec![2], Some(2), t1);

        assert_eq!(queue.next_expiry(), Some(t0 + Duration::from_millis(50)));
    }

    #[test]
    fn next_expiry_advances_once_the_oldest_datagram_is_gone() {
        let mut queue = WebTransportDatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Duration::from_millis(50), t0);

        queue.enqueue(vec![1], Some(1), t0);
        let t1 = t0 + Duration::from_millis(10);
        queue.enqueue(vec![2], Some(2), t1);

        let (_, to_send) = queue.drain(t1, 1);
        assert_eq!(to_send.len(), 1);
        assert_eq!(queue.next_expiry(), Some(t1 + Duration::from_millis(50)));
    }

    #[test]
    fn drain() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();

        queue.enqueue(vec![0, 1], Some(1), t);
        queue.enqueue(vec![0, 2], None, t);

        let (expired, to_send) = queue.drain(t, usize::MAX);

        assert!(expired.is_empty());
        assert_eq!(to_send.len(), 2);
        assert_eq!(to_send[0].id, Some(1));
        assert_eq!(to_send[1].id, None);
        assert!(queue.is_empty());
    }

    #[test]
    fn drain_reports_every_expired_datagram() {
        // Untracked datagrams produce no outcome, but the caller still has to be
        // able to count them, so `drain` reports one entry per expired datagram.
        let mut queue = WebTransportDatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Duration::from_millis(50), t0);

        queue.enqueue(vec![1], Some(1), t0);
        queue.enqueue(vec![2], None, t0);

        let (expired, to_send) = queue.drain(t0 + Duration::from_millis(80), usize::MAX);
        assert_eq!(expired, vec![Some(1), None]);
        assert!(to_send.is_empty());
    }

    #[test]
    fn below_watermark_recovers_after_drain() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        queue.set_high_water_mark(Some(2));

        assert_eq!(
            queue.enqueue(vec![1], Some(1), t),
            (DatagramQueueOutcome::Ok, None)
        );
        assert_eq!(
            queue.enqueue(vec![2], Some(2), t),
            (DatagramQueueOutcome::AboveWatermark, None)
        );

        drop(queue.drain(t, usize::MAX));

        assert_eq!(
            queue.enqueue(vec![3], Some(3), t),
            (DatagramQueueOutcome::Ok, None),
            "draining the queue must put it back below the high water mark"
        );
    }

    #[test]
    fn drain_stops_at_budget() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        for i in 1..=5 {
            queue.enqueue(vec![0, i], Some(u64::from(i)), t);
        }

        let (_, to_send) = queue.drain(t, 2);
        assert_eq!(
            to_send.iter().map(|d| d.id).collect::<Vec<_>>(),
            vec![Some(1), Some(2)]
        );
        assert_eq!(queue.len(), 3, "the rest stays queued");
    }

    #[test]
    fn drain_budget_zero_keeps_everything() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        queue.enqueue(vec![1], Some(1), t);

        let (expired, to_send) = queue.drain(t, 0);
        assert!(expired.is_empty());
        assert!(to_send.is_empty());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn budgeted_drain_expires_even_with_no_budget() {
        // Expiry is not a send, so it must not be gated on the QUIC layer
        // having room; otherwise stale datagrams pile up while it is full.
        let mut queue = WebTransportDatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Duration::from_millis(50), t0);
        queue.enqueue(vec![1], Some(1), t0);

        let (expired, to_send) = queue.drain(t0 + Duration::from_millis(80), 0);
        assert_eq!(expired, vec![Some(1)]);
        assert!(to_send.is_empty());
        assert!(queue.is_empty());
    }

    #[test]
    fn partial_drain_leaves_remainder_for_a_later_call() {
        let mut queue = WebTransportDatagramQueue::new();
        let t = now();
        for i in 1..=3 {
            queue.enqueue(vec![0, i], Some(u64::from(i)), t);
        }

        let mut served = Vec::new();
        for _ in 0..3 {
            let (_, to_send) = queue.drain(t, 1);
            served.extend(to_send.into_iter().filter_map(|d| d.id));
        }

        assert_eq!(served, vec![1, 2, 3]);
        assert!(queue.is_empty());
    }
}
