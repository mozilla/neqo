// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use indexmap::IndexMap;
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

/// Per-send-group priority queue.
///
/// Datagrams are organized by `send_order`; higher order = higher priority.
/// Within the same `send_order`, datagrams are served FIFO (insertion order).
#[derive(Debug, Default)]
struct GroupQueue {
    /// Keyed by `send_order` (ascending). Higher key = higher priority.
    by_order: BTreeMap<i64, VecDeque<QueuedDatagram>>,
    /// Total datagram count in this group.
    count: usize,
}

impl GroupQueue {
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn push(&mut self, send_order: i64, dgram: QueuedDatagram) {
        self.by_order
            .entry(send_order)
            .or_default()
            .push_back(dgram);
        self.count += 1;
    }

    fn pop_front(&mut self, order: i64) -> Option<QueuedDatagram> {
        let queue = self.by_order.get_mut(&order)?;
        let dgram = queue.pop_front()?;
        self.count -= 1;
        if queue.is_empty() {
            self.by_order.remove(&order);
        }
        Some(dgram)
    }

    /// The lowest `send_order` present in this group (i.e. lowest-priority bucket).
    fn lowest_order(&self) -> Option<i64> {
        self.by_order.keys().next().copied()
    }

    /// Evict the oldest datagram from the lowest-priority bucket.
    fn evict_lowest(&mut self) -> Option<QueuedDatagram> {
        let mut entry = self.by_order.first_entry()?;
        let dgram = entry.get_mut().pop_front()?;
        self.count -= 1;
        if entry.get().is_empty() {
            entry.remove();
        }
        Some(dgram)
    }

    /// Expire all datagrams older than `max_age`. Returns their IDs.
    fn expire_old(&mut self, now: Instant, max_age: Duration) -> Vec<u64> {
        let mut expired = Vec::new();
        let mut empty_orders = Vec::new();
        for (&order, queue) in &mut self.by_order {
            loop {
                match queue.front() {
                    Some(d) if d.age(now) > max_age => {
                        let d = queue.pop_front().unwrap();
                        self.count -= 1;
                        expired.push(d.id);
                    }
                    _ => break,
                }
            }
            if queue.is_empty() {
                empty_orders.push(order);
            }
        }
        for o in empty_orders {
            self.by_order.remove(&o);
        }
        expired
    }

    /// Find the highest `send_order` that has non-expired datagrams.
    ///
    /// Removes expired entries encountered during the scan and appends their IDs
    /// to `expired_ids`. Returns the winning `send_order`, or `None` if the group
    /// is empty after expiry.
    fn highest_valid_order(
        &mut self,
        now: Instant,
        max_age: Duration,
        expired_ids: &mut Vec<u64>,
    ) -> Option<i64> {
        loop {
            // last key = highest send_order = highest priority
            let order = *self.by_order.keys().next_back()?;
            {
                let queue = self.by_order.get_mut(&order).unwrap();
                // Expire stale entries at the front of this bucket (FIFO ⟹ front = oldest).
                while matches!(queue.front(), Some(d) if d.age(now) > max_age) {
                    let d = queue.pop_front().unwrap();
                    self.count -= 1;
                    expired_ids.push(d.id);
                }
                if !queue.is_empty() {
                    return Some(order);
                }
            }
            self.by_order.remove(&order);
        }
    }
}

/// Per-session outgoing datagram queue with send-group round-robin, within-group
/// send-order priority, high water mark, and max-age support.
///
/// ## Scheduling
///
/// Datagrams are enqueued with a `send_group_id` and a `send_order`:
///
/// * **Between groups** — groups receive equal bandwidth via round-robin:
///   the scheduler walks the active groups in insertion order and, on each
///   turn, allows at most one datagram to be sent from each group (if any are
///   queued). This matches the WebTransport send-group semantics and is
///   analogous to the fair-share stream send scheduler used in the
///   `neqo-transport` crate.
/// * **Within a group** — the datagram with the highest `send_order` is always
///   sent first. Equal-order datagrams are served FIFO.
///
/// ## Lifecycle
///
/// Datagrams are enqueued by `send_datagram()` and drained into the QUIC layer
/// by `process_queue()`, called during `process_http3()` as part of
/// `process_output()`. The caller must invoke `process_output()` after enqueuing
/// to ensure transmission. In Gecko this happens via
/// `StreamHasDataToWrite()` → `ForceSend()` → `SendData()` → `ProcessOutput()`.
#[derive(Debug)]
pub struct WebTransportDatagramQueue {
    /// Send groups in insertion order, for stable round-robin scheduling.
    ///
    /// The key is a raw `u64` group ID. `0` is used as the sentinel for the
    /// null sendGroup (datagrams with no group assigned), and is intentionally
    /// not a valid [`SendGroupId`] value. This differs from the stream
    /// scheduling path, which uses `SendGroupId` directly.
    groups: IndexMap<u64, GroupQueue>,
    /// Round-robin cursor: index in `groups` of the first group to serve next
    /// round.
    ///
    /// Currently [`Self::drain`] always empties the queue, so every group is
    /// removed by the end of the call and the cursor position has no effect on
    /// subsequent calls (new groups start fresh in insertion order). If a
    /// partial-drain mode is added in the future (e.g. a byte-budget cap so
    /// that only N bytes are moved to the QUIC layer per call), the cursor
    /// must be advanced at the end of each [`Self::drain`] call — otherwise
    /// the first-inserted group would always be served first, violating the
    /// spec-mandated equal-bandwidth round-robin between send groups. In that
    /// case, add `test_round_robin_cursor_advances` back to verify cross-call
    /// fairness under partial drain.
    rr_next: usize,
    /// Total datagram count across all groups.
    total_count: usize,
    hard_limit: usize,
    high_water_mark: Option<f64>,
    max_age: Duration,
}

impl WebTransportDatagramQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            groups: IndexMap::default(),
            rr_next: 0,
            total_count: 0,
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
        let max_age = self.max_age;
        let mut all_expired = Vec::new();
        let mut total_expired = 0usize;
        let mut empty_groups = Vec::new();

        for (&group_id, group) in &mut self.groups {
            let expired = group.expire_old(now, max_age);
            total_expired += expired.len();
            all_expired.extend(expired);
            if group.is_empty() {
                empty_groups.push(group_id);
            }
        }

        self.total_count -= total_expired;
        for gid in empty_groups {
            self.groups.shift_remove(&gid);
        }
        if self.rr_next >= self.groups.len() && !self.groups.is_empty() {
            self.rr_next = 0;
        }
        all_expired
    }

    /// Evict the oldest datagram from the globally lowest-priority bucket.
    ///
    /// "Lowest priority" means the lowest `send_order` across all groups. Ties
    /// are broken by `group_id` (lowest first) for determinism.
    fn evict_lowest_priority(&mut self) -> Option<(u64, DatagramOutcome)> {
        let group_id = self
            .groups
            .iter()
            .filter(|(_, g)| !g.is_empty())
            .min_by_key(|(gid, g)| (g.lowest_order().unwrap_or(i64::MAX), **gid))
            .map(|(gid, _)| *gid)?;

        let (dgram, group_empty) = {
            let group = self.groups.get_mut(&group_id).unwrap();
            let dgram = group.evict_lowest()?;
            (dgram, group.is_empty())
        };
        self.total_count -= 1;
        qdebug!(
            "Queue at hard limit ({}), dropping datagram {:?} from group {} (lowest priority order {})",
            self.hard_limit,
            dgram.id,
            group_id,
            self.groups
                .get(&group_id)
                .and_then(|g| g.lowest_order())
                .unwrap_or(i64::MAX)
        );
        if group_empty {
            self.groups.shift_remove(&group_id);
            if self.rr_next >= self.groups.len() && !self.groups.is_empty() {
                self.rr_next = 0;
            }
        }
        Some((dgram.id, DatagramOutcome::DroppedQueueFull))
    }

    /// `send_group_id` is a raw `u64`; `0` means no group (null sendGroup).
    /// Note: `0` is intentionally not a valid `SendGroupId`, but is used here
    /// as a sentinel so that ungrouped datagrams participate in the same
    /// round-robin queue as grouped ones without requiring a separate path.
    pub fn enqueue(
        &mut self,
        data: Bytes,
        id: u64,
        payload_len: usize,
        now: Instant,
        send_group_id: u64,
        send_order: i64,
    ) -> (bool, Option<(u64, DatagramOutcome)>) {
        let dropped = if self.total_count >= self.hard_limit {
            self.evict_lowest_priority()
        } else {
            None
        };

        self.groups
            .entry(send_group_id)
            .or_default()
            .push(send_order, QueuedDatagram::new(data, id, payload_len, now));
        self.total_count += 1;

        let below_watermark = self
            .high_water_mark
            .map_or(true, |mark| (self.total_count as f64) < mark);
        qtrace!(
            "Enqueued datagram {id:?} (group={send_group_id}, order={send_order}), \
             total={}, below_wm={below_watermark}",
            self.total_count
        );

        (below_watermark, dropped)
    }

    /// Drain the queue, expiring old datagrams and returning ready-to-send ones
    /// in scheduling order.
    ///
    /// **Scheduling:** groups are served round-robin; within each group the
    /// highest `send_order` is sent first; equal-order datagrams are FIFO.
    ///
    /// This always drains all non-expired datagrams. If a partial-drain mode
    /// is ever needed (e.g. a byte-budget parameter), [`Self::rr_next`] must
    /// be advanced at the end of the call to maintain cross-call round-robin
    /// fairness — see the comment on that field.
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
        let mut to_send = Vec::new();

        for id in self.expire_old_datagrams(now) {
            expired.push((id, DatagramOutcome::DroppedTooOld));
        }

        // Round-robin drain: one datagram per group per round until empty.
        loop {
            if self.groups.is_empty() {
                break;
            }

            let to_visit = self.groups.len();
            let mut visited = 0;
            let mut any_this_round = false;
            let mut expired_ids = Vec::new();

            while visited < to_visit && !self.groups.is_empty() {
                let idx = self.rr_next % self.groups.len();
                let group_id = *self.groups.get_index(idx).unwrap().0;
                expired_ids.clear();
                let order = self.groups.get_mut(&group_id).unwrap().highest_valid_order(
                    now,
                    self.max_age,
                    &mut expired_ids,
                );

                for id in &expired_ids {
                    self.total_count -= 1;
                    expired.push((*id, DatagramOutcome::DroppedTooOld));
                }

                let order = match order {
                    Some(o) => o,
                    None => {
                        self.groups.shift_remove(&group_id);
                        if !self.groups.is_empty() && self.rr_next >= self.groups.len() {
                            self.rr_next = 0;
                        }
                        visited += 1;
                        continue;
                    }
                };

                let (dgram, group_empty) = {
                    let group = self.groups.get_mut(&group_id).unwrap();
                    let dgram = group.pop_front(order).unwrap();
                    (dgram, group.is_empty())
                };
                self.total_count -= 1;
                qtrace!(
                    "Datagram {} drained (group={group_id}, order={order})",
                    dgram.id
                );
                to_send.push(dgram);

                if group_empty {
                    self.groups.shift_remove(&group_id);
                    if !self.groups.is_empty() && self.rr_next >= self.groups.len() {
                        self.rr_next = 0;
                    }
                } else {
                    self.rr_next = (idx + 1) % self.groups.len();
                }
                any_this_round = true;
                visited += 1;
            }

            if !any_this_round {
                break;
            }
        }

        (expired, to_send)
    }

    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.total_count
    }

    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
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

    fn drain_ids(q: &mut WebTransportDatagramQueue) -> Vec<u64> {
        let (_, to_send) = q.drain(now());
        to_send.into_iter().map(|d| d.id).collect()
    }

    // ── Basic behaviour ────────────────────────────────────────────────────────

    #[test]
    fn test_queue_basic() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        let (below, _) = q.enqueue(Bytes::from(vec![1, 2, 3]), 1, 3, t, 0, 0);
        assert!(below);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_high_water_mark() {
        let mut q = WebTransportDatagramQueue::new();
        q.set_high_water_mark(2.0);
        let t = now();
        assert!(q.enqueue(Bytes::from(vec![1]), 1, 1, t, 0, 0).0);
        assert!(!q.enqueue(Bytes::from(vec![2]), 2, 1, t, 0, 0).0);
        assert!(!q.enqueue(Bytes::from(vec![3]), 3, 1, t, 0, 0).0);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_drain_basic() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 0, 0);

        let (expired, to_send) = q.drain(now());
        assert!(expired.is_empty());
        assert_eq!(to_send.len(), 2);
        assert_eq!(to_send[0].id, 1);
        assert_eq!(to_send[1].id, 2);
        assert!(q.is_empty());
    }

    #[test]
    fn test_max_age_expiration() {
        let mut q = WebTransportDatagramQueue::new();
        let t0 = now();
        q.set_max_age(100.0, t0);
        q.enqueue(Bytes::from(vec![1]), 1, 1, t0, 0, 0);
        // Advance time by 150 ms without sleeping.
        let t1 = t0 + Duration::from_millis(150);

        let expired = q.expire_old_datagrams(t1);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], 1);
        assert!(q.is_empty());
    }

    // ── Priority ordering within a single group ────────────────────────────────

    #[test]
    fn test_priority_order_within_group() {
        // Enqueue low-priority datagrams first, then high-priority.
        // The queue should send highest send_order first.
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 10); // order 10
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 0, 30); // order 30 (highest)
        q.enqueue(Bytes::from(vec![0, 3]), 3, 1, t, 0, 20); // order 20

        let sent = drain_ids(&mut q);
        assert_eq!(sent, vec![2, 3, 1], "highest order first");
    }

    #[test]
    fn test_fifo_within_same_order() {
        let mut q = WebTransportDatagramQueue::new();
        // All same group, same order → FIFO.
        let t = now();
        q.enqueue(Bytes::from(vec![0, 10]), 10, 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 11]), 11, 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 12]), 12, 1, t, 0, 5);

        assert_eq!(drain_ids(&mut q), vec![10, 11, 12]);
    }

    #[test]
    fn test_priority_mixed_orders_same_group() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 1);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 0, 3);
        q.enqueue(Bytes::from(vec![0, 3]), 3, 1, t, 0, 1); // same as id=1
        q.enqueue(Bytes::from(vec![0, 4]), 4, 1, t, 0, 3); // same as id=2

        // Expected: id=2 then id=4 (order 3), then id=1 then id=3 (order 1)
        assert_eq!(drain_ids(&mut q), vec![2, 4, 1, 3]);
    }

    // ── Round-robin between groups ─────────────────────────────────────────────

    #[test]
    fn test_round_robin_two_groups() {
        let mut q = WebTransportDatagramQueue::new();
        // Group A (id 0): 3 datagrams, Group B (id 1): 2 datagrams.
        // Round-robin should interleave: A, B, A, B, A.
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 0); // group A
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 1, 0); // group B
        q.enqueue(Bytes::from(vec![0, 3]), 3, 1, t, 0, 0); // group A
        q.enqueue(Bytes::from(vec![0, 4]), 4, 1, t, 1, 0); // group B
        q.enqueue(Bytes::from(vec![0, 5]), 5, 1, t, 0, 0); // group A

        assert_eq!(drain_ids(&mut q), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_round_robin_priority_across_groups() {
        // Each group has datagrams at different send_orders.
        // Group 0: order 10, order 5
        // Group 1: order 20, order 1
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 10);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 3]), 3, 1, t, 1, 20);
        q.enqueue(Bytes::from(vec![0, 4]), 4, 1, t, 1, 1);

        // Round 1: group 0 sends id=1 (order 10), group 1 sends id=3 (order 20)
        // Round 2: group 0 sends id=2 (order 5), group 1 sends id=4 (order 1)
        assert_eq!(drain_ids(&mut q), vec![1, 3, 2, 4]);
    }

    #[test]
    fn test_round_robin_three_groups() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        // One datagram per group; should all be sent in one round.
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 10, 0);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 20, 0);
        q.enqueue(Bytes::from(vec![0, 3]), 3, 1, t, 30, 0);

        assert_eq!(drain_ids(&mut q), vec![1, 2, 3]);
    }

    // ── Hard-limit eviction ────────────────────────────────────────────────────

    #[test]
    fn test_hard_limit_evicts_lowest_priority() {
        let mut q = WebTransportDatagramQueue::new();
        q.hard_limit = 3;

        // Fill with order-0 datagrams.
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 3]), 3, 1, t, 0, 0);
        assert_eq!(q.len(), 3);

        // Adding a higher-priority datagram should evict the lowest-priority one (id=1, order 0).
        let (_, dropped) = q.enqueue(Bytes::from(vec![0, 4]), 4, 1, t, 0, 10);
        assert_eq!(q.len(), 3);
        assert_eq!(dropped.map(|(id, _)| id), Some(1));

        // The high-priority datagram should be sent first.
        let sent = drain_ids(&mut q);
        assert_eq!(sent[0], 4, "highest order (10) sent first");
    }

    #[test]
    fn test_hard_limit_evicts_across_groups() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.hard_limit = 2;

        // Group 0 has order 5, group 1 has order 1 (lower priority).
        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t, 1, 1);

        // Adding a third datagram evicts the globally lowest-priority one (id=2, order 1).
        let (_, dropped) = q.enqueue(Bytes::from(vec![0, 3]), 3, 1, t, 0, 5);
        assert_eq!(dropped.map(|(id, _)| id), Some(2));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn test_hard_limit_same_count() {
        // Backwards-compatibility: with one group and equal priorities, behaves like before.
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.hard_limit = 3;
        q.enqueue(Bytes::from(vec![1]), 1, 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![2]), 2, 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![3]), 3, 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![4]), 4, 1, t, 0, 0);
        assert_eq!(q.len(), 3);
    }

    // ── Max-age expiry ─────────────────────────────────────────────────────────

    #[test]
    fn test_max_age_expiry_during_drain() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.set_max_age(50.0, t);

        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 0);
        let t1 = t + Duration::from_millis(80);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t1, 0, 0);

        let (expired, to_send) = q.drain(t1);
        let expired_ids: Vec<_> = expired.iter().map(|(id, _)| *id).collect();
        let sent_ids: Vec<_> = to_send.iter().map(|d| d.id).collect();
        assert_eq!(expired_ids, vec![1]);
        assert_eq!(sent_ids, vec![2]);
        assert!(q.is_empty());
    }

    #[test]
    fn test_max_age_expiry_high_priority_bucket() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.set_max_age(50.0, t);

        q.enqueue(Bytes::from(vec![0, 1]), 1, 1, t, 0, 100); // high priority, will expire
        let t1 = t + Duration::from_millis(80);
        q.enqueue(Bytes::from(vec![0, 2]), 2, 1, t1, 0, 1); // low priority, fresh

        let (_, to_send) = q.drain(t1);
        let sent_ids: Vec<_> = to_send.iter().map(|d| d.id).collect();
        assert_eq!(
            sent_ids,
            vec![2],
            "lower-priority-but-fresh datagram is sent"
        );
    }
}
