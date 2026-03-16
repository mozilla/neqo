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
    pub id: Option<u64>,
    /// Length of the original payload before framing (varint session ID + protocol prefix).
    pub payload_len: usize,
    pub timestamp: Instant,
}

impl QueuedDatagram {
    pub fn new(data: Bytes, id: Option<u64>, payload_len: usize, now: Instant) -> Self {
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
        self.by_order.entry(send_order).or_default().push_back(dgram);
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
    fn expire_old(&mut self, now: Instant, max_age: Duration) -> Vec<Option<u64>> {
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
        expired_ids: &mut Vec<Option<u64>>,
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
/// * **Between groups** — groups receive equal bandwidth via round-robin
///   (matching the WebTransport send-group spec semantics and the behavior of
///   `pq` / `wwruotkk` for streams).
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
    /// Round-robin cursor: index in `groups` of the first group to serve next round.
    rr_next: usize,
    /// Total datagram count across all groups.
    total_count: usize,
    hard_limit: usize,
    high_water_mark: f64,
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

    pub fn set_max_age(&mut self, age_ms: f64, now: Instant) -> Vec<(Option<u64>, DatagramOutcome)> {
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

    fn expire_old_datagrams(&mut self, now: Instant) -> Vec<Option<u64>> {
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
    fn evict_lowest_priority(&mut self) -> Option<(Option<u64>, DatagramOutcome)> {
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
            self.hard_limit, dgram.id, group_id,
            self.groups.get(&group_id).and_then(|g| g.lowest_order()).unwrap_or(i64::MAX)
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
        id: Option<u64>,
        payload_len: usize,
        now: Instant,
        send_group_id: u64,
        send_order: i64,
    ) -> (bool, Option<(Option<u64>, DatagramOutcome)>) {
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

        let below_watermark = (self.total_count as f64) < self.high_water_mark;
        qtrace!(
            "Enqueued datagram {id:?} (group={send_group_id}, order={send_order}), \
             total={}, below_wm={below_watermark}",
            self.total_count
        );

        (below_watermark, dropped)
    }

    /// Drain datagrams into the QUIC layer via `send_fn`.
    ///
    /// Scheduling: groups are served round-robin; within each group the highest
    /// `send_order` is sent first; equal-order datagrams are FIFO.
    ///
    /// Returns `(outcomes, payload_bytes_sent, overhead_bytes_sent)`.
    ///
    /// `payload_bytes_sent` is the sum of original application payload sizes
    /// (excludes framing). `overhead_bytes_sent` is the framing overhead for
    /// those same datagrams.
    pub fn process_queue(
        &mut self,
        now: Instant,
        send_fn: &mut dyn FnMut(&[u8], Option<u64>) -> Result<(), ()>,
    ) -> (Vec<(Option<u64>, DatagramOutcome)>, u64, u64) {
        let mut outcomes = Vec::new();
        let mut payload_bytes: u64 = 0;
        let mut overhead_bytes: u64 = 0;

        // Expire old datagrams from all groups before draining.
        for id in self.expire_old_datagrams(now) {
            outcomes.push((id, DatagramOutcome::DroppedTooOld));
        }

        // Round-robin drain: one datagram per group per round until congested or empty.
        'drain: loop {
            if self.groups.is_empty() {
                break;
            }

            let n = self.groups.len();
            // Snapshot group order for this round starting at rr_next.
            let group_ids: Vec<u64> = (0..n)
                .map(|i| *self.groups.get_index((self.rr_next + i) % n).unwrap().0)
                .collect();

            let mut sent_this_round = false;

            for group_id in group_ids {
                // Find the highest-priority valid datagram in this group,
                // expiring any stale ones we encounter along the way.
                let mut expired_ids = Vec::new();
                let order = match self.groups.get_mut(&group_id) {
                    None => continue, // removed earlier this round
                    Some(group) => group.highest_valid_order(now, self.max_age, &mut expired_ids),
                };

                for id in expired_ids {
                    self.total_count -= 1;
                    outcomes.push((id, DatagramOutcome::DroppedTooOld));
                }

                let order = match order {
                    Some(o) => o,
                    None => {
                        // Group is now empty.
                        self.groups.shift_remove(&group_id);
                        if self.rr_next >= self.groups.len() && !self.groups.is_empty() {
                            self.rr_next = 0;
                        }
                        continue;
                    }
                };

                // Peek: clone the Bytes handle (O(1)) and copy the id so we hold no
                // reference across the send_fn call, then pop only on success.
                let (data, dgram_id) = {
                    let front = self.groups[&group_id]
                        .by_order[&order]
                        .front()
                        .unwrap();
                    (front.data.clone(), front.id)
                };

                match send_fn(data.as_ref(), dgram_id) {
                    Ok(()) => {
                        let (dgram, group_empty) = {
                            let group = self.groups.get_mut(&group_id).unwrap();
                            let dgram = group.pop_front(order).unwrap();
                            (dgram, group.is_empty())
                        };
                        self.total_count -= 1;
                        payload_bytes += dgram.payload_len as u64;
                        overhead_bytes += (dgram.data.len() - dgram.payload_len) as u64;
                        qtrace!(
                            "Datagram {:?} sent (group={group_id}, order={order})",
                            dgram.id
                        );
                        outcomes.push((dgram.id, DatagramOutcome::Sent));
                        if group_empty {
                            self.groups.shift_remove(&group_id);
                            if self.rr_next >= self.groups.len() && !self.groups.is_empty() {
                                self.rr_next = 0;
                            }
                        }
                        sent_this_round = true;
                    }
                    Err(()) => break 'drain,
                }
            }

            if !sent_this_round {
                break;
            }
        }

        // Advance the round-robin cursor once per process_queue call so that
        // the next call starts from a different group, ensuring long-term fairness.
        if !self.groups.is_empty() {
            self.rr_next = (self.rr_next + 1) % self.groups.len();
        }

        (outcomes, payload_bytes, overhead_bytes)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.total_count
    }

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

    // Helper: enqueue with a default group/order (group 0, order 0) and time.
    fn enq(q: &mut WebTransportDatagramQueue, payload: u8, id: u64) -> bool {
        q.enqueue(Bytes::from(vec![0, payload]), Some(id), 1, now(), 0, 0).0
    }

    // Helper: collect sent datagram IDs from process_queue.
    fn drain_ids(q: &mut WebTransportDatagramQueue) -> Vec<u64> {
        let (outcomes, _, _) = q.process_queue(now(), &mut |_, _| Ok(()));
        outcomes
            .into_iter()
            .filter_map(|(id, o)| if o == DatagramOutcome::Sent { id } else { None })
            .collect()
    }

    // ── Basic behaviour ────────────────────────────────────────────────────────

    #[test]
    fn test_queue_basic() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        let (below, _) = q.enqueue(Bytes::from(vec![1, 2, 3]), Some(1), 3, t, 0, 0);
        assert!(below);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_high_water_mark() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.set_high_water_mark(2.0);
        assert!(q.enqueue(Bytes::from(vec![1]), Some(1), 1, t, 0, 0).0);
        assert!(!q.enqueue(Bytes::from(vec![2]), Some(2), 1, t, 0, 0).0);
        assert!(!q.enqueue(Bytes::from(vec![3]), Some(3), 1, t, 0, 0).0);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_process_queue_byte_accounting() {
        let mut q = WebTransportDatagramQueue::new();
        // data = [overhead_byte, payload_byte], payload_len = 1
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 0, 0);

        let (outcomes, payload, overhead) = q.process_queue(now(), &mut |_, _| Ok(()));
        assert_eq!(outcomes.len(), 2);
        assert_eq!(payload, 2);
        assert_eq!(overhead, 2);
        assert!(q.is_empty());
    }

    #[test]
    fn test_max_age_expiration() {
        let mut q = WebTransportDatagramQueue::new();
        let t0 = now();
        q.set_max_age(100.0, t0);
        q.enqueue(Bytes::from(vec![1]), Some(1), 1, t0, 0, 0);

        // Advance time by 150 ms without sleeping.
        let t1 = t0 + Duration::from_millis(150);

        let expired = q.expire_old_datagrams(t1);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], Some(1));
        assert!(q.is_empty());
    }

    // ── Priority ordering within a single group ────────────────────────────────

    #[test]
    fn test_priority_order_within_group() {
        // Enqueue low-priority datagrams first, then high-priority.
        let t = now();
        // The queue should send highest send_order first.
        let mut q = WebTransportDatagramQueue::new();
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 10); // order 10
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 0, 30); // order 30 (highest)
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 0, 20); // order 20

        let sent = drain_ids(&mut q);
        assert_eq!(sent, vec![2, 3, 1], "highest order first");
    }

    #[test]
    fn test_fifo_within_same_order() {
        let mut q = WebTransportDatagramQueue::new();
        // All same group, same order → FIFO.
        let t = now();
        q.enqueue(Bytes::from(vec![0, 10]), Some(10), 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 11]), Some(11), 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 12]), Some(12), 1, t, 0, 5);

        assert_eq!(drain_ids(&mut q), vec![10, 11, 12]);
    }

    #[test]
    fn test_priority_mixed_orders_same_group() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 1);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 0, 3);
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 0, 1); // same as id=1
        q.enqueue(Bytes::from(vec![0, 4]), Some(4), 1, t, 0, 3); // same as id=2

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
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 0); // group A
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 1, 0); // group B
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 0, 0); // group A
        q.enqueue(Bytes::from(vec![0, 4]), Some(4), 1, t, 1, 0); // group B
        q.enqueue(Bytes::from(vec![0, 5]), Some(5), 1, t, 0, 0); // group A

        assert_eq!(drain_ids(&mut q), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_round_robin_priority_across_groups() {
        // Each group has datagrams at different send_orders.
        // Group 0: order 10, order 5
        // Group 1: order 20, order 1
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 10);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 1, 20);
        q.enqueue(Bytes::from(vec![0, 4]), Some(4), 1, t, 1, 1);

        // Round 1: group 0 sends id=1 (order 10), group 1 sends id=3 (order 20)
        // Round 2: group 0 sends id=2 (order 5), group 1 sends id=4 (order 1)
        assert_eq!(drain_ids(&mut q), vec![1, 3, 2, 4]);
    }

    #[test]
    fn test_round_robin_three_groups() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        // One datagram per group; should all be sent in one round.
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 10, 0);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 20, 0);
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 30, 0);

        assert_eq!(drain_ids(&mut q), vec![1, 2, 3]);
    }

    #[test]
    fn test_round_robin_cursor_advances() {
        // Verify the cursor advances across process_queue calls so that the group
        // that went first in the previous call goes second in the next.
        //
        // We use congestion (allow only 2 sends per call) to prevent full draining
        // and to observe one round at a time.
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 0); // group 0
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 1, 0); // group 1
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 0, 0); // group 0
        q.enqueue(Bytes::from(vec![0, 4]), Some(4), 1, t, 1, 0); // group 1

        // First call (rr_next=0): round starts at group 0 → [1, 2]. Cursor → 1.
        let mut count = 0;
        let (outcomes, _, _) = q.process_queue(now(), &mut |_, _| {
            count += 1;
            if count <= 2 { Ok(()) } else { Err(()) }
        });
        let sent1: Vec<_> = outcomes.into_iter()
            .filter_map(|(id, o)| if o == DatagramOutcome::Sent { id } else { None })
            .collect();
        assert_eq!(sent1, vec![1, 2]);

        // Second call (rr_next=1): round starts at group 1 → [4, 3].
        assert_eq!(drain_ids(&mut q), vec![4, 3]);
    }

    // ── Hard-limit eviction ────────────────────────────────────────────────────

    #[test]
    fn test_hard_limit_evicts_lowest_priority() {
        let mut q = WebTransportDatagramQueue::new();
        q.hard_limit = 3;

        // Fill with order-0 datagrams.
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 0, 0);
        assert_eq!(q.len(), 3);

        // Adding a higher-priority datagram should evict the lowest-priority one (id=1, order 0).
        let (_, dropped) = q.enqueue(Bytes::from(vec![0, 4]), Some(4), 1, t, 0, 10);
        assert_eq!(q.len(), 3);
        assert_eq!(dropped.and_then(|(id, _)| id), Some(1));

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
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 5);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 1, 1);

        // Adding a third datagram evicts the globally lowest-priority one (id=2, order 1).
        let (_, dropped) = q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 0, 5);
        assert_eq!(dropped.and_then(|(id, _)| id), Some(2));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn test_hard_limit_same_count() {
        // Backwards-compatibility: with one group and equal priorities, behaves like before.
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.hard_limit = 3;
        q.enqueue(Bytes::from(vec![1]), Some(1), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![2]), Some(2), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![3]), Some(3), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![4]), Some(4), 1, t, 0, 0);
        assert_eq!(q.len(), 3);
    }

    // ── Congestion (partial drain) ─────────────────────────────────────────────

    #[test]
    fn test_congestion_stops_drain() {
        let mut q = WebTransportDatagramQueue::new();
        enq(&mut q, 1, 1);
        enq(&mut q, 2, 2);
        enq(&mut q, 3, 3);

        let mut count = 0;
        let (outcomes, _, _) = q.process_queue(now(), &mut |_, _| {
            count += 1;
            if count <= 1 { Ok(()) } else { Err(()) }
        });
        assert_eq!(outcomes.iter().filter(|(_, o)| *o == DatagramOutcome::Sent).count(), 1);
        assert_eq!(q.len(), 2, "two datagrams remain after congestion");
    }

    #[test]
    fn test_congestion_round_robin_fairness() {
        // Two groups, each with 2 datagrams. Congestion kicks in after 1 datagram.
        // Verify one datagram from one group was sent (not two from the same).
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t, 0, 0);
        q.enqueue(Bytes::from(vec![0, 3]), Some(3), 1, t, 1, 0);
        q.enqueue(Bytes::from(vec![0, 4]), Some(4), 1, t, 1, 0);

        let mut count = 0;
        let (outcomes, _, _) = q.process_queue(now(), &mut |_, _| {
            count += 1;
            if count <= 1 { Ok(()) } else { Err(()) }
        });
        let sent: Vec<_> = outcomes.iter().filter(|(_, o)| *o == DatagramOutcome::Sent)
            .filter_map(|(id, _)| *id).collect();
        assert_eq!(sent.len(), 1);
        assert_eq!(q.len(), 3);
    }

    // ── Max-age expiry ─────────────────────────────────────────────────────────

    #[test]
    fn test_max_age_expiry_during_drain() {
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.set_max_age(50.0, t);

        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 0);
        // Advance time by 80 ms without sleeping.
        let t1 = t + Duration::from_millis(80);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t1, 0, 0); // fresh

        let (outcomes, _, _) = q.process_queue(t1, &mut |_, _| Ok(()));
        let expired: Vec<_> = outcomes.iter()
            .filter_map(|(id, o)| if *o == DatagramOutcome::DroppedTooOld { *id } else { None })
            .collect();
        let sent: Vec<_> = outcomes.iter()
            .filter_map(|(id, o)| if *o == DatagramOutcome::Sent { *id } else { None })
            .collect();
        assert_eq!(expired, vec![1]);
        assert_eq!(sent, vec![2]);
        assert!(q.is_empty());
    }

    #[test]
    fn test_max_age_expiry_high_priority_bucket() {
        // A high-priority datagram can expire; the lower-priority one should still be sent.
        let mut q = WebTransportDatagramQueue::new();
        let t = now();
        q.set_max_age(50.0, t);

        q.enqueue(Bytes::from(vec![0, 1]), Some(1), 1, t, 0, 100); // high priority, will expire
        // Advance time by 80 ms without sleeping.
        let t1 = t + Duration::from_millis(80);
        q.enqueue(Bytes::from(vec![0, 2]), Some(2), 1, t1, 0, 1);   // low priority, fresh

        let (outcomes, _, _) = q.process_queue(t1, &mut |_, _| Ok(()));
        let sent: Vec<_> = outcomes.iter()
            .filter_map(|(id, o)| if *o == DatagramOutcome::Sent { *id } else { None })
            .collect();
        assert_eq!(sent, vec![2], "lower-priority-but-fresh datagram is sent");
    }
}
