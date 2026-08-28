// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cmp::max,
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use neqo_common::{qdebug, qtrace};
use neqo_transport::DEFAULT_INITIAL_RTT;
/// Byte-budget memory backstop for the outgoing datagram queue.
///
/// A datagram *count* bound does not bound memory - a flood of tiny
/// datagrams would fit comfortably under a count sized for average-sized
/// ones, while a fixed count sized for a burst of large datagrams standing
/// at a much smaller size is needless bufferbloat (mxinden: a 1000-datagram
/// limit at ~1200B/datagram is ~1.2MB of pending, potentially outdated data).
/// A byte budget scales with what is actually queued either way, and is a
/// backstop only: `outgoingMaxAge` is what actually bounds delay in the
/// common case, by shedding stale datagrams before this budget is ever
/// reached.
///
/// 256KB is one [`DEFAULT_MAX_AGE_FLOOR`] (20ms) window at 100 Mbps, so
/// anything deeper would expire before it could plausibly be sent; it is also
/// ~213 datagrams at a 1200B MTU-sized payload, comfortably above the
/// 64-datagram GSO-batch floor a single `sendmmsg` call can amortize.
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 256 * 1024;

/// Conservative per-datagram bookkeeping overhead charged in addition to
/// payload bytes when accounting against [`DEFAULT_MAX_QUEUED_BYTES`], so a
/// flood of tiny datagrams is bounded by the same budget as large ones
/// instead of needing a separate count cap. Approximates the queue's own
/// per-entry cost (the [`QueuedDatagram`] struct plus its slot in the group's
/// `VecDeque`/`BTreeMap`), not wire overhead.
pub const PER_DATAGRAM_OVERHEAD: usize = 64;

/// The byte charge against [`DEFAULT_MAX_QUEUED_BYTES`] for a datagram whose
/// payload is `len` bytes: the payload itself plus [`PER_DATAGRAM_OVERHEAD`].
const fn charge(len: usize) -> usize {
    len + PER_DATAGRAM_OVERHEAD
}

/// Numerator/denominator of the multiplier applied to the path's minimum RTT
/// by [`default_max_age`]. Kept as an integer ratio rather than a float so the
/// `Duration` arithmetic stays exact.
const DEFAULT_MAX_AGE_RTT_MULTIPLIER_NUM: u32 = 5;
const DEFAULT_MAX_AGE_RTT_MULTIPLIER_DEN: u32 = 4;

/// Lower bound for [`default_max_age`]. Rooted in app performance targets
/// rather than RTT: roughly one frame at 60fps, the pace a responsive site is
/// already expected to service input at, so a low-RTT path (loopback, LAN)
/// does not expire datagrams faster than that.
const DEFAULT_MAX_AGE_FLOOR: Duration = Duration::from_millis(20);

/// The "[implementation-defined] value" that [`sendDatagrams`] step 4
/// substitutes when the application leaves `outgoingMaxAge` unset.
///
/// This is a latency bound, not a delivery guarantee. A datagram still queued
/// after a couple of round trips has been overtaken by whatever the application
/// sent after it, and on a link too slow to drain the queue, holding it only
/// adds delay to everything behind it. Datagrams are best-effort, so the queue
/// sheds it rather than growing without bound.
///
/// The 1.25x multiplier matches Chromium's QUICHE
/// `QuicDatagramQueue::GetMaxTimeInQueue()`. The floor deliberately does not
/// match Chromium's 4ms: a fixed few milliseconds is too tight for a
/// intercontinental or satellite path to plausibly drain a burst - a video key
/// frame, say - before it is shed, so the floor instead comes from how fast a
/// site is expected to service input (one frame at 60fps), and RTT scaling
/// takes over above that on higher-latency paths.
///
/// [implementation-defined]: https://infra.spec.whatwg.org/#implementation-defined
/// [`sendDatagrams`]: https://w3c.github.io/webtransport/#senddatagrams
#[must_use]
pub fn default_max_age(min_rtt: Duration) -> Duration {
    // A zero `min_rtt` means the connection has no RTT sample yet, not that the
    // path is instantaneous. Scaling that would collapse the bound onto the
    // floor and shed datagrams sent in the first round trip, so stand in the
    // same initial estimate the transport itself starts from.
    let rtt = if min_rtt.is_zero() {
        DEFAULT_INITIAL_RTT
    } else {
        min_rtt
    };
    max(
        rtt * DEFAULT_MAX_AGE_RTT_MULTIPLIER_NUM / DEFAULT_MAX_AGE_RTT_MULTIPLIER_DEN,
        DEFAULT_MAX_AGE_FLOOR,
    )
}

/// Floor applied to an explicit `outgoingMaxAge`. Below this, the value stops
/// bounding anything meaningful relative to our own timer granularity.
const EXPLICIT_MAX_AGE_FLOOR: Duration = Duration::from_millis(1);

/// The minimum ceiling applied to an explicit `outgoingMaxAge`, used only when
/// it would otherwise exceed [`default_max_age`] for the path (see
/// [`DatagramQueue::set_max_age`] for why the ceiling tracks the default
/// rather than being fixed).
const EXPLICIT_MAX_AGE_CEILING_FLOOR: Duration = Duration::from_millis(100);

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramQueueOutcome {
    /// The queue was below the high water mark.
    Ok,
    /// The queue had space, but it was at or above the high water mark.
    AboveWatermark,
    /// The byte budget was exceeded, so one or more of the lowest-priority
    /// datagrams were dropped to make room - a single incoming datagram can
    /// be larger than what any one eviction frees. Always non-empty. Each
    /// entry is a dropped datagram's tracking ID, or `None` if it was sent
    /// untracked; the caller reports a [`DatagramOutcome::Dropped`] event for
    /// each tracked one separately, to avoid reporting the same eviction twice.
    Overflowed { dropped: Vec<Option<DatagramId>> },
}

/// A snapshot of this session's outgoing-datagram queue state, meant for
/// driving a content-process credit grant (see [`DatagramQueue::capacity`]).
///
/// This deliberately does not come from
/// [`Connection::remaining_datagram_queue_capacity`][neqo_transport::Connection::remaining_datagram_queue_capacity]:
/// that reflects the small, constantly-refilled 10-slot transport FIFO,
/// which tracks nothing meaningful about the connection's real send rate. A
/// grant meant to be cwnd-shaped should track *this* queue instead - its
/// byte budget is drained by [`DatagramQueue::drain`] only as fast as the
/// transport can actually take datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramQueueCapacity {
    /// Bytes free before [`DEFAULT_MAX_QUEUED_BYTES`] is reached.
    pub remaining_bytes: usize,
    /// Datagrams currently queued here, awaiting a drain.
    pub queued_datagrams: usize,
    /// The queue's byte budget itself, i.e. `remaining_bytes` when empty.
    /// Exposed so a caller deriving a windowed credit grant from
    /// `remaining_bytes` (e.g. a cumulative, `MAX_DATA`-style grant) has the
    /// window size to dedupe updates against, without duplicating
    /// [`DEFAULT_MAX_QUEUED_BYTES`] on the other side of the FFI boundary -
    /// this can differ from the default in tests, which override it.
    pub max_queued_bytes: usize,
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
    const fn is_empty(&self) -> bool {
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
        self.pop_front(self.lowest_order()?)
    }

    /// Expire all datagrams older than `max_age`. Returns the expired
    /// datagrams themselves (not just their IDs), so the caller can also
    /// account for their bytes.
    fn expire_old(&mut self, now: Instant, max_age: Duration) -> Vec<QueuedDatagram> {
        let mut expired = Vec::new();
        let mut empty_orders = Vec::new();
        for (&order, queue) in &mut self.by_order {
            loop {
                if !matches!(queue.front(), Some(d) if d.age(now) > max_age) {
                    break;
                }
                let Some(d) = queue.pop_front() else { break };
                self.count -= 1;
                expired.push(d);
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

    /// The highest `send_order` present in this group (i.e. the next to send).
    fn highest_order(&self) -> Option<i64> {
        self.by_order.keys().next_back().copied()
    }

    /// The timestamp of the longest-queued datagram in this group, across
    /// all `send_order` buckets. Each bucket is FIFO, so its front is its
    /// oldest.
    fn oldest_timestamp(&self) -> Option<Instant> {
        self.by_order
            .values()
            .filter_map(|q| q.front())
            .map(|d| d.timestamp)
            .min()
    }
}

/// Per-session outgoing datagram queue with send-group round-robin, within-group
/// send-order priority, high water mark, and max-age support.
///
/// ## Scheduling
///
/// Datagrams are enqueued with a `send_group_id` and a `send_order`:
///
/// * **Between groups** — groups receive equal bandwidth via round-robin: each round takes at most
///   one datagram from every non-empty group, in ascending group-ID order. This matches the
///   WebTransport send-group semantics and is analogous to the fair-share stream send scheduler
///   used in the `neqo-transport` crate.
/// * **Within a group** — the datagram with the highest `send_order` is always sent first.
///   Equal-order datagrams are served FIFO.
///
/// This queue is scheduled independently of `neqo-transport`'s stream scheduler. A
/// [`crate::SendGroupId`] shared between a `WebTransportSendStream` and a datagram writable does
/// not get cross-type starvation avoidance, as the WebTransport spec's send-order rules require.
///
/// ## Lifecycle
///
/// Datagrams are enqueued by `send_datagram()` and drained into the QUIC layer
/// by `process_queue()`, called during `process_http3()` as part of
/// `process_output()`. The caller must invoke `process_output()` after enqueuing
/// to ensure transmission. In Gecko this happens via
/// `StreamHasDataToWrite()` → `ForceSend()` → `SendData()` → `ProcessOutput()`.
#[derive(Debug)]
pub struct DatagramQueue {
    /// Send groups, keyed by a raw `u64` group ID. `0` is the sentinel for the
    /// null sendGroup (datagrams with no group assigned), and is intentionally
    /// not a valid [`crate::SendGroupId`] value. This differs from the stream
    /// scheduling path, which uses `SendGroupId` directly.
    ///
    /// Ordered by group ID so that round-robin is deterministic. A group is
    /// removed as soon as it becomes empty, so every entry here is non-empty.
    groups: BTreeMap<u64, GroupQueue>,
    /// Group ID at which the next round-robin round starts. Persisted across
    /// [`Self::drain`] calls so a drain that stops on its budget resumes at the
    /// group after the last one served; restarting at the lowest group ID every
    /// time would starve higher-numbered groups whenever the budget is smaller
    /// than the number of groups.
    rr_next: u64,
    /// Total datagram count across all groups.
    total_count: usize,
    /// Total charged bytes across all groups: the sum of each queued
    /// datagram's payload length plus [`PER_DATAGRAM_OVERHEAD`].
    total_bytes: usize,
    max_queued_bytes: usize,
    high_water_mark: Option<usize>,
    /// The application's `outgoingMaxAge`, or `None` if it never set one, in
    /// which case [`default_max_age`] applies. Which of the two is in force is
    /// not observable from script: the attribute reports the application's
    /// value, so it stays null.
    max_age: Option<Duration>,
}

impl DatagramQueue {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            rr_next: 0,
            total_count: 0,
            total_bytes: 0,
            max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
            high_water_mark: None,
            max_age: None,
        }
    }

    pub fn set_high_water_mark(&mut self, mark: Option<usize>) {
        qtrace!("Setting high water mark to {mark:?}");
        self.high_water_mark = mark;
    }

    /// `None` means the application has not set `outgoingMaxAge`, in which case
    /// [`DEFAULT_MAX_AGE`] applies. The distinction is not observable from
    /// script: the attribute reports the application's value, which stays null.
    ///
    /// An explicit value is clamped to `[1ms, max(100ms, default_max_age)]`.
    /// The 1ms floor is a timer-granularity bound. The ceiling is *at least*
    /// 100ms, but never less than what the application would get by leaving
    /// `outgoingMaxAge` unset on this path: an app that explicitly asks for
    /// more buffering than the default must not end up bounded tighter than
    /// an app that asks for nothing at all.
    ///
    /// Returns one entry per expired datagram, `Some(id)` for tracked ones.
    /// The caller reports outcomes for the tracked ones and counts them all.
    pub fn set_max_age(
        &mut self,
        max_age: Option<Duration>,
        now: Instant,
        default_max_age: Duration,
    ) -> Vec<Option<DatagramId>> {
        let clamped = max_age.map(|v| {
            v.clamp(
                EXPLICIT_MAX_AGE_FLOOR,
                max(default_max_age, EXPLICIT_MAX_AGE_CEILING_FLOOR),
            )
        });
        qtrace!("Setting max age to {max_age:?} (clamped: {clamped:?})");
        self.max_age = clamped;
        self.expire_old_datagrams(now, default_max_age)
    }

    fn expire_old_datagrams(
        &mut self,
        now: Instant,
        default_max_age: Duration,
    ) -> Vec<Option<DatagramId>> {
        let max_age = self.max_age.unwrap_or(default_max_age);
        let mut all_expired = Vec::new();
        self.groups.retain(|_, group| {
            all_expired.extend(group.expire_old(now, max_age));
            !group.is_empty()
        });
        self.total_count -= all_expired.len();
        self.total_bytes -= all_expired
            .iter()
            .map(|d| charge(d.data.len()))
            .sum::<usize>();
        all_expired.into_iter().map(|d| d.id).collect()
    }

    /// The `(send_order, group_id)` key of the globally lowest-priority
    /// occupied bucket: lowest `send_order` across all groups, ties broken by
    /// `group_id` (lowest first) for determinism.
    fn lowest_priority_key(&self) -> Option<(i64, u64)> {
        self.groups
            .iter()
            .filter(|(_, g)| !g.is_empty())
            .map(|(gid, g)| {
                (
                    g.lowest_order()
                        .expect("filtered groups are non-empty, so have a lowest order"),
                    *gid,
                )
            })
            .min()
    }

    /// Evict the oldest datagram from the globally lowest-priority bucket.
    ///
    /// "Lowest priority" means the lowest `send_order` across all groups. Ties
    /// are broken by `group_id` (lowest first) for determinism.
    ///
    /// Returns the evicted datagram, or `None` if there was nothing to evict.
    fn evict_lowest_priority(&mut self) -> Option<QueuedDatagram> {
        let (_, group_id) = self.lowest_priority_key()?;

        let (dgram, group_empty) = {
            let Some(group) = self.groups.get_mut(&group_id) else {
                unreachable!("group_id from lowest_priority_key must exist")
            };
            let dgram = group.evict_lowest()?;
            (dgram, group.is_empty())
        };
        self.total_count -= 1;
        self.total_bytes -= charge(dgram.data.len());
        qdebug!(
            "Queue at byte budget ({}/{}), dropping datagram {:?} from group {group_id}",
            self.total_bytes,
            self.max_queued_bytes,
            dgram.id,
        );
        if group_empty {
            self.groups.remove(&group_id);
        }
        Some(dgram)
    }

    /// Returns the outcome for the caller to apply backpressure with. On
    /// [`DatagramQueueOutcome::Overflowed`] the caller reports a
    /// [`DatagramOutcome::Dropped`] event for each tracked ID in `dropped`.
    ///
    /// `send_group_id` is a raw `u64`; `0` means no group (null sendGroup).
    /// Note: `0` is intentionally not a valid `SendGroupId`, but is used here
    /// as a sentinel so that ungrouped datagrams participate in the same
    /// round-robin queue as grouped ones without requiring a separate path.
    pub fn enqueue(
        &mut self,
        data: Vec<u8>,
        id: Option<DatagramId>,
        now: Instant,
        send_group_id: u64,
        send_order: i64,
    ) -> DatagramQueueOutcome {
        let new_charge = charge(data.len());
        if self.total_bytes + new_charge > self.max_queued_bytes
            && self
                .lowest_priority_key()
                .is_some_and(|victim| (send_order, send_group_id) < victim)
        {
            // The incoming datagram is itself the lowest-priority one in the
            // queue, including everything already queued: drop it instead of
            // evicting something that outranks it.
            qdebug!(
                "Queue at byte budget ({}/{}), dropping incoming datagram {id:?} \
                 (group={send_group_id}, order={send_order}): lower priority than everything queued",
                self.total_bytes,
                self.max_queued_bytes
            );
            return DatagramQueueOutcome::Overflowed { dropped: vec![id] };
        }
        // A single incoming datagram can be larger than what any one eviction
        // frees, so evict until there is room rather than at most once. If
        // eviction empties the queue and the datagram alone still exceeds the
        // budget, let it in anyway: refusing it would need a new error path,
        // and the next enqueue evicts it immediately in turn.
        let mut dropped = Vec::new();
        while self.total_bytes + new_charge > self.max_queued_bytes {
            let Some(dgram) = self.evict_lowest_priority() else {
                break;
            };
            dropped.push(dgram.id);
        }

        self.groups
            .entry(send_group_id)
            .or_default()
            .push(send_order, QueuedDatagram::new(data, id, now));
        self.total_count += 1;
        self.total_bytes += new_charge;

        let below_watermark = self
            .high_water_mark
            .is_none_or(|mark| self.total_count < mark);
        // An overflowing queue is full, so backpressure applies regardless of where
        // the high water mark sits.
        let outcome = if dropped.is_empty() {
            if below_watermark {
                DatagramQueueOutcome::Ok
            } else {
                DatagramQueueOutcome::AboveWatermark
            }
        } else {
            DatagramQueueOutcome::Overflowed { dropped }
        };
        qtrace!(
            "Enqueued datagram {id:?} (group={send_group_id}, order={send_order}), \
             total={} ({} bytes), outcome: {outcome:?}",
            self.total_count,
            self.total_bytes,
        );

        outcome
    }

    /// Drain up to `budget` datagrams, expiring old ones first and returning
    /// ready-to-send ones in scheduling order.
    ///
    /// `budget` is how many datagrams the QUIC layer can currently accept, i.e.
    /// [`Connection::remaining_datagram_queue_capacity`][neqo_transport::Connection::remaining_datagram_queue_capacity].
    /// Whatever exceeds it stays queued here, where eviction honours
    /// `send_order` and `max_age`, rather than being handed to the QUIC layer's
    /// fixed-size FIFO only to be head-dropped there — which would discard the
    /// *highest*-priority datagrams of a burst, since they are drained first.
    /// Later drains pick the remainder up as that queue empties, which paces
    /// the handover to what the connection can actually send.
    ///
    /// **Scheduling:** groups are served round-robin; within each group the
    /// highest `send_order` is sent first; equal-order datagrams are FIFO. The
    /// round-robin cursor persists across calls (see [`Self::rr_next`]), so a
    /// drain cut short by its budget resumes at the next group instead of
    /// always starting at the same one.
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
        default_max_age: Duration,
    ) -> (Vec<Option<DatagramId>>, Vec<QueuedDatagram>) {
        // Expiry runs once, up front: after this every remaining datagram is fresh.
        // It is not gated on `budget`, since expiry is not a send: otherwise stale
        // datagrams would pile up while the QUIC layer's queue is full.
        let expired = self.expire_old_datagrams(now, default_max_age);
        let count = budget.min(self.total_count);
        let mut to_send = Vec::with_capacity(count);

        // Round-robin drain: one datagram per group per round, resuming at
        // `rr_next` and wrapping back to the lowest group ID, until the budget
        // is spent. A group is removed as soon as it runs dry, so the next
        // round only visits groups that still have something to send.
        while to_send.len() < count {
            let group_id = self
                .groups
                .range(self.rr_next..)
                .chain(self.groups.iter())
                .map(|(id, _)| *id)
                .next()
                .expect("a queue with datagrams left has a non-empty group");

            let group = self
                .groups
                .get_mut(&group_id)
                .expect("group_id was just read from this map");
            let order = group
                .highest_order()
                .expect("an empty group is removed as soon as it drains");
            let dgram = group
                .pop_front(order)
                .expect("the highest-order bucket is non-empty");
            let drained = group.is_empty();
            qtrace!(
                "Datagram {:?} drained (group={group_id}, order={order})",
                dgram.id
            );
            to_send.push(dgram);
            if drained {
                self.groups.remove(&group_id);
            }
            self.rr_next = group_id.wrapping_add(1);
        }
        self.total_count -= to_send.len();
        self.total_bytes -= to_send.iter().map(|d| charge(d.data.len())).sum::<usize>();

        (expired, to_send)
    }

    /// Every remaining queued datagram, regardless of age. Used when the
    /// session is closing and nothing will call [`Self::drain`] again.
    pub fn take_all(&mut self) -> Vec<QueuedDatagram> {
        self.total_count = 0;
        self.rr_next = 0;
        std::mem::take(&mut self.groups)
            .into_values()
            .flat_map(|group| group.by_order.into_values().flatten())
            .collect()
    }

    /// The instant at which the oldest queued datagram crosses the
    /// effective max-age, if any datagram is queued. The caller uses this to
    /// schedule a wakeup so that expiry is not left to whichever unrelated
    /// timer happens to fire next (see `Http3Connection::next_datagram_expiry`).
    ///
    /// `max_age` is applied uniformly across the whole queue at expiry time
    /// (see [`Self::expire_old_datagrams`]), so the next datagram to expire
    /// is always whichever one has been queued the longest - not
    /// necessarily the next one [`Self::drain`] would send, since scheduling
    /// is priority-, not age-, ordered. `None` if the queue is empty.
    #[must_use]
    pub fn next_expiry(&self, default_max_age: Duration) -> Option<Instant> {
        let max_age = self.max_age.unwrap_or(default_max_age);
        self.groups
            .values()
            .filter_map(GroupQueue::oldest_timestamp)
            .min()?
            .checked_add(max_age)
    }

    /// See [`DatagramQueueCapacity`].
    #[must_use]
    pub const fn capacity(&self) -> DatagramQueueCapacity {
        DatagramQueueCapacity {
            remaining_bytes: self.max_queued_bytes.saturating_sub(self.total_bytes),
            queued_datagrams: self.total_count,
            max_queued_bytes: self.max_queued_bytes,
        }
    }
    #[cfg(test)]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_count
    }

    #[cfg(test)]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_count == 0
    }
}

impl Default for DatagramQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use test_fixture::now;

    use super::*;

    /// Tests that set an explicit max age are unaffected by the default, so
    /// they pass one that never expires anything.
    const NO_DEFAULT: Duration = Duration::MAX;

    fn drain_ids(q: &mut DatagramQueue) -> Vec<u64> {
        let (_, to_send) = q.drain(now(), usize::MAX, NO_DEFAULT);
        to_send
            .into_iter()
            .map(|d| d.id.expect("test datagrams are tracked"))
            .collect()
    }

    // ── Basic behaviour ────────────────────────────────────────────────────────

    #[test]
    fn queue_basic() {
        let mut q = DatagramQueue::new();
        let t = now();

        let outcome = q.enqueue(vec![1, 2, 3], Some(1), t, 0, 0);
        assert_eq!(outcome, DatagramQueueOutcome::Ok);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn capacity_tracks_bytes_and_count() {
        let mut q = DatagramQueue::new();
        q.max_queued_bytes = 3 * charge(2); // room for exactly three 2-byte datagrams
        let t = now();

        assert_eq!(
            q.capacity(),
            DatagramQueueCapacity {
                remaining_bytes: 3 * charge(2),
                queued_datagrams: 0,
                max_queued_bytes: 3 * charge(2),
            }
        );

        q.enqueue(vec![0, 1], Some(1), t, 0, 0);
        assert_eq!(
            q.capacity(),
            DatagramQueueCapacity {
                remaining_bytes: 2 * charge(2),
                queued_datagrams: 1,
                max_queued_bytes: 3 * charge(2),
            }
        );

        // Draining frees capacity back up.
        q.drain(t, usize::MAX, NO_DEFAULT);
        assert_eq!(
            q.capacity(),
            DatagramQueueCapacity {
                remaining_bytes: 3 * charge(2),
                queued_datagrams: 0,
                max_queued_bytes: 3 * charge(2),
            }
        );
    }

    #[test]
    fn high_water_mark() {
        let mut q = DatagramQueue::new();
        q.set_high_water_mark(Some(2));
        let t = now();

        assert_eq!(
            q.enqueue(vec![1], Some(1), t, 0, 0),
            DatagramQueueOutcome::Ok
        );
        assert_eq!(
            q.enqueue(vec![2], Some(2), t, 0, 0),
            DatagramQueueOutcome::AboveWatermark
        );
        assert_eq!(
            q.enqueue(vec![3], Some(3), t, 0, 0),
            DatagramQueueOutcome::AboveWatermark
        );
        assert_eq!(q.len(), 3);
    }

    #[test]

    fn drain_basic() {
        let mut q = DatagramQueue::new();
        let t = now();

        q.enqueue(vec![0, 1], Some(1), t, 0, 0);
        q.enqueue(vec![0, 2], Some(2), t, 0, 0);

        let (expired, to_send) = q.drain(now(), usize::MAX, NO_DEFAULT);
        assert!(expired.is_empty());
        assert_eq!(to_send.len(), 2);
        assert_eq!(to_send[0].id, Some(1));
        assert_eq!(to_send[1].id, Some(2));
        assert!(q.is_empty());
    }

    #[test]
    fn hard_limit_untracked_datagram_drops_silently() {
        let mut queue = DatagramQueue::new();
        let t = now();
        queue.max_queued_bytes = charge(1); // room for exactly one 1-byte datagram

        queue.enqueue(vec![1], None, t, 0, 0);

        assert_eq!(
            queue.enqueue(vec![2], Some(2), t, 0, 0),
            DatagramQueueOutcome::Overflowed {
                dropped: vec![None]
            },
            "an untracked datagram must not be reported with an ID"
        );
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn byte_budget_zero_does_not_panic() {
        let mut queue = DatagramQueue::new();
        queue.max_queued_bytes = 0;
        let t = now();

        // Nothing queued yet to evict, so the first datagram is accepted
        // for free rather than panicking on an empty evict_lowest_priority.
        assert_eq!(
            queue.enqueue(vec![1], Some(1), t, 0, 0),
            DatagramQueueOutcome::Ok
        );
        assert_eq!(
            queue.enqueue(vec![2], Some(2), t, 0, 0),
            DatagramQueueOutcome::Overflowed {
                dropped: vec![Some(1)]
            }
        );
    }

    #[test]
    fn max_age_expiration() {
        let mut queue = DatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Some(Duration::from_millis(100)), t0, NO_DEFAULT);
        queue.enqueue(vec![1], Some(1), t0, 0, 0);

        // Advance time by 150 ms without sleeping.
        let t1 = t0 + Duration::from_millis(150);

        let expired = queue.expire_old_datagrams(t1, NO_DEFAULT);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], Some(1));
        assert!(queue.is_empty());
    }

    #[test]
    fn max_age_expiration_untracked_datagram_reports_nothing() {
        let mut queue = DatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Some(Duration::from_millis(100)), t0, NO_DEFAULT);

        queue.enqueue(vec![1], None, t0, 0, 0);

        let t1 = t0 + Duration::from_millis(150);
        let expired = queue.expire_old_datagrams(t1, NO_DEFAULT);
        assert_eq!(expired, vec![None]);
        assert!(queue.is_empty());
    }

    #[test]
    fn next_expiry_is_none_when_empty() {
        let queue = DatagramQueue::new();
        assert_eq!(queue.next_expiry(NO_DEFAULT), None);
    }

    #[test]
    fn next_expiry_is_none_without_a_max_age() {
        let mut queue = DatagramQueue::new();
        let t = now();
        queue.enqueue(vec![1], Some(1), t, 0, 0);
        assert_eq!(queue.next_expiry(NO_DEFAULT), None);
    }

    #[test]
    fn next_expiry_tracks_the_oldest_datagram_across_groups() {
        let mut queue = DatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Some(Duration::from_millis(50)), t0, NO_DEFAULT);

        queue.enqueue(vec![1], Some(1), t0, 0, 0);
        let t1 = t0 + Duration::from_millis(10);
        // A later-enqueued datagram in a different group must not shadow the
        // oldest one: `next_expiry` looks across every group, not just one.
        queue.enqueue(vec![2], Some(2), t1, 1, 0);

        assert_eq!(
            queue.next_expiry(NO_DEFAULT),
            Some(t0 + Duration::from_millis(50))
        );
    }

    #[test]
    fn next_expiry_advances_once_the_oldest_datagram_is_gone() {
        let mut queue = DatagramQueue::new();
        let t0 = now();
        queue.set_max_age(Some(Duration::from_millis(50)), t0, NO_DEFAULT);

        queue.enqueue(vec![1], Some(1), t0, 0, 0);
        let t1 = t0 + Duration::from_millis(10);
        queue.enqueue(vec![2], Some(2), t1, 0, 0);

        let (_, to_send) = queue.drain(t1, 1, NO_DEFAULT);
        assert_eq!(to_send.len(), 1);
        assert_eq!(
            queue.next_expiry(NO_DEFAULT),
            Some(t1 + Duration::from_millis(50))
        );
    }

    #[test]
    fn next_expiry_uses_the_default_when_no_explicit_max_age_is_set() {
        let mut queue = DatagramQueue::new();
        let t0 = now();
        queue.enqueue(vec![1], Some(1), t0, 0, 0);

        assert_eq!(
            queue.next_expiry(Duration::from_millis(30)),
            Some(t0 + Duration::from_millis(30))
        );
    }

    #[test]
    fn drain() {
        let mut queue = DatagramQueue::new();
        let t = now();

        queue.enqueue(vec![0, 1], Some(1), t, 0, 0);
        queue.enqueue(vec![0, 2], None, t, 0, 0);

        let (expired, to_send) = queue.drain(t, usize::MAX, NO_DEFAULT);

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
        let mut q = DatagramQueue::new();
        let t0 = now();
        q.set_max_age(Some(Duration::from_millis(50)), t0, NO_DEFAULT);

        q.enqueue(vec![1], Some(1), t0, 0, 0);
        q.enqueue(vec![2], None, t0, 0, 0);

        let (expired, to_send) = q.drain(t0 + Duration::from_millis(80), usize::MAX, NO_DEFAULT);
        assert_eq!(expired, vec![Some(1), None]);
        assert!(to_send.is_empty());
    }

    #[test]
    fn below_watermark_recovers_after_drain() {
        let mut q = DatagramQueue::new();
        let t = now();
        q.set_high_water_mark(Some(2));

        assert_eq!(
            q.enqueue(vec![1], Some(1), t, 0, 0),
            DatagramQueueOutcome::Ok
        );
        assert_eq!(
            q.enqueue(vec![2], Some(2), t, 0, 0),
            DatagramQueueOutcome::AboveWatermark
        );

        drop(q.drain(t, usize::MAX, NO_DEFAULT));

        assert_eq!(
            q.enqueue(vec![3], Some(3), t, 0, 0),
            DatagramQueueOutcome::Ok,
            "draining the queue must put it back below the high water mark"
        );
    }

    // ── Priority ordering within a single group ────────────────────────────────

    #[test]
    fn priority_order_within_group() {
        // Enqueue low-priority datagrams first, then high-priority.
        // The queue should send highest send_order first.
        let mut q = DatagramQueue::new();
        let t = now();
        q.enqueue(vec![0, 1], Some(1), t, 0, 10); // order 10
        q.enqueue(vec![0, 2], Some(2), t, 0, 30); // order 30 (highest)
        q.enqueue(vec![0, 3], Some(3), t, 0, 20); // order 20

        let sent = drain_ids(&mut q);
        assert_eq!(sent, vec![2, 3, 1], "highest order first");
    }

    #[test]
    fn fifo_within_same_order() {
        let mut q = DatagramQueue::new();
        // All same group, same order → FIFO.
        let t = now();
        q.enqueue(vec![0, 10], Some(10), t, 0, 5);
        q.enqueue(vec![0, 11], Some(11), t, 0, 5);
        q.enqueue(vec![0, 12], Some(12), t, 0, 5);

        assert_eq!(drain_ids(&mut q), vec![10, 11, 12]);
    }

    #[test]
    fn priority_mixed_orders_same_group() {
        let mut q = DatagramQueue::new();
        let t = now();
        q.enqueue(vec![0, 1], Some(1), t, 0, 1);
        q.enqueue(vec![0, 2], Some(2), t, 0, 3);
        q.enqueue(vec![0, 3], Some(3), t, 0, 1); // same as id=1
        q.enqueue(vec![0, 4], Some(4), t, 0, 3); // same as id=2

        // Expected: id=2 then id=4 (order 3), then id=1 then id=3 (order 1)
        assert_eq!(drain_ids(&mut q), vec![2, 4, 1, 3]);
    }

    // ── Round-robin between groups ─────────────────────────────────────────────

    #[test]
    fn round_robin_two_groups() {
        let mut q = DatagramQueue::new();
        // Group A (id 0): 3 datagrams, Group B (id 1): 2 datagrams.
        // Round-robin should interleave: A, B, A, B, A.
        let t = now();
        q.enqueue(vec![0, 1], Some(1), t, 0, 0); // group A
        q.enqueue(vec![0, 2], Some(2), t, 1, 0); // group B
        q.enqueue(vec![0, 3], Some(3), t, 0, 0); // group A
        q.enqueue(vec![0, 4], Some(4), t, 1, 0); // group B
        q.enqueue(vec![0, 5], Some(5), t, 0, 0); // group A

        assert_eq!(drain_ids(&mut q), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn round_robin_priority_across_groups() {
        // Each group has datagrams at different send_orders.
        // Group 0: order 10, order 5
        // Group 1: order 20, order 1
        let mut q = DatagramQueue::new();
        let t = now();
        q.enqueue(vec![0, 1], Some(1), t, 0, 10);
        q.enqueue(vec![0, 2], Some(2), t, 0, 5);
        q.enqueue(vec![0, 3], Some(3), t, 1, 20);
        q.enqueue(vec![0, 4], Some(4), t, 1, 1);

        // Round 1: group 0 sends id=1 (order 10), group 1 sends id=3 (order 20)
        // Round 2: group 0 sends id=2 (order 5), group 1 sends id=4 (order 1)
        assert_eq!(drain_ids(&mut q), vec![1, 3, 2, 4]);
    }

    #[test]
    fn round_robin_three_groups() {
        let mut q = DatagramQueue::new();
        let t = now();
        // One datagram per group; should all be sent in one round.
        q.enqueue(vec![0, 1], Some(1), t, 10, 0);
        q.enqueue(vec![0, 2], Some(2), t, 20, 0);
        q.enqueue(vec![0, 3], Some(3), t, 30, 0);

        assert_eq!(drain_ids(&mut q), vec![1, 2, 3]);
    }

    // ── Default max age ────────────────────────────────────────────────────────

    #[test]
    fn default_max_age_falls_back_before_the_first_rtt_sample() {
        // min_rtt is zero until the connection measures one; that must not
        // collapse onto the floor.
        assert_eq!(
            default_max_age(Duration::ZERO),
            DEFAULT_INITIAL_RTT * DEFAULT_MAX_AGE_RTT_MULTIPLIER_NUM
                / DEFAULT_MAX_AGE_RTT_MULTIPLIER_DEN
        );
    }

    #[test]
    fn default_max_age_scales_with_rtt() {
        // Above the floor: scales at 1.25x.
        assert_eq!(
            default_max_age(Duration::from_millis(50)),
            Duration::from_micros(62_500)
        );
        // Below the floor: clamped to the 20ms floor rather than following RTT
        // down.
        assert_eq!(
            default_max_age(Duration::from_millis(3)),
            Duration::from_millis(20)
        );
    }

    #[test]
    fn unset_max_age_uses_the_default() {
        let mut q = DatagramQueue::new();
        let t0 = now();
        // Never call set_max_age: the application left outgoingMaxAge null.
        q.enqueue(vec![1], Some(1), t0, 0, 0);

        let default = Duration::from_millis(20);
        let (expired, to_send) = q.drain(t0 + Duration::from_millis(50), 10, default);
        assert_eq!(
            expired,
            vec![Some(1)],
            "the default bounds an unset max age"
        );
        assert!(to_send.is_empty());
    }

    #[test]
    fn explicit_max_age_overrides_the_default() {
        let mut q = DatagramQueue::new();
        let t0 = now();
        // A longer explicit value must win over a shorter default.
        q.set_max_age(
            Some(Duration::from_millis(100)),
            t0,
            Duration::from_millis(5),
        );
        q.enqueue(vec![1], Some(1), t0, 0, 0);

        let (expired, to_send) =
            q.drain(t0 + Duration::from_millis(50), 10, Duration::from_millis(5));
        assert!(expired.is_empty());
        assert_eq!(to_send.len(), 1);
    }

    #[test]
    fn clearing_max_age_restores_the_default() {
        let mut q = DatagramQueue::new();
        let t0 = now();
        let default = Duration::from_millis(20);

        q.set_max_age(Some(Duration::from_millis(100)), t0, default);
        // outgoingMaxAge = null (or 0, which the setter maps to null).
        q.set_max_age(None, t0, default);
        q.enqueue(vec![1], Some(1), t0, 0, 0);

        let (expired, _) = q.drain(t0 + Duration::from_millis(50), 10, default);
        assert_eq!(expired, vec![Some(1)], "the default is back in force");
    }

    #[test]
    fn explicit_max_age_is_clamped_to_the_1ms_floor() {
        let mut q = DatagramQueue::new();
        let t0 = now();
        let default = Duration::from_millis(20);
        q.set_max_age(Some(Duration::from_micros(1)), t0, default);
        q.enqueue(vec![1], Some(1), t0, 0, 0);

        let (expired, to_send) = q.drain(t0 + Duration::from_micros(500), 10, default);
        assert!(
            expired.is_empty(),
            "clamped to the 1ms floor, so 500us old is not yet expired"
        );
        assert_eq!(to_send.len(), 1);
    }

    #[test]
    fn explicit_max_age_ceiling_floor_on_low_rtt_paths() {
        let mut q = DatagramQueue::new();
        let t0 = now();
        // A low-RTT path: the default is well under the 100ms ceiling floor.
        let default = Duration::from_millis(20);
        q.set_max_age(Some(Duration::from_millis(300)), t0, default);
        q.enqueue(vec![1], Some(1), t0, 0, 0);

        let (expired, _) = q.drain(t0 + Duration::from_millis(150), 10, default);
        assert_eq!(
            expired,
            vec![Some(1)],
            "300ms must be clamped to the 100ms ceiling floor even though the default is 20ms"
        );
    }

    #[test]
    fn explicit_max_age_ceiling_tracks_a_higher_default() {
        let mut q = DatagramQueue::new();
        let t0 = now();
        // A high-RTT path (e.g. ~200ms min_rtt): the default already exceeds
        // the 100ms ceiling floor, so the ceiling must track it up rather than
        // clamping down to 100ms.
        let default = Duration::from_millis(250);
        q.set_max_age(Some(Duration::from_millis(300)), t0, default);
        q.enqueue(vec![1], Some(1), t0, 0, 0);

        let (expired, _) = q.drain(t0 + Duration::from_millis(270), 10, default);
        assert_eq!(
            expired,
            vec![Some(1)],
            "an explicit value above a 250ms default must be clamped to 250ms, not to 100ms"
        );
    }

    // ── Budgeted drain ─────────────────────────────────────────────────────────

    #[test]
    fn drain_stops_at_budget() {
        let mut q = DatagramQueue::new();
        let t = now();
        for i in 1..=5 {
            q.enqueue(vec![0, i], Some(u64::from(i)), t, 0, 0);
        }

        let (_, to_send) = q.drain(t, 2, NO_DEFAULT);
        assert_eq!(
            to_send.iter().map(|d| d.id).collect::<Vec<_>>(),
            vec![Some(1), Some(2)]
        );
        assert_eq!(q.len(), 3, "the rest stays queued");
    }

    #[test]
    fn drain_budget_zero_keeps_everything() {
        let mut q = DatagramQueue::new();
        let t = now();
        q.enqueue(vec![1], Some(1), t, 0, 0);

        let (expired, to_send) = q.drain(t, 0, NO_DEFAULT);
        assert!(expired.is_empty());
        assert!(to_send.is_empty());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn budgeted_drain_expires_even_with_no_budget() {
        // Expiry is not a send, so it must not be gated on the QUIC layer
        // having room; otherwise stale datagrams pile up while it is full.
        let mut q = DatagramQueue::new();
        let t0 = now();
        q.set_max_age(Some(Duration::from_millis(50)), t0, NO_DEFAULT);
        q.enqueue(vec![1], Some(1), t0, 0, 0);

        let (expired, to_send) = q.drain(t0 + Duration::from_millis(80), 0, NO_DEFAULT);
        assert_eq!(expired, vec![Some(1)]);
        assert!(to_send.is_empty());
        assert!(q.is_empty());
    }

    #[test]
    fn budgeted_drain_sends_highest_priority_first() {
        // The whole point of budgeting: when only part of a burst fits, the
        // part that goes out is the high-priority part.
        let mut q = DatagramQueue::new();
        let t = now();
        q.enqueue(vec![0, 1], Some(1), t, 0, 1);
        q.enqueue(vec![0, 2], Some(2), t, 0, 100);
        q.enqueue(vec![0, 3], Some(3), t, 0, 50);

        let (_, to_send) = q.drain(t, 1, NO_DEFAULT);
        assert_eq!(
            to_send.iter().map(|d| d.id).collect::<Vec<_>>(),
            vec![Some(2)]
        );
    }

    #[test]
    fn partial_drain_resumes_round_robin_across_calls() {
        // One datagram per group, three groups, one datagram of budget per
        // call: each group must get a turn instead of group 0 taking every one.
        let mut q = DatagramQueue::new();
        let t = now();
        for g in 0..3_u64 {
            q.enqueue(vec![0, 1], Some(g), t, g, 0);
        }

        let mut served = Vec::new();
        for _ in 0..3 {
            let (_, to_send) = q.drain(t, 1, NO_DEFAULT);
            served.extend(to_send.into_iter().filter_map(|d| d.id));
        }

        assert_eq!(served, vec![0, 1, 2]);
        assert!(q.is_empty());
    }

    #[test]
    fn round_robin_cursor_wraps() {
        let mut q = DatagramQueue::new();
        let t = now();
        // Two datagrams in each of two groups.
        for g in 0..2_u64 {
            for i in 0..2_u64 {
                q.enqueue(vec![0, 1], Some(g * 10 + i), t, g, 0);
            }
        }

        // Budget of one per call: alternate groups, wrapping back to group 0.
        let mut served = Vec::new();
        for _ in 0..4 {
            let (_, to_send) = q.drain(t, 1, NO_DEFAULT);
            served.extend(to_send.into_iter().filter_map(|d| d.id));
        }

        assert_eq!(served, vec![0, 10, 1, 11]);
        assert!(q.is_empty());
    }

    // ── Byte-budget eviction ───────────────────────────────────────────────────

    #[test]
    fn byte_budget_evicts_lowest_priority() {
        let mut q = DatagramQueue::new();
        q.max_queued_bytes = 3 * charge(2); // room for exactly three 2-byte datagrams

        // Fill with order-0 datagrams.
        let t = now();
        q.enqueue(vec![0, 1], Some(1), t, 0, 0);
        q.enqueue(vec![0, 2], Some(2), t, 0, 0);
        q.enqueue(vec![0, 3], Some(3), t, 0, 0);
        assert_eq!(q.len(), 3);

        // Adding a higher-priority datagram should evict the lowest-priority one (id=1, order 0).
        assert_eq!(
            q.enqueue(vec![0, 4], Some(4), t, 0, 10),
            DatagramQueueOutcome::Overflowed {
                dropped: vec![Some(1)]
            }
        );
        assert_eq!(q.len(), 3);

        // The high-priority datagram should be sent first.
        let sent = drain_ids(&mut q);
        assert_eq!(sent[0], 4, "highest order (10) sent first");
    }

    #[test]
    fn byte_budget_evicts_across_groups() {
        let mut q = DatagramQueue::new();
        let t = now();
        q.max_queued_bytes = 2 * charge(2); // room for exactly two 2-byte datagrams

        // Group 0 has order 5, group 1 has order 1 (lower priority).
        q.enqueue(vec![0, 1], Some(1), t, 0, 5);
        q.enqueue(vec![0, 2], Some(2), t, 1, 1);

        // Adding a third datagram evicts the globally lowest-priority one (id=2, order 1).
        assert_eq!(
            q.enqueue(vec![0, 3], Some(3), t, 0, 5),
            DatagramQueueOutcome::Overflowed {
                dropped: vec![Some(2)]
            }
        );
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn byte_budget_rejects_lower_priority_newcomer() {
        let mut q = DatagramQueue::new();
        q.max_queued_bytes = 3 * charge(2); // room for exactly three 2-byte datagrams

        // Fill with high-priority (order 10) datagrams.
        let t = now();
        q.enqueue(vec![0, 1], Some(1), t, 0, 10);
        q.enqueue(vec![0, 2], Some(2), t, 0, 10);
        q.enqueue(vec![0, 3], Some(3), t, 0, 10);
        assert_eq!(q.len(), 3);

        // A lower-priority newcomer must not evict any of the higher-priority
        // datagrams already queued: it is the one that gets dropped.
        assert_eq!(
            q.enqueue(vec![0, 4], Some(4), t, 0, 0),
            DatagramQueueOutcome::Overflowed {
                dropped: vec![Some(4)]
            }
        );
        assert_eq!(q.len(), 3);
        assert_eq!(
            drain_ids(&mut q),
            vec![1, 2, 3],
            "the queued high-priority datagrams are untouched"
        );
    }

    #[test]
    fn byte_budget_rejects_lower_priority_newcomer_across_groups() {
        let mut q = DatagramQueue::new();
        let t = now();
        q.max_queued_bytes = 2 * charge(2); // room for exactly two 2-byte datagrams

        // Group 0 has order 5, group 1 has order 1 (lower priority already queued).
        q.enqueue(vec![0, 1], Some(1), t, 0, 5);
        q.enqueue(vec![0, 2], Some(2), t, 1, 1);

        // A newcomer with a lower priority than the current global lowest
        // (group 1, order 1) must be dropped itself, not evict group 1's datagram.
        assert_eq!(
            q.enqueue(vec![0, 3], Some(3), t, 2, 0),
            DatagramQueueOutcome::Overflowed {
                dropped: vec![Some(3)]
            }
        );
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn byte_budget_evicts_multiple_datagrams_for_one_large_one() {
        // A single incoming datagram can be larger than what any one eviction
        // frees, so eviction must loop rather than run at most once.
        let mut q = DatagramQueue::new();
        let t = now();
        q.max_queued_bytes = 4 * charge(1); // room for exactly four 1-byte datagrams

        q.enqueue(vec![1], Some(1), t, 0, 0);
        q.enqueue(vec![2], Some(2), t, 0, 0);
        q.enqueue(vec![3], Some(3), t, 0, 0);
        q.enqueue(vec![4], Some(4), t, 0, 0);
        assert_eq!(q.len(), 4);

        // A 67-byte datagram (charge 131) needs to evict three of the
        // existing 1-byte ones (each freeing only 65) before it fits: after
        // evicting two, 130 bytes are free, and 130 + 131 still exceeds the
        // 260-byte budget.
        assert_eq!(
            q.enqueue(vec![9; 67], Some(5), t, 0, 0),
            DatagramQueueOutcome::Overflowed {
                dropped: vec![Some(1), Some(2), Some(3)]
            }
        );
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn byte_budget_same_count() {
        // Backwards-compatibility: with one group and equal priorities, behaves like before.
        let mut q = DatagramQueue::new();
        let t = now();
        q.max_queued_bytes = 3 * charge(1); // room for exactly three 1-byte datagrams
        q.enqueue(vec![1], Some(1), t, 0, 0);
        q.enqueue(vec![2], Some(2), t, 0, 0);
        q.enqueue(vec![3], Some(3), t, 0, 0);
        q.enqueue(vec![4], Some(4), t, 0, 0);
        assert_eq!(q.len(), 3);
    }

    // ── Max-age expiry ─────────────────────────────────────────────────────────

    #[test]
    fn max_age_expiry_during_drain() {
        let mut q = DatagramQueue::new();
        let t = now();
        q.set_max_age(Some(Duration::from_millis(50)), t, NO_DEFAULT);

        q.enqueue(vec![0, 1], Some(1), t, 0, 0);
        let t1 = t + Duration::from_millis(80);
        q.enqueue(vec![0, 2], Some(2), t1, 0, 0);

        let (expired, to_send) = q.drain(t1, usize::MAX, NO_DEFAULT);
        let sent_ids: Vec<_> = to_send.iter().map(|d| d.id).collect();
        assert_eq!(expired, vec![Some(1)]);
        assert_eq!(sent_ids, vec![Some(2)]);
        assert!(q.is_empty());
    }

    #[test]
    fn max_age_expiry_high_priority_bucket() {
        let mut q = DatagramQueue::new();
        let t = now();
        q.set_max_age(Some(Duration::from_millis(50)), t, NO_DEFAULT);

        q.enqueue(vec![0, 1], Some(1), t, 0, 100); // high priority, will expire
        let t1 = t + Duration::from_millis(80);
        q.enqueue(vec![0, 2], Some(2), t1, 0, 1); // low priority, fresh

        let (_, to_send) = q.drain(t1, usize::MAX, NO_DEFAULT);
        let sent_ids: Vec<_> = to_send.iter().map(|d| d.id).collect();
        assert_eq!(
            sent_ids,
            vec![Some(2)],
            "lower-priority-but-fresh datagram is sent"
        );
    }

    #[test]
    fn partial_drain_leaves_remainder_for_a_later_call() {
        let mut q = DatagramQueue::new();
        let t = now();
        for i in 1..=3 {
            q.enqueue(vec![0, i], Some(u64::from(i)), t, 0, 0);
        }

        let mut served = Vec::new();
        for _ in 0..3 {
            let (_, to_send) = q.drain(t, 1, NO_DEFAULT);
            served.extend(to_send.into_iter().filter_map(|d| d.id));
        }

        assert_eq!(served, vec![1, 2, 3]);
        assert!(q.is_empty());
    }

    #[test]
    fn round_robin_cursor_advances_under_partial_drain() {
        // Three groups, two datagrams each, drained two at a time. Without
        // advancing `rr_next` past whatever the budget cut off, the group
        // that missed its turn this round would be pushed to the back of
        // every future round too, instead of just this one.
        let mut q = DatagramQueue::new();
        let t = now();
        q.enqueue(vec![0, 1], Some(100), t, 0, 0);
        q.enqueue(vec![0, 2], Some(110), t, 1, 0);
        q.enqueue(vec![0, 3], Some(120), t, 2, 0);
        q.enqueue(vec![0, 4], Some(101), t, 0, 0);
        q.enqueue(vec![0, 5], Some(111), t, 1, 0);
        q.enqueue(vec![0, 6], Some(121), t, 2, 0);

        let mut served = Vec::new();
        for _ in 0..3 {
            let (_, to_send) = q.drain(t, 2, NO_DEFAULT);
            served.extend(to_send.into_iter().filter_map(|d| d.id));
        }

        assert_eq!(
            served,
            vec![100, 110, 120, 101, 111, 121],
            "group 2 gets its first turn in round 2, not pushed back to round 3"
        );
        assert!(q.is_empty());
    }
}
