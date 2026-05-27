// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is test code.")]

use std::{
    cmp::{max, min},
    collections::VecDeque,
    fmt::{self, Debug, Display},
    time::{Duration, Instant},
};

use neqo_common::{Datagram, Dscp, Ecn, Tos, qinfo, qtrace};
use neqo_transport::Output;

use super::Node;

/// One second in nanoseconds.
const ONE_SECOND_NS: u128 = 1_000_000_000;

const CODEL_TARGET: Duration = Duration::from_millis(5);
const CODEL_INTERVAL: Duration = Duration::from_millis(100);

/// `CoDel` (RFC 8289) algorithm state.
#[derive(Clone, Default)]
struct CodelState {
    /// When sojourn time first exceeded TARGET in the current busy period,
    /// offset by INTERVAL. None when sojourn is below target or queue is empty.
    first_above_time: Option<Instant>,
    /// Whether we are currently in the "dropping" (signalling) state.
    dropping: bool,
    /// How many marks/drops have occurred in the current dropping interval.
    count: u32,
    /// `count` at entry to the last dropping period; used for fast restart.
    lastcount: u32,
    /// The time at which the next mark/drop is due (only valid when dropping).
    drop_next: Option<Instant>,
}

impl CodelState {
    /// Update the `CoDel` state machine for the packet just dequeued.
    /// Returns true if congestion should be signalled for this packet.
    fn update(&mut self, sojourn: Duration, queue_empty: bool, now: Instant) -> bool {
        // Track when sojourn first exceeded TARGET.
        if sojourn < CODEL_TARGET || queue_empty {
            self.first_above_time = None;
        } else if self.first_above_time.is_none() {
            self.first_above_time = Some(now + CODEL_INTERVAL);
        }

        let over_interval = self.first_above_time.is_some_and(|fat| now >= fat);

        if self.dropping {
            if !over_interval {
                // ok_to_drop became false (RFC 8289): leave dropping state.
                self.dropping = false;
            } else if let Some(dn) = self.drop_next.filter(|&dn| now >= dn) {
                // Time for another mark/drop in the current dropping interval.
                // RFC 8289: next drop is relative to the previous drop_next, not now.
                self.count += 1;
                self.drop_next = Some(self.control_law(dn));
                return true;
            }
        } else if over_interval {
            // Enter dropping state.
            self.dropping = true;
            // Fast restart: if we re-enter quickly, ramp up from where we left off
            // rather than starting from count=1 (RFC 8289 §4: 16×INTERVAL window).
            let delta = self.count.saturating_sub(self.lastcount);
            let recently_dropping = self
                .drop_next
                .is_some_and(|dn| now.saturating_duration_since(dn) < CODEL_INTERVAL * 16);
            self.count = if delta > 1 && recently_dropping {
                delta
            } else {
                1
            };
            self.lastcount = self.count;
            self.drop_next = Some(self.control_law(now));
            return true;
        }

        false
    }

    /// Apply the `CoDel` congestion signal: CE-mark ECT(0) packets, drop others.
    /// Returns `None` if the packet was dropped.
    fn signal(dgram: &Datagram) -> Option<Datagram> {
        let tos = dgram.tos();
        let ecn = Ecn::from(tos);
        if ecn.is_ect() {
            assert_ne!(ecn, Ecn::Ect1, "ECT(1)/L4S is not implemented");
            qtrace!(
                "codel marking {} bytes (sojourn exceeded target)",
                dgram.len()
            );
            Some(Datagram::new(
                dgram.source(),
                dgram.destination(),
                Tos::from((Dscp::from(tos), Ecn::Ce)),
                dgram.to_vec(),
            ))
        } else {
            qtrace!(
                "codel dropping {} bytes (sojourn exceeded target)",
                dgram.len()
            );
            None
        }
    }

    /// next = now + INTERVAL / sqrt(count)
    fn control_law(&self, base: Instant) -> Instant {
        base + Duration::from_secs_f64(
            CODEL_INTERVAL.as_secs_f64() / f64::from(self.count.max(1)).sqrt(),
        )
    }
}

#[derive(Clone)]
struct Stats {
    /// The number of packets received.
    received: usize,
    /// The number of packets marked.
    marked: usize,
    /// The number of packets dropped.
    dropped: usize,
    /// The number of packets delivered.
    delivered: usize,
    /// The maximum amount of queue capacity ever used.
    /// As packets leave the queue as soon as they start being used, this doesn't
    /// count them.
    maxq: usize,
    /// The buffer capacity.
    capacity: usize,

    /// The start time.
    start_time: Option<Instant>,
    /// The start time.
    last_update: Option<Instant>,
    /// Accumulated queue usage multiplied by time.
    /// This is in units of `bytes * nanoseconds`, which will get big.
    /// For a test that transfers 1 gigabyte and takes a month,
    /// that's still well within 64 bits.  Use `u128` to be safe.
    cumulative_usage: u128,
}

impl Stats {
    // Const constructor for compile-time initialization in TailDrop::new().
    // Could derive Default if const was not required.
    const fn new() -> Self {
        Self {
            received: 0,
            marked: 0,
            dropped: 0,
            delivered: 0,
            maxq: 0,
            capacity: 0,
            start_time: None,
            last_update: None,
            cumulative_usage: 0,
        }
    }

    fn update_maxq(&mut self, used: usize) {
        self.maxq = max(self.maxq, used);
    }

    fn set_start(&mut self, now: Instant, capacity: usize) {
        assert!(self.start_time.is_none());
        self.start_time = Some(now);
        self.last_update = Some(now);
        self.capacity = capacity;
    }

    /// Given an updated time and current usage level,
    /// compute the elapsed time and add that to the usage tally.
    /// This should be called *before* changing the usage level.
    /// Only do this when we have a `last_update` value set,
    /// which is set once setup is complete.
    fn accumulate_usage(&mut self, now: Instant, usage: usize) {
        if let Some(last_update) = self.last_update {
            let elapsed = now.duration_since(last_update).as_nanos();
            self.cumulative_usage += elapsed * u128::try_from(usage).unwrap();
            self.last_update = Some(now);
        }
    }
}

impl Display for Stats {
    #[expect(clippy::cast_precision_loss, reason = "precision loss in an estimate")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let utilization =
            if let (Some(last_update), Some(start_time)) = (self.last_update, self.start_time) {
                let t = last_update.duration_since(start_time);
                self.cumulative_usage as f64 / t.as_nanos() as f64 / self.capacity as f64
            } else {
                0.0
            };
        write!(
            f,
            "rx {} mark {} drop {} tx {} maxq {} util {utilization}",
            self.received, self.marked, self.dropped, self.delivered, self.maxq,
        )
    }
}

/// This models a link with a tail drop router at the front of it.
/// ECN marking uses `CoDel` (RFC 8289) with TARGET=5ms / INTERVAL=100ms.
#[derive(Clone)]
pub struct TailDrop {
    /// An overhead associated with each entry.  This accounts for
    /// layer 2, IP, and UDP overheads.
    overhead: usize,
    /// The rate at which bytes egress the link, in bytes per second.
    rate: usize,
    /// The depth of the queue, in bytes.
    capacity: usize,
    /// Whether to apply ECN markings.
    ecn: bool,

    /// A counter for how many bytes are enqueued.
    used: usize,
    /// A queue of unsent datagrams with their enqueue timestamps.
    queue: VecDeque<(Instant, Datagram)>,
    /// The time that the next datagram can enter the link.
    /// Includes any sub-ns remainder (which helps absorb rounding errors).
    next_deque: Option<(Instant, u32)>,

    /// The time it takes a byte to exit the other end of the link.
    delay: Duration,
    /// The packets that are on the link and when they can be delivered.
    on_link: VecDeque<(Instant, Datagram)>,

    stats: Stats,

    /// `CoDel` state — only consulted when `ecn` is true.
    codel: CodelState,
}

impl TailDrop {
    /// Make a new taildrop node with the given rate, ECN, queue capacity, and link delay.
    /// When ECN is enabled, `CoDel` (TARGET=5ms / INTERVAL=100ms) CE-marks ECT-capable
    /// packets when their sojourn time exceeds the target.
    ///
    /// # Panics
    ///
    /// Panics if rate is zero or over 1Gbps.
    #[must_use]
    pub fn new(rate: usize, capacity: usize, ecn: bool, delay: Duration) -> Self {
        assert!(rate != 0, "zero rate gets you nowhere");
        assert!(rate <= 1_000_000_000, "rates over 1Gbps are not supported");
        Self {
            overhead: 80,
            rate,
            capacity,
            ecn,
            used: 0,
            queue: VecDeque::new(),
            next_deque: None,
            delay,
            on_link: VecDeque::new(),
            stats: Stats::new(),
            codel: CodelState::default(),
        }
    }

    /// A tail drop queue on a 10Mbps link (approximated to 1 million bytes per second)
    /// with a fat 32k buffer (about 30ms), and the default forward delay of 50ms.
    #[must_use]
    pub fn dsl_downlink() -> Self {
        Self::new(1_000_000, 32_768, false, Duration::from_millis(50))
    }

    /// Cut uplink to one fifth of the downlink (2Mbps), and reduce the buffer to 1/4.
    #[must_use]
    pub fn dsl_uplink() -> Self {
        Self::new(200_000, 8_192, false, Duration::from_millis(50))
    }

    /// How "big" is this datagram, accounting for overheads.
    /// This approximates by using the same overhead for storing in the queue
    /// and for sending on the wire.
    fn size(&self, d: &Datagram) -> usize {
        d.len() + self.overhead
    }

    /// Start sending a datagram.
    /// Send at the given time, with the given sub-nanosecond extra delay.
    fn send(&mut self, d: Datagram, now: Instant, sub_ns: u32) {
        // How many bytes are we "transmitting"?
        let sz = u128::try_from(self.size(&d)).unwrap();

        // Calculate how long it takes to put the packet on the link.
        // Perform the calculation based on 2^32 seconds and save any remainder.
        // This ensures that high rates and small packets don't result in rounding
        // down times too badly.
        // Duration consists of a u64 and a u32, so we have 32 high bits to spare.
        let t =
            sz * (ONE_SECOND_NS << 32) / u128::try_from(self.rate).unwrap() + u128::from(sub_ns);
        let send_ns = u64::try_from(t >> 32).unwrap();
        let deque_time = now + Duration::from_nanos(send_ns);
        let sub_ns = u32::try_from(t & u128::from(u32::MAX)).unwrap();
        self.next_deque = Some((deque_time, sub_ns));

        // Now work out when the packet is fully received at the other end of
        // the link. Setup to deliver the packet then.
        let delivery_time = deque_time + self.delay;
        self.on_link.push_back((delivery_time, d));
    }

    /// Enqueue for sending.  Maybe.  If this overflows the queue, drop it instead.
    fn maybe_enqueue(&mut self, d: Datagram, now: Instant) {
        self.stats.received += 1;
        if self.next_deque.is_none() {
            // Nothing in the queue and nothing still sending.
            debug_assert!(self.queue.is_empty());
            self.send(d, now, 0);
        } else if self.used + self.size(&d) <= self.capacity {
            self.stats.accumulate_usage(now, self.used);
            self.used += self.size(&d);
            self.stats.update_maxq(self.used);
            self.queue.push_back((now, d));
        } else {
            qtrace!("taildrop dropping {} bytes", d.len());
            self.stats.dropped += 1;
        }
    }

    /// If the last packet that was sending has been sent, start sending
    /// the next one.
    fn maybe_send(&mut self, now: Instant) {
        if let Some((t, subns)) = self.next_deque {
            if now < t {
                return;
            }

            self.stats.accumulate_usage(now, self.used);
            if let Some(d) = self.codel_dequeue(now) {
                self.send(d, t, subns);
            } else {
                self.next_deque = None;
            }
        }
    }

    /// Pop the front packet and apply `CoDel` if ECN is enabled.
    /// Returns `None` if the packet was dropped (do not send).
    fn codel_dequeue(&mut self, now: Instant) -> Option<Datagram> {
        let (enqueue_time, pkt) = self.queue.pop_front()?;
        self.used -= self.size(&pkt);

        if !self.ecn {
            return Some(pkt);
        }

        let sojourn = now.saturating_duration_since(enqueue_time);
        if self.codel.update(sojourn, self.used == 0, now) {
            let result = CodelState::signal(&pkt);
            if result.is_some() {
                self.stats.marked += 1;
            } else {
                self.stats.dropped += 1;
            }
            result
        } else {
            Some(pkt)
        }
    }
}

impl Node for TailDrop {
    fn prepare(&mut self, now: Instant) {
        self.stats.set_start(now, self.capacity);
    }

    fn process(&mut self, d: Option<Datagram>, now: Instant) -> Output {
        if let Some(dgram) = d {
            self.maybe_enqueue(dgram, now);
        }

        self.maybe_send(now);

        if let Some((t, _)) = self.on_link.front() {
            if *t <= now {
                let (_, d) = self.on_link.pop_front().unwrap();
                self.stats.delivered += 1;
                Output::Datagram(d)
            } else {
                let next = self
                    .next_deque
                    .as_ref()
                    .map_or(*t, |(next, _)| min(*next, *t));
                Output::Callback(next - now)
            }
        } else {
            Output::None
        }
    }

    fn print_summary(&self, test_name: &str) {
        qinfo!("{test_name}: taildrop: {stats}", stats = self.stats);
    }
}

impl Debug for TailDrop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("taildrop")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{Duration, Instant},
    };

    use neqo_common::{Datagram, Dscp, Ecn, Tos};
    use neqo_transport::Output;

    use crate::{
        now,
        sim::{Node as _, network::TailDrop},
    };

    fn make_datagram(ecn: Ecn) -> Datagram {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let tos = Tos::from((Dscp::default(), ecn));
        Datagram::new(addr, addr, tos, vec![0u8; 1200])
    }

    fn drain(td: &mut TailDrop, now: Instant) {
        let mut t = now;
        loop {
            match td.process(None, t) {
                Output::Callback(d) => t += d,
                Output::Datagram(_) => {}
                Output::None => return,
            }
        }
    }

    /// Packets with sojourn well below TARGET should not be marked or dropped.
    #[test]
    fn no_mark_below_target() {
        // 100 Mbps link with a large buffer; packets drain in < 1ms so sojourn < TARGET.
        let mut td = TailDrop::new(100_000_000, 1_000_000, true, Duration::from_millis(1));
        let t0 = now();
        td.prepare(t0);

        for _ in 0..10 {
            td.process(Some(make_datagram(Ecn::Ect0)), t0);
        }
        drain(&mut td, t0);

        assert_eq!(td.stats.marked, 0);
        assert_eq!(td.stats.dropped, 0);
    }

    /// Packets that queue for longer than INTERVAL should trigger a mark (ECN) or drop.
    #[test]
    fn marks_after_interval() {
        // 100 Kbps link forces long queuing (>>5ms sojourn).
        let mut td = TailDrop::new(100_000, 500_000, true, Duration::from_millis(1));
        let t0 = now();
        td.prepare(t0);

        // Enqueue enough packets to fill >100ms of link time.
        for _ in 0..100 {
            td.process(Some(make_datagram(Ecn::Ect0)), t0);
        }

        // Advance well past INTERVAL so CoDel has time to act.
        let mut t = t0;
        for _ in 0..500 {
            t += Duration::from_millis(1);
            td.process(None, t);
        }

        assert!(
            td.stats.marked > 0,
            "expected marks after INTERVAL, got stats: {}",
            td.stats
        );
    }

    /// After entering dropping state, successive marks should be spaced at
    /// decreasing intervals (control law: INTERVAL / sqrt(count)).
    #[test]
    fn mark_rate_increases() {
        // Very slow link to ensure long sojourn times.
        let mut td = TailDrop::new(50_000, 1_000_000, true, Duration::from_millis(1));
        let t0 = now();
        td.prepare(t0);

        for _ in 0..200 {
            td.process(Some(make_datagram(Ecn::Ect0)), t0);
        }

        // Collect times at which marks occur.
        let mut mark_times = Vec::new();
        let mut t = t0;
        while mark_times.len() < 4 {
            t += Duration::from_millis(1);
            let prev = td.stats.marked;
            td.process(None, t);
            if td.stats.marked > prev {
                mark_times.push(t);
            }
            if t > t0 + Duration::from_secs(5) {
                break;
            }
        }

        assert!(mark_times.len() >= 3, "expected at least 3 marks");

        // Each successive gap should be smaller than the previous.
        let gap0 = mark_times[1].duration_since(mark_times[0]);
        let gap1 = mark_times[2].duration_since(mark_times[1]);
        assert!(
            gap1 < gap0,
            "expected decreasing inter-mark gaps: {gap0:?} then {gap1:?}"
        );
    }

    /// With ECN disabled, the node is a pure tail-drop queue: no `CoDel` signalling,
    /// drops only when the buffer overflows.
    #[test]
    fn drop_when_ecn_disabled() {
        // Small buffer: 10 000 bytes holds ~7 packets (1280 bytes each with overhead).
        let mut td = TailDrop::new(100_000, 10_000, false, Duration::from_millis(1));
        let t0 = now();
        td.prepare(t0);

        // Burst 20 packets at once — far more than the buffer can hold.
        for _ in 0..20 {
            td.process(Some(make_datagram(Ecn::NotEct)), t0);
        }

        assert_eq!(td.stats.marked, 0, "should not mark when ECN disabled");
        assert!(
            td.stats.dropped > 0,
            "expected tail-drop on overflow, got stats: {}",
            td.stats
        );
    }
}
