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

use neqo_common::{Datagram, qinfo, qtrace};
use neqo_transport::Output;

use super::{
    Node, Rng,
    aqm::{Aqm, MarkResult},
};

/// One second in nanoseconds.
const ONE_SECOND_NS: u128 = 1_000_000_000;

#[derive(Clone, Default)]
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
    /// The time of the last usage accumulation.
    last_update: Option<Instant>,
    /// Accumulated queue usage multiplied by time.
    /// This is in units of `bytes * nanoseconds`, which will get big.
    /// For a test that transfers 1 gigabyte and takes a month,
    /// that's still well within 64 bits.  Use `u128` to be safe.
    cumulative_usage: u128,
}

impl Stats {
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
#[derive(Clone)]
pub struct TailDrop {
    /// An overhead associated with each entry.  This accounts for
    /// layer 2, IP, and UDP overheads.
    overhead: usize,
    /// The rate at which bytes egress the link, in bytes per second.
    rate: usize,
    /// The depth of the queue, in bytes.
    capacity: usize,

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
    aqm: Aqm,
}

impl TailDrop {
    /// Make a new taildrop node with the given rate, AQM, queue capacity, and link delay.
    ///
    /// # Panics
    ///
    /// Panics if rate is zero or over 1Gbps, or if `Aqm::Red` is used and capacity is too large
    /// for its overflow-avoiding arithmetic.
    #[must_use]
    pub fn new(rate: usize, capacity: usize, aqm: Aqm, delay: Duration) -> Self {
        assert!(rate != 0, "zero rate gets you nowhere");
        assert!(rate <= 1_000_000_000, "rates over 1Gbps are not supported");
        if matches!(aqm, Aqm::Red(_)) {
            // We multiply capacity by 4096 below and need to avoid overflow.
            assert!(capacity < usize::MAX / 4096, "too much capacity");
            // We need to square a value close to 1000x this and have it fit within a u128.
            #[cfg(target_pointer_width = "64")]
            assert!(capacity < (1 << 54), "too much capacity");
        }
        Self {
            overhead: 80,
            rate,
            capacity,
            used: 0,
            queue: VecDeque::new(),
            next_deque: None,
            delay,
            on_link: VecDeque::new(),
            stats: Stats::default(),
            aqm,
        }
    }

    /// A tail drop queue on a 10Mbps link (approximated to 1 million bytes per second)
    /// with a fat 32k buffer (about 30ms), and the default forward delay of 50ms.
    #[must_use]
    pub fn dsl_downlink() -> Self {
        Self::new(1_000_000, 32_768, Aqm::None, Duration::from_millis(50))
    }

    /// Cut uplink to one fifth of the downlink (2Mbps), and reduce the buffer to 1/4.
    #[must_use]
    pub fn dsl_uplink() -> Self {
        Self::new(200_000, 8_192, Aqm::None, Duration::from_millis(50))
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
            // Keep dequeuing until we send a packet or exhaust the queue; an AQM drop
            // should not stall the packets behind it.
            while !self.queue.is_empty() {
                if let Some(d) = self.dequeue(now) {
                    self.send(d, t, subns);
                    return;
                }
            }
            self.next_deque = None;
        }
    }

    /// Pop the front packet and apply the AQM policy.
    /// Returns `None` if the packet was dropped (do not send).
    fn dequeue(&mut self, now: Instant) -> Option<Datagram> {
        let (enqueue_time, pkt) = self.queue.pop_front()?;
        self.used -= self.size(&pkt);
        let sojourn = now.saturating_duration_since(enqueue_time);
        // Note: RED evaluates occupancy at dequeue time (self.used after decrement), which
        // is slightly lower than the enqueue-time occupancy the original code used.
        match self.aqm.mark(pkt, sojourn, self.used, self.capacity, now) {
            MarkResult::Forward(d) => Some(d),
            MarkResult::Marked(d) => {
                self.stats.marked += 1;
                Some(d)
            }
            MarkResult::Dropped => {
                self.stats.dropped += 1;
                None
            }
        }
    }
}

impl Node for TailDrop {
    fn init(&mut self, rng: Rng, _now: Instant) {
        self.aqm.init_rng(rng);
    }

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
        cell::RefCell,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        rc::Rc,
        time::{Duration, Instant},
    };

    use neqo_common::{Datagram, Dscp, Ecn, Encoder, Tos, qinfo};
    use neqo_transport::Output;

    use crate::{
        now,
        sim::{
            Node as _,
            aqm::CodelState,
            network::{Aqm, TailDrop},
            rng::Random,
        },
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
        let mut td = TailDrop::new(
            100_000_000,
            1_000_000,
            Aqm::codel(),
            Duration::from_millis(1),
        );
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
        let mut td = TailDrop::new(100_000, 500_000, Aqm::codel(), Duration::from_millis(1));
        let t0 = now();
        td.prepare(t0);

        // Enqueue enough packets to fill >100ms of link time.
        for _ in 0..100 {
            td.process(Some(make_datagram(Ecn::Ect0)), t0);
        }

        // Advance well past INTERVAL so CoDel has time to act.
        let mut t = t0;
        let mut first_mark_time = None;
        for _ in 0..500 {
            t += Duration::from_millis(1);
            let prev = td.stats.marked;
            td.process(None, t);
            if td.stats.marked > prev && first_mark_time.is_none() {
                first_mark_time = Some(t);
            }
        }

        assert!(td.stats.marked > 0);
        // The first mark must not arrive before one full INTERVAL of above-target sojourn.
        assert!(first_mark_time.is_some_and(|ft| ft >= t0 + Duration::from_millis(100)));
    }

    /// After entering dropping state, successive marks should be spaced at
    /// decreasing intervals (control law: INTERVAL / sqrt(count)).
    #[test]
    fn mark_rate_increases() {
        // Very slow link to ensure long sojourn times.
        let mut td = TailDrop::new(50_000, 1_000_000, Aqm::codel(), Duration::from_millis(1));
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

        assert!(mark_times.len() >= 4);

        // Each successive gap should be smaller than the previous (control law: INTERVAL/sqrt(n)).
        let gaps: Vec<_> = mark_times
            .windows(2)
            .map(|w| w[1].duration_since(w[0]))
            .collect();
        assert!(gaps.windows(2).all(|w| w[1] < w[0]));
    }

    fn mark_rate(used: usize, capacity: usize, trials: usize, salt: u64) -> usize {
        let mut enc = Encoder::default();
        enc.encode_uint(8, u64::try_from(used).unwrap());
        enc.encode_uint(8, u64::try_from(capacity).unwrap());
        enc.encode_uint(8, u64::try_from(trials).unwrap());
        enc.encode_uint(8, salt);
        let rng = Rc::new(RefCell::new(Random::new(
            <&[u8; 32]>::try_from(enc.as_ref()).unwrap(),
        )));
        let mut td = TailDrop::new(1, capacity, Aqm::red(), Duration::from_secs(2));
        td.init(rng, now());
        let Aqm::Red(state) = &td.aqm else {
            unreachable!()
        };
        let successes = (0..trials)
            .filter(|_| state.should_mark(used, capacity))
            .count();
        qinfo!("{successes} out of {trials} trials at {used}/{capacity}");
        successes
    }

    fn check_mark_rates(salt: u64) {
        // At 0.4, no marking at all.
        assert_eq!(mark_rate(4, 10, 100, salt), 0);
        // At 0.6, we're at 0.2 over the base: (0.2*2)**2 gives an expectation of 0.16.
        assert!((1450..=1750).contains(&mark_rate(6, 10, 10_000, salt)));
        // At 0.8, marks are applied almost 2/3: (0.4*2)**2 = 0.64
        assert!((6200..=6600).contains(&mark_rate(8, 10, 10_000, salt)));
        // At 0.9, we hit the cap of 0.95.
        assert!((9350..=9650).contains(&mark_rate(9, 10, 10_000, salt)));
        // At 0.99, we are still at the cap.
        assert!((9350..=9650).contains(&mark_rate(99, 100, 10_000, salt)));
    }

    /// Check that the mark rate is approximately correct.
    #[test]
    fn mark_distribution() {
        /// This test tests with a range of values, even though the values are
        /// 100% consistent run-to-run (because it uses the same seed).
        /// Replacing this salt with a random number can be used to test sampling.
        const SALT: u64 = 17;
        check_mark_rates(SALT);
    }

    /// With ECN disabled, the node is a pure tail-drop queue: no `CoDel` signalling,
    /// drops only when the buffer overflows.
    #[test]
    fn drop_when_ecn_disabled() {
        // Small buffer: 10 000 bytes holds ~7 packets (1280 bytes each with overhead).
        let mut td = TailDrop::new(100_000, 10_000, Aqm::None, Duration::from_millis(1));
        let t0 = now();
        td.prepare(t0);

        // Burst 20 packets at once — far more than the buffer can hold.
        for _ in 0..20 {
            td.process(Some(make_datagram(Ecn::NotEct)), t0);
        }

        assert_eq!(td.stats.marked, 0, "should not mark when ECN disabled");
        assert!(td.stats.dropped > 0);
    }

    /// When `CoDel` drops a non-ECT packet mid-queue, the packets behind it must
    /// still be delivered — a drop should not stall the rest of the queue.
    #[test]
    fn codel_drop_does_not_stall_queue() {
        // Slow link with a large buffer so packets queue long enough for CoDel to
        // act, and non-ECT traffic so signalling drops rather than marks.
        let mut td = TailDrop::new(100_000, 500_000, Aqm::codel(), Duration::from_millis(1));
        let t0 = now();
        td.prepare(t0);

        for _ in 0..100 {
            td.process(Some(make_datagram(Ecn::NotEct)), t0);
        }
        drain(&mut td, t0);

        assert_eq!(td.stats.marked, 0, "non-ECT packets cannot be CE-marked");
        assert!(td.stats.dropped > 0);
        // Every received packet must be accounted for as either delivered or dropped;
        // a stalled queue would leave packets unaccounted for.
        assert_eq!(td.stats.delivered + td.stats.dropped, td.stats.received);
        assert!(td.stats.delivered > 0);
    }

    /// Step `state` in 1 ms increments until `n` signals fire; return their timestamps.
    fn codel_marks(state: &mut CodelState, n: usize, t0: Instant) -> Vec<Instant> {
        let mut times = Vec::new();
        let mut t = t0;
        while times.len() < n {
            t += Duration::from_millis(1);
            if state.update(Duration::from_millis(10), false, t) {
                times.push(t);
            }
            assert!(t < t0 + Duration::from_secs(5));
        }
        times
    }

    /// No signal fires before one full INTERVAL of above-target sojourn.
    #[test]
    fn codel_no_signal_before_interval() {
        let mut state = CodelState::default();
        let t0 = now();
        for ms in 0..99 {
            assert!(!state.update(
                Duration::from_millis(10),
                false,
                t0 + Duration::from_millis(ms)
            ));
        }
    }

    /// `queue_empty` resets sojourn tracking; no signal fires while the queue is empty.
    #[test]
    fn codel_queue_empty_resets_tracking() {
        let mut state = CodelState::default();
        let t0 = now();
        // Arm first_above_time: 10 calls with above-target sojourn.
        for ms in 0..10 {
            state.update(
                Duration::from_millis(10),
                false,
                t0 + Duration::from_millis(ms),
            );
        }
        // Pass queue_empty=true for well over INTERVAL; must never signal.
        for ms in 10..210 {
            assert!(!state.update(
                Duration::from_millis(10),
                true,
                t0 + Duration::from_millis(ms)
            ));
        }
    }

    /// Successive marks in the dropping state have strictly decreasing gaps.
    #[test]
    fn codel_dropping_gaps_decrease() {
        let mut state = CodelState::default();
        let mark_times = codel_marks(&mut state, 4, now());
        let gaps: Vec<_> = mark_times
            .windows(2)
            .map(|w| w[1].duration_since(w[0]))
            .collect();
        assert!(gaps.windows(2).all(|w| w[1] < w[0]));
    }

    /// Re-entering the dropping state shortly after leaving gives a shorter second-mark
    /// gap than a cold start, because count is resumed rather than reset to 1.
    #[test]
    fn codel_fast_restart_shorter_gap() {
        let t0 = now();

        // Phase 1: accumulate several marks to build up count.
        let mut state = CodelState::default();
        let phase1_end = *codel_marks(&mut state, 4, t0).last().unwrap();

        // Phase 2: leave dropping by draining the queue.
        for i in 1..=5 {
            state.update(Duration::ZERO, true, phase1_end + Duration::from_millis(i));
        }

        // Measure the second-mark gap with fast restart vs. cold start.
        let reenter = phase1_end + Duration::from_millis(10); // well within the 1600 ms window
        let fast = codel_marks(&mut state.clone(), 2, reenter);
        let cold = codel_marks(&mut CodelState::default(), 2, reenter);

        // Fast restart resumes with count > 1, so INTERVAL/sqrt(count) < INTERVAL.
        let gap_fast = fast[1].duration_since(fast[0]);
        let gap_cold = cold[1].duration_since(cold[0]);
        assert!(gap_fast < gap_cold);
    }
}
