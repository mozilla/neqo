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
use crate::sim::Rng;

/// One second in nanoseconds.
const ONE_SECOND_NS: u128 = 1_000_000_000;

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
    /// A queue of unsent bytes.
    queue: VecDeque<Datagram>,
    /// The time that the next datagram can enter the link.
    /// Includes any sub-ns remainder (which helps absorb rounding errors).
    next_deque: Option<(Instant, u32)>,

    /// The time it takes a byte to exit the other end of the link.
    delay: Duration,
    /// The packets that are on the link and when they can be delivered.
    on_link: VecDeque<(Instant, Datagram)>,

    stats: Stats,

    // The random number generator we use for RED.
    rng: Option<Rng>,
}

impl TailDrop {
    /// Make a new taildrop node with the given rate, ECN, queue capacity, and link delay.
    /// When ECN is enabled, the stack will avoid filling the buffer and sit around 50%
    /// capacity, so you might need to double the buffer size to get comparable throughput.
    /// Of course, a smaller buffer will mean less latency.
    ///
    /// # Panics
    ///
    /// Panics if rate is zero or over 1Gbps, or if capacity is too large.
    #[must_use]
    pub const fn new(rate: usize, capacity: usize, ecn: bool, delay: Duration) -> Self {
        assert!(rate != 0, "zero rate gets you nowhere");
        assert!(rate <= 1_000_000_000, "rates over 1Gbps are not supported");
        // We multiply this by 4096 below and need to avoid overflow.
        assert!(capacity < usize::MAX / 4096, "too much capacity");
        // We need to square a value close to 1000x this and have it fit within a u128.
        #[cfg(target_pointer_width = "64")]
        assert!(capacity < (1 << 54), "too much capacity");
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
            rng: None,
        }
    }

    /// A tail drop queue on a 10Mbps link (approximated to 1 million bytes per second)
    /// with a fat 32k buffer (about 30ms), and the default forward delay of 50ms.
    #[must_use]
    pub const fn dsl_downlink() -> Self {
        Self::new(1_000_000, 32_768, false, Duration::from_millis(50))
    }

    /// Cut uplink to one fifth of the downlink (2Mbps), and reduce the buffer to 1/4.
    #[must_use]
    pub const fn dsl_uplink() -> Self {
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
    /// If the queue is too deep, CE mark it before saving.
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
            let d = self.maybe_mark(d);
            self.queue.push_back(d);
        } else {
            qtrace!("taildrop dropping {} bytes", d.len());
            self.stats.dropped += 1;
        }
    }

    /// If the last packet that was sending has been sent, start sending
    /// the next one.
    fn maybe_send(&mut self, now: Instant) {
        if let Some((t, subns)) = &self.next_deque {
            if now < *t {
                return;
            }

            self.stats.accumulate_usage(now, self.used);
            if let Some(d) = self.queue.pop_front() {
                self.used -= self.size(&d);
                self.send(d, *t, *subns);
            } else {
                self.next_deque = None;
            }
        }
    }

    /// Apply ECN-CE markings to packets if they are ECT(0) marked.
    /// This is classic, simple ECN using RED; we don't know about L4S yet.
    fn maybe_mark(&mut self, dgram: Datagram) -> Datagram {
        if self.ecn && Ecn::from(dgram.tos()).is_ect() && self.should_mark(self.used) {
            assert!(
                Ecn::from(dgram.tos()) != Ecn::Ect1,
                "ECT(1)/L4S is not implemented"
            );
            qtrace!("taildrop marking {} bytes", dgram.len());
            self.stats.marked += 1;
            let tos = Tos::from((Dscp::from(dgram.tos()), Ecn::Ce));
            Datagram::new(dgram.source(), dgram.destination(), tos, dgram.to_vec())
        } else {
            dgram
        }
    }

    fn should_mark(&self, used: usize) -> bool {
        // Apply RED which starts at 0 mark chance at 40% of the capacity.
        // From there, follow a quadratic that reaches 1 at 90% capacity.
        // Cap at around 95% mark probability.
        //
        // let p = (2 * ((used / capacity) - 0.4));
        // if rand(0, 1) < p.pow(2).clamp(0, 0.95) { mark(d) } else { d }
        //
        // This code scales that up by a factor of 1024 so we can use integers.
        // This is mostly because our RNG can't sample from 0..1_f64.

        let Some(n) = (2048 * used).checked_sub(self.capacity * 4096 / 5) else {
            return false; // (used / capacity) < 0.4
        };
        // Cap pre-squaring: 998 =~ 1024 * Math.pow(0.95, 1/2)
        let p = u128::try_from(n.min(self.capacity * 998)).unwrap();
        let c = u128::try_from(self.capacity).unwrap();
        let p = u64::try_from(p * p / c / c).unwrap();
        let r = self
            .rng
            .as_ref()
            .unwrap()
            .borrow_mut()
            .random_from(0..(1 << 20));
        r < p
    }
}

impl Node for TailDrop {
    fn init(&mut self, rng: Rng, _now: Instant) {
        self.rng = Some(rng);
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
        rc::Rc,
        time::{Duration, Instant},
    };

    use neqo_common::{Encoder, qinfo};

    use crate::sim::{Node as _, network::TailDrop, rng::Random};

    fn mark_rate(used: usize, capacity: usize, trials: usize, salt: u64) -> usize {
        let mut enc = Encoder::default();
        enc.encode_uint(8, u64::try_from(used).unwrap());
        enc.encode_uint(8, u64::try_from(capacity).unwrap());
        enc.encode_uint(8, u64::try_from(trials).unwrap());
        enc.encode_uint(8, salt);
        let rng = Rc::new(RefCell::new(Random::new(
            <&[u8; 32]>::try_from(enc.as_ref()).unwrap(),
        )));
        // We use only the capacity of these config parameters.
        let mut td = TailDrop::new(1, capacity, true, Duration::from_secs(2));
        td.init(rng, Instant::now());
        let mut successes = 0;
        for _ in 0..trials {
            successes += usize::from(td.should_mark(used));
        }
        qinfo!("{successes} out of {trials} trails at {used}/{capacity}");
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
}
