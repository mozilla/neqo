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

use neqo_common::{qinfo, qtrace, Datagram, Dscp, Ecn, Tos};
use neqo_transport::Output;

use super::Node;

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
}

impl Stats {
    const fn new() -> Self {
        Self {
            received: 0,
            marked: 0,
            dropped: 0,
            delivered: 0,
            maxq: 0,
        }
    }

    fn update_maxq(&mut self, used: usize) {
        self.maxq = max(self.maxq, used);
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rx {} mark {} drop {} tx {} maxq {}",
            self.received, self.marked, self.dropped, self.delivered, self.maxq
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
    /// The depth of the queue where arriving packets get marked.
    /// Set this to `capacity` or higher so that it has no effect.
    mark_capacity: usize,

    /// A counter for how many bytes are enqueued.
    used: usize,
    /// A queue of unsent bytes.
    queue: VecDeque<Datagram>,
    /// The time that the next datagram can enter the link.
    next_deque: Option<(Instant, u32)>,

    /// The time it takes a byte to exit the other end of the link.
    delay: Duration,
    /// The packets that are on the link and when they can be delivered.
    on_link: VecDeque<(Instant, Datagram)>,

    stats: Stats,
}

impl TailDrop {
    /// Make a new taildrop node with the given rate, queue capacity, and link delay.
    #[must_use]
    pub const fn new(rate: usize, capacity: usize, mark_capacity: usize, delay: Duration) -> Self {
        assert!(rate != 0, "zero rate gets you nowhere");
        assert!(rate <= 1_000_000_000, "rates over 1Gbps are not supported");
        Self {
            overhead: 80,
            rate,
            capacity,
            mark_capacity,
            used: 0,
            queue: VecDeque::new(),
            next_deque: None,
            delay,
            on_link: VecDeque::new(),
            stats: Stats::new(),
        }
    }

    /// A tail drop queue on a 10Mbps link (approximated to 1 million bytes per second)
    /// with a fat 32k buffer (about 30ms), and the default forward delay of 50ms.
    #[must_use]
    pub const fn dsl_downlink() -> Self {
        Self::new(1_000_000, 32_768, 32_768, Duration::from_millis(50))
    }

    /// Cut uplink to one fifth of the downlink (2Mbps), and reduce the buffer to 1/4.
    #[must_use]
    pub const fn dsl_uplink() -> Self {
        Self::new(200_000, 8_192, 8_192, Duration::from_millis(50))
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

            if let Some(d) = self.queue.pop_front() {
                self.used -= self.size(&d);
                self.send(d, *t, *subns);
            } else {
                self.next_deque = None;
            }
        }
    }

    /// Apply ECN-CE markings to packets if they are ECT(0) marked.
    /// This is classic, simple ECN; we don't know about L4S yet.
    fn maybe_mark(&mut self, d: Datagram) -> Datagram {
        if self.used <= self.mark_capacity || Ecn::from(d.tos()) != Ecn::Ect0 {
            return d;
        }

        qtrace!("taildrop marking {} bytes", d.len());
        self.stats.marked += 1;
        let tos = Tos::from((Dscp::from(d.tos()), Ecn::Ce));
        Datagram::new(d.source(), d.destination(), tos, d.to_vec())
    }
}

impl Node for TailDrop {
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
