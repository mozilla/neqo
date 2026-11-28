// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::{
    cell::RefCell,
    hint::black_box,
    ops::{Deref, DerefMut},
    rc::Rc,
    time::{Duration, Instant},
};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use neqo_transport::{
    packet,
    recovery::{self, sent, sent::LossTrigger},
};

const MTU: usize = 1_350;
const PACKETS: u64 = 2_000;

fn make_packet(i: u64, now: Instant) -> sent::Packet {
    sent::Packet::new(
        packet::Type::Short,
        packet::Number::from(i),
        now,
        true,
        recovery::Tokens::new(),
        MTU,
    )
}

fn make_lost_packet(i: u64, now: Instant) -> sent::Packet {
    let mut p = make_packet(i, now);
    p.declare_lost(now, LossTrigger::TimeThreshold);
    p
}

type Pool = Rc<RefCell<Vec<sent::Packets>>>;

/// A `sent::Packets` that returns to its pool when dropped, keeping its buffer, as a long-lived
/// connection does. Freeing the buffer after each timed call lets glibc trim the heap, and the
/// next timed call then measures page faults.
struct Reused {
    pkts: sent::Packets,
    pool: Pool,
}

impl Drop for Reused {
    fn drop(&mut self) {
        self.pool.borrow_mut().push(std::mem::take(&mut self.pkts));
    }
}

impl Deref for Reused {
    type Target = sent::Packets;

    fn deref(&self) -> &Self::Target {
        &self.pkts
    }
}

impl DerefMut for Reused {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pkts
    }
}

fn collect_packets(pool: &Pool, iter: impl IntoIterator<Item = sent::Packet>) -> Reused {
    let mut pkts = pool.borrow_mut().pop().unwrap_or_default();
    drop(pkts.take_ranges(std::iter::once(0..=PACKETS - 1))); // Empties it; the buffer stays.
    iter.into_iter().for_each(|p| pkts.track(p));
    Reused {
        pkts,
        pool: Rc::clone(pool),
    }
}

/// Confirm that taking a small number of ranges from the front of
/// a large span of sent packets is performant.
/// This is the most common pattern when sending at a higher rate.
/// New acknowledgments will include low-numbered packets,
/// while the acknowledgment rate will ensure that most of the
/// outstanding packets remain in flight.
fn take_ranges(c: &mut Criterion) {
    let now = test_fixture::now();
    let pool = Pool::default();
    c.bench_function("sent::Packets::take_ranges", |b| {
        b.iter_batched_ref(
            || collect_packets(&pool, (0..PACKETS).map(|i| make_packet(i, now))),
            // Take the first 90 packets, minus some gaps.
            |pkts| black_box(pkts.take_ranges([70..=89, 40..=59, 10..=29])),
            // One fresh input per timed call, so the routine does not start on a cold cache.
            BatchSize::PerIteration,
        );
    });
}

/// Track 2 000 packets with monotonically increasing
/// packet numbers.  This is the only insertion pattern that occurs in practice
/// (the sender assigns packet numbers and they always increase).
fn track(c: &mut Criterion) {
    let now = test_fixture::now();
    let pool = Pool::default();
    c.bench_function("sent::Packets::track", |b| {
        b.iter_batched_ref(
            || collect_packets(&pool, std::iter::empty()),
            |pkts| {
                for i in 0..PACKETS {
                    pkts.track(make_packet(i, now));
                }
                black_box(&**pkts);
            },
            BatchSize::PerIteration,
        );
    });
}

/// Measure bulk expiry of the oldest in-flight packets (loss-detection
/// housekeeping): first half expired, second half not.
fn remove_expired(c: &mut Criterion) {
    let cd = Duration::from_millis(300);
    // First half lost at `old` (expired by `now`); second half lost at `now` (not yet).
    let old = test_fixture::now();
    let now = old + cd * 2;
    let pool = Pool::default();

    c.bench_function("sent::Packets::remove_expired half-expired", |b| {
        b.iter_batched_ref(
            || {
                collect_packets(
                    &pool,
                    (0..PACKETS / 2)
                        .map(|i| make_lost_packet(i, old))
                        .chain((PACKETS / 2..PACKETS).map(|i| make_lost_packet(i, now))),
                )
            },
            |pkts| black_box(pkts.remove_expired(now, cd)),
            BatchSize::PerIteration,
        );
    });
}

criterion_group! {
    name = benches;
    config = { neqo_common::log::init(None); Criterion::default() };
    targets = take_ranges, track, remove_expired
}
criterion_main!(benches);
