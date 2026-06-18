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
    hint::black_box,
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

fn collect_packets(iter: impl IntoIterator<Item = sent::Packet>) -> sent::Packets {
    let mut pkts = sent::Packets::default();
    iter.into_iter().for_each(|p| pkts.track(p));
    pkts
}

/// Confirm that taking a small number of ranges from the front of
/// a large span of sent packets is performant.
/// This is the most common pattern when sending at a higher rate.
/// New acknowledgments will include low-numbered packets,
/// while the acknowledgment rate will ensure that most of the
/// outstanding packets remain in flight.
fn take_ranges(c: &mut Criterion) {
    let now = Instant::now();
    c.bench_function("sent::Packets::take_ranges", |b| {
        b.iter_batched_ref(
            || collect_packets((0..PACKETS).map(|i| make_packet(i, now))),
            // Take the first 90 packets, minus some gaps.
            |pkts| black_box(pkts.take_ranges([70..=89, 40..=59, 10..=29])),
            BatchSize::SmallInput,
        );
    });
}

/// Track 2 000 packets with monotonically increasing
/// packet numbers.  This is the only insertion pattern that occurs in practice
/// (the sender assigns packet numbers and they always increase).
fn track(c: &mut Criterion) {
    let now = Instant::now();
    c.bench_function("sent::Packets::track", |b| {
        b.iter_batched(
            sent::Packets::default,
            |mut pkts| {
                for i in 0..PACKETS {
                    pkts.track(make_packet(i, now));
                }
                black_box(pkts)
            },
            BatchSize::SmallInput,
        );
    });
}

/// Measure periodic expiry of the oldest in-flight packets (loss-detection
/// housekeeping).  The common case is that the first packet is not yet expired
/// and the function returns immediately; measure both that and the bulk-expiry
/// case.
fn remove_expired(c: &mut Criterion) {
    let now = Instant::now();
    let cd = Duration::from_millis(300);

    c.bench_function("sent::Packets::remove_expired none-expired", |b| {
        // All packets lost at `now`: loss_info is populated but not yet expired — fast exit.
        b.iter_batched_ref(
            || collect_packets((0..PACKETS).map(|i| make_lost_packet(i, now))),
            |pkts| black_box(pkts.remove_expired(now + cd / 2, cd)),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("sent::Packets::remove_expired half-expired", |b| {
        b.iter_batched_ref(
            || {
                // First half lost at `now - 2*cd` (expired); second half lost at `now` (not yet).
                let old = now - cd * 2;
                collect_packets(
                    (0..PACKETS / 2)
                        .map(|i| make_lost_packet(i, old))
                        .chain((PACKETS / 2..PACKETS).map(|i| make_lost_packet(i, now))),
                )
            },
            |pkts| black_box(pkts.remove_expired(now, cd)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, take_ranges, track, remove_expired);
criterion_main!(benches);
