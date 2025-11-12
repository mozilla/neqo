// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::{hint::black_box, time::Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use neqo_transport::{
    self, packet,
    recovery::{self, sent},
};

fn sent_packets() -> sent::Packets {
    let mut pkts = sent::Packets::default();
    let now = Instant::now();
    // Simulate high bandwidth-delay-product connection.
    for i in 0..2_000u64 {
        pkts.track(sent::Packet::new(
            packet::Type::Short,
            packet::Number::from(i),
            now,
            true,
            recovery::Tokens::new(),
            100,
        ));
    }
    pkts
}

/// Confirm that taking a small number of ranges from the front of
/// a large span of sent packets is performant.
/// This is the most common pattern when sending at a higher rate.
/// New acknowledgments will include low-numbered packets,
/// while the acknowledgment rate will ensure that most of the
/// outstanding packets remain in flight.
fn take_ranges(c: &mut Criterion) {
    c.bench_function("sent::Packets::take_ranges", |b| {
        b.iter_batched_ref(
            sent_packets,
            // Take the first 90 packets, minus some gaps.
            |pkts| black_box(pkts.take_ranges([70..=89, 40..=59, 10..=29])),
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, take_ranges);
criterion_main!(benches);
