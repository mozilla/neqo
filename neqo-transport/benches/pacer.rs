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
use neqo_transport::Pacer;

const RTT: Duration = Duration::from_millis(50);
const MTU: usize = 1_350;
const CWND: usize = MTU * 100;

/// PRIMARY: `spend()` when pacing is enabled and each call is credit-limited.
/// This is the dominant case during a paced bulk transfer: the pacer has just
/// enough credit for each packet and the call does the full division.
///
/// For pacing to actually limit, the inter-packet interval
/// `RTT * MTU / (CWND * 2)` must exceed GRANULARITY (1 ms).
/// With RTT=50ms, MTU=1350: CWND must be ≤ 33 750 bytes.
/// CWND_LIMITED=MTU*10=13 500 gives a 2.5ms inter-packet interval.
fn pacer_spend_pacing_limited(c: &mut Criterion) {
    const CWND_LIMITED: usize = MTU * 10;
    c.bench_function("Pacer::spend pacing-limited", |b| {
        b.iter_batched(
            || {
                let now = Instant::now();
                // Pacer starts with one packet of credit; after the first
                // spend() call it reaches zero credit and subsequent calls
                // exercise the pacing-limited path (full division + wait
                // interval computation).
                Pacer::new(true, now, MTU, MTU)
            },
            |mut p| {
                let now = Instant::now();
                for _ in 0..1_000 {
                    black_box(p.spend(now, RTT, CWND_LIMITED, MTU));
                }
                black_box(p)
            },
            BatchSize::SmallInput,
        );
    });
}

/// `next()` fast path: credit is available, function returns `self.t`
/// without computing a division.
fn pacer_next_fast_path(c: &mut Criterion) {
    c.bench_function("Pacer::next fast-path", |b| {
        b.iter_batched(
            || {
                let now = Instant::now();
                // Full credit: next() will return immediately.
                Pacer::new(true, now, CWND, MTU)
            },
            |p| {
                for _ in 0..1_000 {
                    black_box(p.next(RTT, CWND));
                }
                black_box(p)
            },
            BatchSize::SmallInput,
        );
    });
}

/// `spend()` when pacing is disabled: the function must still update
/// `self.t` but should return `false` immediately without any arithmetic.
fn pacer_spend_disabled(c: &mut Criterion) {
    c.bench_function("Pacer::spend disabled", |b| {
        b.iter_batched(
            || {
                let now = Instant::now();
                Pacer::new(false, now, CWND, MTU)
            },
            |mut p| {
                let now = Instant::now();
                for _ in 0..1_000 {
                    black_box(p.spend(now, RTT, CWND, MTU));
                }
                black_box(p)
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    pacer_spend_pacing_limited,
    pacer_next_fast_path,
    pacer_spend_disabled,
);
criterion_main!(benches);
