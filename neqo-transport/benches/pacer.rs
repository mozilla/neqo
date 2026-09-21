// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use neqo_transport::Pacer;

const RTT: Duration = Duration::from_millis(50);
const MTU: usize = 1_350;
const CWND: usize = MTU * 100;
const CALLS: usize = 1_000;

// These loops need `black_box` to survive the optimizer: `&p` keeps the pacer's
// loads and stores, and opaque arguments keep `spend()`'s arithmetic.

/// PRIMARY: `spend()` in the steady state of a paced bulk transfer, where the
/// sender waits out the pacing interval and `self.c` returns to zero each call.
fn pacer_spend_pacing_limited(c: &mut Criterion) {
    const CWND_LIMITED: usize = MTU * 10;
    // One packet of credit per call: `RTT * MTU / (CWND_LIMITED * SPEEDUP)`.
    const INTERVAL: Duration = RTT.checked_div(20).expect("divisor is not zero");
    let now = test_fixture::now();
    c.bench_function("Pacer::spend pacing-limited", |b| {
        b.iter_batched(
            || {
                let mut p = Pacer::new(true, now, MTU, MTU);
                // Drain the initial burst to reach the steady state.
                p.spend(now, RTT, CWND_LIMITED, MTU);
                assert_eq!(p.next(RTT, CWND_LIMITED), now + INTERVAL);
                p
            },
            |mut p| {
                let (rtt, cwnd, count) = black_box((RTT, CWND_LIMITED, MTU));
                let mut t = now;
                for _ in 0..CALLS {
                    t += INTERVAL;
                    p.spend(t, rtt, cwnd, count);
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
    let now = test_fixture::now();
    c.bench_function("Pacer::next fast-path", |b| {
        b.iter_batched(
            // Full credit: next() will return immediately.
            || Pacer::new(true, now, CWND, MTU),
            |p| {
                for _ in 0..CALLS {
                    black_box(p.next(RTT, CWND));
                    black_box(&p);
                }
            },
            BatchSize::SmallInput,
        );
    });
}

/// `spend()` when pacing is disabled: the function must still update
/// `self.t` but should return immediately without any arithmetic.
fn pacer_spend_disabled(c: &mut Criterion) {
    let now = test_fixture::now();
    c.bench_function("Pacer::spend disabled", |b| {
        b.iter_batched(
            || Pacer::new(false, now, CWND, MTU),
            |mut p| {
                for _ in 0..CALLS {
                    p.spend(now, RTT, CWND, MTU);
                    black_box(&p);
                }
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = { neqo_common::log::init(None); Criterion::default() };
    targets = pacer_spend_pacing_limited, pacer_next_fast_path, pacer_spend_disabled
}
criterion_main!(benches);
