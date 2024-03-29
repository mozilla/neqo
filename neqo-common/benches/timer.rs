// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use neqo_common::timer::Timer;
use test_fixture::now;

fn benchmark_timer(c: &mut Criterion) {
    c.bench_function("drain a small timer quickly", |b| {
        b.iter_batched(make_small_timer, drain, criterion::BatchSize::SmallInput)
    });
    c.bench_function("drain a large mostly empty timer quickly", |b| {
        b.iter_batched(
            make_large_mostly_empty_timer,
            drain,
            criterion::BatchSize::SmallInput,
        )
    });
}

fn make_small_timer() -> Timer<()> {
    const TIMES: &[u64] = &[1, 2, 3, 5, 8, 13, 21, 34];

    let now = now();
    let mut timer = Timer::new(now, Duration::from_millis(777), 100);
    for &t in TIMES {
        timer.add(now + Duration::from_secs(t), ());
    }
    timer
}

fn make_large_mostly_empty_timer() -> Timer<()> {
    let now = now();
    let mut timer = Timer::new(now, Duration::from_millis(4), 16384);
    timer.add(now + Duration::from_millis(400), ());
    timer
}

fn drain(mut timer: Timer<()>) {
    while let Some(t) = timer.next_time() {
        assert!(timer.take_next(t).is_some());
    }
}

criterion_group!(benches, benchmark_timer);
criterion_main!(benches);
