// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmark with walltime, i.e., measure the compute efficiency.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

#[path = "common.rs"]
mod common;

fn benchmark(c: &mut Criterion) {
    common::benchmark(c, |group, name, streams, data_size| {
        group.bench_function(name, |b| {
            b.iter_batched(
                || common::setup(streams, data_size),
                |sim| black_box(sim.run()),
                criterion::BatchSize::SmallInput,
            );
        });
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
