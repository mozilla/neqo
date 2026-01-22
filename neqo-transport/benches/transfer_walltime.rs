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

use criterion::{criterion_group, criterion_main, BatchSize::SmallInput};

#[path = "transfer_common.rs"]
mod common;

fn benchmark(c: &mut criterion::Criterion) {
    common::benchmark(c, |group, name, label, seed, pacing| {
        group.bench_function(name, |b| {
            b.iter_batched(
                || common::setup(label, seed, pacing),
                |sim| black_box(sim.run()),
                SmallInput,
            );
        });
    });
}

criterion_group! {
    name = transfer;
    config = common::criterion_config();
    targets = benchmark
}
criterion_main!(transfer);
