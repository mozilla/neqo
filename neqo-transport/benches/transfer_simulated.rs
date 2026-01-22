// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmark with simulated time, i.e., measure the network protocol efficiency.
//!
//! Given that this uses simulated time, we can measure actual throughput.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Throughput};

#[path = "transfer_common.rs"]
mod common;

fn benchmark(c: &mut criterion::Criterion) {
    common::benchmark(c, |group, name, label, seed, pacing| {
        group.throughput(Throughput::Bytes(common::TRANSFER_AMOUNT as u64));
        group.bench_function(name, |b| {
            b.iter_custom(|iters| {
                let mut d_sum = Duration::ZERO;
                for _i in 0..iters {
                    d_sum += common::setup(label, seed, pacing).run();
                }
                d_sum
            });
        });
    });
}

criterion_group! {
    name = transfer;
    config = common::criterion_config();
    targets = benchmark
}
criterion_main!(transfer);
