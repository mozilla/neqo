// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Benchmark over a simulated network, measuring instruction count via CodSpeed.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use criterion::{criterion_group, criterion_main};

#[path = "transfer_common.rs"]
mod common;

fn benchmark(c: &mut criterion::Criterion) {
    common::bench(c, "simulated");
}

criterion_group! {
    name = transfer;
    config = common::criterion_config();
    targets = benchmark
}
criterion_main!(transfer);
