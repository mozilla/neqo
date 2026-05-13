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

use criterion::{Criterion, criterion_group, criterion_main};

#[path = "common.rs"]
mod common;

fn benchmark(c: &mut Criterion) {
    common::simulated(c);
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
