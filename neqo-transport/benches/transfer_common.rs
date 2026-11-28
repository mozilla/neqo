// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize::SmallInput, Criterion, Throughput};
use neqo_common::to_u64;
use neqo_transport::{ConnectionParameters, State};
use test_fixture::{
    boxed,
    sim::{
        ReadySimulator, Simulator,
        connection::{Node, ReachState, ReceiveData, SendData},
        network::{Delay, TailDrop},
    },
};

const DELAY: Duration = Duration::from_millis(10);
const TRANSFER_AMOUNT: usize = 1 << 22; // 4MiB

const FIXED_SEED: &str = "62df6933ba1f543cece01db8f27fb2025529b27f93df39e19f006e1db3b8c843";

/// Creates a ready simulator for benchmarking transfer.
#[must_use]
fn setup(pacing: bool) -> ReadySimulator {
    let nodes = boxed![
        Node::new_client(
            ConnectionParameters::default()
                .pmtud(true)
                .pacing(pacing)
                .mlkem(false),
            boxed![ReachState::new(State::Confirmed)],
            boxed![SendData::new(TRANSFER_AMOUNT)]
        ),
        TailDrop::dsl_uplink(),
        Delay::new(DELAY),
        Node::new_server(
            ConnectionParameters::default()
                .pmtud(true)
                .pacing(pacing)
                .mlkem(false),
            boxed![ReachState::new(State::Confirmed)],
            boxed![ReceiveData::new(TRANSFER_AMOUNT)]
        ),
        TailDrop::dsl_downlink(),
        Delay::new(DELAY),
    ];
    let mut sim = Simulator::new("transfer", nodes);
    sim.seed_str(FIXED_SEED);
    sim.setup()
}

/// Runs transfer benchmarks using `iter_batched`, grouping results under
/// `name_prefix` (e.g. `"walltime"` or `"simulated"`).
pub fn bench(c: &mut Criterion, name_prefix: &str) {
    let mut group = c.benchmark_group("transfer");
    group.noise_threshold(0.03);
    group.throughput(Throughput::Bytes(to_u64(TRANSFER_AMOUNT)));
    // One seed only: no node here draws from the simulator's RNG, so other seeds would measure
    // the same transfer.
    for pacing in [false, true] {
        group.bench_function(format!("{name_prefix}/pacing-{pacing}/same-seed"), |b| {
            b.iter_batched(|| setup(pacing), |sim| black_box(sim.run()), SmallInput);
        });
    }
    group.finish();
}

/// Returns the criterion configuration for transfer benchmarks.
#[must_use]
pub fn criterion_config() -> Criterion {
    Criterion::default()
        // A longer warm-up builds large `SmallInput` batches, which slow and destabilize the run.
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(15))
}
