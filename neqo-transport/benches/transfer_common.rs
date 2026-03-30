// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use criterion::{BenchmarkGroup, Criterion};
use neqo_transport::{ConnectionParameters, State};
use test_fixture::{
    bench::NOISE_THRESHOLD,
    boxed,
    sim::{
        ReadySimulator, Simulator,
        connection::{Node, ReachState, ReceiveData, SendData},
        network::{Delay, TailDrop},
    },
};

const DELAY: Duration = Duration::from_millis(10);
pub const TRANSFER_AMOUNT: usize = 1 << 22; // 4Mbyte

const FIXED_SEED: &str = "62df6933ba1f543cece01db8f27fb2025529b27f93df39e19f006e1db3b8c843";

/// Creates a ready simulator for benchmarking transfer.
#[must_use]
pub fn setup(label: &str, seed: Option<&str>, pacing: bool) -> ReadySimulator {
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
    let mut sim = Simulator::new(label, nodes);
    if let Some(seed) = seed {
        sim.seed_str(seed);
    }
    sim.setup()
}

/// Runs transfer benchmarks for all configurations.
///
/// The closure receives the benchmark group, label, seed, and pacing flag,
/// allowing each benchmark to define its own measurement approach.
pub fn benchmark<M>(c: &mut Criterion, mut measure: M)
where
    M: FnMut(&mut BenchmarkGroup<'_, criterion::measurement::WallTime>, &str, Option<&str>, bool),
{
    let mut group = c.benchmark_group("transfer");
    group.noise_threshold(NOISE_THRESHOLD);
    for pacing in [false, true] {
        measure(&mut group, "fixed-seed", Some(FIXED_SEED), pacing);
    }
    group.finish();
}
