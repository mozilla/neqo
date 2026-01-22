// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use criterion::{BenchmarkGroup, Criterion};
use test_fixture::{
    boxed, fixture_init,
    sim::{
        http3_connection::{Node, Requests, Responses},
        network::{RandomDelay, TailDrop},
        ReadySimulator, Simulator,
    },
};

const ZERO: Duration = Duration::from_millis(0);
const JITTER: Duration = Duration::from_millis(10);

/// Benchmark parameters: `(streams, data_size)`.
const BENCHMARK_PARAMS: [(usize, usize); 3] = [(1, 1_000), (1_000, 1), (1_000, 1_000)];

/// Creates a ready simulator for benchmarking HTTP/3 streams.
pub fn setup(streams: usize, data_size: usize) -> ReadySimulator {
    let nodes = boxed![
        Node::default_client(boxed![Requests::new(streams, data_size)]),
        TailDrop::dsl_uplink(),
        RandomDelay::new(ZERO..JITTER),
        Node::default_server(boxed![Responses::new(streams, data_size)]),
        TailDrop::dsl_uplink(),
        RandomDelay::new(ZERO..JITTER),
    ];
    Simulator::new("", nodes).setup()
}

/// Runs benchmarks for all parameter combinations.
///
/// The closure receives the benchmark group, group name, and parameters, allowing each
/// benchmark to define its own measurement approach.
pub fn benchmark<M>(c: &mut Criterion, mut measure: M)
where
    M: FnMut(&mut BenchmarkGroup<'_, criterion::measurement::WallTime>, &str, usize, usize),
{
    fixture_init();

    for (streams, data_size) in BENCHMARK_PARAMS {
        let name = format!("{streams}-streams/each-{data_size}-bytes");
        let mut group = c.benchmark_group(&name);
        measure(&mut group, &name, streams, data_size);
        group.finish();
    }
}
