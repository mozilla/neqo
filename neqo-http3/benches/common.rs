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
        ReadySimulator, Simulator,
        http3_connection::{Node, Requests, Responses},
        network::{Delay, TailDrop},
    },
};

const RTT: Duration = Duration::from_millis(10);

/// Benchmark parameters: `(streams, data_size)`.
const BENCHMARK_PARAMS: [(usize, usize); 3] = [(1, 1_000), (1_000, 1), (1_000, 1_000)];

/// Creates a ready simulator for benchmarking HTTP/3 streams.
pub fn setup(streams: usize, data_size: usize) -> ReadySimulator {
    let nodes = boxed![
        Node::default_client(boxed![Requests::new(streams, data_size)]),
        TailDrop::dsl_uplink(),
        Delay::new(RTT),
        Node::default_server(boxed![Responses::new(streams, data_size)]),
        TailDrop::dsl_uplink(),
        Delay::new(RTT),
    ];
    Simulator::new("", nodes).setup()
}

/// Runs benchmarks for all parameter combinations.
///
/// The closure receives the benchmark group and parameters, allowing each
/// benchmark to define its own measurement approach.
pub fn benchmark<M>(c: &mut Criterion, mut measure: M)
where
    M: FnMut(&mut BenchmarkGroup<'_, criterion::measurement::WallTime>, usize, usize),
{
    fixture_init();

    let mut group = c.benchmark_group("streams");
    for (streams, data_size) in BENCHMARK_PARAMS {
        measure(&mut group, streams, data_size);
    }
    group.finish();
}
