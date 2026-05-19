// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    dead_code,
    reason = "Included by two bench binaries; each uses only one entry point."
)]

use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput};
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
///
/// Data sizes are well below the 1 MB per-stream flow-control window, so these
/// benchmarks measure raw throughput and scheduling overhead without any
/// flow-control blocking.
const BENCHMARK_PARAMS: [(usize, usize); 3] = [(1, 1_000), (1_000, 1), (1_000, 1_000)];

/// Flow-control benchmark parameters: `(streams, data_size)`.
///
/// Data sizes meet or exceed the 1 MB per-stream and 2 MB connection-level flow-control
/// windows, so streams regularly block waiting for `MAX_STREAM_DATA` grants.
const FC_BENCHMARK_PARAMS: [(usize, usize); 2] = [
    (1, 4 * 1024 * 1024),  // 4× per-stream window
    (10, 1 * 1024 * 1024), // each stream hits per-stream window; 5× connection-level window
];

fn setup_with_link(
    streams: usize,
    data_size: usize,
    link: impl Fn() -> TailDrop,
) -> ReadySimulator {
    let nodes = boxed![
        Node::default_client(boxed![Requests::new(streams, data_size)]),
        link(),
        Delay::new(RTT),
        Node::default_server(boxed![Responses::new(streams, data_size)]),
        link(),
        Delay::new(RTT),
    ];
    Simulator::new("", nodes).setup()
}

/// Creates a ready simulator over a DSL-like link.
///
/// The DSL uplink (200 KB/s, 60 ms one-way delay) keeps the bandwidth-delay
/// product well below the default flow-control window, so no FC blocking occurs.
pub fn setup(streams: usize, data_size: usize) -> ReadySimulator {
    setup_with_link(streams, data_size, TailDrop::dsl_uplink)
}

/// Creates a ready simulator over a fast link where flow-control blocking occurs.
///
/// At 100 MB/s with a 20 ms RTT the bandwidth-delay product (~2 MB) exceeds the
/// 1 MB per-stream flow-control window, so streams regularly exhaust their window
/// and block waiting for `MAX_STREAM_DATA`.
pub fn setup_flow_controlled(streams: usize, data_size: usize) -> ReadySimulator {
    // Link delay is zero so propagation RTT comes entirely from the Delay nodes
    // (10 ms each way = 20 ms RTT).
    setup_with_link(streams, data_size, || {
        TailDrop::new(100_000_000, 2_000_000, false, Duration::ZERO)
    })
}

type SetupFn = fn(usize, usize) -> ReadySimulator;

/// All benchmark configurations: `(criterion group, setup fn, params)`.
const CONFIGS: [(&str, SetupFn, &[(usize, usize)]); 2] = [
    ("streams", setup, &BENCHMARK_PARAMS),
    (
        "streams-flow-controlled",
        setup_flow_controlled,
        &FC_BENCHMARK_PARAMS,
    ),
];

/// Runs all stream benchmarks measuring wall-clock CPU time.
pub fn walltime(c: &mut Criterion) {
    fixture_init();
    for (group_name, setup_fn, params) in CONFIGS {
        let mut group = c.benchmark_group(group_name);
        for &(streams, data_size) in params {
            let name = format!("walltime/{streams}-streams/each-{data_size}-bytes");
            group.bench_function(&name, |b| {
                b.iter_batched(
                    || setup_fn(streams, data_size),
                    |sim| black_box(sim.run()),
                    criterion::BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

/// Runs all stream benchmarks measuring simulated network time (throughput).
pub fn simulated(c: &mut Criterion) {
    fixture_init();
    for (group_name, setup_fn, params) in CONFIGS {
        let mut group = c.benchmark_group(group_name);
        for &(streams, data_size) in params {
            let name = format!("simulated/{streams}-streams/each-{data_size}-bytes");
            group.throughput(Throughput::Bytes((streams * data_size) as u64));
            group.bench_function(&name, |b| {
                b.iter_custom(|iters| {
                    (0..iters)
                        .map(|_| setup_fn(streams, data_size).run())
                        .sum::<Duration>()
                });
            });
        }
        group.finish();
    }
}
