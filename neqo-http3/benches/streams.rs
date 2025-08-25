// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{hint::black_box, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
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

fn criterion_benchmark(c: &mut Criterion) {
    fixture_init();

    for (streams, data_size) in [(1usize, 1_000usize), (1_000, 1), (1_000, 1_000)] {
        let setup = || {
            let nodes = boxed![
                Node::default_client(boxed![Requests::new(streams, data_size)]),
                TailDrop::dsl_uplink(),
                RandomDelay::new(ZERO..JITTER),
                Node::default_server(boxed![Responses::new(streams, data_size)]),
                TailDrop::dsl_uplink(),
                RandomDelay::new(ZERO..JITTER),
            ];
            Simulator::new("", nodes).setup()
        };
        let routine = |sim: ReadySimulator| black_box(sim.run());

        let mut group = c.benchmark_group(format!("{streams}-streams/each-{data_size}-bytes"));

        // Benchmark with wallclock time, i.e. measure the compute efficiency.
        group.bench_function("wallclock-time", |b| {
            b.iter_batched(setup, routine, criterion::BatchSize::SmallInput);
        });

        // Benchmark with simulated time, i.e. measure the network protocol
        // efficiency.
        //
        // Note: Given that this is using simulated time, we can measure actual
        // throughput.
        group.throughput(Throughput::Bytes((streams * data_size) as u64));
        group.bench_function("simulated-time", |b| {
            b.iter_custom(|iters| {
                let mut d_sum = Duration::ZERO;
                for _i in 0..iters {
                    d_sum += setup().run();
                }

                d_sum
            });
        });

        group.finish();
    }

    Criterion::default().configure_from_args().final_summary();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
