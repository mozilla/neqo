use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize::SmallInput, Criterion};
use test_fixture::{
    boxed,
    sim::{
        connection::{ConnectionNode, ReceiveData, SendData},
        network::{Delay, TailDrop},
        Simulator,
    },
};

const ZERO: Duration = Duration::from_millis(0);
const JITTER: Duration = Duration::from_millis(10);
const TRANSFER_AMOUNT: usize = 1 << 20; // 1M

fn benchmark_transfer(c: &mut Criterion) {
    c.bench_function("Simulate a transfer", |b| {
        b.iter_batched(
            || {
                let nodes = boxed![
                    ConnectionNode::default_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
                    TailDrop::dsl_uplink(),
                    Delay::new(ZERO..JITTER),
                    ConnectionNode::default_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
                    TailDrop::dsl_downlink(),
                    Delay::new(ZERO..JITTER),
                ];
                let mut sim = Simulator::new("benchmark transfer", nodes);
                if let Ok(seed) = std::env::var("SIMULATION_SEED") {
                    sim.seed_str(seed);
                }
                sim.setup()
            },
            |sim| {
                sim.run();
            },
            SmallInput,
        )
    });
}

criterion_group!(benches, benchmark_transfer);
criterion_main!(benches);
