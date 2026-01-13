// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use neqo_transport::{
    recv_stream::RxStreamOrdererBTreeMap as BTreeMapOrderer,
    rx_stream_orderer_heap::RxStreamOrdererView as HeapOrderer,
};

const FRAME_SIZE: usize = 1337;

fn benchmark_in_order_btreemap(c: &mut Criterion) {
    c.bench_function("BTreeMap: in-order frames", |b| {
        b.iter(|| {
            let mut rx = BTreeMapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in 0..1000 {
                rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
            }
        });
    });
}

fn benchmark_in_order_heap(c: &mut Criterion) {
    c.bench_function("BinaryHeap: in-order frames", |b| {
        b.iter(|| {
            let mut rx = HeapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in 0..1000 {
                rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
            }
        });
    });
}

fn benchmark_reverse_order_btreemap(c: &mut Criterion) {
    c.bench_function("BTreeMap: reverse-order frames", |b| {
        b.iter(|| {
            let mut rx = BTreeMapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in (0..1000).rev() {
                rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
            }
        });
    });
}

fn benchmark_reverse_order_heap(c: &mut Criterion) {
    c.bench_function("BinaryHeap: reverse-order frames", |b| {
        b.iter(|| {
            let mut rx = HeapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in (0..1000).rev() {
                rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
            }
        });
    });
}

fn benchmark_random_order_btreemap(c: &mut Criterion) {
    // Create a deterministic "random" order by using a simple permutation.
    let mut order: Vec<usize> = (0..1000).collect();
    // Simple shuffle using XOR swap.
    for i in 0..order.len() {
        let j = (i * 7 + 13) % order.len();
        order.swap(i, j);
    }

    c.bench_function("BTreeMap: random-order frames", |b| {
        b.iter(|| {
            let mut rx = BTreeMapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for &i in &order {
                rx.inbound_frame(black_box(i as u64 * FRAME_SIZE as u64), black_box(data));
            }
        });
    });
}

fn benchmark_random_order_heap(c: &mut Criterion) {
    let mut order: Vec<usize> = (0..1000).collect();
    for i in 0..order.len() {
        let j = (i * 7 + 13) % order.len();
        order.swap(i, j);
    }

    c.bench_function("BinaryHeap: random-order frames", |b| {
        b.iter(|| {
            let mut rx = HeapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for &i in &order {
                rx.inbound_frame(black_box(i as u64 * FRAME_SIZE as u64), black_box(data));
            }
        });
    });
}

fn benchmark_with_gaps_btreemap(c: &mut Criterion) {
    c.bench_function("BTreeMap: frames with gaps", |b| {
        b.iter(|| {
            let mut rx = BTreeMapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            // Send every other frame.
            for i in 0..1000 {
                if i % 2 == 0 {
                    rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
                }
            }
        });
    });
}

fn benchmark_with_gaps_heap(c: &mut Criterion) {
    c.bench_function("BinaryHeap: frames with gaps", |b| {
        b.iter(|| {
            let mut rx = HeapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in 0..1000 {
                if i % 2 == 0 {
                    rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
                }
            }
        });
    });
}

fn benchmark_overlapping_btreemap(c: &mut Criterion) {
    c.bench_function("BTreeMap: overlapping frames", |b| {
        b.iter(|| {
            let mut rx = BTreeMapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in 0..1000 {
                // Each frame overlaps with the previous by half.
                rx.inbound_frame(black_box(i * (FRAME_SIZE / 2) as u64), black_box(data));
            }
        });
    });
}

fn benchmark_overlapping_heap(c: &mut Criterion) {
    c.bench_function("BinaryHeap: overlapping frames", |b| {
        b.iter(|| {
            let mut rx = HeapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in 0..1000 {
                rx.inbound_frame(black_box(i * (FRAME_SIZE / 2) as u64), black_box(data));
            }
        });
    });
}

fn benchmark_read_to_end_btreemap(c: &mut Criterion) {
    c.bench_function("BTreeMap: read_to_end after in-order insert", |b| {
        b.iter(|| {
            let mut rx = BTreeMapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in 0..1000 {
                rx.inbound_frame(i * FRAME_SIZE as u64, data);
            }

            let mut buf = Vec::new();
            black_box(rx.read_to_end(&mut buf));
        });
    });
}

fn benchmark_read_to_end_heap(c: &mut Criterion) {
    c.bench_function("BinaryHeap: read_to_end after in-order insert", |b| {
        b.iter(|| {
            let mut rx = HeapOrderer::new();
            let data: &[u8] = &[0; FRAME_SIZE];

            for i in 0..1000 {
                rx.inbound_frame(i * FRAME_SIZE as u64, data);
            }

            let mut buf = Vec::new();
            black_box(rx.read_to_end(&mut buf));
        });
    });
}

fn benchmark_varying_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("varying_frame_counts");

    for count in [100, 500, 1000, 5000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("BTreeMap", count), count, |b, &count| {
            b.iter(|| {
                let mut rx = BTreeMapOrderer::new();
                let data: &[u8] = &[0; FRAME_SIZE];

                for i in 0..count {
                    rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("BinaryHeap", count), count, |b, &count| {
            b.iter(|| {
                let mut rx = HeapOrderer::new();
                let data: &[u8] = &[0; FRAME_SIZE];

                for i in 0..count {
                    rx.inbound_frame(black_box(i * FRAME_SIZE as u64), black_box(data));
                }
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_in_order_btreemap,
    benchmark_in_order_heap,
    benchmark_reverse_order_btreemap,
    benchmark_reverse_order_heap,
    benchmark_random_order_btreemap,
    benchmark_random_order_heap,
    benchmark_with_gaps_btreemap,
    benchmark_with_gaps_heap,
    benchmark_overlapping_btreemap,
    benchmark_overlapping_heap,
    benchmark_read_to_end_btreemap,
    benchmark_read_to_end_heap,
    benchmark_varying_sizes,
);
criterion_main!(benches);
