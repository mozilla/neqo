// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use neqo_transport::recv_stream::RxStreamOrderer;

fn rx_stream_orderer() {
    let mut rx = RxStreamOrderer::new();
    let data: &[u8] = &[0; 1337];

    for i in 0..100_000 {
        rx.inbound_frame(i * 1337, data);
    }
}

fn bench_sequential_insert(c: &mut Criterion) {
    c.bench_function("sequential_insert", |b| {
        b.iter(|| {
            let mut rx = RxStreamOrderer::new();
            let data: &[u8] = &[0; 1337];
            for i in 0..1000 {
                rx.inbound_frame(i * 1337, data);
            }
            black_box(rx);
        });
    });
}

fn bench_read_all_at_once(c: &mut Criterion) {
    c.bench_function("read_all_at_once", |b| {
        b.iter(|| {
            let mut rx = RxStreamOrderer::new();
            let data = vec![0u8; 1337];
            for i in 0..100 {
                rx.inbound_frame(i * 1337, &data);
            }
            let mut buf = Vec::new();
            black_box(rx.read_to_end(&mut buf));
        });
    });
}

fn bench_insert_and_read_interleaved(c: &mut Criterion) {
    c.bench_function("insert_and_read_interleaved", |b| {
        b.iter(|| {
            let mut rx = RxStreamOrderer::new();
            let data = vec![0u8; 1337];
            let mut buf = Vec::new();

            for i in 0..1000 {
                rx.inbound_frame(i * 1337, &data);
                if i % 10 == 0 {
                    black_box(rx.read_to_end(&mut buf));
                    buf.clear();
                }
            }
        });
    });
}

fn bench_inbound_frame(c: &mut Criterion) {
    c.bench_function("RxStreamOrderer::inbound_frame()", |b| {
        b.iter(black_box(rx_stream_orderer));
    });
}

criterion_group!(
    benches,
    bench_inbound_frame,
    bench_sequential_insert,
    bench_read_all_at_once,
    bench_insert_and_read_interleaved,
);
criterion_main!(benches);
