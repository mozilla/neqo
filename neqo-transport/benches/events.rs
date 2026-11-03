// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use neqo_transport::{ConnectionEvents, StreamId};

/// `n` queued datagrams, then readable and writable events on `n` streams each, optionally
/// cancelled by a reset and a `STOP_SENDING`, as in one batch of peer input.
fn events(c: &mut Criterion, n: u64, cull: bool) {
    let name = if cull { "cull" } else { "no-cull" };
    c.bench_function(
        &format!("ConnectionEvents {n} datagrams {n} streams {name}"),
        |b| {
            b.iter_batched(
                || {
                    let evts = ConnectionEvents::default();
                    for _ in 0..n {
                        evts.add_datagram(&[0; 3]);
                    }
                    evts
                },
                |evts| {
                    for i in 0..n {
                        evts.recv_stream_readable(StreamId::new(i * 4));
                        evts.send_stream_writable(StreamId::new(i * 4 + 1));
                        if cull {
                            evts.recv_stream_reset(StreamId::new(i * 4), 0);
                            evts.send_stream_stop_sending(StreamId::new(i * 4 + 1), 0);
                        }
                    }
                    black_box(evts)
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn benchmark_events(c: &mut Criterion) {
    for n in [1000, 2000, 4000] {
        events(c, n, false);
        events(c, n, true);
    }
}

criterion_group! {
    name = benches;
    config = { neqo_common::log::init(None); Criterion::default() };
    targets = benchmark_events
}
criterion_main!(benches);
