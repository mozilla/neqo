// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::{cell::RefCell, hint::black_box, rc::Rc};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use neqo_common::Encoder;
use neqo_transport::{
    ConnectionEvents, FrameStats, SenderFlowControl,
    packet::{self, Builder},
    recovery,
    send_stream::{SendStream, SendStreams, TransmissionPriority},
    stream_id::StreamId,
};

const MAX_STREAM_DATA: u64 = 1 << 20; // 1 MiB credit
const DATA: &[u8] = &[0x5a; 200];

fn make_streams(n_streams: usize) -> SendStreams {
    let conn_fc = Rc::new(RefCell::new(SenderFlowControl::new((), u64::MAX)));
    let conn_events = ConnectionEvents::default();
    let mut ss = SendStreams::default();
    for i in 0..n_streams as u64 {
        let id = StreamId::from(i * 4); // client-initiated bidi IDs
        let mut s = SendStream::new(
            id,
            MAX_STREAM_DATA,
            Rc::clone(&conn_fc),
            conn_events.clone(),
        );
        if i == 0 {
            // Only stream 0 has data; the rest are idle.
            s.send(DATA).expect("send failed");
        }
        ss.insert(id, s);
    }
    ss
}

fn do_write_frames(ss: &mut SendStreams) {
    let mut builder = Builder::short(Encoder::default(), false, None::<&[u8]>, packet::LIMIT);
    let mut tokens = recovery::Tokens::new();
    let mut stats = FrameStats::default();
    ss.write_frames(
        TransmissionPriority::default(),
        &mut builder,
        &mut tokens,
        &mut stats,
    );
    black_box((builder, tokens, stats));
}

/// `SendStreams::write_frames` with 1 stream (baseline: no idle iteration).
fn write_frames_1_stream(c: &mut Criterion) {
    c.bench_function("SendStreams::write_frames 1-stream", |b| {
        b.iter_batched_ref(|| make_streams(1), do_write_frames, BatchSize::SmallInput);
    });
}

/// `SendStreams::write_frames` with 5 streams, only 1 has data.
/// Typical HTTP/3 connection: data stream + control + 2 QPACK + settings.
fn write_frames_5_streams(c: &mut Criterion) {
    c.bench_function("SendStreams::write_frames 5-streams 1-active", |b| {
        b.iter_batched_ref(|| make_streams(5), do_write_frames, BatchSize::SmallInput);
    });
}

/// `SendStreams::write_frames` with 20 streams, only 1 has data.
/// Amplifies the idle-iteration cost to make it measurable.
fn write_frames_20_streams(c: &mut Criterion) {
    c.bench_function("SendStreams::write_frames 20-streams 1-active", |b| {
        b.iter_batched_ref(|| make_streams(20), do_write_frames, BatchSize::SmallInput);
    });
}

criterion_group!(
    benches,
    write_frames_1_stream,
    write_frames_5_streams,
    write_frames_20_streams,
);
criterion_main!(benches);
