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
    streams::{SendGroupId, SendOrder},
};

const MAX_STREAM_DATA: u64 = 1 << 20; // 1 MiB credit
// Must be small enough that a STREAM frame fits inside `packet::LIMIT` with room to spare,
// so the packet builder doesn't fill before idle streams are visited.
const DATA: &[u8] = &[0x5a; 200];

fn make_streams(n_streams: usize) -> SendStreams {
    make_streams_inner(n_streams, false, false)
}

fn make_fair_streams(n_streams: usize) -> SendStreams {
    make_streams_inner(n_streams, true, true)
}

fn make_streams_inner(n_streams: usize, all_have_data: bool, fair: bool) -> SendStreams {
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
        if i == 0 || all_have_data {
            s.send(DATA).expect("send failed");
        }
        ss.insert(id, s);
        if fair {
            ss.set_fairness(id, true).expect("set_fairness failed");
        }
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

/// `SendStreams::write_frames` with 5 fair streams, all with data.
/// Measures per-packet utilization when multiple ungrouped fair streams
/// compete for the same packet-builder pass.
fn write_frames_5_fair_all_active(c: &mut Criterion) {
    c.bench_function("SendStreams::write_frames 5-fair-streams all-active", |b| {
        b.iter_batched_ref(
            || make_fair_streams(5),
            do_write_frames,
            BatchSize::SmallInput,
        );
    });
}

/// `SendStreams::write_frames` with 20 fair streams, all with data.
fn write_frames_20_fair_all_active(c: &mut Criterion) {
    c.bench_function(
        "SendStreams::write_frames 20-fair-streams all-active",
        |b| {
            b.iter_batched_ref(
                || make_fair_streams(20),
                do_write_frames,
                BatchSize::SmallInput,
            );
        },
    );
}

/// Create `n_streams` fair streams with data, distributed across `n_groups` sendGroups.
fn make_grouped_streams(n_streams: usize, n_groups: usize) -> SendStreams {
    let conn_fc = Rc::new(RefCell::new(SenderFlowControl::new((), u64::MAX)));
    let conn_events = ConnectionEvents::default();
    let mut ss = SendStreams::default();
    for i in 0..n_streams as u64 {
        let id = StreamId::from(i * 4);
        let mut s = SendStream::new(
            id,
            MAX_STREAM_DATA,
            Rc::clone(&conn_fc),
            conn_events.clone(),
        );
        s.send(DATA).expect("send failed");
        ss.insert(id, s);
        ss.set_fairness(id, true).expect("set_fairness failed");
        let group_id = SendGroupId::new((i as usize % n_groups) as u64 + 1);
        ss.set_sendgroup(id, Some(group_id))
            .expect("set_sendgroup failed");
    }
    ss
}

/// Create `n_streams` fair streams with data and sendOrder, in a single group.
fn make_sendordered_streams(n_streams: usize) -> SendStreams {
    let conn_fc = Rc::new(RefCell::new(SenderFlowControl::new((), u64::MAX)));
    let conn_events = ConnectionEvents::default();
    let mut ss = SendStreams::default();
    for i in 0..n_streams as u64 {
        let id = StreamId::from(i * 4);
        let mut s = SendStream::new(
            id,
            MAX_STREAM_DATA,
            Rc::clone(&conn_fc),
            conn_events.clone(),
        );
        s.send(DATA).expect("send failed");
        ss.insert(id, s);
        ss.set_sendorder(id, Some(i as SendOrder))
            .expect("set_sendorder failed");
    }
    ss
}

/// 3 sendGroups, 9 streams (3 per group), all active — exercises round-robin.
fn write_frames_3_groups_9_streams(c: &mut Criterion) {
    c.bench_function(
        "SendStreams::write_frames 3-groups 9-streams all-active",
        |b| {
            b.iter_batched_ref(
                || make_grouped_streams(9, 3),
                do_write_frames,
                BatchSize::SmallInput,
            );
        },
    );
}

/// 5 fair streams with sendOrder, no explicit sendGroup — exercises per_group
/// path (not the fast path).
fn write_frames_5_sendordered(c: &mut Criterion) {
    c.bench_function("SendStreams::write_frames 5-sendordered no-group", |b| {
        b.iter_batched_ref(
            || make_sendordered_streams(5),
            do_write_frames,
            BatchSize::SmallInput,
        );
    });
}

/// 3 sendGroups with sendOrder, 9 streams — full multi-group ordered path.
fn write_frames_3_groups_9_sendordered(c: &mut Criterion) {
    c.bench_function("SendStreams::write_frames 3-groups 9-sendordered", |b| {
        b.iter_batched_ref(
            || {
                let mut ss = make_grouped_streams(9, 3);
                for i in 0..9u64 {
                    let id = StreamId::from(i * 4);
                    ss.set_sendorder(id, Some(i as SendOrder))
                        .expect("set_sendorder failed");
                }
                ss
            },
            do_write_frames,
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    write_frames_1_stream,
    write_frames_5_streams,
    write_frames_20_streams,
    write_frames_5_fair_all_active,
    write_frames_20_fair_all_active,
    write_frames_3_groups_9_streams,
    write_frames_5_sendordered,
    write_frames_3_groups_9_sendordered,
);
criterion_main!(benches);
