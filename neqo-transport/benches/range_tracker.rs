use criterion::{criterion_group, criterion_main, Criterion}; // black_box
use neqo_transport::send_stream::{RangeState, RangeTracker};

const CHUNK: u64 = 1000;
const END: u64 = 100_000;
fn build_coalesce(len: u64) -> RangeTracker {
    let mut used = RangeTracker::default();
    used.mark_range(0, CHUNK as usize, RangeState::Acked);
    used.mark_range(CHUNK, END as usize, RangeState::Sent);
    // leave a gap or it will coalesce here
    for i in 2..=len {
        // These do not get immediately coalesced when marking since they're not at the end or start
        used.mark_range(i * CHUNK, CHUNK as usize, RangeState::Acked);
    }
    return used;
}

fn coalesce(used: &mut RangeTracker) {
    used.mark_range(CHUNK, CHUNK as usize, RangeState::Acked);
    used.mark_range(END, CHUNK as usize, RangeState::Sent);
    used.mark_range(END, CHUNK as usize, RangeState::Acked);
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut used = build_coalesce(1);
    c.bench_function("coalesce_acked_from_zero 2 entries", |b| {
        b.iter(|| coalesce(&mut used))
    });
    used = build_coalesce(100);
    c.bench_function("coalesce_acked_from_zero 100 entries", |b| {
        b.iter(|| coalesce(&mut used))
    });
    used = build_coalesce(1000);
    c.bench_function("coalesce_acked_from_zero 1000 entries", |b| {
        b.iter(|| coalesce(&mut used))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
