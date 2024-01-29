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

fn coalesce(c: &mut Criterion, count: u64) {
    let mut used = build_coalesce(count);
    c.bench_function(
        &format!("coalesce_acked_from_zero {count}+1 entries"),
        |b| {
            b.iter(|| {
                let used: &mut RangeTracker = &mut used;
                used.mark_range(CHUNK, CHUNK as usize, RangeState::Acked);
                let tail = (count + 1) * CHUNK;
                used.mark_range(tail, CHUNK as usize, RangeState::Sent);
                used.mark_range(tail, CHUNK as usize, RangeState::Acked);
            })
        },
    );
}

fn benchmark_coalesce(c: &mut Criterion) {
    coalesce(c, 1);
    coalesce(c, 3);
    coalesce(c, 10);
    coalesce(c, 1000);
}

criterion_group!(benches, benchmark_coalesce);
criterion_main!(benches);
