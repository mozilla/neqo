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
use neqo_common::{Decoder, Encoder};
use neqo_transport::frame::Frame;

const FRAME_PAYLOAD: usize = 100;

/// Encode `n` STREAM frames (with offset and length) into a flat buffer,
/// then decode them all in one pass.  This isolates `Frame::decode` and the
/// varint path it calls.
///
/// Frame type 0x0e = StreamWithOffLen (offset present, length present, no FIN).
fn encode_stream_frames(n: usize) -> Vec<u8> {
    let payload = vec![0u8; FRAME_PAYLOAD];
    let mut enc = Encoder::default();
    for i in 0..n as u64 {
        enc.encode_byte(0x0e); // StreamWithOffLen
        enc.encode_varint(1u64); // stream id = 1
        enc.encode_varint(i * FRAME_PAYLOAD as u64); // offset
        enc.encode_vvec(&payload); // length-prefixed payload
    }
    enc.into()
}

fn frame_decode(c: &mut Criterion, n: usize) {
    let buf = encode_stream_frames(n);
    c.bench_function(&format!("Frame::decode {n} STREAM frames"), |b| {
        b.iter_batched(
            || buf.clone(),
            |buf| {
                let mut dec = Decoder::new(&buf);
                while dec.remaining() > 0 {
                    black_box(Frame::decode(&mut dec).ok());
                }
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });
}

fn benchmark(c: &mut Criterion) {
    frame_decode(c, 10);
    frame_decode(c, 100);
    frame_decode(c, 1_000);
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
