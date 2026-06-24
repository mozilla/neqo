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

use criterion::{Criterion, criterion_group, criterion_main};
use neqo_common::{Decoder, Encoder, to_u64};
use neqo_transport::frame::{Frame, FrameType};

const FRAME_PAYLOAD: usize = 100;

/// Encode `n` STREAM frames (with offset and length) into a flat buffer,
/// then decode them all in one pass.  This isolates `Frame::decode` and the
/// varint path it calls.
///
/// Frame type 0x0e = StreamWithOffLen (offset present, length present, no FIN).
fn encode_stream_frames(n: usize) -> Vec<u8> {
    let mut enc = Encoder::default();
    for i in 0..to_u64(n) {
        enc.encode_varint(FrameType::StreamWithOffLen)
            .encode_varint(1u8) // stream id = 1
            .encode_varint(i * to_u64(FRAME_PAYLOAD)) // offset
            .encode_vvec(&[0u8; FRAME_PAYLOAD]); // length-prefixed payload
    }
    enc.into()
}

fn frame_decode(c: &mut Criterion, n: usize) {
    let buf = encode_stream_frames(n);
    c.bench_function(&format!("Frame::decode {n} STREAM frames"), |b| {
        b.iter(|| {
            let mut dec = Decoder::new(&buf);
            while dec.remaining() > 0 {
                black_box(Frame::decode(&mut dec).expect("decode frame"));
            }
        });
    });
}

fn benchmark(c: &mut Criterion) {
    frame_decode(c, 10);
    frame_decode(c, 100);
    frame_decode(c, 1_000);
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
