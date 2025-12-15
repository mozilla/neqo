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

use criterion::{criterion_group, criterion_main, Criterion};
use neqo_common::Decoder;

/// Fill the buffer with sequentially increasing values, wrapping at 255.
fn fill_buffer(n: usize, mask: u8) -> Vec<u8> {
    let mut buf = vec![0; n];
    #[expect(clippy::cast_possible_truncation, reason = "% makes this safe")]
    for (i, x) in buf.iter_mut().enumerate() {
        *x = (i % 256) as u8 & mask;
    }
    buf
}

fn decoder(c: &mut Criterion, count: usize, mask: u8) {
    c.bench_function(&format!("decode {count} bytes, mask {mask:x}"), |b| {
        b.iter_batched_ref(
            || fill_buffer(count, mask),
            |buf| {
                let mut dec = Decoder::new(&buf[..]);
                while black_box(dec.decode_varint()).is_some() {
                    // Do nothing;
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn benchmark_decoder(c: &mut Criterion) {
    for mask in [0xff, 0x7f, 0x3f] {
        for exponent in [12, 20] {
            decoder(c, 1 << exponent, mask);
        }
    }
}

criterion_group!(benches, benchmark_decoder);
criterion_main!(benches);
