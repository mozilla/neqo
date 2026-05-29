// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::{hint::black_box, time::Instant};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use neqo_common::{Decoder, Encoder};
use neqo_transport::{
    CryptoDxState, CryptoStates, RandomConnectionIdGenerator,
    frame::{Frame, FrameEncoder, FrameType},
    packet::{Builder, Public},
};
use test_fixture::fixture_init;

const DCID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
const MTU: usize = 1_500;
const AEAD_EXPANSION: usize = 16;

static STREAM_DATA: [u8; MTU] = [0x5a; MTU];

fn make_builder() -> Builder<Vec<u8>> {
    let mut builder = Builder::short(
        Encoder::default(),
        false,
        Some(DCID.as_ref()),
        MTU - AEAD_EXPANSION,
    );
    builder.scramble(false);
    builder.pn(0, 1);
    builder
}

fn build_stream_packet(crypto: &mut CryptoDxState) -> Vec<u8> {
    let mut builder = make_builder();
    // Single fill STREAM frame (no offset, no length): data runs to end of packet.
    // Subtract 2 from remaining() to account for the frame-type and stream_id varints
    // that encode_frame and the closure will write before the payload.
    let data_len = builder.remaining() - 2;
    builder.encode_frame(FrameType::Stream, |b| {
        b.encode_varint(1u64); // stream_id=1
        b.encode(&STREAM_DATA[..data_len]);
    });
    builder.mark_full();
    builder.build(crypto).expect("build stream packet").into()
}

fn build_ack_packet(crypto: &mut CryptoDxState) -> Vec<u8> {
    let mut builder = make_builder();
    builder.encode_frame(FrameType::Ack, |b| {
        b.encode_varint(999u64) // largest acked
            .encode_varint(25u64) // ack delay
            .encode_varint(3u64) // additional range count
            .encode_varint(99u64) // first range: acks 900..=999
            .encode_varint(9u64) // gap
            .encode_varint(89u64) // range: acks 800..=889
            .encode_varint(9u64) // gap
            .encode_varint(89u64) // range: acks 700..=789
            .encode_varint(9u64) // gap
            .encode_varint(89u64); // range: acks 600..=689
    });
    builder.build(crypto).expect("build ACK packet").into()
}

fn bench_encode(c: &mut Criterion, name: &str, build: fn(&mut CryptoDxState) -> Vec<u8>) {
    c.bench_function(name, |b| {
        b.iter_batched(
            CryptoDxState::test_default_write,
            |mut crypto| black_box(build(&mut crypto)),
            BatchSize::SmallInput,
        );
    });
}

fn bench_decode(c: &mut Criterion, name: &str, pkt: Vec<u8>) {
    let cid_decoder = RandomConnectionIdGenerator::new(DCID.len());
    let now = Instant::now();
    c.bench_function(name, |b| {
        b.iter_batched(
            || (pkt.clone(), CryptoStates::test_default()),
            |(mut buf, mut crypto): (Vec<u8>, CryptoStates)| {
                let (public, _) = Public::decode(&mut buf, &cid_decoder).expect("decode");
                let decrypted = public.decrypt(&mut crypto, now).expect("decrypt");
                let mut dec = Decoder::new(&decrypted);
                while dec.remaining() > 0 {
                    black_box(Frame::decode(&mut dec).ok());
                }
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });
}

fn packet_encode_stream(c: &mut Criterion) {
    bench_encode(
        c,
        "packet::Builder encode+encrypt STREAM packet",
        build_stream_packet,
    );
}

fn packet_decode_stream(c: &mut Criterion) {
    let pkt = build_stream_packet(&mut CryptoDxState::test_default_write());
    bench_decode(c, "packet::Public decrypt+decode STREAM packet", pkt);
}

fn packet_encode_ack(c: &mut Criterion) {
    bench_encode(
        c,
        "packet::Builder encode+encrypt ACK packet",
        build_ack_packet,
    );
}

fn packet_decode_ack(c: &mut Criterion) {
    let pkt = build_ack_packet(&mut CryptoDxState::test_default_write());
    bench_decode(c, "packet::Public decrypt+decode ACK packet", pkt);
}

fn benchmark(c: &mut Criterion) {
    fixture_init();
    packet_encode_stream(c);
    packet_decode_stream(c);
    packet_encode_ack(c);
    packet_decode_ack(c);
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
