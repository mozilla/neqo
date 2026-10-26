// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::significant_drop_tightening,
    reason = "Inherent in codspeed criterion_group! macro."
)]

use std::{cmp::min, collections::VecDeque, hint::black_box};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use neqo_transport::send_stream::TxBuffer;

const CHUNK: usize = 1200;
const PACKETS: usize = 4000;
/// Packets in flight before the first acknowledgment arrives.
const IN_FLIGHT: usize = 100;

#[derive(Clone, Copy)]
enum Peer {
    /// Acknowledges every packet in order.
    InOrder,
    /// Acknowledges every packet in order, except that every `n`th is lost and retransmitted.
    Lossy(usize),
    /// Only ever acknowledges every other packet.
    EveryOther,
}

fn setup() -> (TxBuffer, VecDeque<(u64, usize)>) {
    let mut tx = TxBuffer::new();
    assert_eq!(tx.send(&vec![0; PACKETS * CHUNK]), PACKETS * CHUNK);
    (tx, VecDeque::with_capacity(2 * IN_FLIGHT))
}

/// Send the whole buffer one packet at a time, processing feedback once `IN_FLIGHT` packets are
/// outstanding.
fn transfer((tx, in_flight): &mut (TxBuffer, VecDeque<(u64, usize)>), peer: Peer) {
    let mut n = 0;
    loop {
        if let Some((off, data)) = tx.next_bytes() {
            let len = min(data.len(), CHUNK);
            tx.mark_as_sent(off, len);
            in_flight.push_back((off, len));
            if in_flight.len() <= IN_FLIGHT {
                continue;
            }
        }
        let Some((off, len)) = in_flight.pop_front() else {
            break;
        };
        n += 1;
        match peer {
            Peer::Lossy(every) if n % every == 0 => tx.mark_as_lost(off, len),
            Peer::EveryOther if n % 2 == 0 => {}
            _ => tx.mark_as_acked(off, len),
        }
    }
    black_box(tx);
}

fn benches(c: &mut Criterion) {
    for (name, peer) in [
        ("in-order acks", Peer::InOrder),
        ("2% loss", Peer::Lossy(50)),
        ("acks every other packet", Peer::EveryOther),
    ] {
        c.bench_function(&format!("TxBuffer transfer {name}"), |b| {
            b.iter_batched_ref(setup, |input| transfer(input, peer), BatchSize::LargeInput);
        });
    }
}

criterion_group!(tx_transfer, benches);
criterion_main!(tx_transfer);
