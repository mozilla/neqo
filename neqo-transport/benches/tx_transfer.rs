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

/// Acknowledges every packet in order, except as configured.
#[derive(Clone, Copy)]
struct Peer {
    /// Every `n`th packet is lost and retransmitted.
    lose_every: Option<usize>,
    /// Every `n`th packet is left unacknowledged until nothing else is in flight, then lost.
    defer_every: Option<usize>,
}

type Input = (TxBuffer, VecDeque<(u64, usize)>, Vec<(u64, usize)>);

fn setup() -> Input {
    let mut tx = TxBuffer::new();
    assert_eq!(tx.send(&vec![0; PACKETS * CHUNK]), PACKETS * CHUNK);
    (
        tx,
        VecDeque::with_capacity(IN_FLIGHT + 1),
        Vec::with_capacity(PACKETS / 2),
    )
}

/// Send the whole buffer one packet at a time, processing feedback once `IN_FLIGHT` packets are
/// outstanding.
fn transfer((tx, in_flight, holes): &mut Input, peer: Peer) {
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
            if holes.is_empty() {
                break;
            }
            for (off, len) in holes.drain(..) {
                tx.mark_as_lost(off, len);
            }
            continue;
        };
        n += 1;
        let hit = |every: Option<usize>| every.is_some_and(|every| n % every == 0);
        if hit(peer.lose_every) {
            tx.mark_as_lost(off, len);
        } else if hit(peer.defer_every) {
            holes.push((off, len));
        } else {
            tx.mark_as_acked(off, len);
        }
    }
    black_box(tx);
}

fn benches(c: &mut Criterion) {
    for (name, lose_every, defer_every) in [
        ("in-order acks", None, None),
        ("2% loss", Some(50), None),
        ("20% loss", Some(5), None),
        ("acks every other packet", None, Some(2)),
        ("2% loss, acks every other packet", Some(50), Some(2)),
    ] {
        let peer = Peer {
            lose_every,
            defer_every,
        };
        c.bench_function(&format!("TxBuffer transfer {name}"), |b| {
            b.iter_batched_ref(setup, |input| transfer(input, peer), BatchSize::LargeInput);
        });
    }
}

criterion_group!(tx_transfer, benches);
criterion_main!(tx_transfer);
