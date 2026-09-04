// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::num::NonZeroUsize;

use neqo_common::{Encoder, event::Provider as _, to_u64};
use neqo_transport::{ConnectionParameters, DatagramQueueOutcome, streams::SendGroupId};
use test_fixture::now;

use crate::{
    Http3ClientEvent, Http3ServerEvent, WebTransportEvent,
    features::extended_connect::tests::webtransport::{
        DATAGRAM_SIZE, WtTest, wt_default_parameters,
    },
    webtransport::{ClientSession as _, ServerEvent, ServerSession},
};

const DGRAM: &[u8] = &[0, 100];

fn do_datagram_test(wt: &mut WtTest, wt_session: &ServerSession) {
    assert_eq!(
        wt_session.max_datagram_size(),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64())))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64())))
    );

    assert_eq!(
        wt_session.send_datagram(DGRAM, None, now(), SendGroupId::new(0), 0),
        Ok(DatagramQueueOutcome::Ok)
    );
    assert_eq!(wt.send_datagram(wt_session.stream_id(), DGRAM), Ok(()));

    wt.exchange_packets();
    wt.check_datagram_received_client(wt_session.stream_id(), DGRAM);
    wt.check_datagram_received_server(wt_session, DGRAM);
}

#[test]
fn datagrams() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    do_datagram_test(&mut wt, &wt_session);
}

#[test]
fn datagrams_multiple_session() {
    let mut wt = WtTest::new();

    let wt_session1 = wt.create_wt_session();
    do_datagram_test(&mut wt, &wt_session1);

    let wt_session_2 = wt.create_wt_session();
    do_datagram_test(&mut wt, &wt_session_2);
}

// A peer is allowed to advertise a max_datagram_frame_size smaller than the
// per-datagram quarter-stream-id prefix. Once a session lands on a stream id
// whose quarter stream id needs a longer varint than the available datagram
// size (quarter stream id >= 64, i.e. stream id >= 256, needs two bytes), the
// prefix subtraction must clamp to zero instead of wrapping.
#[test]
fn max_datagram_size_smaller_than_session_prefix() {
    let params = || {
        wt_default_parameters()
            .connection_parameters(ConnectionParameters::default().datagram_size(1))
    };
    let mut wt = WtTest::new_with_params(params(), params());

    let mut wt_session = wt.create_wt_session();
    while wt_session.stream_id().as_u64() < 256 {
        wt_session = wt.create_wt_session();
    }
    assert_eq!(Encoder::varint_len(wt_session.stream_id().as_u64() >> 2), 2);

    assert_eq!(wt_session.max_datagram_size(), Ok(0));
    assert_eq!(wt.max_datagram_size(wt_session.stream_id()), Ok(0));
}

#[test]
fn datagram_high_water_mark_signals_backpressure() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    wt_session.set_datagram_high_water_mark(Some(NonZeroUsize::new(2).unwrap()));
    assert_eq!(
        wt_session.send_datagram(DGRAM, Some(1), t0, SendGroupId::new(0), 0),
        Ok(DatagramQueueOutcome::Ok)
    );
    assert_eq!(
        wt_session.send_datagram(DGRAM, Some(2), t0, SendGroupId::new(0), 0),
        Ok(DatagramQueueOutcome::AboveWatermark),
        "the second datagram crosses the high water mark"
    );
}

/// Draining a queue that reported `AboveWatermark` must surface the resume
/// event on both sides: [`Http3ClientEvent::OutgoingDatagramSpaceAvailable`]
/// to the client and [`Http3ServerEvent::OutgoingDatagramSpaceAvailable`] to
/// the server.
#[test]
fn outgoing_datagram_space_available_forwarded() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();
    let t0 = now();

    let (conn, handler) = wt.client.connection_and_handler();
    handler
        .extended_connect_set_datagram_high_water_mark(
            session_id,
            conn,
            Some(NonZeroUsize::new(1).unwrap()),
        )
        .unwrap();
    assert_eq!(
        wt.client
            .webtransport_send_datagram(session_id, DGRAM, None, t0, SendGroupId::new(0), 0),
        Ok(DatagramQueueOutcome::AboveWatermark)
    );
    assert!(
        !wt.client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable)),
        "client resume event fired before the queue drained"
    );

    wt_session.set_datagram_high_water_mark(Some(NonZeroUsize::new(1).unwrap()));
    assert_eq!(
        wt_session.send_datagram(DGRAM, Some(1), t0, SendGroupId::new(0), 0),
        Ok(DatagramQueueOutcome::AboveWatermark)
    );
    assert!(
        !wt.server
            .events()
            .any(|e| matches!(e, Http3ServerEvent::OutgoingDatagramSpaceAvailable { .. })),
        "server resume event fired before the queue drained"
    );

    wt.exchange_packets();

    assert!(
        wt.client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable)),
        "OutgoingDatagramSpaceAvailable was not forwarded to the HTTP/3 client"
    );
    assert!(
        wt.server
            .events()
            .any(|e| matches!(e, Http3ServerEvent::OutgoingDatagramSpaceAvailable { .. })),
        "OutgoingDatagramSpaceAvailable was not forwarded to the HTTP/3 server"
    );
}

#[test]
fn datagram_send_order_controls_priority() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    // Enqueue the low-priority one first; both ungrouped (SendGroupId::new(0)),
    // so send_order alone must decide delivery order.
    assert_eq!(
        wt_session.send_datagram(b"low", Some(1), t0, SendGroupId::new(0), 1),
        Ok(DatagramQueueOutcome::Ok)
    );
    assert_eq!(
        wt_session.send_datagram(b"high", Some(2), t0, SendGroupId::new(0), 10),
        Ok(DatagramQueueOutcome::Ok)
    );

    wt.exchange_packets();

    let received: Vec<Vec<u8>> = wt
        .client
        .events()
        .filter_map(|e| match e {
            Http3ClientEvent::WebTransport(WebTransportEvent::Datagram { datagram, .. }) => {
                Some(datagram.as_ref().to_vec())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        received,
        vec![b"high".to_vec(), b"low".to_vec()],
        "the higher send_order datagram must be delivered first"
    );
}

/// A burst exceeding the byte budget, with a mix of send-order priorities,
/// must evict low-priority datagrams to make room for high-priority ones -
/// verified through the real `Http3Client` API and a live connection, not
/// just on a bare `DatagramQueue` in isolation. `DatagramQueueOutcome::Overflowed`
/// reports only how many were evicted, not which ones, so identity is
/// checked the same way the receiving peer would: by which content (each
/// datagram's payload is its own id, as 8 little-endian bytes) actually
/// arrives - checked against whatever has been delivered so far, since a
/// full drain of a backlog this size isn't practical in one exchange.
#[test]
fn datagram_burst_exceeding_byte_budget_preserves_priority_through_a_live_connection() {
    const HIGH_PRIORITY_COUNT: usize = 5;

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Fill the byte budget with low-priority (order=0) datagrams, without
    // draining, until eviction starts - i.e. until the budget is full.
    let mut low_priority_ids = Vec::new();
    let mut total_evicted: usize = 0;
    let mut next_id: u64 = 0;
    loop {
        let outcome = wt
            .client
            .webtransport_send_datagram(
                session_id,
                &next_id.to_le_bytes(),
                Some(next_id),
                now(),
                SendGroupId::new(0),
                0,
            )
            .unwrap();
        low_priority_ids.push(next_id);
        next_id += 1;
        if let DatagramQueueOutcome::Overflowed { dropped } = outcome {
            total_evicted += dropped;
            break;
        }
        assert_eq!(
            outcome,
            DatagramQueueOutcome::Ok,
            "unexpected outcome before the byte budget is hit"
        );
        assert!(
            next_id < 1_000_000,
            "byte budget should have been hit by now"
        );
    }

    // Now send a few high-priority datagrams, each forced to evict at least
    // one more low-priority datagram to make room.
    let high_priority_ids: Vec<u64> = (0..to_u64(HIGH_PRIORITY_COUNT))
        .map(|i| next_id + i)
        .collect();
    for &id in &high_priority_ids {
        let outcome = wt
            .client
            .webtransport_send_datagram(
                session_id,
                &id.to_le_bytes(),
                Some(id),
                now(),
                SendGroupId::new(0),
                10,
            )
            .unwrap();
        match outcome {
            DatagramQueueOutcome::Overflowed { dropped } => total_evicted += dropped,
            other => panic!("expected an eviction for the high-priority datagram: {other:?}"),
        }
    }

    // The backlog is tens of thousands of bytes deep; a real connection's
    // pacer/congestion window won't drain all of it in one exchange, so
    // this only checks what has arrived so far - not full delivery.
    wt.exchange_packets();

    let received: Vec<u64> = wt
        .server
        .events()
        .filter_map(|e| match e {
            Http3ServerEvent::WebTransport(ServerEvent::Datagram { session, datagram })
                if session.stream_id() == session_id =>
            {
                Some(u64::from_le_bytes(datagram.as_ref().try_into().unwrap()))
            }
            _ => None,
        })
        .collect();

    for &id in &high_priority_ids {
        assert!(
            received.contains(&id),
            "high-priority datagram {id} must be sent ahead of the low-priority backlog"
        );
    }

    // Whatever low-priority datagrams made it out in this exchange, in
    // delivery order, must be exactly the earliest survivors - proving both
    // that eviction took the oldest ones first (a gap here would mean some
    // other one was evicted instead) and that delivery still respects FIFO
    // within the order-0 bucket. `DatagramQueueOutcome::Overflowed` no
    // longer names which ids it evicted, so this is the only ground truth
    // left for that check.
    let received_low: Vec<u64> = received
        .iter()
        .copied()
        .filter(|id| !high_priority_ids.contains(id))
        .collect();
    assert!(
        !received_low.is_empty(),
        "at least some of the surviving low-priority datagrams must have been delivered"
    );
    assert_eq!(
        received_low,
        low_priority_ids[total_evicted..total_evicted + received_low.len()],
        "surviving low-priority datagrams must be exactly the oldest ones eviction spared, in FIFO order"
    );
}
