// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{num::NonZeroUsize, time::Duration};

use neqo_common::{Encoder, event::Provider as _, to_u64};
use neqo_transport::{ConnectionParameters, DatagramQueueOutcome, StreamId, streams::SendGroupId};
use test_fixture::now;

use crate::{
    Http3ClientEvent, Http3ServerEvent, WebTransportEvent,
    features::extended_connect::{
        DatagramOutcome,
        tests::webtransport::{DATAGRAM_SIZE, WtTest, wt_default_parameters},
    },
    webtransport::{ClientSession as _, ServerEvent, ServerSession},
};

fn server_datagram_outcomes(wt: &WtTest, session_id: StreamId) -> Vec<DatagramOutcome> {
    wt.server
        .events()
        .filter_map(|e| match e {
            Http3ServerEvent::WebTransport(ServerEvent::DatagramOutcome { session, outcome })
                if session.stream_id() == session_id =>
            {
                Some(outcome)
            }
            _ => None,
        })
        .collect()
}

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
fn datagram_expires_before_being_sent() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    wt_session
        .set_datagram_max_age(Some(Duration::from_millis(5)), t0)
        .unwrap();
    assert_eq!(
        wt_session.send_datagram(DGRAM, Some(1), t0, SendGroupId::new(0), 0),
        Ok(DatagramQueueOutcome::Ok)
    );
    assert_eq!(wt_session.datagram_queue_capacity().queued_datagrams, 1);

    // No packets ever need to be built in between: expiry must not wait on
    // that. Driving the server's own HTTP/3 tick (not exchange_packets,
    // which uses its own clock) is enough on its own.
    let later = t0 + Duration::from_millis(10);
    drop(wt.server.process_output(later));

    assert_eq!(
        wt_session.datagram_queue_capacity().queued_datagrams,
        0,
        "the stale datagram must be gone before it is ever handed to the QUIC layer"
    );
    assert_eq!(wt_session.stats().datagrams_expired_outgoing, 1);
}

#[test]
fn datagram_larger_than_peers_limit_is_rejected_synchronously() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    let max = wt_session
        .max_datagram_size()
        .expect("datagrams are enabled by default");
    let oversized = vec![0; usize::try_from(max).unwrap() + 1];

    assert_eq!(
        wt_session.send_datagram(&oversized, Some(1), now(), SendGroupId::new(0), 0),
        Err(crate::Error::Transport(neqo_transport::Error::TooMuchData)),
        "an oversized datagram must fail before ever reaching the queue"
    );
    assert_eq!(wt_session.datagram_queue_capacity().queued_datagrams, 0);
}

/// `SessionStats::datagrams_sent_outgoing` must count a datagram sent
/// without a tracking id -- an aggregate delta covering untracked sends is
/// the whole point of counting it here instead of only via per-datagram
/// `DatagramOutcome` events.
#[test]
fn untracked_datagram_sent_is_counted_in_aggregate_stats() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    assert_eq!(
        wt.client
            .webtransport_send_datagram(session_id, DGRAM, None, now(), SendGroupId::new(0), 0)
            .unwrap(),
        DatagramQueueOutcome::Ok
    );
    wt.exchange_packets();

    let stats = wt.client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(stats.datagrams_sent_outgoing, 1);
    assert_eq!(stats.datagrams_dropped_outgoing, 0);
}

/// `SessionStats::datagrams_dropped_outgoing` must count a datagram evicted
/// from the queue to make room under the byte budget, even without a
/// tracking id.
#[test]
fn untracked_datagram_eviction_is_counted_in_aggregate_stats() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    for sent in 0.. {
        let outcome = wt
            .client
            .webtransport_send_datagram(session_id, DGRAM, None, now(), SendGroupId::new(0), 0)
            .unwrap();
        if matches!(outcome, DatagramQueueOutcome::Overflowed { .. }) {
            break;
        }
        assert!(sent < 1_000_000, "byte budget should have been hit by now");
    }

    let stats = wt.client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(stats.datagrams_dropped_outgoing, 1);
}

#[test]
fn datagram_high_water_mark_signals_backpressure() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    wt_session
        .set_datagram_high_water_mark(Some(NonZeroUsize::new(2).unwrap()))
        .unwrap();
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

/// The queue's resume signal must still reach the HTTP/3 server's event
/// queue, which nothing else covers any more:
/// `datagram_high_water_mark_signals_backpressure` stops at the transport
/// outcome, and connect-udp has no way to set a high water mark to drive
/// this from.
#[test]
fn outgoing_datagram_space_available_forwarded() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    wt_session
        .set_datagram_high_water_mark(Some(NonZeroUsize::new(1).unwrap()))
        .unwrap();
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
        wt.server
            .events()
            .any(|e| matches!(e, Http3ServerEvent::OutgoingDatagramSpaceAvailable { .. })),
        "OutgoingDatagramSpaceAvailable was not forwarded to the HTTP/3 server"
    );
}

#[test]
fn server_processes_a_connection_whose_only_pending_work_is_an_expired_datagram() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    wt_session
        .set_datagram_max_age(Some(Duration::from_millis(5)), t0)
        .unwrap();
    // set_datagram_max_age marks the connection as needing processing on its
    // own; flush that here so it can't mask the check below. From this point
    // on, only the datagram's own expiry may give the connection a reason to
    // be processed.
    drop(wt.server.process_output(t0));
    // Untracked (id: None): the queue reports no per-datagram outcome for a
    // send either way, but a tracked one leaves an ID to report on later,
    // and this test wants the datagram's expiry to be the only thing that
    // can give the connection a reason to be processed.
    _ = wt_session
        .send_datagram_without_marking_needs_processing(DGRAM, None, t0)
        .unwrap();
    assert_eq!(wt_session.datagram_queue_capacity().queued_datagrams, 1);

    let later = t0 + Duration::from_millis(10);
    drop(wt.server.process_output(later));

    assert_eq!(
        wt_session.datagram_queue_capacity().queued_datagrams,
        0,
        "the datagram's own expiry must get this connection processed"
    );
    assert_eq!(wt_session.stats().datagrams_expired_outgoing, 1);
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

#[test]
fn datagram_send_updates_sent_stat() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    assert_eq!(
        wt_session.send_datagram(DGRAM, None, t0, SendGroupId::new(0), 0),
        Ok(DatagramQueueOutcome::Ok)
    );
    assert_eq!(wt_session.stats().datagrams_sent_outgoing, 0);

    wt.exchange_packets();

    assert_eq!(wt_session.stats().datagrams_sent_outgoing, 1);
}

#[test]
fn datagram_expiry_reports_expired_outcome() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    wt_session
        .set_datagram_max_age(Some(Duration::from_millis(5)), t0)
        .unwrap();
    _ = wt_session
        .send_datagram(DGRAM, Some(9), t0, SendGroupId::new(0), 0)
        .unwrap();

    drop(wt.server.process_output(t0 + Duration::from_millis(10)));

    assert_eq!(
        server_datagram_outcomes(&wt, wt_session.stream_id()),
        vec![DatagramOutcome::Expired(9)]
    );
    assert_eq!(wt_session.stats().datagrams_sent_outgoing, 0);
}

#[test]
fn session_close_reports_dropped_outcome_for_queued_datagrams() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    _ = wt_session
        .send_datagram(DGRAM, Some(3), t0, SendGroupId::new(0), 0)
        .unwrap();
    let stats = wt_session.close_session(0, "bye", t0).unwrap();
    drop(wt.server.process_output(t0));

    assert_eq!(
        server_datagram_outcomes(&wt, wt_session.stream_id()),
        vec![DatagramOutcome::Dropped(3)],
        "close_session must drop and report any datagram still queued"
    );
    assert_eq!(
        stats.datagrams_dropped_outgoing, 1,
        "the stats close_session returns must already count that drop"
    );
}

#[test]
fn datagram_expires_on_the_implementation_defined_default_max_age() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    // No set_datagram_max_age call: outgoingMaxAge is left at its default.
    _ = wt_session
        .send_datagram(DGRAM, Some(13), t0, SendGroupId::new(0), 0)
        .unwrap();

    // Comfortably past the default, so this expires on the very first
    // drain rather than getting sent.
    drop(wt.server.process_output(t0 + Duration::from_secs(1)));

    assert_eq!(
        server_datagram_outcomes(&wt, wt_session.stream_id()),
        vec![DatagramOutcome::Expired(13)]
    );
}

fn client_datagram_outcomes(wt: &mut WtTest, session_id: StreamId) -> Vec<DatagramOutcome> {
    wt.client
        .events()
        .filter_map(|e| match e {
            Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                session_id: sid,
                outcome,
            }) if sid == session_id => Some(outcome),
            _ => None,
        })
        .collect()
}

#[test]
fn client_set_datagram_max_age_reports_expired_outcome() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();
    let t0 = now();

    assert_eq!(
        wt.client.webtransport_send_datagram(
            session_id,
            DGRAM,
            Some(7),
            t0,
            SendGroupId::new(0),
            0
        ),
        Ok(DatagramQueueOutcome::Ok)
    );

    let t1 = t0 + Duration::from_millis(200);
    wt.client
        .webtransport_set_datagram_max_age(session_id, Some(Duration::from_millis(100)), t1)
        .unwrap();

    assert_eq!(
        client_datagram_outcomes(&mut wt, session_id),
        vec![DatagramOutcome::Expired(7)],
        "shortening max_age past an already-queued datagram must expire it immediately"
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

#[test]
fn client_set_datagram_high_water_mark_signals_backpressure() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();
    let t0 = now();

    wt.client
        .webtransport_set_datagram_high_water_mark(session_id, Some(NonZeroUsize::new(2).unwrap()))
        .unwrap();

    assert_eq!(
        wt.client.webtransport_send_datagram(
            session_id,
            DGRAM,
            Some(1),
            t0,
            SendGroupId::new(0),
            0
        ),
        Ok(DatagramQueueOutcome::Ok)
    );
    assert_eq!(
        wt.client.webtransport_send_datagram(
            session_id,
            DGRAM,
            Some(2),
            t0,
            SendGroupId::new(0),
            0
        ),
        Ok(DatagramQueueOutcome::AboveWatermark),
        "the second datagram crosses the high water mark"
    );
}
