// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

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

#[test]
fn datagram_high_water_mark_signals_backpressure() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let t0 = now();

    wt_session.set_datagram_high_water_mark(Some(2)).unwrap();
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

    wt_session.set_datagram_high_water_mark(Some(1)).unwrap();
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

    // Enqueue without marking the connection as needing processing: the
    // datagram's own expiry must be enough on its own to get this
    // connection processed later, with nothing else giving it a reason.
    wt_session
        .set_datagram_max_age(Some(Duration::from_millis(5)), t0)
        .unwrap();
    wt_session
        .send_datagram_without_marking_needs_processing(DGRAM, Some(1), t0)
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

/// A burst exceeding the byte budget, with a mix of send-order priorities,
/// must evict low-priority datagrams to make room for high-priority ones -
/// verified through the real `Http3Client` API and a live connection, not
/// just on a bare `DatagramQueue` in isolation. Each datagram's payload is
/// its own id (as 8 little-endian bytes), so delivery can be checked by
/// content rather than relying on a per-datagram "sent" outcome, which the
/// queue deliberately does not report (see `DatagramOutcome`).
#[test]
fn datagram_burst_exceeding_byte_budget_preserves_priority_through_a_live_connection() {
    // Each must evict a low-priority one (the oldest, lowest send_order
    // present) rather than each other.
    const HIGH_PRIORITY_COUNT: usize = 5;

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Fill the byte budget with low-priority (order=0) datagrams, without
    // draining, until eviction starts - i.e. until the budget is full.
    let mut low_priority_ids = Vec::new();
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
        if let DatagramQueueOutcome::Overflowed { dropped } = outcome {
            // enqueue() always accepts: this datagram itself got in,
            // evicting `dropped` (the oldest) to make room for it.
            for id in dropped.into_iter().flatten() {
                low_priority_ids.retain(|&x| x != id);
            }
            low_priority_ids.push(next_id);
            next_id += 1;
            break;
        }
        assert_eq!(
            outcome,
            DatagramQueueOutcome::Ok,
            "unexpected outcome before the byte budget is hit"
        );
        low_priority_ids.push(next_id);
        next_id += 1;
        assert!(
            next_id < 1_000_000,
            "byte budget should have been hit by now"
        );
    }

    // Now send a few high-priority datagrams.
    let high_priority_ids: Vec<u64> = (0..to_u64(HIGH_PRIORITY_COUNT))
        .map(|i| next_id + i)
        .collect();
    let mut evicted = Vec::new();
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
            DatagramQueueOutcome::Overflowed { dropped } => evicted.extend(dropped),
            other => panic!("expected an eviction for the high-priority datagram: {other:?}"),
        }
    }
    assert_eq!(
        evicted,
        low_priority_ids[..HIGH_PRIORITY_COUNT]
            .iter()
            .map(|&id| Some(id))
            .collect::<Vec<_>>(),
        "eviction must take the oldest low-priority datagrams first, never the high-priority ones"
    );

    wt.exchange_packets();

    let received: Vec<_> = wt
        .server
        .events()
        .filter_map(|e| match e {
            Http3ServerEvent::WebTransport(ServerEvent::Datagram { session, datagram })
                if session.stream_id() == session_id =>
            {
                Some(datagram)
            }
            _ => None,
        })
        .collect();
    let was_received = |id: u64| received.iter().any(|d| d.as_ref() == id.to_le_bytes());

    for &id in &high_priority_ids {
        assert!(was_received(id), "high-priority datagram {id} must be sent");
    }
    for dropped in &evicted {
        let id = dropped.expect("test datagrams are tracked");
        assert!(
            !was_received(id),
            "evicted low-priority datagram {id} must not be sent"
        );
    }
}

#[test]
fn client_set_datagram_high_water_mark_signals_backpressure() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();
    let t0 = now();

    wt.client
        .webtransport_set_datagram_high_water_mark(session_id, Some(2))
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
