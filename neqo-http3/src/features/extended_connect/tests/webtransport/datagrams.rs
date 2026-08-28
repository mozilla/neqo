// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use neqo_common::{Encoder, event::Provider as _, to_u64};
use neqo_transport::{ConnectionParameters, Output};
use test_fixture::now;

use crate::{
    Http3ClientEvent, Http3ServerEvent, WebTransportEvent,
    features::extended_connect::{
        DatagramOutcome, DatagramQueueOutcome,
        tests::webtransport::{DATAGRAM_SIZE, WtTest, wt_default_parameters},
    },
    webtransport::{ClientSession as _, ServerEvent, ServerSession},
};

const DGRAM: &[u8] = &[0, 100];

fn do_datagram_test(wt: &mut WtTest, wt_session: &ServerSession) {
    assert_eq!(
        wt_session.max_datagram_size(),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64() / 4)))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64() / 4)))
    );

    assert_eq!(
        wt_session.send_datagram(DGRAM, None, now(), 0, 0),
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
fn datagram_high_water_mark_reported_via_send_datagram() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    wt.client
        .webtransport_set_datagram_high_water_mark(session_id, Some(2))
        .unwrap();

    let mut send = || {
        wt.client
            .webtransport_send_datagram(session_id, DGRAM, None, now(), 0, 0)
            .unwrap()
    };

    assert_eq!(send(), DatagramQueueOutcome::Ok);
    assert_eq!(send(), DatagramQueueOutcome::AboveWatermark);
    assert_eq!(send(), DatagramQueueOutcome::AboveWatermark);
}

/// [`Http3Client::webtransport_datagram_queue_capacity`] must reflect the
/// http3-level queue (which a content-process credit grant should track),
/// not the small transport-level FIFO.
#[test]
fn datagram_queue_capacity_reflects_the_http3_queue_not_the_transport_fifo() {
    // A burst larger than the 10-slot transport FIFO must still be reflected
    // faithfully by the http3-level queue's own count, since nothing here is
    // handed to the transport until the client processes output.
    const BURST: u8 = 20;

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let before = wt
        .client
        .webtransport_datagram_queue_capacity(session_id)
        .unwrap();
    assert_eq!(before.queued_datagrams, 0);

    for i in 0..BURST {
        wt.client
            .webtransport_send_datagram(session_id, &[0, i], Some(u64::from(i)), now(), 0, 0)
            .unwrap();
    }

    let after = wt
        .client
        .webtransport_datagram_queue_capacity(session_id)
        .unwrap();
    assert_eq!(after.queued_datagrams, usize::from(BURST));
    assert!(
        after.remaining_bytes < before.remaining_bytes,
        "enqueuing datagrams must consume some of the byte budget"
    );
}

#[test]
fn datagram_hard_limit_overflow_reports_outcome() {
    // Drive the queue until the byte budget is actually hit, rather than
    // pre-computing an iteration count: the wire-encoded datagram (session-id
    // varint prefix + protocol prefix + payload) is larger than DGRAM alone,
    // so the exact count depends on encoding details this test shouldn't need
    // to know.
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    for id in 0.. {
        let outcome = wt
            .client
            .webtransport_send_datagram(session_id, DGRAM, Some(id), now(), 0, 0)
            .unwrap();
        match outcome {
            DatagramQueueOutcome::Ok => {}
            DatagramQueueOutcome::Overflowed { dropped } => {
                assert_eq!(
                    dropped,
                    vec![Some(0)],
                    "the oldest (lowest-priority) datagram is evicted first"
                );
                // The synchronous `Overflowed` return value carries the
                // evicted id too, but a consumer reconciling ids purely
                // through the event stream must also see it there.
                let dropped_event = |e| {
                    matches!(
                        e,
                        Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                            session_id: sid,
                            outcome: DatagramOutcome::Dropped(0),
                        }) if sid == session_id
                    )
                };
                assert!(wt.client.events().any(dropped_event));
                assert_eq!(
                    wt.client
                        .webtransport_session_stats(session_id)
                        .unwrap()
                        .datagrams_dropped_outgoing,
                    1
                );
                return;
            }
            DatagramQueueOutcome::AboveWatermark => {
                panic!("unexpected AboveWatermark outcome before the byte budget is hit")
            }
        }
        assert!(id < 1_000_000, "byte budget should have been hit by now");
    }
}

/// `datagrams_dropped_outgoing` must count every eviction, tracked or not:
/// unlike the `DatagramOutcome::Dropped` event, which only fires for tracked
/// datagrams, this is the only signal an untracked drop leaves behind.
#[test]
fn datagram_hard_limit_overflow_counts_untracked_drops() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    for id in 0.. {
        let outcome = wt
            .client
            .webtransport_send_datagram(session_id, DGRAM, None, now(), 0, 0)
            .unwrap();
        if matches!(outcome, DatagramQueueOutcome::Overflowed { .. }) {
            break;
        }
        assert!(id < 1_000_000, "byte budget should have been hit by now");
    }

    assert_eq!(
        wt.client
            .webtransport_session_stats(session_id)
            .unwrap()
            .datagrams_dropped_outgoing,
        1
    );
}

/// A burst far larger than the QUIC layer's outgoing datagram queue
/// (`MAX_QUEUED_DATAGRAMS_DEFAULT`) must still be delivered in full. `drain()`
/// hands over only what that queue can hold and keeps the remainder, so the
/// backlog goes out over successive drains as the queue empties. Draining the
/// whole session queue at once instead let the QUIC layer head-drop everything
/// but the last few, and because the highest `send_order` is drained first, the
/// survivors were the *lowest*-priority datagrams of the burst.
#[test]
fn datagram_burst_larger_than_quic_queue_is_fully_delivered() {
    // Comfortably more than the QUIC layer's queue, so the burst can only get
    // through if the leftovers are picked up by later drains.
    const BURST: u8 = 100;

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    for i in 0..BURST {
        wt.client
            .webtransport_send_datagram(session_id, &[0, i], Some(u64::from(i)), now(), 0, 0)
            .unwrap();
    }

    wt.exchange_packets();

    let mut received: Vec<u8> = wt
        .server
        .events()
        .filter_map(|e| match e {
            Http3ServerEvent::WebTransport(ServerEvent::Datagram { session, datagram })
                if session.stream_id() == session_id =>
            {
                Some(datagram.as_ref()[1])
            }
            _ => None,
        })
        .collect();
    received.sort_unstable();

    assert_eq!(
        received,
        (0..BURST).collect::<Vec<_>>(),
        "every datagram of the burst must arrive exactly once"
    );

    // Nothing may be reported as dropped either.
    let bad_outcome = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                outcome: DatagramOutcome::Dropped(_),
                ..
            })
        )
    };
    assert!(!wt.client.events().any(bad_outcome));
}

#[test]
fn datagram_sent_reports_client_event() {
    // The `Sent` outcome is what tells the application its datagram actually
    // reached the QUIC layer; it is only produced when the queue is drained
    // during `process_output()`.
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    wt.client
        .webtransport_send_datagram(session_id, DGRAM, Some(9u64), now(), 0, 0)
        .unwrap();
    wt.exchange_packets();

    let wt_sent_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                session_id: sid,
                outcome: DatagramOutcome::Sent(9),
            }) if sid == session_id
        )
    };
    assert!(wt.client.events().any(wt_sent_event));
}

#[test]
fn datagram_max_age_expiry_reports_client_event() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let t0 = now();
    wt.client
        .webtransport_send_datagram(session_id, DGRAM, Some(7u64), t0, 0, 0)
        .unwrap();

    let t1 = t0 + Duration::from_millis(200);
    wt.client
        .webtransport_set_datagram_max_age(session_id, Some(Duration::from_millis(100)), t1)
        .unwrap();

    let wt_expired_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                session_id: sid,
                outcome: DatagramOutcome::Expired(7),
            }) if sid == session_id
        )
    };
    assert!(wt.client.events().any(wt_expired_event));
}

/// A datagram still sitting in the queue when its session closes must be
/// reported as `Dropped`, not silently discarded: a consumer tracking ids
/// through the event stream would otherwise wait forever for an outcome
/// that will never arrive.
#[test]
fn datagram_dropped_on_session_close_reports_outcome() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Enqueued but not yet drained: no `process_output`/`exchange_packets`
    // call happens between this and the cancellation below.
    wt.client
        .webtransport_send_datagram(session_id, DGRAM, Some(42u64), now(), 0, 0)
        .unwrap();

    wt.cancel_session_client(session_id);

    let dropped_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                session_id: sid,
                outcome: DatagramOutcome::Dropped(42),
            }) if sid == session_id
        )
    };
    assert!(wt.client.events().any(dropped_event));
}

/// A peer-initiated close (the `CLOSE_WEBTRANSPORT_SESSION` capsule, handled
/// via `read_control_stream`) must drop and report queued datagrams exactly
/// like the locally-initiated paths above: it is the more common close, and
/// without this a consumer waits forever for an outcome that never arrives.
#[test]
fn datagram_dropped_on_peer_initiated_session_close_reports_outcome() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Produce the server's close capsule before the client enqueues its
    // datagram, so the datagram is still queued (nothing has called
    // `process_output` on the client yet) when the capsule is delivered.
    // The pacer can defer the very first packet after the frame is queued,
    // so retry with time advanced by the requested delay until it ships.
    WtTest::session_close_frame_server(&wt_session, 0, "");
    let mut when = now();
    let close_dgram = loop {
        match wt.server.process_output(when) {
            Output::Datagram(d) => break Some(d),
            Output::Callback(delay) => when += delay,
            Output::None => break None,
        }
    };

    wt.client
        .webtransport_send_datagram(session_id, DGRAM, Some(42u64), now(), 0, 0)
        .unwrap();

    // A single `process` call both reads the close capsule (driving the
    // session out of `Active` via `read_control_stream`) and attempts to
    // drain the datagram queue; before drop was wired into that path, the
    // still-queued datagram was silently abandoned instead of reported.
    drop(wt.client.process(close_dgram, now()));

    let dropped_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                session_id: sid,
                outcome: DatagramOutcome::Dropped(42),
            }) if sid == session_id
        )
    };
    assert!(wt.client.events().any(dropped_event));
}

/// `ServerSession::set_datagram_high_water_mark` is new public API introduced
/// alongside its client-side counterpart (see
/// `datagram_high_water_mark_reported_via_send_datagram`), but had no test of
/// its own.
#[test]
fn server_datagram_high_water_mark_reported_via_send_datagram() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt_session.set_datagram_high_water_mark(Some(2)).unwrap();

    let send = || wt_session.send_datagram(DGRAM, None, now(), 0, 0).unwrap();
    assert_eq!(send(), DatagramQueueOutcome::Ok);
    assert_eq!(send(), DatagramQueueOutcome::AboveWatermark);
    assert_eq!(send(), DatagramQueueOutcome::AboveWatermark);
}

/// `ServerSession::set_datagram_max_age` and `ServerEvent::DatagramOutcome`
/// are new public API introduced alongside their client-side counterparts,
/// but had no test of their own.
#[test]
fn server_datagram_sent_and_max_age_expiry_report_server_event() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    wt_session
        .send_datagram(DGRAM, Some(1u64), now(), 0, 0)
        .unwrap();
    wt.exchange_packets();

    let sent_event = |e| {
        matches!(
            e,
            Http3ServerEvent::WebTransport(ServerEvent::DatagramOutcome {
                session,
                outcome: DatagramOutcome::Sent(1),
            }) if session.stream_id() == session_id
        )
    };
    assert!(wt.server.events().any(sent_event));

    let t0 = now();
    wt_session
        .send_datagram(DGRAM, Some(2u64), t0, 0, 0)
        .unwrap();
    let t1 = t0 + Duration::from_millis(200);
    wt_session
        .set_datagram_max_age(Some(Duration::from_millis(100)), t1)
        .unwrap();
    // `set_datagram_max_age` only pushes the expiry onto the per-connection
    // handler's event queue; a `process_*` call is what drains that into the
    // top-level `Http3Server`'s own event queue `wt.server.events()` reads.
    wt.server.process_output(t1);

    let expired_event = |e| {
        matches!(
            e,
            Http3ServerEvent::WebTransport(ServerEvent::DatagramOutcome {
                session,
                outcome: DatagramOutcome::Expired(2),
            }) if session.stream_id() == session_id
        )
    };
    assert!(wt.server.events().any(expired_event));
}

/// A datagram queued on the server must still expire once its max-age
/// passes, even when nothing else - no other data to send, no other
/// events, no explicit `set_datagram_max_age` call - would otherwise cause
/// that connection to be processed. Without `should_be_processed` checking
/// the pending expiry itself, the connection is skipped indefinitely and
/// the datagram is never expired.
#[test]
fn server_datagram_expires_on_an_otherwise_idle_connection() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    wt_session
        .set_datagram_max_age(Some(Duration::from_millis(30)), now())
        .unwrap();

    // Enough filler datagrams to exhaust the transport's 10-slot queue on
    // the first (needs-processing-triggered) drain below, so the tracked
    // datagram is left stuck in the http3-level queue rather than sent
    // immediately.
    for _ in 0..15 {
        wt_session.send_datagram(DGRAM, None, now(), 0, 0).unwrap();
    }
    wt_session
        .send_datagram(DGRAM, Some(77u64), now(), 0, 0)
        .unwrap();

    let t0 = now();
    wt.server.process_output(t0);

    // Otherwise idle: nothing else happens between here and the deadline,
    // so only `should_be_processed`'s datagram-expiry check can trigger
    // the drain that actually expires it.
    wt.server.process_output(t0 + Duration::from_millis(35));

    let expired_event = |e| {
        matches!(
            e,
            Http3ServerEvent::WebTransport(ServerEvent::DatagramOutcome {
                session,
                outcome: DatagramOutcome::Expired(77),
            }) if session.stream_id() == session_id
        )
    };
    assert!(wt.server.events().any(expired_event));
}

/// Shortening `max_age` on an idle server connection must take effect at the
/// new deadline, not linger until the original one: `set_max_age` only
/// refreshes `Http3Connection`'s cached `next_datagram_expiry` when the
/// connection is actually processed, so the setter must mark the connection
/// as needing processing or an otherwise idle connection is never revisited
/// to pick up the shorter deadline.
#[test]
fn server_shortening_max_age_on_idle_connection_still_expires_on_new_deadline() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    wt_session
        .set_datagram_max_age(Some(Duration::from_secs(10)), now())
        .unwrap();

    // Enough filler datagrams to exhaust the transport's 10-slot queue on
    // the first (needs-processing-triggered) drain below, so the tracked
    // datagram is left stuck in the http3-level queue - and so still
    // subject to max-age - rather than handed to the QUIC layer immediately.
    for _ in 0..15 {
        wt_session.send_datagram(DGRAM, None, now(), 0, 0).unwrap();
    }
    wt_session.send_datagram(DGRAM, Some(77u64), now(), 0, 0).unwrap();

    let t0 = now();
    wt.server.process_output(t0);

    // Shorten the deadline well inside the original one; the datagram is
    // not yet stale at `t0`, so nothing expires synchronously here.
    wt_session
        .set_datagram_max_age(Some(Duration::from_millis(30)), t0)
        .unwrap();

    // Otherwise idle: only the datagram-expiry check in `should_be_processed`
    // (fed by the refreshed cache) can trigger the drain that expires this.
    wt.server.process_output(t0 + Duration::from_millis(35));

    let expired_event = |e| {
        matches!(
            e,
            Http3ServerEvent::WebTransport(ServerEvent::DatagramOutcome {
                session,
                outcome: DatagramOutcome::Expired(77),
            }) if session.stream_id() == session_id
        )
    };
    assert!(wt.server.events().any(expired_event));
}

/// `drain()` reports every expired datagram, but that's only exercised via an
/// explicit `set_datagram_max_age` call elsewhere. A datagram must also expire
/// as a side effect of an ordinary `process_output` drain, using the default
/// max-age, with no explicit call setting it.
#[test]
fn datagram_expires_during_a_normal_process_output_drain() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let t0 = now();
    wt.client
        .webtransport_send_datagram(session_id, DGRAM, Some(13u64), t0, 0, 0)
        .unwrap();

    // Comfortably past the default max-age, so this expires on the very
    // first drain rather than getting sent.
    wt.client.process_output(t0 + Duration::from_secs(1));

    let wt_expired_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::DatagramOutcome {
                session_id: sid,
                outcome: DatagramOutcome::Expired(13),
            }) if sid == session_id
        )
    };
    assert!(wt.client.events().any(wt_expired_event));
}
