// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use neqo_common::{Encoder, event::Provider as _, to_u64};
use neqo_transport::{ConnectionParameters, Error as TransportError};
use test_fixture::now;

use crate::{
    Error, Http3ClientEvent, Http3Parameters, WebTransportEvent,
    features::extended_connect::{
        DatagramOutcome,
        datagram_queue::DEFAULT_HARD_LIMIT,
        tests::webtransport::{DATAGRAM_SIZE, WtTest, wt_default_parameters},
    },
    webtransport::{ClientSession as _, ServerSession},
};

const DGRAM: &[u8] = &[0, 100];

#[test]
fn no_datagrams() {
    let mut wt = WtTest::new_with_params(
        Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(0))
            .http3_datagram(false)
            .webtransport(true),
        Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(0))
            .http3_datagram(false)
            .webtransport(true),
    );
    let wt_session = wt.create_wt_session();

    assert_eq!(
        wt_session.max_datagram_size(),
        Err(Error::Transport(TransportError::NotAvailable))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Err(Error::Transport(TransportError::NotAvailable))
    );

    assert_eq!(
        wt_session.send_datagram(DGRAM, None, now(), 0, 0),
        Err(Error::Transport(TransportError::NotAvailable))
    );
    assert_eq!(
        wt.send_datagram(wt_session.stream_id(), DGRAM),
        Err(Error::Transport(TransportError::NotAvailable))
    );

    wt.exchange_packets();
    wt.check_no_datagram_received_client();
    wt.check_no_datagram_received_server();
}

fn do_datagram_test(wt: &mut WtTest, wt_session: &ServerSession) {
    assert_eq!(
        wt_session.max_datagram_size(),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64() / 4)))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64() / 4)))
    );

    assert_eq!(wt_session.send_datagram(DGRAM, None, now(), 0, 0), Ok(()));
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
fn datagrams_server_only() {
    let mut wt = WtTest::new_with_params(
        Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(0))
            .http3_datagram(false)
            .webtransport(true),
        wt_default_parameters(),
    );
    let wt_session = wt.create_wt_session();

    assert_eq!(
        wt_session.max_datagram_size(),
        Err(Error::Transport(TransportError::NotAvailable))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64() / 4)))
    );

    assert_eq!(
        wt_session.send_datagram(DGRAM, None, now(), 0, 0),
        Err(Error::Transport(TransportError::NotAvailable))
    );
    assert_eq!(wt.send_datagram(wt_session.stream_id(), DGRAM), Ok(()));

    wt.exchange_packets();
    wt.check_datagram_received_server(&wt_session, DGRAM);
    wt.check_no_datagram_received_client();
}

#[test]
fn datagrams_client_only() {
    let mut wt = WtTest::new_with_params(
        wt_default_parameters(),
        Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(0))
            .http3_datagram(false)
            .webtransport(true),
    );
    let wt_session = wt.create_wt_session();

    assert_eq!(
        wt_session.max_datagram_size(),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64() / 4)))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Err(Error::Transport(TransportError::NotAvailable))
    );

    assert_eq!(wt_session.send_datagram(DGRAM, None, now(), 0, 0), Ok(()));
    assert_eq!(
        wt.send_datagram(wt_session.stream_id(), DGRAM),
        Err(Error::Transport(TransportError::NotAvailable))
    );

    wt.exchange_packets();
    wt.check_datagram_received_client(wt_session.stream_id(), DGRAM);
    wt.check_no_datagram_received_server();
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
        .webtransport_set_datagram_high_water_mark(session_id, 2.0)
        .unwrap();

    let (below1, dropped1) = wt
        .client
        .webtransport_send_datagram(session_id, DGRAM, None, now(), 0, 0)
        .unwrap();
    let (below2, dropped2) = wt
        .client
        .webtransport_send_datagram(session_id, DGRAM, None, now(), 0, 0)
        .unwrap();
    let (below3, dropped3) = wt
        .client
        .webtransport_send_datagram(session_id, DGRAM, None, now(), 0, 0)
        .unwrap();

    assert!(below1);
    assert!(!below2);
    assert!(!below3);
    assert_eq!((dropped1, dropped2, dropped3), (None, None, None));
}

#[test]
fn datagram_hard_limit_overflow_reports_outcome() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let limit = u64::try_from(DEFAULT_HARD_LIMIT).unwrap();
    for id in 0..limit {
        let (_, dropped) = wt
            .client
            .webtransport_send_datagram(session_id, DGRAM, Some(id), now(), 0, 0)
            .unwrap();
        assert_eq!(dropped, None);
    }

    let (_, dropped) = wt
        .client
        .webtransport_send_datagram(session_id, DGRAM, Some(limit), now(), 0, 0)
        .unwrap();
    assert_eq!(dropped, Some(DatagramOutcome::Overflowed(0)));
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
        .webtransport_set_datagram_max_age(session_id, 100.0, t1)
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
