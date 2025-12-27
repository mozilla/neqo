// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_transport::{ConnectionParameters, StreamId, StreamType};

use crate::{
    Error, Http3State,
    connection::HTTP3_UNI_CONTROL_STREAMS,
    features::extended_connect::tests::webtransport::{WtTest, wt_default_parameters},
};

/// Connection-level baseline for stream limits. Values at or below this require no
/// `MAX_STREAMS` frame, since the transport already granted that much.
fn stream_limit_default(stream_type: StreamType) -> u16 {
    u16::try_from(ConnectionParameters::default().get_max_streams(stream_type)).unwrap()
}

fn client_max_streams_sent(wt: &WtTest) -> usize {
    wt.client.transport_stats().frame_tx.max_streams
}

#[test]
fn anticipated_uni_invalid_session() {
    let mut wt = WtTest::new();
    let bogus = StreamId::from(9999);
    assert_eq!(
        wt.client.webtransport_increase_max_uni_streams(bogus, 10),
        Err(Error::InvalidStreamId)
    );
}

#[test]
fn anticipated_bidi_invalid_session() {
    let mut wt = WtTest::new();
    let bogus = StreamId::from(9999);
    assert_eq!(
        wt.client.webtransport_increase_max_bidi_streams(bogus, 10),
        Err(Error::InvalidStreamId)
    );
}

#[test]
fn anticipated_uni_valid_session() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    assert_eq!(
        wt.client
            .webtransport_increase_max_uni_streams(session.stream_id(), 10),
        Ok(())
    );
}

#[test]
fn anticipated_bidi_valid_session() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    assert_eq!(
        wt.client
            .webtransport_increase_max_bidi_streams(session.stream_id(), 10),
        Ok(())
    );
}

// Setting a value that, after adding control streams, stays at or below the default
// should not trigger a MAX_STREAMS frame.
#[test]
fn anticipated_uni_at_default_sends_no_frame() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let before = client_max_streams_sent(&wt);

    wt.client
        .webtransport_increase_max_uni_streams(
            session.stream_id(),
            stream_limit_default(StreamType::UniDi)
                - u16::try_from(HTTP3_UNI_CONTROL_STREAMS).unwrap(),
        )
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        before,
        "no MAX_STREAMS frame should be sent when value equals the default"
    );
}

// Setting a value above the default should trigger a MAX_STREAMS frame.
#[test]
fn anticipated_uni_above_default_sends_frame() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let before = client_max_streams_sent(&wt);

    wt.client
        .webtransport_increase_max_uni_streams(
            session.stream_id(),
            stream_limit_default(StreamType::UniDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert!(
        client_max_streams_sent(&wt) > before,
        "a MAX_STREAMS frame should be sent when value exceeds the default"
    );
}

#[test]
fn anticipated_bidi_above_default_sends_frame() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let before = client_max_streams_sent(&wt);

    wt.client
        .webtransport_increase_max_bidi_streams(
            session.stream_id(),
            stream_limit_default(StreamType::BiDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert!(
        client_max_streams_sent(&wt) > before,
        "a MAX_STREAMS frame should be sent when bidi value exceeds the default"
    );
}

// Reducing the value below a previously-set value must not send a frame
// (QUIC stream limits can only increase).
#[test]
fn anticipated_uni_decrease_sends_no_frame() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();

    wt.client
        .webtransport_increase_max_uni_streams(
            session.stream_id(),
            stream_limit_default(StreamType::UniDi) + 50,
        )
        .unwrap();
    wt.exchange_packets();
    let after_increase = client_max_streams_sent(&wt);

    // Now lower the value — the connection limit should not decrease.
    wt.client
        .webtransport_increase_max_uni_streams(
            session.stream_id(),
            stream_limit_default(StreamType::UniDi) + 10,
        )
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        after_increase,
        "lowering anticipated streams must not send another MAX_STREAMS frame"
    );
}

// With two sessions, the connection limit should be the sum of their
// anticipated values, not just the last-set value.
#[test]
fn anticipated_uni_two_sessions_sums_values() {
    let mut wt = WtTest::new_with_params(wt_default_parameters(), wt_default_parameters());
    let session_a = wt.create_wt_session();
    let session_b = wt.create_wt_session();

    // Set session A to just above the default so a frame is sent.
    wt.client
        .webtransport_increase_max_uni_streams(
            session_a.stream_id(),
            stream_limit_default(StreamType::UniDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();
    let after_a = client_max_streams_sent(&wt);
    assert!(
        after_a > 0,
        "first session should trigger a MAX_STREAMS frame"
    );

    // Now set session B.  The new total (A+B) exceeds the previously-sent
    // limit, so another MAX_STREAMS frame must be sent.
    wt.client
        .webtransport_increase_max_uni_streams(
            session_b.stream_id(),
            stream_limit_default(StreamType::UniDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert!(
        client_max_streams_sent(&wt) > after_a,
        "adding a second session's anticipated streams should send another MAX_STREAMS frame"
    );
}

#[test]
fn anticipated_bidi_two_sessions_sums_values() {
    let mut wt = WtTest::new_with_params(wt_default_parameters(), wt_default_parameters());
    let session_a = wt.create_wt_session();
    let session_b = wt.create_wt_session();

    wt.client
        .webtransport_increase_max_bidi_streams(
            session_a.stream_id(),
            stream_limit_default(StreamType::BiDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();
    let after_a = client_max_streams_sent(&wt);
    assert!(
        after_a > 0,
        "first session should trigger a MAX_STREAMS frame"
    );

    wt.client
        .webtransport_increase_max_bidi_streams(
            session_b.stream_id(),
            stream_limit_default(StreamType::BiDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert!(
        client_max_streams_sent(&wt) > after_a,
        "adding a second session's anticipated bidi streams should send another MAX_STREAMS frame"
    );
}

// Setting both uni and bidi at the same time triggers exactly two MAX_STREAMS
// frames (one for each type).
#[test]
fn anticipated_uni_and_bidi_both_send_frames() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let before = client_max_streams_sent(&wt);

    wt.client
        .webtransport_increase_max_uni_streams(
            session.stream_id(),
            stream_limit_default(StreamType::UniDi) + 1,
        )
        .unwrap();
    wt.client
        .webtransport_increase_max_bidi_streams(
            session.stream_id(),
            stream_limit_default(StreamType::BiDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        before + 2,
        "one MAX_STREAMS frame for uni and one for bidi"
    );
}

// A session that has been closed is no longer active; increasing its
// anticipated streams must be rejected like any other invalid session ID.
#[test]
fn anticipated_uni_rejected_after_session_closed() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let session_id = session.stream_id();
    wt.cancel_session_client(session_id);

    assert_eq!(
        wt.client
            .webtransport_increase_max_uni_streams(session_id, 10),
        Err(Error::InvalidStreamId)
    );
}

#[test]
fn anticipated_bidi_rejected_after_session_closed() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let session_id = session.stream_id();
    wt.cancel_session_client(session_id);

    assert_eq!(
        wt.client
            .webtransport_increase_max_bidi_streams(session_id, 10),
        Err(Error::InvalidStreamId)
    );
}

// A closed session's anticipated streams must not count toward the
// connection-wide total, or a stale session could inflate the advertised
// limit indefinitely.
#[test]
fn anticipated_uni_excludes_closed_session_from_total() {
    let mut wt = WtTest::new_with_params(wt_default_parameters(), wt_default_parameters());
    let session_a = wt.create_wt_session();
    let session_b = wt.create_wt_session();

    // Session A anticipates far more streams than B ever will, raising the
    // limit well above what B alone would need.
    wt.client
        .webtransport_increase_max_uni_streams(
            session_a.stream_id(),
            stream_limit_default(StreamType::UniDi) + 100,
        )
        .unwrap();
    wt.exchange_packets();
    let after_a = client_max_streams_sent(&wt);
    assert!(after_a > 0, "session A should trigger a MAX_STREAMS frame");

    wt.cancel_session_client(session_a.stream_id());

    // If A's stale value still counted, A + B would exceed the limit A
    // already set and trigger another MAX_STREAMS frame.
    wt.client
        .webtransport_increase_max_uni_streams(
            session_b.stream_id(),
            stream_limit_default(StreamType::UniDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        after_a,
        "closed session A's anticipated streams must not count toward the total"
    );
}

#[test]
fn anticipated_bidi_excludes_closed_session_from_total() {
    let mut wt = WtTest::new_with_params(wt_default_parameters(), wt_default_parameters());
    let session_a = wt.create_wt_session();
    let session_b = wt.create_wt_session();

    wt.client
        .webtransport_increase_max_bidi_streams(
            session_a.stream_id(),
            stream_limit_default(StreamType::BiDi) + 100,
        )
        .unwrap();
    wt.exchange_packets();
    let after_a = client_max_streams_sent(&wt);
    assert!(after_a > 0, "session A should trigger a MAX_STREAMS frame");

    wt.cancel_session_client(session_a.stream_id());

    wt.client
        .webtransport_increase_max_bidi_streams(
            session_b.stream_id(),
            stream_limit_default(StreamType::BiDi) + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        after_a,
        "closed session A's anticipated bidi streams must not count toward the total"
    );
}

// Counting MAX_STREAMS frames only proves we advertised a bigger limit. This checks
// the limit is actually usable: the peer must be able to open more streams than the
// transport default once the session anticipates them.
#[test]
fn anticipated_uni_lets_peer_open_more_streams() {
    const BUF: &[u8] = &[0; 10];

    let default_limit = stream_limit_default(StreamType::UniDi);
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt.client
        .webtransport_increase_max_uni_streams(wt_session.stream_id(), default_limit + 1)
        .unwrap();
    wt.exchange_packets();

    // The server opens one more unidirectional stream than the transport default
    // would have allowed. HTTP/3's own control streams share the same limit, so
    // going past the default at all requires the raised limit to have taken effect.
    for _ in 0..=default_limit {
        let stream = WtTest::create_wt_stream_server(&wt_session, StreamType::UniDi);
        wt.send_data_server(&stream, BUF);
    }
    wt.exchange_packets();

    assert_eq!(
        wt.client.state(),
        Http3State::Connected,
        "raising the anticipated stream count must not break the connection"
    );
}
