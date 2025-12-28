// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_transport::StreamId;

use crate::{
    Error,
    features::extended_connect::tests::webtransport::{WtTest, wt_default_parameters},
};

/// The connection-level baseline for stream limits (from LOCAL_STREAM_LIMIT_*
/// in neqo-transport).  Values at or below this require no MAX_STREAMS frame.
const STREAM_LIMIT_DEFAULT: u64 = 100;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Returns the number of MAX_STREAMS frames the client has sent so far.
fn client_max_streams_sent(wt: &WtTest) -> usize {
    wt.client.transport_stats().frame_tx.max_streams
}

// ── basic API tests ───────────────────────────────────────────────────────────

#[test]
fn anticipated_uni_invalid_session() {
    let mut wt = WtTest::new();
    // Use a StreamId that was never used for a WebTransport session.
    let bogus = StreamId::from(9999);
    assert_eq!(
        wt.client
            .webtransport_set_anticipated_incoming_uni(bogus, 10),
        Err(Error::InvalidStreamId)
    );
}

#[test]
fn anticipated_bidi_invalid_session() {
    let mut wt = WtTest::new();
    let bogus = StreamId::from(9999);
    assert_eq!(
        wt.client
            .webtransport_set_anticipated_incoming_bidi(bogus, 10),
        Err(Error::InvalidStreamId)
    );
}

#[test]
fn anticipated_uni_valid_session() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    assert_eq!(
        wt.client
            .webtransport_set_anticipated_incoming_uni(session.stream_id(), 10),
        Ok(())
    );
}

#[test]
fn anticipated_bidi_valid_session() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    assert_eq!(
        wt.client
            .webtransport_set_anticipated_incoming_bidi(session.stream_id(), 10),
        Ok(())
    );
}

// ── MAX_STREAMS frame behaviour ───────────────────────────────────────────────

/// Setting a value at or below the default should not trigger a MAX_STREAMS frame.
#[test]
fn anticipated_uni_at_default_sends_no_frame() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let before = client_max_streams_sent(&wt);

    wt.client
        .webtransport_set_anticipated_incoming_uni(session.stream_id(), STREAM_LIMIT_DEFAULT as u16)
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        before,
        "no MAX_STREAMS frame should be sent when value equals the default"
    );
}

/// Setting a value above the default should trigger a MAX_STREAMS frame.
#[test]
fn anticipated_uni_above_default_sends_frame() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let before = client_max_streams_sent(&wt);

    wt.client
        .webtransport_set_anticipated_incoming_uni(
            session.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
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
        .webtransport_set_anticipated_incoming_bidi(
            session.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert!(
        client_max_streams_sent(&wt) > before,
        "a MAX_STREAMS frame should be sent when bidi value exceeds the default"
    );
}

/// Reducing the value below a previously-set value must not send a frame
/// (QUIC stream limits can only increase).
#[test]
fn anticipated_uni_decrease_sends_no_frame() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();

    wt.client
        .webtransport_set_anticipated_incoming_uni(
            session.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 50,
        )
        .unwrap();
    wt.exchange_packets();
    let after_increase = client_max_streams_sent(&wt);

    // Now lower the value — the connection limit should not decrease.
    wt.client
        .webtransport_set_anticipated_incoming_uni(
            session.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 10,
        )
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        after_increase,
        "lowering anticipated streams must not send another MAX_STREAMS frame"
    );
}

// ── multi-session summing ─────────────────────────────────────────────────────

/// With two sessions, the connection limit should be the sum of their
/// anticipated values, not just the last-set value.
#[test]
fn anticipated_uni_two_sessions_sums_values() {
    let mut wt = WtTest::new_with_params(
        wt_default_parameters(),
        wt_default_parameters(),
    );
    let session_a = wt.create_wt_session();
    let session_b = wt.create_wt_session();

    // Set session A to just above the default so a frame is sent.
    wt.client
        .webtransport_set_anticipated_incoming_uni(
            session_a.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
        )
        .unwrap();
    wt.exchange_packets();
    let after_a = client_max_streams_sent(&wt);
    assert!(after_a > 0, "first session should trigger a MAX_STREAMS frame");

    // Now set session B.  The new total (A+B) exceeds the previously-sent
    // limit, so another MAX_STREAMS frame must be sent.
    wt.client
        .webtransport_set_anticipated_incoming_uni(
            session_b.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
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
    let mut wt = WtTest::new_with_params(
        wt_default_parameters(),
        wt_default_parameters(),
    );
    let session_a = wt.create_wt_session();
    let session_b = wt.create_wt_session();

    wt.client
        .webtransport_set_anticipated_incoming_bidi(
            session_a.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
        )
        .unwrap();
    wt.exchange_packets();
    let after_a = client_max_streams_sent(&wt);
    assert!(after_a > 0, "first session should trigger a MAX_STREAMS frame");

    wt.client
        .webtransport_set_anticipated_incoming_bidi(
            session_b.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert!(
        client_max_streams_sent(&wt) > after_a,
        "adding a second session's anticipated bidi streams should send another MAX_STREAMS frame"
    );
}

/// Setting both uni and bidi at the same time triggers exactly two MAX_STREAMS
/// frames (one for each type).
#[test]
fn anticipated_uni_and_bidi_both_send_frames() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let before = client_max_streams_sent(&wt);

    wt.client
        .webtransport_set_anticipated_incoming_uni(
            session.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
        )
        .unwrap();
    wt.client
        .webtransport_set_anticipated_incoming_bidi(
            session.stream_id(),
            STREAM_LIMIT_DEFAULT as u16 + 1,
        )
        .unwrap();
    wt.exchange_packets();

    assert_eq!(
        client_max_streams_sent(&wt),
        before + 2,
        "one MAX_STREAMS frame for uni and one for bidi"
    );
}
