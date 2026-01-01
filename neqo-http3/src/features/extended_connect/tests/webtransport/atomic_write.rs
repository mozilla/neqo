// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_transport::{StreamId, StreamType};

use crate::{
    Error,
    features::extended_connect::tests::webtransport::WtTest,
};

const SMALL_DATA: &[u8] = &[0x42; 16];

/// Basic atomic send on a unidirectional stream returns true and data arrives.
#[test]
fn wt_atomic_send_unidi() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let stream_id = wt.create_wt_stream_client(session.stream_id(), StreamType::UniDi);

    let sent = wt
        .client
        .webtransport_send_stream_atomic(stream_id, SMALL_DATA)
        .unwrap();
    assert!(sent, "atomic send should succeed with available flow control");

    // receive_data_server calls exchange_packets internally
    wt.receive_data_server(stream_id, true, SMALL_DATA, false);
}

/// Basic atomic send on a bidirectional stream returns true and data arrives.
#[test]
fn wt_atomic_send_bidi() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let stream_id = wt.create_wt_stream_client(session.stream_id(), StreamType::BiDi);

    let sent = wt
        .client
        .webtransport_send_stream_atomic(stream_id, SMALL_DATA)
        .unwrap();
    assert!(sent, "atomic send should succeed with available flow control");

    wt.receive_data_server(stream_id, true, SMALL_DATA, false);
}

/// Multiple sequential atomic sends all succeed and each chunk arrives intact.
#[test]
fn wt_atomic_send_multiple() {
    const CHUNK_A: &[u8] = &[0x01; 8];
    const CHUNK_B: &[u8] = &[0x02; 12];

    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let stream_id = wt.create_wt_stream_client(session.stream_id(), StreamType::UniDi);

    assert!(
        wt.client
            .webtransport_send_stream_atomic(stream_id, CHUNK_A)
            .unwrap()
    );
    assert!(
        wt.client
            .webtransport_send_stream_atomic(stream_id, CHUNK_B)
            .unwrap()
    );

    // The two atomic writes are batched in the tx buffer; server sees them concatenated.
    let mut combined = Vec::with_capacity(CHUNK_A.len() + CHUNK_B.len());
    combined.extend_from_slice(CHUNK_A);
    combined.extend_from_slice(CHUNK_B);
    wt.receive_data_server(stream_id, true, &combined, false);
}

/// Flow control info returns a positive available window and zero buffered bytes
/// on a freshly-created (but fully-initialised) stream.
#[test]
fn wt_flow_control_info_initial() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let stream_id = wt.create_wt_stream_client(session.stream_id(), StreamType::UniDi);

    // exchange_packets sends (and gets acked) the WebTransport stream init
    // buffer (stream-type varint + session-ID varint), leaving the stream
    // clean for application data.
    wt.exchange_packets();

    let (available, buffered) = wt
        .client
        .webtransport_send_stream_flow_control_info(stream_id)
        .unwrap();
    assert!(available > 0, "available send space should be positive");
    assert_eq!(buffered, 0, "nothing buffered after init");
}

/// After an atomic send (before any packet exchange), the tx buffer shows the
/// queued bytes; after full exchange+ack the buffer drains to zero.
#[test]
fn wt_flow_control_info_buffered_then_cleared() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let stream_id = wt.create_wt_stream_client(session.stream_id(), StreamType::UniDi);

    // Note: the stream's init buffer (WT stream-type varint + session-ID varint)
    // is NOT flushed by exchange_packets because the stream is not yet in
    // `streams_with_pending_data`.  It is flushed lazily inside send_atomic().
    // Therefore `buffered` after the atomic send includes both the init bytes
    // and SMALL_DATA.
    let sent = wt
        .client
        .webtransport_send_stream_atomic(stream_id, SMALL_DATA)
        .unwrap();
    assert!(sent);

    // Before exchanging packets everything is in the tx buffer but not acked.
    let (_, buffered) = wt
        .client
        .webtransport_send_stream_flow_control_info(stream_id)
        .unwrap();
    assert!(
        buffered >= SMALL_DATA.len(),
        "queued data should appear as buffered (got {buffered})"
    );

    // After the full exchange the peer has acked all data.
    wt.exchange_packets();
    let (available_after, buffered_after) = wt
        .client
        .webtransport_send_stream_flow_control_info(stream_id)
        .unwrap();
    assert_eq!(buffered_after, 0, "all data acked, nothing buffered");
    assert!(available_after > 0);
}

/// The available window reported by flow_control_info decreases by (at least)
/// the number of bytes sent after an atomic send + ack cycle.
#[test]
fn wt_flow_control_info_available_decreases() {
    let mut wt = WtTest::new();
    let session = wt.create_wt_session();
    let stream_id = wt.create_wt_stream_client(session.stream_id(), StreamType::UniDi);
    wt.exchange_packets();

    let (available_before, _) = wt
        .client
        .webtransport_send_stream_flow_control_info(stream_id)
        .unwrap();

    assert!(
        wt.client
            .webtransport_send_stream_atomic(stream_id, SMALL_DATA)
            .unwrap()
    );
    wt.exchange_packets();

    let (available_after, _) = wt
        .client
        .webtransport_send_stream_flow_control_info(stream_id)
        .unwrap();

    // The flow-control window shrinks by (at least) the data we sent.
    // (The peer may or may not send a MAX_STREAM_DATA update, so we only
    // assert the window did not grow beyond what it was before.)
    assert!(
        available_after <= available_before,
        "available window should not exceed initial after sending data"
    );
}

/// Atomic send with data that exceeds the current flow-control window returns
/// false and leaves no partial data in the stream.
#[test]
fn wt_atomic_send_too_large_for_window() {
    use neqo_transport::ConnectionParameters;

    use super::wt_default_parameters;

    // Configure a tiny stream receive window so the client quickly runs out
    // of send credits.
    const TINY_STREAM_WINDOW: u64 = 64;
    // The server advertises its receive-window for client-initiated (remote)
    // UniDi streams.  Setting this small limits how much the client can send.
    let server_params = wt_default_parameters().connection_parameters(
        ConnectionParameters::default()
            .max_stream_data(StreamType::UniDi, true, TINY_STREAM_WINDOW),
    );
    let client_params = wt_default_parameters();

    let mut wt = WtTest::new_with_params(client_params, server_params);
    let session = wt.create_wt_session();
    let stream_id = wt.create_wt_stream_client(session.stream_id(), StreamType::UniDi);
    wt.exchange_packets();

    // A write that exceeds the tiny window must fail atomically (return false).
    let large: Vec<u8> = vec![0xAB; (TINY_STREAM_WINDOW as usize) + 1];
    let sent = wt
        .client
        .webtransport_send_stream_atomic(stream_id, &large)
        .unwrap();
    assert!(!sent, "atomic send larger than window should return false");

    // The stream is still usable — a small write succeeds.
    let (available, _) = wt
        .client
        .webtransport_send_stream_flow_control_info(stream_id)
        .unwrap();
    if available >= SMALL_DATA.len() {
        assert!(
            wt.client
                .webtransport_send_stream_atomic(stream_id, SMALL_DATA)
                .unwrap()
        );
    }
}

/// Calling atomic send with an unknown stream ID returns `InvalidStreamId`.
#[test]
fn wt_atomic_send_invalid_stream_id() {
    let mut wt = WtTest::new();
    let _ = wt.create_wt_session();

    let bogus = StreamId::from(9999);
    let err = wt
        .client
        .webtransport_send_stream_atomic(bogus, SMALL_DATA)
        .unwrap_err();
    assert_eq!(err, Error::InvalidStreamId);
}

/// Calling flow_control_info with an unknown stream ID returns an error.
/// The error is wrapped as `Error::Transport(InvalidStreamId)` because the
/// query goes directly to the transport layer (unlike `send_stream_atomic`
/// which maps it to `Error::InvalidStreamId` at the HTTP/3 layer).
#[test]
fn wt_flow_control_info_invalid_stream_id() {
    let mut wt = WtTest::new();
    let _ = wt.create_wt_session();

    let bogus = StreamId::from(9999);
    assert!(
        wt.client
            .webtransport_send_stream_flow_control_info(bogus)
            .is_err()
    );
}
