// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tests for RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset).

use neqo_common::event::Provider as _;
use test_fixture::now;

use super::{
    connect, default_client, default_server, exchange, new_client, new_server, send_with_extra,
};
use crate::{
    Connection, ConnectionParameters, Error, StreamId, StreamType,
    connection::test_internal::FrameWriter, events::ConnectionEvent, frame::FrameType, packet,
};

const DATA: &[u8] = b"the quick brown fox";
const RELIABLE: usize = 9; // commit "the quick"

/// Create a stream, buffer and commit the reliable prefix, buffer the rest, then reset.
fn commit_prefix_and_reset(c: &mut Connection) -> StreamId {
    let stream_id = c.stream_create(StreamType::UniDi).unwrap();
    c.stream_send(stream_id, &DATA[..RELIABLE]).unwrap();
    c.stream_commit(stream_id).unwrap();
    c.stream_send(stream_id, &DATA[RELIABLE..]).unwrap();
    c.stream_reset_send(stream_id, 0).unwrap();
    stream_id
}

/// The send side emits a `RESET_STREAM_AT` frame when a commitment exists and the peer
/// advertised support. (Send-side only; the server does not process the frame here.)
#[test]
fn emits_reset_stream_at_on_wire() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    _ = commit_prefix_and_reset(&mut client);

    let before = client.stats().frame_tx.reset_stream_at;
    // Flush; the RESET_STREAM_AT frame should be written.
    _ = client.process_output(now()).dgram();
    let after = &client.stats().frame_tx;
    assert_eq!(after.reset_stream_at, before + 1);
    assert_eq!(after.reset_stream, 0);
}

/// Against a peer that did not advertise reliable resets, `stream_commit` is rejected,
/// and a plain `RESET_STREAM` is the only option.
#[test]
fn commit_unavailable_without_peer_support() {
    let mut client = default_client();
    let mut server = new_server(ConnectionParameters::default().reliable_stream_reset(false));
    connect(&mut client, &mut server);

    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(stream_id, DATA).unwrap();
    assert_eq!(
        client.stream_commit(stream_id).unwrap_err(),
        Error::NotAvailable
    );

    // A plain reset still works.
    client.stream_reset_send(stream_id, 0).unwrap();
    let before = client.stats().frame_tx.reset_stream;
    _ = client.process_output(now()).dgram();
    assert_eq!(client.stats().frame_tx.reset_stream, before + 1);
    assert_eq!(client.stats().frame_tx.reset_stream_at, 0);
}

/// Happy path: the receiver delivers exactly `[0, RELIABLE)` and then observes the reset; bytes
/// beyond the reliable offset are not delivered.
#[test]
fn happy_path() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let stream_id = commit_prefix_and_reset(&mut client);
    exchange(&mut client, &mut server);

    // Until the data is read, no reset is signaled.
    assert!(
        !server
            .events()
            .any(|e| matches!(e, ConnectionEvent::RecvStreamReset { .. }))
    );

    // The reliable prefix is readable.
    let mut buf = [0; 64];
    let (n, _fin) = server.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(n, RELIABLE);
    assert_eq!(&buf[..n], &DATA[..n]);

    // After draining the prefix, the reset is surfaced.
    assert!(server.events().any(
        |e| matches!(e, ConnectionEvent::RecvStreamReset { stream_id: id, .. } if id == stream_id)
    ));
}

/// No STREAM FIN is emitted while a reliable reset is in progress: the receiver never sees a
/// clean end, only the reset.
#[test]
fn no_stream_fin() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let stream_id = commit_prefix_and_reset(&mut client);
    exchange(&mut client, &mut server);

    let mut buf = [0; 64];
    let (_n, fin) = server.stream_recv(stream_id, &mut buf).unwrap();
    assert!(!fin, "reliable reset must not deliver a STREAM FIN");
}

/// Reaching `ResetRecvd` after a reliable reset does not surface a `SendStreamComplete` event
/// (delivery-of-committed-data notification is tracked separately; see the project issue).
#[test]
fn reliable_reset_emits_no_send_complete() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    _ = commit_prefix_and_reset(&mut client);
    exchange(&mut client, &mut server);

    let completes = client
        .events()
        .filter(|e| matches!(e, ConnectionEvent::SendStreamComplete { .. }))
        .count();
    assert_eq!(completes, 0);
}

/// Writes a raw `RESET_STREAM_AT` frame for `stream_id` with zero error/final/reliable sizes.
struct ResetStreamAtWriter(u64);

impl FrameWriter for ResetStreamAtWriter {
    fn write_frames(&mut self, builder: &mut packet::Builder<&mut Vec<u8>>) {
        // type, stream_id, application_error_code, final_size, reliable_size
        builder.write_varint_frame(&[FrameType::ResetStreamAt.into(), self.0, 0, 0, 0]);
    }
}

/// Receiving a `RESET_STREAM_AT` after not advertising support is a protocol violation.
#[test]
fn unadvertised_reset_stream_at_is_rejected() {
    let mut client = new_client(ConnectionParameters::default().reliable_stream_reset(false));
    let mut server = default_server();
    connect(&mut client, &mut server);

    // The server sends a crafted RESET_STREAM_AT for a client-initiated stream. The client did
    // not advertise the extension, so it must close the connection.
    let dgram = send_with_extra(&mut server, ResetStreamAtWriter(0), now());
    client.process_input(dgram, now());
    assert!(client.state().closed());
}
