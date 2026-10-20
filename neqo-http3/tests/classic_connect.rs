// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{event::Provider as _, header::HeadersExt as _};
use neqo_http3::{
    Error, Header, Http3Client, Http3ClientEvent, Http3OrWebTransportStream, Http3Server,
    Http3ServerEvent, Priority, StreamId, webtransport::ClientSession as _,
};
use test_fixture::{default_http3_client, default_http3_server, exchange_packets, now};

const AUTHORITY: &str = "something.com";

/// Connects a client and a server and discards the server events produced so
/// far.
fn connect() -> (Http3Client, Http3Server) {
    let mut client = default_http3_client();
    let mut server = default_http3_server();
    let out = test_fixture::connect_peers(&mut client, &mut server);
    assert_eq!(server.process(out, now()).dgram(), None);
    drop(server.events());
    (client, server)
}

#[test]
fn classic_connect() {
    let (mut client, mut server) = connect();

    // Have client send a CONNECT request.
    let stream_id = client
        .connect(now(), AUTHORITY, &[], Priority::default())
        .unwrap();
    client.send_data(stream_id, b"ping", now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    let Some(Http3ServerEvent::Headers { headers, .. }) = server.next_event() else {
        panic!("Expected Headers event");
    };
    assert_eq!(
        headers.find_header(":method").map(Header::value),
        Some(b"CONNECT".as_ref())
    );
    assert_eq!(
        headers.find_header(":authority").map(Header::value),
        Some(AUTHORITY.as_bytes())
    );
    // > The :scheme and :path pseudo-header fields are omitted
    //
    // <https://datatracker.ietf.org/doc/html/rfc9114#section-4.4>
    assert_eq!(headers.find_header(":scheme"), None);
    assert_eq!(headers.find_header(":path"), None);

    let Some(Http3ServerEvent::Data { stream, data, .. }) = server.next_event() else {
        panic!("Expected Data event");
    };
    assert_eq!(stream.stream_id(), stream_id);
    assert_eq!(data, b"ping");

    // Have server respond.
    stream
        .send_headers(&[Header::new(":status", "200")])
        .unwrap();
    stream.send_data(b"pong", now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    // Ignore some client events.
    let mut next_event = None;
    while let Some(event) = client.next_event() {
        match event {
            Http3ClientEvent::StateChange { .. }
            | Http3ClientEvent::RequestsCreatable
            | Http3ClientEvent::ResumptionToken { .. }
            | Http3ClientEvent::DataWritable { .. } => {}
            e => {
                next_event = Some(e);
                break;
            }
        }
    }

    let Http3ClientEvent::HeaderReady {
        stream_id, headers, ..
    } = next_event.unwrap()
    else {
        unreachable!()
    };
    assert_eq!(stream_id, stream.stream_id());
    assert_eq!(
        headers.find_header(":status").map(Header::value),
        Some(b"200".as_ref())
    );

    let Some(Http3ClientEvent::DataReadable { stream_id }) = client.next_event() else {
        unreachable!()
    };
    assert_eq!(stream_id, stream.stream_id());
    let mut data = vec![0; 4];
    let (amount, _fin) = client.read_data(now(), stream_id, &mut data).unwrap();
    assert_eq!(&data[..amount], b"pong");
}

#[test]
fn classic_connect_via_fetch_panics_in_debug() {
    let (mut client, _server) = connect();

    let res = client.fetch(
        now(),
        "CONNECT",
        ("https", AUTHORITY, "/"),
        &[],
        Priority::default(),
    );
    assert_eq!(res, Err(Error::InvalidInput));
}

/// Connects a client and a server and establishes a classic CONNECT tunnel,
/// i.e. the server has answered the CONNECT request with a 2xx response.
fn establish_tunnel() -> (
    Http3Client,
    Http3Server,
    StreamId,
    Http3OrWebTransportStream,
) {
    let (mut client, mut server) = connect();

    let stream_id = client
        .connect(now(), AUTHORITY, &[], Priority::default())
        .expect("client should open a CONNECT tunnel");
    exchange_packets(&mut client, &mut server, false, None);

    let stream = server
        .events()
        .find_map(|e| match e {
            Http3ServerEvent::Headers { stream, .. } => Some(stream),
            _ => None,
        })
        .expect("server should receive the CONNECT request");
    assert_eq!(stream.stream_id(), stream_id);
    stream
        .send_headers(&[Header::new(":status", "200")])
        .expect("server should accept the CONNECT request");
    exchange_packets(&mut client, &mut server, false, None);

    assert!(client.events().any(|e| matches!(
        &e,
        Http3ClientEvent::HeaderReady { stream_id: id, headers, .. }
            if *id == stream_id
                && headers.find_header(":status").map(Header::value) == Some(b"200".as_ref())
    )));

    (client, server, stream_id, stream)
}

/// Collects tunnel data received by the server until the client closes its
/// sending side.
fn server_read_until_fin(server: &Http3Server, stream_id: StreamId) -> Vec<u8> {
    let mut received = Vec::new();
    for event in server.events() {
        match event {
            Http3ServerEvent::Data { stream, data, fin } => {
                assert_eq!(stream.stream_id(), stream_id);
                received.extend_from_slice(&data);
                if fin {
                    return received;
                }
            }
            Http3ServerEvent::StreamReset { .. } | Http3ServerEvent::StreamStopSending { .. } => {
                panic!("unexpected event on the tunnel stream: {event:?}");
            }
            _ => {}
        }
    }
    panic!("server did not receive FIN on the tunnel stream");
}

/// Reads tunnel data on the client until the server closes its sending side.
fn client_read_until_fin(client: &mut Http3Client, stream_id: StreamId) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buf = [0; 64];
    loop {
        let (amount, fin) = client
            .read_data(now(), stream_id, &mut buf)
            .expect("client should be able to read from the tunnel");
        received.extend_from_slice(&buf[..amount]);
        if fin {
            return received;
        }
        assert_ne!(amount, 0, "client did not receive FIN on the tunnel stream");
    }
}

/// Drains the pending client events and returns those for the tunnel stream.
fn client_tunnel_events(client: &mut Http3Client, stream_id: StreamId) -> Vec<Http3ClientEvent> {
    client
        .events()
        .filter(|e| match e {
            Http3ClientEvent::HeaderReady { stream_id: id, .. }
            | Http3ClientEvent::DataWritable { stream_id: id }
            | Http3ClientEvent::DataReadable { stream_id: id }
            | Http3ClientEvent::Reset { stream_id: id, .. }
            | Http3ClientEvent::StopSending { stream_id: id, .. } => *id == stream_id,
            _ => false,
        })
        .collect()
}

/// > TCP connections that remain half closed in a single direction are not
/// > invalid
///
/// <https://datatracker.ietf.org/doc/html/rfc9114#section-4.4>
///
/// Closing the client's sending side of a tunnel must not tear down the
/// receiving side.
#[test]
fn classic_connect_client_half_close() {
    let (mut client, mut server, stream_id, stream) = establish_tunnel();

    client.send_data(stream_id, b"ping", now()).unwrap();
    client.stream_close_send(stream_id, now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(server_read_until_fin(&server, stream_id), b"ping");

    // The server keeps sending after the client's half-close.
    stream.send_data(b"pong", now()).unwrap();
    stream.stream_close_send(now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(
        client_tunnel_events(&mut client, stream_id),
        [Http3ClientEvent::DataReadable { stream_id }]
    );
    assert_eq!(client_read_until_fin(&mut client, stream_id), b"pong");
}

/// The server closing its sending side of a tunnel must not tear down the
/// client's sending side.
#[test]
fn classic_connect_server_half_close() {
    let (mut client, mut server, stream_id, stream) = establish_tunnel();

    stream.send_data(b"pong", now()).unwrap();
    stream.stream_close_send(now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(
        client_tunnel_events(&mut client, stream_id),
        [Http3ClientEvent::DataReadable { stream_id }]
    );
    assert_eq!(client_read_until_fin(&mut client, stream_id), b"pong");

    // The client keeps sending after the server's half-close.
    assert_eq!(client.send_data(stream_id, b"ping", now()), Ok(4));
    client.stream_close_send(stream_id, now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(server_read_until_fin(&server, stream_id), b"ping");
}

/// The server aborting the client's sending side of a tunnel with
/// `STOP_SENDING` must not tear down the client's receiving side.
#[test]
fn classic_connect_server_stop_sending() {
    let (mut client, mut server, stream_id, stream) = establish_tunnel();

    stream
        .stream_stop_sending(Error::HttpConnect.code())
        .unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(
        client_tunnel_events(&mut client, stream_id),
        [Http3ClientEvent::StopSending {
            stream_id,
            error: Error::HttpConnect.code()
        }]
    );
    assert_eq!(
        client.send_data(stream_id, b"ping", now()),
        Err(Error::InvalidStreamId)
    );

    // The server keeps sending after aborting the client's sending side.
    stream.send_data(b"pong", now()).unwrap();
    stream.stream_close_send(now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(client_read_until_fin(&mut client, stream_id), b"pong");
}

/// The server resetting its sending side of a tunnel must not tear down the
/// client's sending side.
#[test]
fn classic_connect_server_reset() {
    let (mut client, mut server, stream_id, stream) = establish_tunnel();

    stream.stream_reset_send(Error::HttpConnect.code()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    // A local reset makes the server report `StreamStopSending` for its own
    // sending side; discard that event.
    drop(server.events());
    assert_eq!(
        client_tunnel_events(&mut client, stream_id),
        [Http3ClientEvent::Reset {
            stream_id,
            error: Error::HttpConnect.code(),
            local: false
        }]
    );

    // The client keeps sending after the server's reset.
    assert_eq!(client.send_data(stream_id, b"ping", now()), Ok(4));
    client.stream_close_send(stream_id, now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(server_read_until_fin(&server, stream_id), b"ping");
}

/// Reprioritizing a tunnel sends a `PRIORITY_UPDATE` for its request stream.
#[test]
fn classic_connect_priority_update() {
    let (mut client, mut server, stream_id, _stream) = establish_tunnel();

    let priority = Priority::new(3, true);
    assert_eq!(client.priority_update(stream_id, priority), Ok(true));
    exchange_packets(&mut client, &mut server, false, None);
    assert!(server.events().any(|e| matches!(
        e,
        Http3ServerEvent::PriorityUpdate { stream_id: id, priority: p }
            if id == stream_id && p == priority
    )));
}

/// A classic CONNECT tunnel is not an extended CONNECT session.
#[test]
fn classic_connect_is_not_extended_connect_session() {
    let (client, _server, stream_id, _stream) = establish_tunnel();
    assert_eq!(
        client.webtransport_session_protocol(stream_id),
        Err(Error::InvalidStreamId)
    );
}
