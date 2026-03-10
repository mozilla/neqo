// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(test)]

use std::{cell::RefCell, rc::Rc};

use neqo_common::{event::Provider as _, header::HeadersExt as _};
use neqo_crypto::AuthenticationStatus;
use neqo_http3::{
    Http3Client, Http3ClientEvent, Http3OrWebTransportStream, Http3Parameters, Http3Server,
    Http3ServerEvent, Http3State, SessionAcceptAction, WebTransportEvent, WebTransportRequest,
    WebTransportServerEvent,
};
use neqo_transport::{ConnectionParameters, StreamId, StreamType};
use test_fixture::{
    CountingConnectionIdGenerator, DEFAULT_ADDR, DEFAULT_ALPN_H3, DEFAULT_KEYS,
    DEFAULT_SERVER_NAME, anti_replay, exchange_packets, fixture_init, now,
};

fn connect() -> (Http3Client, Http3Server) {
    fixture_init();
    let mut client = Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR,
        DEFAULT_ADDR,
        Http3Parameters::default().webtransport(true),
        now(),
    )
    .expect("create a default client");
    let mut server = Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN_H3,
        anti_replay(),
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        Http3Parameters::default().webtransport(true),
        None,
    )
    .expect("create a server");
    assert_eq!(client.state(), Http3State::Initializing);
    let out = client.process_output(now());
    let out2 = client.process_output(now());
    assert_eq!(client.state(), Http3State::Initializing);

    _ = server.process(out.dgram(), now());
    let out = server.process(out2.dgram(), now());
    let out = client.process(out.dgram(), now());
    let out = server.process(out.dgram(), now());
    let out = client.process(out.dgram(), now());
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());

    let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
    assert!(client.events().any(authentication_needed));
    client.authenticated(AuthenticationStatus::Ok, now());

    let mut out = client.process(out.dgram(), now()).dgram();
    let connected = |e| matches!(e, Http3ClientEvent::StateChange(Http3State::Connected));
    assert!(client.events().any(connected));

    assert_eq!(client.state(), Http3State::Connected);

    // Exchange H3 settings
    loop {
        out = server.process(out, now()).dgram();
        let dgram_present = out.is_some();
        out = client.process(out, now()).dgram();
        if out.is_none() && !dgram_present {
            break;
        }
    }
    (client, server)
}

fn create_wt_session(client: &mut Http3Client, server: &mut Http3Server) -> WebTransportRequest {
    let wt_session_id = client
        .webtransport_create_session(now(), ("https", "something.com", "/"), &[])
        .unwrap();
    exchange_packets(client, server, false, None);

    let mut wt_server_session = None;
    while let Some(event) = server.next_event() {
        match event {
            Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
                session,
                headers,
            }) => {
                assert!(
                    headers.contains_header(":method", "CONNECT")
                        && headers.contains_header(":protocol", "webtransport")
                );
                session
                    .response(&SessionAcceptAction::Accept, now())
                    .unwrap();
                wt_server_session = Some(session);
            }
            Http3ServerEvent::Data { .. } => {
                panic!("There should not be any data events!");
            }
            _ => {}
        }
    }

    exchange_packets(client, server, false, None);

    let wt_session_negotiated_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::NewSession{
                stream_id,
                status,
                headers,
            }) if (
                stream_id == wt_session_id &&
                status == 200 &&
                headers.contains_header(":status", "200")
            )
        )
    };
    assert!(client.events().any(wt_session_negotiated_event));

    let wt_server_session = wt_server_session.unwrap();
    assert_eq!(wt_session_id, wt_server_session.stream_id());
    wt_server_session
}

fn send_data_client(
    client: &mut Http3Client,
    server: &mut Http3Server,
    wt_stream_id: StreamId,
    data: &[u8],
) {
    assert_eq!(
        client.send_data(wt_stream_id, data, now()).unwrap(),
        data.len()
    );
    exchange_packets(client, server, false, None);
}

fn send_data_server(
    client: &mut Http3Client,
    server: &mut Http3Server,
    wt_stream: &Http3OrWebTransportStream,
    data: &[u8],
) {
    assert_eq!(wt_stream.send_data(data, now()).unwrap(), data.len());
    exchange_packets(client, server, false, None);
}

fn receive_data_client(
    client: &mut Http3Client,
    expected_stream_id: StreamId,
    new_stream: bool,
    expected_data: &[u8],
    expected_fin: bool,
) {
    let mut new_stream_received = false;
    let mut data_received = false;
    while let Some(event) = client.next_event() {
        match event {
            Http3ClientEvent::WebTransport(WebTransportEvent::NewStream { stream_id, .. }) => {
                assert_eq!(stream_id, expected_stream_id);
                new_stream_received = true;
                assert!(!data_received, "expect NewStream before DataReadable");
            }
            Http3ClientEvent::DataReadable { stream_id } => {
                assert_eq!(stream_id, expected_stream_id);
                let mut buf = [0; 100];
                let (amount, fin) = client.read_data(now(), stream_id, &mut buf).unwrap();
                assert_eq!(fin, expected_fin);
                assert_eq!(amount, expected_data.len());
                assert_eq!(&buf[..amount], expected_data);
                data_received = true;
            }
            _ => {}
        }
    }
    assert!(data_received);
    assert_eq!(new_stream, new_stream_received);
}

fn receive_data_server(
    client: &mut Http3Client,
    server: &mut Http3Server,
    stream_id: StreamId,
    new_stream: bool,
    expected_data: &[u8],
    expected_fin: bool,
) -> Http3OrWebTransportStream {
    exchange_packets(client, server, false, None);
    let mut new_stream_received = false;
    let mut data_received = false;
    let mut wt_stream = None;
    let mut stream_closed = false;
    let mut recv_data = Vec::new();
    while let Some(event) = server.next_event() {
        match event {
            Http3ServerEvent::WebTransport(WebTransportServerEvent::NewStream(request)) => {
                assert_eq!(stream_id, request.stream_id());
                new_stream_received = true;
            }
            Http3ServerEvent::Data {
                mut data,
                fin,
                stream,
            } => {
                recv_data.append(&mut data);
                stream_closed = fin;
                data_received = true;
                wt_stream = Some(stream);
            }
            _ => {}
        }
    }
    assert_eq!(&recv_data[..], expected_data);
    assert!(data_received);
    assert_eq!(new_stream, new_stream_received);
    assert_eq!(stream_closed, expected_fin);
    wt_stream.unwrap()
}

#[test]
fn wt_keepalive() {
    let (mut client, mut server) = connect();
    let _wt_session = create_wt_session(&mut client, &mut server);
    // Expect client and server to send PING after half of the idle timeout in order to keep
    // connection alive.
    assert_eq!(
        client.process_output(now()).callback(),
        ConnectionParameters::DEFAULT_IDLE_TIMEOUT / 2
    );
    assert_eq!(
        server.process_output(now()).callback(),
        ConnectionParameters::DEFAULT_IDLE_TIMEOUT / 2
    );
}

#[test]
fn wt_client_stream_uni() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);
    let wt_stream = client
        .webtransport_create_stream(wt_session.stream_id(), StreamType::UniDi)
        .unwrap();
    send_data_client(&mut client, &mut server, wt_stream, BUF_CLIENT);
    exchange_packets(&mut client, &mut server, false, None);
    receive_data_server(&mut client, &mut server, wt_stream, true, BUF_CLIENT, false);
}

#[test]
fn wt_client_stream_bidi() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);
    let wt_client_stream = client
        .webtransport_create_stream(wt_session.stream_id(), StreamType::BiDi)
        .unwrap();
    send_data_client(&mut client, &mut server, wt_client_stream, BUF_CLIENT);
    let wt_server_stream = receive_data_server(
        &mut client,
        &mut server,
        wt_client_stream,
        true,
        BUF_CLIENT,
        false,
    );
    send_data_server(&mut client, &mut server, &wt_server_stream, BUF_SERVER);
    receive_data_client(&mut client, wt_client_stream, false, BUF_SERVER, false);
}

#[test]
fn wt_server_stream_uni() {
    const BUF_SERVER: &[u8] = &[2; 30];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);
    let wt_server_stream = wt_session.create_stream(StreamType::UniDi).unwrap();
    send_data_server(&mut client, &mut server, &wt_server_stream, BUF_SERVER);
    receive_data_client(
        &mut client,
        wt_server_stream.stream_id(),
        true,
        BUF_SERVER,
        false,
    );
}

#[test]
fn wt_server_stream_bidi() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);
    let wt_server_stream = wt_session.create_stream(StreamType::BiDi).unwrap();
    send_data_server(&mut client, &mut server, &wt_server_stream, BUF_SERVER);
    receive_data_client(
        &mut client,
        wt_server_stream.stream_id(),
        true,
        BUF_SERVER,
        false,
    );
    send_data_client(
        &mut client,
        &mut server,
        wt_server_stream.stream_id(),
        BUF_CLIENT,
    );
    assert_eq!(
        receive_data_server(
            &mut client,
            &mut server,
            wt_server_stream.stream_id(),
            false,
            BUF_CLIENT,
            false
        )
        .stream_id(),
        wt_server_stream.stream_id()
    );
}

#[test]
fn wt_race_condition_server_stream_before_confirmation() {
    let now = now();

    for in_order in [true, false] {
        let (mut client, mut server) = connect();

        // Client creates a WebTransport session.
        client
            .webtransport_create_session(now, ("https", "something.com", "/"), &[])
            .unwrap();
        exchange_packets(&mut client, &mut server, false, None);
        assert_eq!(server.process_output(now).dgram(), None);
        while client.next_event().is_some() {}

        // Server accepts the session, but hold back the UDP datagram.
        let wt_server_session = server
            .events()
            .find_map(|event| {
                if let Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
                    session,
                    ..
                }) = event
                {
                    Some(session)
                } else {
                    None
                }
            })
            .expect("Should receive WebTransport session request");
        wt_server_session
            .response(&SessionAcceptAction::Accept, now)
            .unwrap();
        let server_accept_dgram = server
            .process_output(now)
            .dgram()
            .expect("Expected server to produce session acceptance datagram");
        assert_eq!(server.process_output(now).dgram(), None);

        // Server creates a stream, but hold back the UDP datagram.
        let wt_server_stream = wt_server_session.create_stream(StreamType::UniDi).unwrap();
        assert_eq!(wt_server_stream.send_data(&[42], now).unwrap(), 1);
        let server_stream_dgram = server
            .process_output(now)
            .dgram()
            .expect("Expected server to produce a datagram with stream data");

        if in_order {
            // Client processes the server UDP datagrams in order, i.e. the
            // session acceptance before the stream data.
            client.process_input(server_accept_dgram, now);
            assert!(
                matches!(
                    client.events().next(),
                    Some(Http3ClientEvent::WebTransport(
                        WebTransportEvent::NewSession { .. }
                    ))
                ),
                "Should receive session acceptance event"
            );
            client.process_input(server_stream_dgram, now);
        } else {
            // Client processes the server UDP datagrams out-of-order, i.e. the
            // stream data before the session acceptance.
            client.process_input(server_stream_dgram, now);
            client.process_input(server_accept_dgram, now);
            assert!(
                matches!(
                    client.events().next(),
                    Some(Http3ClientEvent::WebTransport(
                        WebTransportEvent::NewSession { .. }
                    ))
                ),
                "Should receive session acceptance event"
            );
        }

        let mut events = client.events();
        assert!(
            matches!(
            events.next(),
            Some(Http3ClientEvent::WebTransport(
                WebTransportEvent::NewStream {
                stream_id,
                session_id,
                }
            )) if stream_id == wt_server_stream.stream_id() && session_id == wt_server_session.stream_id()
            ),
            "Should receive early stream event"
        );

        assert_eq!(
            events.next(),
            Some(Http3ClientEvent::DataReadable {
                stream_id: wt_server_stream.stream_id()
            }),
            "Should receive data readable event for early stream"
        );

        assert_eq!(events.next(), None);
    }
}

#[test]
fn wt_session_ok_and_wt_datagram_in_same_udp_datagram() {
    fixture_init();
    let now = now();

    let (mut client, mut server) = connect();

    // Client creates a WebTransport session.
    client
        .webtransport_create_session(now, ("https", "something.com", "/"), &[])
        .unwrap();
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(server.process_output(now).dgram(), None);
    while client.next_event().is_some() {}

    // Server accepts the session, and sends a WebTransport datagram, all in the same UDP datagram.
    let wt_server_session = server
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
                session,
                ..
            }) = event
            {
                Some(session)
            } else {
                None
            }
        })
        .expect("Should receive WebTransport session request");
    wt_server_session
        .response(&SessionAcceptAction::Accept, now)
        .unwrap();
    wt_server_session.send_datagram(b"PING", None, now, 0, 0).unwrap();
    let accept_and_wt_datagram = server
        .process_output(now)
        .dgram()
        .expect("Expected server to produce session acceptance datagram");
    assert_eq!(server.process_output(now).dgram(), None);

    // Client processes the server's UDP datagram, first the session acceptance,
    // then the WebTransport datagram.
    client.process_input(accept_and_wt_datagram, now);
    assert!(
        matches!(
            client.events().next(),
            Some(Http3ClientEvent::WebTransport(
                WebTransportEvent::NewSession { .. }
            ))
        ),
        "Should receive session acceptance event"
    );
    assert!(
        matches!(
            client.events().next(),
            Some(Http3ClientEvent::WebTransport(
                WebTransportEvent::Datagram{ session_id, datagram }
            )) if session_id == wt_server_session.stream_id() && &datagram == b"PING",
        ),
        "Should receive datagram"
    );

    assert_eq!(client.events().next(), None);
}

#[test]
fn wt_session_stats_basic() {
    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);

    // Get initial stats
    let stats = client.webtransport_session_stats(wt_session.stream_id());
    assert!(stats.is_ok(), "Should have stats for active session");
    let stats = stats.unwrap();

    // Session stats track datagrams, not streams, so initially should be 0
    assert_eq!(stats.bytes_sent, 0, "No datagrams sent yet");
    assert_eq!(stats.bytes_received, 0, "No datagrams received yet");
    assert_eq!(stats.datagrams_sent, 0);
    assert_eq!(stats.datagrams_received, 0);
}

#[test]
fn wt_session_stats_after_datagram_transfer() {
    const DATAGRAM_DATA: &[u8] = &[1, 2, 3, 4, 5];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);
    let session_id = wt_session.stream_id();

    // Get initial stats
    let initial_stats = client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(initial_stats.bytes_sent, 0);
    assert_eq!(initial_stats.datagrams_sent, 0);

    // Send a datagram
    client
        .webtransport_send_datagram(session_id, DATAGRAM_DATA, None, now(), 0, 0)
        .unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    // Get stats after transfer
    let final_stats = client.webtransport_session_stats(session_id).unwrap();

    // Verify datagram stats increased
    assert_eq!(
        final_stats.datagrams_sent, 1,
        "Should have sent one datagram"
    );
    assert!(
        final_stats.bytes_sent >= DATAGRAM_DATA.len() as u64,
        "bytes_sent should be at least datagram size: {} >= {}",
        final_stats.bytes_sent,
        DATAGRAM_DATA.len()
    );
}

#[test]
fn wt_transport_stats_populated() {
    let (mut client, mut server) = connect();
    let _wt_session = create_wt_session(&mut client, &mut server);

    // Get transport-level stats
    let transport_stats = client.transport_stats();

    // Verify transport stats are populated
    assert!(transport_stats.packets_tx > 0, "Should have transmitted packets");
    assert!(transport_stats.packets_rx > 0, "Should have received packets");
    assert!(transport_stats.bytes_tx > 0, "Should have transmitted bytes");
    assert!(transport_stats.bytes_rx > 0, "Should have received bytes");

    // RTT may or may not be measured yet in test environment
    // Just verify the fields exist and have reasonable values
    assert!(transport_stats.rttvar >= std::time::Duration::ZERO, "RTT variation should be non-negative");
    if transport_stats.min_rtt > std::time::Duration::ZERO {
        assert!(transport_stats.min_rtt <= transport_stats.rtt, "min_rtt should be <= smoothed RTT");
    }

    // Congestion control stats
    assert!(transport_stats.cwnd > 0, "cwnd should be positive");
}

#[test]
fn wt_stats_track_packets() {
    const BUF: &[u8] = &[0; 100];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);

    let initial_stats = client.transport_stats();
    let initial_packets_tx = initial_stats.packets_tx;
    let initial_packets_rx = initial_stats.packets_rx;

    // Send data to generate more packets
    let wt_stream = client
        .webtransport_create_stream(wt_session.stream_id(), StreamType::UniDi)
        .unwrap();
    send_data_client(&mut client, &mut server, wt_stream, BUF);
    receive_data_server(&mut client, &mut server, wt_stream, true, BUF, false);

    let final_stats = client.transport_stats();

    // Verify packet counts increased
    assert!(
        final_stats.packets_tx > initial_packets_tx,
        "packets_tx should increase: {} -> {}",
        initial_packets_tx,
        final_stats.packets_tx
    );
    assert!(
        final_stats.packets_rx > initial_packets_rx,
        "packets_rx should increase: {} -> {}",
        initial_packets_rx,
        final_stats.packets_rx
    );
}

#[test]
fn wt_stats_at_session_close() {
    const DATAGRAM_DATA: &[u8] = &[1, 2, 3, 4, 5];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);
    let session_id = wt_session.stream_id();

    // Send a datagram to have some stats
    client
        .webtransport_send_datagram(session_id, DATAGRAM_DATA, None, now(), 0, 0)
        .unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    // Get stats before close
    let stats_before = client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(stats_before.datagrams_sent, 1);

    // Close the session - webtransport_close_session returns stats at close time
    let close_stats = client.webtransport_close_session(session_id, 0, "", now()).unwrap();

    // The stats returned at close should match the pre-close stats
    assert_eq!(
        close_stats.datagrams_sent, stats_before.datagrams_sent,
        "Close stats should match pre-close stats"
    );
}

#[test]
fn wt_stats_rtt_reasonable() {
    let (mut client, mut server) = connect();
    let _wt_session = create_wt_session(&mut client, &mut server);

    let stats = client.transport_stats();

    // For loopback connection, RTT should be small
    assert!(
        stats.rtt < std::time::Duration::from_secs(1),
        "RTT should be < 1s for loopback: {:?}",
        stats.rtt
    );
    assert!(
        stats.min_rtt < std::time::Duration::from_secs(1),
        "min_rtt should be < 1s for loopback: {:?}",
        stats.min_rtt
    );

    // Sanity check: min_rtt should be <= smoothed RTT
    assert!(
        stats.min_rtt <= stats.rtt,
        "min_rtt ({:?}) should be <= smoothed RTT ({:?})",
        stats.min_rtt,
        stats.rtt
    );
}

#[test]
fn wt_stats_bytes_acknowledged() {
    const DATA: &[u8] = &[1; 500];

    let (mut client, mut server) = connect();
    let wt_session = create_wt_session(&mut client, &mut server);

    let initial_stats = client.transport_stats();
    let initial_acked = initial_stats.bytes_acked;

    // Send data and wait for ACK
    let wt_stream = client
        .webtransport_create_stream(wt_session.stream_id(), StreamType::UniDi)
        .unwrap();
    send_data_client(&mut client, &mut server, wt_stream, DATA);

    // Ensure packets are acknowledged
    receive_data_server(&mut client, &mut server, wt_stream, true, DATA, false);

    let final_stats = client.transport_stats();

    // bytes_acked should increase
    assert!(
        final_stats.bytes_acked > initial_acked,
        "bytes_acked should increase after ACK: {} -> {}",
        initial_acked,
        final_stats.bytes_acked
    );
}
