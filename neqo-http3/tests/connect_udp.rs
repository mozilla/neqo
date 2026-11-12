// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(test)]

use std::time::Duration;

use http::Uri;
use neqo_common::{Datagram, Tos, event::Provider as _, header::HeadersExt as _};
use neqo_http3::{
    ConnectUdpEvent, Error, Http3Client, Http3ClientEvent, Http3Parameters, Http3Server,
    Http3ServerEvent, Http3State, Priority, SessionAcceptAction,
    connect_udp::{ClientSession as _, ServerEvent, ServerSession},
    features::extended_connect::session::CloseReason,
    webtransport::ClientSession as _,
};
use neqo_transport::{
    ConnectionParameters, DatagramQueueOutcome, Output, StreamDataLimit, StreamType,
};
use nss::AuthenticationStatus;
use test_fixture::{
    DEFAULT_ADDR, default_http3_client, default_http3_server, exchange_packets, fixture_init,
    http3_client_with_params, http3_server_with_params, now,
};
use tracing::info;

const PING: &[u8] = b"ping";
const PONG: &[u8] = b"pong";

const DATAGRAM_FRAME_TYPE_VARINT_LEN: usize = 1;

#[test]
fn disabled_by_default() {
    let mut client = default_http3_client();
    let mut server = default_http3_server();
    // Connect client and proxy.
    let _out = test_fixture::connect_peers(&mut client, &mut server);
    assert!(!client.connect_udp_enabled());
}

/// The URI every connect-udp session in these tests connects to through the proxy.
fn target_uri() -> Uri {
    format!("https://[{}]:{}/", DEFAULT_ADDR.ip(), DEFAULT_ADDR.port())
        .parse()
        .unwrap()
}

fn initiate_new_session() -> (Http3Client, Http3Server, neqo_http3::StreamId) {
    initiate_new_session_with_client_params(
        ConnectionParameters::default()
            .pmtud(true)
            .datagram_size(1500),
    )
}

fn initiate_new_session_with_client_params(
    client_conn_params: ConnectionParameters,
) -> (Http3Client, Http3Server, neqo_http3::StreamId) {
    let proxy_conn_params = ConnectionParameters::default()
        .pmtud(true)
        .datagram_size(1500);

    let mut client = http3_client_with_params(
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(client_conn_params),
    );

    let mut proxy = http3_server_with_params(
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(proxy_conn_params),
    );

    // Connect client and proxy.
    let out = test_fixture::connect_peers(&mut client, &mut proxy);
    let out = proxy.process(out, now()).dgram().unwrap();
    client.process_input(out, now());
    assert!(client.connect_udp_enabled());

    // Establish connect-udp session.
    let connect_udp_session_id = client
        .connect_udp_create_session(now(), &target_uri(), &[])
        .unwrap();
    (client, proxy, connect_udp_session_id)
}

fn establish_new_session() -> (Http3Client, Http3Server, ServerSession) {
    establish_new_session_with_client_params(
        ConnectionParameters::default()
            .pmtud(true)
            .datagram_size(1500),
    )
}

fn establish_new_session_with_client_params(
    client_conn_params: ConnectionParameters,
) -> (Http3Client, Http3Server, ServerSession) {
    let (mut client, mut proxy, connect_udp_session_id) =
        initiate_new_session_with_client_params(client_conn_params);
    exchange_packets(&mut client, &mut proxy, false, None);
    let proxy_session = proxy
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ServerEvent::NewSession { session, headers }) =
                event
            {
                assert_eq!(session.stream_id(), connect_udp_session_id);

                assert!(
                    headers.contains_header(":method", "CONNECT")
                        && headers.contains_header(":protocol", "connect-udp")
                        && headers.contains_header("capsule-protocol", "?1")
                );

                session
                    .response(&SessionAcceptAction::Accept, now())
                    .unwrap();
                Some(session)
            } else {
                None
            }
        })
        .unwrap();
    exchange_packets(&mut client, &mut proxy, false, None);
    client
        .events()
        .find(|e| matches!(
            e,
            Http3ClientEvent::ConnectUdp(ConnectUdpEvent::NewSession { stream_id, status, ..}) if *stream_id == connect_udp_session_id && *status == 200)
        )
        .unwrap();
    (client, proxy, proxy_session)
}

fn exchange_packets_through_proxy(
    client_outer: &mut Http3Client,
    client_inner: &mut Http3Client,
    proxy: &mut Http3Server,
    server: &mut Http3Server,
    proxy_session: &ServerSession,
) {
    let connect_udp_session_id = proxy_session.stream_id();

    info!("Processing client_inner");
    while let Some(dgram) = client_inner.process_output(now()).dgram() {
        _ = client_outer
            .connect_udp_send_datagram(connect_udp_session_id, dgram.as_ref(), None, now())
            .unwrap();
    }

    info!("Processing client_outer");
    let mut client_outer_dgrams = client_outer
        .process_multiple_output(now(), 64.try_into().unwrap())
        .dgram()
        .unwrap();

    info!("Processing proxy");
    let proxy_out = proxy
        .process_multiple(
            client_outer_dgrams.iter_mut(),
            now(),
            64.try_into().unwrap(),
        )
        .dgram();
    if let Some(mut dgram) = proxy_out {
        client_outer.process_multiple_input(dgram.iter_mut(), now());
    }
    let server_dgrams = proxy.events().filter_map(|event| match event {
        Http3ServerEvent::ConnectUdp(ServerEvent::Datagram { datagram, session }) => {
            assert_eq!(session.stream_id(), connect_udp_session_id);
            Some(Datagram::from_bytes(
                DEFAULT_ADDR,
                DEFAULT_ADDR,
                Tos::default(),
                datagram,
            ))
        }
        _ => None,
    });

    info!("Processing server");
    let mut server_out = vec![];
    for dgram in server_dgrams {
        if let Some(dgram) = server.process(Some(dgram), now()).dgram() {
            server_out.push(dgram);
        }
    }
    while let Some(dgram) = server.process(Option::<Datagram>::None, now()).dgram() {
        server_out.push(dgram);
    }

    info!("Processing proxy");
    for dgram in server_out {
        _ = proxy_session
            .send_datagram(dgram.as_ref(), None, now())
            .unwrap();
    }
    let mut proxy_out = vec![];
    while let Some(dgram) = proxy.process(Vec::<Datagram>::new(), now()).dgram() {
        proxy_out.push(dgram);
    }

    info!("Processing client_outer");
    client_outer.process_multiple_input(proxy_out, now());

    info!("Processing client_inner");
    let client_inner_dgrams = client_outer.events().filter_map(|event| {
        if let Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Datagram {
            session_id,
            datagram,
        }) = event
        {
            assert_eq!(session_id, connect_udp_session_id);
            Some(Datagram::from_bytes(
                DEFAULT_ADDR,
                DEFAULT_ADDR,
                Tos::default(),
                datagram,
            ))
        } else {
            None
        }
    });
    client_inner.process_multiple_input(client_inner_dgrams, now());
}

fn session_lifecycle(client_closes: bool) {
    fixture_init();
    neqo_common::log::init(None);

    let (mut client, mut proxy, proxy_session) = establish_new_session();
    let session_id = proxy_session.stream_id();

    assert_eq!(
        client.connect_udp_send_datagram(session_id, PING, None, now()),
        Ok(DatagramQueueOutcome::Ok)
    );

    exchange_packets(&mut client, &mut proxy, false, None);

    let (id, datagram) = proxy
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ServerEvent::Datagram { session, datagram }) = event
            {
                Some((session.stream_id(), datagram))
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(session_id, id);
    assert_eq!(&datagram, PING);

    assert_eq!(
        proxy_session.send_datagram(PONG, None, now()),
        Ok(DatagramQueueOutcome::Ok)
    );

    exchange_packets(&mut client, &mut proxy, false, None);

    let (id, datagram) = client
        .events()
        .find_map(|event| {
            if let Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Datagram {
                session_id: id,
                datagram,
            }) = event
            {
                Some((id, datagram))
            } else {
                None
            }
        })
        .unwrap();

    assert_eq!(session_id, id);
    assert_eq!(&datagram, PONG);

    if client_closes {
        client
            .connect_udp_close_session(session_id, 0, "kthxbye", now())
            .unwrap();

        exchange_packets(&mut client, &mut proxy, false, None);

        proxy
            .events()
            .find(|event| {
                matches!(
                    event,
                    Http3ServerEvent::ConnectUdp(ServerEvent::SessionClosed {
                        session,
                        ..
                    }) if session.stream_id() == session_id
                )
            })
            .unwrap();
    } else {
        proxy_session.close_session(0, "kthxbye", now()).unwrap();

        exchange_packets(&mut client, &mut proxy, false, None);

        client
            .events()
            .find(|event| {
                matches!(
                    event,
                    Http3ClientEvent::ConnectUdp(ConnectUdpEvent::SessionClosed {
                        stream_id,
                        ..
                    }) if *stream_id == session_id
                )
            })
            .unwrap();
    }
}

#[test]
fn session_lifecycle_client_closes() {
    session_lifecycle(true);
}

#[test]
fn session_lifecycle_server_closes() {
    session_lifecycle(false);
}

#[test]
fn connect_via_proxy() {
    fixture_init();
    neqo_common::log::init(None);

    let mut client_inner = default_http3_client();
    let mut server = default_http3_server();

    let (mut client_outer, mut proxy, proxy_session) = establish_new_session();

    let mut needs_auth = false;
    // Establish inner connection on top of connect-udp session.
    'outer: loop {
        for event in client_inner.events() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    needs_auth = true;
                }
                Http3ClientEvent::StateChange(Http3State::Connected) => break 'outer,
                _ => {}
            }
        }

        if needs_auth {
            client_inner.authenticated(AuthenticationStatus::Ok, now());
            needs_auth = false;
        }

        exchange_packets_through_proxy(
            &mut client_outer,
            &mut client_inner,
            &mut proxy,
            &mut server,
            &proxy_session,
        );
    }

    client_inner.close(now(), 0, "kthxbye");

    'outer: loop {
        for event in server.events() {
            if let Http3ServerEvent::StateChange {
                state: Http3State::Closing(_),
                ..
            } = event
            {
                break 'outer;
            }
        }

        exchange_packets_through_proxy(
            &mut client_outer,
            &mut client_inner,
            &mut proxy,
            &mut server,
            &proxy_session,
        );
    }
}

#[test]
fn send_dgram_on_non_active_session() {
    let (mut client, _proxy, connect_udp_session_id) = initiate_new_session();

    assert_eq!(
        client.connect_udp_send_datagram(connect_udp_session_id, &[], None, now()),
        Err(Error::InvalidStreamId)
    );
}

/// A server datagram, arriving before the server accepted the session, is dropped.
#[test]
fn server_datagram_before_accept() {
    for in_order in [true, false] {
        let (mut client, mut proxy, _connect_udp_session_id) = initiate_new_session();
        exchange_packets(&mut client, &mut proxy, false, None);

        let proxy_session = proxy
            .events()
            .find_map(|event| {
                if let Http3ServerEvent::ConnectUdp(ServerEvent::NewSession { session, .. }) = event
                {
                    Some(session)
                } else {
                    None
                }
            })
            .unwrap();
        proxy_session
            .response(&SessionAcceptAction::Accept, now())
            .unwrap();
        let proxy_accept = proxy.process_output(now()).dgram().unwrap();
        assert!(proxy.process_output(now()).dgram().is_none());

        _ = proxy_session.send_datagram(b"ping", None, now()).unwrap();
        let proxy_dgram = proxy.process_output(now()).dgram().unwrap();

        while client.next_event().is_some() {}

        if in_order {
            client.process_input(proxy_accept, now());
            assert!(matches!(
                client.events().next(),
                Some(Http3ClientEvent::ConnectUdp(
                    ConnectUdpEvent::NewSession { .. }
                ))
            ));
            client.process_input(proxy_dgram, now());
            assert!(matches!(
                client.events().next(),
                Some(Http3ClientEvent::ConnectUdp(
                    ConnectUdpEvent::Datagram { .. }
                ))
            ));
        } else {
            client.process_input(proxy_dgram, now());
            assert_eq!(client.events().next(), None,);
            client.process_input(proxy_accept, now());
            assert!(matches!(
                client.events().next(),
                Some(Http3ClientEvent::ConnectUdp(
                    ConnectUdpEvent::NewSession { .. }
                ))
            ));
            assert_eq!(client.events().next(), None,);
        }
    }
}

#[test]
fn create_session_without_connect_setting() {
    let mut client = http3_client_with_params(Http3Parameters::default().connect(false));
    assert_eq!(
        client.connect_udp_create_session(now(), &Uri::from_static("https://example.com/"), &[]),
        Err(Error::Unavailable)
    );
}

#[test]
fn server_stream_reset_results_in_client_session_close() {
    let (mut client, mut proxy, _connect_udp_session_id) = initiate_new_session();
    exchange_packets(&mut client, &mut proxy, false, None);

    while client.next_event().is_some() {}

    let proxy_session = proxy
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ServerEvent::NewSession { session, .. }) = event {
                Some(session)
            } else {
                None
            }
        })
        .unwrap();

    proxy_session.reset_send().unwrap();
    exchange_packets(&mut client, &mut proxy, false, None);

    let Some(Http3ClientEvent::ConnectUdp(ConnectUdpEvent::SessionClosed { reason, .. })) =
        client.next_event()
    else {
        panic!("expected SessionClosed");
    };
    assert_eq!(reason, CloseReason::Error(Error::HttpNone.code()));
}

#[test]
fn connect_udp_operation_on_fetch_stream() {
    let (mut client, _proxy, _proxy_session) = establish_new_session();
    let fetch_stream = client
        .fetch(
            now(),
            "GET",
            &("https", "something.com", "/"),
            &[],
            Priority::default(),
        )
        .unwrap();

    assert_eq!(
        client.connect_udp_send_datagram(fetch_stream, PING, None, now()),
        Err(Error::InvalidStreamId)
    );

    assert_eq!(
        client.connect_udp_close_session(fetch_stream, 0, "kthxbye", now()),
        Err(Error::InvalidStreamId)
    );
}

#[test]
fn session_lifecycle_with_http_datagram_capsule() {
    let (mut client, mut proxy, session_id, proxy_session) = establish_capsule_session(None);

    info!("Testing Capsule send (client -> server)");
    assert_eq!(
        client.connect_udp_send_datagram(session_id, PING, None, now()),
        Ok(DatagramQueueOutcome::Ok)
    );

    exchange_packets(&mut client, &mut proxy, false, None);

    let (id, datagram) = proxy
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ServerEvent::Datagram { session, datagram }) = event
            {
                Some((session.stream_id(), datagram))
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(session_id, id);
    assert_eq!(&datagram, PING);
    info!("Capsule decode successful (client -> server)");

    info!("Testing Capsule receive (server -> client)");
    assert_eq!(
        proxy_session.send_datagram(PONG, None, now()),
        Ok(DatagramQueueOutcome::Ok)
    );

    exchange_packets(&mut client, &mut proxy, false, None);

    let (id, datagram) = client
        .events()
        .find_map(|event| {
            if let Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Datagram {
                session_id: id,
                datagram,
            }) = event
            {
                Some((id, datagram))
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(session_id, id);
    assert_eq!(&datagram, PONG);
    info!("Capsule encode/decode successful (server -> client)");

    info!("Testing multiple datagrams via Capsules");
    for i in 0..5 {
        let mut payload = PING.to_vec();
        payload.push(i);
        _ = client
            .connect_udp_send_datagram(session_id, &payload, None, now())
            .unwrap();
    }

    exchange_packets(&mut client, &mut proxy, false, None);

    let mut count = 0;
    for event in proxy.events() {
        if let Http3ServerEvent::ConnectUdp(ServerEvent::Datagram { session, datagram }) = event {
            assert_eq!(session.stream_id(), session_id);
            assert_eq!(&datagram.as_ref()[..4], PING);
            count += 1;
        }
    }
    assert_eq!(count, 5, "Should receive all 5 datagrams via Capsules");
    info!("Multiple Capsules transmitted successfully");

    client
        .connect_udp_close_session(session_id, 0, "capsule test complete", now())
        .unwrap();

    exchange_packets(&mut client, &mut proxy, false, None);

    proxy
        .events()
        .find(|event| {
            matches!(
                event,
                Http3ServerEvent::ConnectUdp(ServerEvent::SessionClosed {
                    session,
                    ..
                }) if session.stream_id() == session_id
            )
        })
        .unwrap();

    assert_eq!(
        client.transport_stats().frame_tx.datagram,
        0,
        "No QUIC datagram frames should have been sent by client"
    );

    info!("HTTP DATAGRAM Capsule test completed successfully");
}

#[test]
fn connect_udp_session_protocol_is_not_webtransport() {
    fixture_init();
    let (mut client, _proxy, proxy_session) = establish_new_session();
    let session_id = proxy_session.stream_id();
    assert_eq!(
        client.webtransport_session_protocol(session_id).unwrap(),
        None,
    );
    assert_eq!(
        client.stream_commit(session_id, now()),
        Err(Error::Unavailable),
        "commit() not implemented for CONNECT-UDP"
    );
}

/// `webtransport_session_stats` must not return stats for a connect-udp
/// session just because it happens to share the extended-CONNECT session
/// machinery with WebTransport.
#[test]
fn connect_udp_session_has_no_webtransport_stats() {
    fixture_init();
    let (client, _proxy, proxy_session) = establish_new_session();
    let session_id = proxy_session.stream_id();
    assert_eq!(
        client.webtransport_session_stats(session_id),
        Err(Error::InvalidStreamId)
    );
}

/// `webtransport_close_session` must not accept a connect-udp session id
/// just because it happens to share the extended-CONNECT session
/// machinery with WebTransport.
#[test]
fn connect_udp_session_rejected_by_webtransport_close_session() {
    fixture_init();
    let (mut client, _proxy, proxy_session) = establish_new_session();
    let session_id = proxy_session.stream_id();
    assert_eq!(
        client.webtransport_close_session(session_id, 0, "", now()),
        Err(Error::InvalidStreamId)
    );
}

/// `webtransport_create_stream` must not accept a connect-udp session id
/// just because it happens to share the extended-CONNECT session
/// machinery with WebTransport.
#[test]
fn connect_udp_session_rejected_by_webtransport_create_stream() {
    fixture_init();
    let (mut client, _proxy, proxy_session) = establish_new_session();
    let session_id = proxy_session.stream_id();
    assert_eq!(
        client.webtransport_create_stream(session_id, StreamType::UniDi),
        Err(Error::InvalidStreamId)
    );
}

/// Backpressure surfaces end-to-end through connect-udp: once
/// `connect_udp_send_datagram` fills the session's outgoing datagram queue
/// up to connect-udp's built-in max-buffered limit and reports
/// `MaxBufferedReached`, draining it must deliver
/// [`OutgoingDatagramSpaceAvailable`], so a datagram sender that backs off
/// on that outcome learns it can resume.
///
/// [`OutgoingDatagramSpaceAvailable`]: neqo_http3::Http3ClientEvent::OutgoingDatagramSpaceAvailable
#[test]
fn outgoing_datagram_space_available_forwarded() {
    fixture_init();
    let (mut client, mut proxy, proxy_session) = establish_new_session_with_client_params(
        ConnectionParameters::default()
            .pmtud(true)
            .datagram_size(1500),
    );
    let session_id = proxy_session.stream_id();

    // Drain session-setup events so the assertions below only observe the
    // datagram backpressure signal.
    while client.next_event().is_some() {}

    // Connect-udp has no API to set a max-buffered limit, so every session gets
    // a built-in one of 10 datagrams: the tenth send reports the queue full.
    for _ in 0..9 {
        assert_eq!(
            client.connect_udp_send_datagram(session_id, PING, None, now()),
            Ok(DatagramQueueOutcome::Ok)
        );
    }
    assert_eq!(
        client.connect_udp_send_datagram(session_id, PING, None, now()),
        Ok(DatagramQueueOutcome::MaxBufferedReached)
    );
    assert!(
        !client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable { .. })),
        "resume event fired before the queue drained"
    );

    exchange_packets(&mut client, &mut proxy, false, None);
    assert!(
        client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable { session_id: id } if id == session_id)),
        "OutgoingDatagramSpaceAvailable was not forwarded through connect-udp"
    );
}

#[test]
fn server_session_has_the_built_in_max_buffered_datagrams() {
    fixture_init();
    let (mut client, mut proxy, proxy_session) = establish_new_session_with_client_params(
        ConnectionParameters::default()
            .pmtud(true)
            .datagram_size(1500),
    );

    while proxy.next_event().is_some() {}

    // The accepted side of a connect-udp session gets the same built-in mark
    // as the side that created it: the proxy is the bulk sender here.
    for _ in 0..9 {
        assert_eq!(
            proxy_session.send_datagram(PONG, None, now()),
            Ok(DatagramQueueOutcome::Ok)
        );
    }
    assert_eq!(
        proxy_session.send_datagram(PONG, None, now()),
        Ok(DatagramQueueOutcome::MaxBufferedReached)
    );
    assert!(
        !proxy
            .events()
            .any(|e| matches!(e, Http3ServerEvent::OutgoingDatagramSpaceAvailable { .. })),
        "resume event fired before the queue drained"
    );

    exchange_packets(&mut client, &mut proxy, false, None);
    assert!(
        proxy
            .events()
            .any(|e| matches!(e, Http3ServerEvent::OutgoingDatagramSpaceAvailable { session_id, .. } if session_id == proxy_session.stream_id())),
        "OutgoingDatagramSpaceAvailable was not forwarded to the connect-udp server"
    );
}

/// Establish a connect-udp session over the HTTP DATAGRAM Capsule path, granting
/// the client only `proxy_max_stream_data` bytes of control-stream flow control.
fn establish_capsule_session(
    proxy_max_stream_data: Option<u64>,
) -> (
    Http3Client,
    Http3Server,
    neqo_http3::StreamId,
    ServerSession,
) {
    fixture_init();
    neqo_common::log::init(None);

    // `datagram_size(0)` forces the HTTP DATAGRAM Capsule path.
    let mut proxy_params = ConnectionParameters::default().datagram_size(0);
    if let Some(v) = proxy_max_stream_data {
        proxy_params = proxy_params.max_stream_data(StreamDataLimit::BiDiRemote, v);
    }
    let mut client = http3_client_with_params(
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(ConnectionParameters::default().datagram_size(0)),
    );
    let mut proxy = http3_server_with_params(
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(proxy_params),
    );

    let out = test_fixture::connect_peers(&mut client, &mut proxy);
    if let Some(dgram) = out
        && let Some(dgram) = proxy.process(Some(dgram), now()).dgram()
    {
        client.process_input(dgram, now());
    }

    let session_id = client
        .connect_udp_create_session(now(), &target_uri(), &[])
        .unwrap();

    exchange_packets(&mut client, &mut proxy, false, None);

    let proxy_session = proxy
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ServerEvent::NewSession { session, headers }) =
                event
            {
                assert_eq!(session.stream_id(), session_id);
                assert!(
                    headers.contains_header(":method", "CONNECT")
                        && headers.contains_header(":protocol", "connect-udp")
                        && headers.contains_header("capsule-protocol", "?1")
                );
                session
                    .response(&SessionAcceptAction::Accept, now())
                    .unwrap();
                Some(session)
            } else {
                None
            }
        })
        .unwrap();

    exchange_packets(&mut client, &mut proxy, false, None);

    client
        .events()
        .find(|e| {
            matches!(
                e,
                Http3ClientEvent::ConnectUdp(ConnectUdpEvent::NewSession { stream_id, status, .. })
                    if *stream_id == session_id && *status == 200)
        })
        .unwrap();

    (client, proxy, session_id, proxy_session)
}

/// A datagram capsule that would exceed the control stream's flow-control window
/// is refused with `FlowControlLimit` rather than silently dropped, and the
/// sender receives a resume event once the window reopens.
#[test]
fn datagram_capsule_flow_control_error_and_resume() {
    let (mut client, mut proxy, session_id, _proxy_session) = establish_capsule_session(Some(2000));

    // Fill the control stream's flow-control window with datagram capsules until
    // one is refused; a refusal is an error, never a silent drop.
    let payload = vec![0x2c; 500];
    let mut refused = false;
    for _ in 0..100 {
        match client.connect_udp_send_datagram(session_id, &payload, None, now()) {
            Ok(_) => {}
            Err(Error::FlowControlLimit) => {
                refused = true;
                break;
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert!(
        refused,
        "the control stream never reached its flow-control limit"
    );
    assert!(
        !client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable { .. })),
        "resume event fired before the window reopened"
    );

    // The proxy reads the buffered capsules and grants more flow-control credit,
    // reopening the control stream, which must surface the resume event.
    exchange_packets(&mut client, &mut proxy, false, None);
    assert!(
        client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable { session_id: id } if id == session_id)),
        "resume event not emitted after control-stream flow control reopened"
    );
}

/// A datagram whose payload fits the window but whose capsule and DATA frame
/// framing does not must be refused, not accepted and then truncated and lost.
#[test]
fn datagram_capsule_at_flow_control_boundary_is_refused_not_lost() {
    const WINDOW: u64 = 150;

    let (mut client, mut proxy, session_id, _proxy_session) =
        establish_capsule_session(Some(WINDOW));

    // A guard that counts only the payload keeps accepting after the framing stops
    // fitting, and the overflowing capsule is truncated and lost.
    let mut sent = 0;
    while client.connect_udp_send_datagram(session_id, &[0x2c; 1], None, now())
        == Ok(DatagramQueueOutcome::Ok)
    {
        sent += 1;
    }
    assert!(sent > 0, "no send space to fill");

    assert!(
        !client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable { .. })),
        "resume event fired while the window was still closed"
    );

    // Count before sending anything else: a later send would flush a stranded tail
    // out of the send buffer and hide the loss.
    exchange_packets(&mut client, &mut proxy, false, None);
    let received = proxy
        .events()
        .filter(|e| {
            matches!(
                e,
                Http3ServerEvent::ConnectUdp(ServerEvent::Datagram { .. })
            )
        })
        .count();
    assert_eq!(
        received, sent,
        "a datagram was accepted and then lost: the guard under-counts the framing"
    );

    assert!(
        client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable { session_id: id } if id == session_id)),
        "resume event not emitted after the window reopened"
    );
}

/// connect-udp datagrams carry a context ID after the quarter stream ID, and
/// both count against the peer's datagram limit.
#[test]
fn datagram_over_the_peers_limit_including_context_id_is_rejected() {
    fixture_init();
    let (mut client, _proxy, proxy_session) = establish_new_session();
    let session_id = proxy_session.stream_id();
    let prefix = neqo_common::Encoder::varint_len(session_id.as_u64() / 4)
        + neqo_common::Encoder::varint_len(0);
    // The proxy's advertised `datagram_size`; see
    // `initiate_new_session_with_client_params`.
    let limit = 1500 - DATAGRAM_FRAME_TYPE_VARINT_LEN;

    assert!(
        client
            .connect_udp_send_datagram(session_id, &vec![0; limit - prefix], None, now())
            .is_ok()
    );
    assert_eq!(
        client.connect_udp_send_datagram(session_id, &vec![0; limit - prefix + 1], None, now()),
        Err(Error::Transport(neqo_transport::Error::TooMuchData))
    );
}

/// The datagram queue setters are `WebTransport` attributes; a connect-udp
/// session must be rejected rather than silently given a mark.
#[test]
fn connect_udp_session_rejected_by_webtransport_datagram_setters() {
    fixture_init();
    let (mut client, _proxy, proxy_session) = establish_new_session();
    let session_id = proxy_session.stream_id();
    assert_eq!(
        client.webtransport_set_max_buffered_datagrams(session_id, std::num::NonZeroUsize::new(1)),
        Err(Error::InvalidStreamId)
    );
    assert_eq!(
        client.webtransport_set_datagram_max_age(session_id, Some(Duration::from_millis(1)), now()),
        Err(Error::InvalidStreamId)
    );
    assert_eq!(
        client.webtransport_datagram_queue_capacity(session_id),
        Err(Error::InvalidStreamId)
    );
}

/// Return a client and proxy with `n` established connect-udp sessions on a single connection.
///
/// `datagram_size == None` uses the HTTP DATAGRAM Capsule path.
fn establish_sessions(
    datagram_size: Option<u64>,
    n: usize,
) -> (Http3Client, Http3Server, Vec<neqo_http3::StreamId>) {
    fixture_init();
    let params = || {
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(
                ConnectionParameters::default().datagram_size(datagram_size.unwrap_or(0)),
            )
    };
    let mut client = http3_client_with_params(params());
    let mut proxy = http3_server_with_params(params());
    let out = test_fixture::connect_peers(&mut client, &mut proxy);
    exchange_packets(&mut client, &mut proxy, false, out);

    let ids: Vec<_> = std::iter::repeat_with(|| {
        client
            .connect_udp_create_session(now(), &target_uri(), &[])
            .unwrap()
    })
    .take(n)
    .collect();
    exchange_packets(&mut client, &mut proxy, false, None);
    let mut accepted = 0;
    while let Some(e) = proxy.next_event() {
        if let Http3ServerEvent::ConnectUdp(ServerEvent::NewSession { session, .. }) = e {
            session
                .response(&SessionAcceptAction::Accept, now())
                .unwrap();
            accepted += 1;
        }
    }
    assert_eq!(accepted, n);
    exchange_packets(&mut client, &mut proxy, false, None);
    let established = client
        .events()
        .filter(|e| {
            matches!(
                e,
                Http3ClientEvent::ConnectUdp(ConnectUdpEvent::NewSession { status: 200, .. })
            )
        })
        .count();
    assert_eq!(established, n);
    (client, proxy, ids)
}

/// Drive client -> proxy one packet at a time until the proxy has surfaced
/// `expected` UDP datagrams.
///
/// Returns the session of each UDP datagram the proxy surfaced, in arrival order.
fn drain_to_proxy(
    client: &mut Http3Client,
    proxy: &mut Http3Server,
    expected: usize,
) -> Vec<neqo_http3::StreamId> {
    assert!(expected < 10_000); // make sure we won't loop forever

    let mut now = now();
    let mut received = Vec::new();
    while received.len() < expected {
        match client.process_output(now) {
            Output::Datagram(d) => {
                let reply = proxy.process(Some(d), now).dgram();
                while let Some(e) = proxy.next_event() {
                    if let Http3ServerEvent::ConnectUdp(ServerEvent::Datagram { session, .. }) = e {
                        received.push(session.stream_id());
                    }
                }
                if let Some(r) = reply {
                    // Send the proxy's ACKs back to the client
                    client.process_input(r, now);
                }
            }
            Output::Callback(t) => {
                now += t;
                if let Some(r) = proxy.process_output(now).dgram() {
                    client.process_input(r, now);
                }
            }
            Output::None => break,
        }
    }

    assert_eq!(
        received.len(),
        expected,
        "proxy received {} of {expected} datagrams",
        received.len()
    );
    received
}

/// Convert the sequence of UDP datagrams into a string for friendlier assertions.
///
/// Each session id gets a letter that identifies it (`A` or `B`).
fn arrival_order(
    received: &[neqo_http3::StreamId],
    session_ids: &[neqo_http3::StreamId],
) -> String {
    received
        .iter()
        .map(|s| match session_ids.iter().position(|id| id == s) {
            Some(0) => 'A',
            Some(1) => 'B',
            _ => '?',
        })
        .collect()
}

fn send_ok(client: &mut Http3Client, id: neqo_http3::StreamId, len: usize) {
    assert_eq!(
        client.connect_udp_send_datagram(id, &vec![0; len], None, now()),
        Ok(DatagramQueueOutcome::Ok)
    );
}

/// Session A queues its whole backlog before session B queues anything.
fn queue_bulk(client: &mut Http3Client, ids: &[neqo_http3::StreamId], per_session: usize) {
    for &id in ids {
        for _ in 0..per_session {
            send_ok(client, id, 1000);
        }
    }
}

/// Sessions take turns queuing one datagram each.
fn queue_interleaved(client: &mut Http3Client, ids: &[neqo_http3::StreamId], per_session: usize) {
    for _ in 0..per_session {
        for &id in ids {
            send_ok(client, id, 1000);
        }
    }
}

/// QUIC DATAGRAMs round-robin between sessions.
#[test]
fn fairness_quic_datagram() {
    // Bulk
    let (mut client, mut proxy, ids) = establish_sessions(Some(1500), 2);
    queue_bulk(&mut client, &ids, 8);
    let received = drain_to_proxy(&mut client, &mut proxy, 16);
    assert_eq!(arrival_order(&received[..8], &ids), "ABABABAB");

    // Interleaved
    let (mut client, mut proxy, ids) = establish_sessions(Some(1500), 2);
    queue_interleaved(&mut client, &ids, 8);
    let received = drain_to_proxy(&mut client, &mut proxy, 16);
    assert_eq!(arrival_order(&received[..8], &ids), "ABABABAB");
}

/// QUIC DATAGRAMs round-robin based on datagrams, not bytes: a session sending
/// large datagrams gets a proportionally larger share of the bandwidth.
#[test]
fn fairness_quic_datagram_counts_datagrams_not_bytes() {
    let (mut client, mut proxy, ids) = establish_sessions(Some(1500), 2);
    for _ in 0..8 {
        send_ok(&mut client, ids[0], 1100);
        send_ok(&mut client, ids[1], 100);
    }
    let received = drain_to_proxy(&mut client, &mut proxy, 16);
    assert_eq!(arrival_order(&received, &ids), "ABABABABABABABAB");
}

/// HTTP DATAGRAM Capsules have their sessions take turns filling packets.
#[test]
fn fairness_capsule() {
    // Bulk, all datagrams of equal size
    let (mut client, mut proxy, ids) = establish_sessions(None, 2);
    queue_bulk(&mut client, &ids, 8);
    let received = drain_to_proxy(&mut client, &mut proxy, 16);
    assert_eq!(arrival_order(&received[..8], &ids), "ABABABAB");

    // Interleaved, all datagrams of equal size
    let (mut client, mut proxy, ids) = establish_sessions(None, 2);
    queue_interleaved(&mut client, &ids, 8);
    let received = drain_to_proxy(&mut client, &mut proxy, 16);
    assert_eq!(arrival_order(&received[..8], &ids), "ABABABAB");

    // Interleaved, different datagram sizes
    let (mut client, mut proxy, ids) = establish_sessions(None, 2);
    for _ in 0..8 {
        send_ok(&mut client, ids[0], 1100);
        send_ok(&mut client, ids[1], 550);
    }
    let received = drain_to_proxy(&mut client, &mut proxy, 16);
    assert_eq!(arrival_order(&received, &ids), "ABBABBABBABBAAAA");
}
