// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(test)]

use neqo_common::{event::Provider as _, header::HeadersExt as _, qinfo, Datagram, Tos};
use neqo_crypto::AuthenticationStatus;
use neqo_http3::{
    ConnectUdpEvent, ConnectUdpRequest, ConnectUdpServerEvent, Error, Http3Client,
    Http3ClientEvent, Http3Parameters, Http3Server, Http3ServerEvent, Http3State, Priority,
    SessionAcceptAction,
};
use neqo_transport::ConnectionParameters;
use test_fixture::{
    default_http3_client, default_http3_server, exchange_packets, fixture_init,
    http3_client_with_params, http3_server_with_params, now, DEFAULT_ADDR,
};
use url::Url;

const PING: &[u8] = b"ping";
const PONG: &[u8] = b"pong";

fn initiate_new_session() -> (Http3Client, Http3Server, neqo_http3::StreamId) {
    let conn_params = ConnectionParameters::default()
        .pmtud(true)
        .datagram_size(1500);

    let mut client = http3_client_with_params(
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(conn_params.clone()),
    );

    let mut proxy = http3_server_with_params(
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(conn_params),
    );

    // Connect client and proxy.
    let out = test_fixture::connect_peers(&mut client, &mut proxy);
    let out = proxy.process(out, now()).dgram().unwrap();
    client.process_input(out, now());

    // Establish connect-udp session.
    let connect_udp_session_id = client
        .connect_udp_create_session(
            now(),
            &Url::parse(&format!(
                "https://[{}]:{}/",
                DEFAULT_ADDR.ip(),
                DEFAULT_ADDR.port()
            ))
            .unwrap(),
            &[],
        )
        .unwrap();
    (client, proxy, connect_udp_session_id)
}

fn establish_new_session() -> (
    Http3Client,
    Http3Server,
    neqo_http3::StreamId,
    ConnectUdpRequest,
) {
    let (mut client, mut proxy, connect_udp_session_id) = initiate_new_session();
    exchange_packets(&mut client, &mut proxy, false, None);
    let proxy_session = proxy
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::NewSession {
                session,
                headers,
            }) = event
            {
                assert_eq!(session.stream_id(), connect_udp_session_id);

                assert!(
                    headers.contains_header(":method", "CONNECT")
                        && headers.contains_header(":protocol", "connect-udp")
                );

                session.response(&SessionAcceptAction::Accept).unwrap();
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
    (client, proxy, connect_udp_session_id, proxy_session)
}

fn exchange_packets_through_proxy(
    client_outer: &mut Http3Client,
    client_inner: &mut Http3Client,
    proxy: &mut Http3Server,
    server: &mut Http3Server,
    connect_udp_session_id: neqo_http3::StreamId,
    proxy_session: &ConnectUdpRequest,
) {
    qinfo!("Processing client_inner");
    while let Some(dgram) = client_inner.process_output(now()).dgram() {
        client_outer
            .connect_udp_send_datagram(connect_udp_session_id, dgram.as_ref(), None)
            .unwrap();
    }

    qinfo!("Processing client_outer");
    let mut client_outer_dgrams = client_outer
        .process_multiple_output(now(), 64.try_into().unwrap())
        .dgram()
        .unwrap();

    qinfo!("Processing proxy");
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
        Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::Datagram { datagram, session }) => {
            assert_eq!(session.stream_id(), connect_udp_session_id);
            Some(Datagram::new(
                DEFAULT_ADDR,
                DEFAULT_ADDR,
                Tos::default(),
                datagram,
            ))
        }
        _ => None,
    });

    qinfo!("Processing server");
    let mut server_out = vec![];
    for dgram in server_dgrams {
        if let Some(dgram) = server.process(Some(dgram), now()).dgram() {
            server_out.push(dgram);
        }
    }
    while let Some(dgram) = server.process(Option::<Datagram>::None, now()).dgram() {
        server_out.push(dgram);
    }

    qinfo!("Processing proxy");
    for dgram in server_out {
        proxy_session.send_datagram(dgram.as_ref(), None).unwrap();
    }
    let mut proxy_out = vec![];
    while let Some(dgram) = proxy.process(Vec::<Datagram>::new(), now()).dgram() {
        proxy_out.push(dgram);
    }

    qinfo!("Processing client_outer");
    client_outer.process_multiple_input(proxy_out, now());

    qinfo!("Processing client_inner");
    let client_inner_dgrams = client_outer.events().filter_map(|event| {
        if let Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Datagram {
            session_id,
            datagram,
        }) = event
        {
            assert_eq!(session_id, connect_udp_session_id);
            Some(Datagram::new(
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

    let (mut client, mut proxy, session_id, proxy_session) = establish_new_session();

    client
        .connect_udp_send_datagram(session_id, PING, None)
        .unwrap();

    exchange_packets(&mut client, &mut proxy, false, None);

    let (id, datagram) = proxy
        .events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::Datagram {
                session,
                datagram,
            }) = event
            {
                Some((session.stream_id(), datagram))
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(session_id, id);
    assert_eq!(datagram, PING);

    proxy_session.send_datagram(PONG, None).unwrap();

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
    assert_eq!(datagram, PONG);

    if client_closes {
        client
            .connect_udp_close_session(session_id, 0, "kthxbye")
            .unwrap();

        exchange_packets(&mut client, &mut proxy, false, None);

        proxy
            .events()
            .find(|event| {
                matches!(
                    event,
                    Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::SessionClosed {
                        session,
                        ..
                    }) if session.stream_id() == session_id
                )
            })
            .unwrap();
    } else {
        proxy_session.close_session(0, "kthxbye").unwrap();

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

    let (mut client_outer, mut proxy, connect_udp_session_id, proxy_session) =
        establish_new_session();

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
            connect_udp_session_id,
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
            connect_udp_session_id,
            &proxy_session,
        );
    }
}

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "assertion failed: false"))]
fn send_dgram_on_non_active_session() {
    let (mut client, _proxy, connect_udp_session_id) = initiate_new_session();

    assert_eq!(
        client.connect_udp_send_datagram(connect_udp_session_id, &[], None),
        Err(Error::Unavailable)
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
                if let Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::NewSession {
                    session,
                    ..
                }) = event
                {
                    Some(session)
                } else {
                    None
                }
            })
            .unwrap();
        proxy_session
            .response(&SessionAcceptAction::Accept)
            .unwrap();
        let proxy_accept = proxy.process_output(now()).dgram().unwrap();
        assert!(proxy.process_output(now()).dgram().is_none());

        proxy_session.send_datagram(b"ping", None).unwrap();
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
        client.connect_udp_create_session(now(), &Url::parse("https://example.com/").unwrap(), &[]),
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
            if let Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::NewSession {
                session, ..
            }) = event
            {
                Some(session)
            } else {
                None
            }
        })
        .unwrap();

    proxy_session.reset_send().unwrap();
    exchange_packets(&mut client, &mut proxy, false, None);

    assert!(matches!(
        client.next_event(),
        Some(Http3ClientEvent::ConnectUdp(
            ConnectUdpEvent::SessionClosed { .. }
        ))
    ));
}

#[test]
fn connect_udp_operation_on_fetch_stream() {
    let (mut client, _proxy, _session_id, _proxy_session) = establish_new_session();
    let fetch_stream = client
        .fetch(
            now(),
            "GET",
            ("https", "something.com", "/"),
            &[],
            Priority::default(),
        )
        .unwrap();

    assert_eq!(
        client.connect_udp_send_datagram(fetch_stream, PING, None),
        Err(Error::InvalidStreamId)
    );

    assert_eq!(
        client.connect_udp_close_session(fetch_stream, 0, "kthxbye"),
        Err(Error::InvalidStreamId)
    );
}
