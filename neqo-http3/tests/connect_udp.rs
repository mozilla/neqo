// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(test)]

use neqo_common::{event::Provider as _, header::HeadersExt as _, qinfo, Datagram, Tos};
use neqo_crypto::AuthenticationStatus;
use neqo_http3::{
    ConnectUdpEvent, ConnectUdpRequest, ConnectUdpServerEvent, ConnectUdpSessionAcceptAction,
    Http3Client, Http3ClientEvent, Http3Parameters, Http3Server, Http3ServerEvent, Http3State,
};
use neqo_transport::ConnectionParameters;
use test_fixture::{
    default_http3_client, default_http3_server, exchange_packets, fixture_init,
    http3_client_with_params, http3_server_with_params, now, DEFAULT_ADDR,
};
use url::Url;

fn new_session() -> (
    Http3Client,
    Http3Server,
    neqo_http3::StreamId,
    ConnectUdpRequest,
) {
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

                session
                    .response(&ConnectUdpSessionAcceptAction::Accept)
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

#[test]
fn session_lifecycle() {
    fixture_init();
    neqo_common::log::init(None);

    const PING: &[u8] = b"ping";
    const PONG: &[u8] = b"pong";

    let (mut client, mut proxy, session_id, proxy_session) = new_session();

    client
        .connect_udp_send_datagram(session_id, PING, None)
        .unwrap();

    exchange_packets(&mut client, &mut proxy, false, None);

    let (id, datagram) = proxy.events()
        .find_map(|event| {
            if let Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::Datagram { session, datagram}) = event {
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
            if let  Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Datagram {session_id:id, datagram }) = event {
                Some((id, datagram) )
            } else {
                None
            }
        })
        .unwrap();

    assert_eq!(session_id, id);
    assert_eq!(datagram, PONG);

    client
        .connect_udp_close_session(session_id, 0, "kthxbye")
        .unwrap();

    exchange_packets(&mut client, &mut proxy, false, None);

    client
        .events()
        .find(|event| {
            matches!(
                event,
                Http3ClientEvent::ConnectUdp(ConnectUdpEvent::SessionClosed { stream_id, .. }) if *stream_id == session_id
            )
        })
        .unwrap();

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
}

#[test]
fn connect_via_proxy() {
    fixture_init();
    neqo_common::log::init(None);

    let mut client_inner = default_http3_client();
    let mut server = default_http3_server();

    let (mut client_outer, mut proxy, connect_udp_session_id, mut proxy_session) = new_session();

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
            &mut proxy_session,
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
            &mut proxy_session,
        );
    }
}
