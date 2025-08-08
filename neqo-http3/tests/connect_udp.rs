// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(test)]

use std::{cell::RefCell, rc::Rc};

use neqo_common::{event::Provider as _, header::HeadersExt as _, Datagram, Tos};
use neqo_crypto::AuthenticationStatus;
use neqo_http3::{
    ConnectUdpEvent, ConnectUdpServerEvent, ConnectUdpSessionAcceptAction, Http3Client,
    Http3ClientEvent, Http3Parameters, Http3Server, Http3ServerEvent,
};
use neqo_transport::ConnectionParameters;
use test_fixture::{
    anti_replay, fixture_init, now, CountingConnectionIdGenerator, DEFAULT_ALPN_H3,
    DEFAULT_KEYS, DEFAULT_SERVER_NAME,
};
use url::Url;
#[test]
fn connect() {
    fixture_init();
    neqo_common::log::init(None);
    let conn_params = ConnectionParameters::default()
        .pmtud(true)
        .datagram_size(1500);
    let client_inner_addr = "[2001:db8::1:1:1:1]:1234".parse().unwrap();
    let client_outer_addr = "[2001:db8::1:1:1:2]:1234".parse().unwrap();
    let proxy_addr = "[2001:db8::1:1:1:3]:443".parse().unwrap();
    let server_addr = "[2001:db8::1:1:1:4]:443".parse().unwrap();

    let mut client_outer = Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        client_outer_addr,
        proxy_addr,
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(conn_params.clone()),
        now(),
    )
    .unwrap();

    let mut client_inner = Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        client_inner_addr,
        server_addr,
        Http3Parameters::default(),
        now(),
    )
    .unwrap();

    let mut proxy = Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN_H3,
        anti_replay(),
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        Http3Parameters::default()
            .connect(true)
            .connection_parameters(conn_params),
        None,
    )
    .unwrap();

    let mut server = Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN_H3,
        anti_replay(),
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        Http3Parameters::default(),
        None,
    )
    .unwrap();

    // Connect client_outer and proxy.
    let mut out = test_fixture::connect_peers(&mut client_outer, &mut proxy);

    // Exchange H3 settings
    loop {
        out = proxy.process(out, now()).dgram();
        let dgram_present = out.is_some();
        out = client_outer.process(out, now()).dgram();
        if out.is_none() && !dgram_present {
            break;
        }
    }

    // Establish connect-udp session.
    let connect_udp_session_id = client_outer
        .connect_udp_create_session(
            now(),
            &Url::parse(&format!(
                "https://[{}]:{}/",
                server_addr.ip(),
                server_addr.port()
            ))
            .unwrap(),
            &[],
        )
        .unwrap();
    let out = client_outer.process_output(now()).dgram().unwrap();
    let out = proxy.process(Some(out), now()).dgram().unwrap();
    client_outer.process_input(out, now());
    let mut proxy_session = None;
    for event in proxy.events() {
        match event {
            Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::NewSession {
                session,
                headers,
            }) => {
                assert_eq!(session.stream_id(), connect_udp_session_id);

                assert!(
                    headers.contains_header(":method", "CONNECT")
                        && headers.contains_header(":protocol", "connect-udp")
                );

                session
                    .response(&ConnectUdpSessionAcceptAction::Accept)
                    .unwrap();
                proxy_session = Some(session);
            }
            Http3ServerEvent::StateChange { .. } => {}
            e => panic!("Unexpected event: {:?}", e),
        }
    }
    assert!(proxy_session.is_some());
    let out = proxy
        .process(Option::<Datagram>::None, now())
        .dgram()
        .unwrap();
    client_outer.process_input(out, now());
    let out = proxy
        .process(Option::<Datagram>::None, now())
        .dgram()
        .unwrap();
    client_outer.process_input(out, now());
    let mut found = false;
    for event in client_outer.events() {
        match event {
            Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Session {
                stream_id,
                status,
                headers: _,
            }) => {
                assert_eq!(stream_id, connect_udp_session_id);
                assert_eq!(status, 200);
                found = true;
            }
            _ => {}
        }
    }
    assert!(found);

    // Establish inner connection on top of connect-udp session.
    let mut i = 0;
    loop {
        i += 1;
        // client_inner
        println!("==== client_inner");

        let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
        if client_inner.events().any(authentication_needed) {
            client_inner.authenticated(AuthenticationStatus::Ok, now());
            break;
        }
        while let Some(dgram) = client_inner.process_output(now()).dgram() {
            client_outer
                .connect_udp_send_datagram(connect_udp_session_id, dgram.as_ref(), None)
                .unwrap();
        }

        if i == 2 {
            panic!();
        }

        // client_outer
        println!("==== client_outer");
        let mut client_outer_dgrams = vec![];
        while let Some(dgram) = client_outer.process_output(now()).dgram() {
            client_outer_dgrams.push(dgram);
        }

        // proxy
        println!("==== proxy");
        let proxy_out = proxy
            .process_multiple(client_outer_dgrams, now(), 64.try_into().unwrap())
            .dgram();
        assert_eq!(proxy.process(Option::<Datagram>::None, now()).dgram(), None);
        if let Some(mut dgram) = proxy_out {
            client_outer.process_multiple_input(dgram.iter_mut(), now());
        }
        let mut events = proxy.events();
        let mut server_dgrams = vec![];
        while let Some(event) = events.next() {
            match event {
                Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::Datagram {
                    datagram,
                    session,
                }) => {
                    assert_eq!(session.stream_id(), connect_udp_session_id);
                    server_dgrams.push(datagram);
                }
                _ => {}
            }
        }

        assert_eq!(server_dgrams.len(), 2);

        // server
        println!("==== server");
        let mut server_dgrams = server_dgrams
            .into_iter()
            .map(|d| Datagram::new(client_inner_addr, server_addr, Tos::default(), d));
        assert_eq!(server_dgrams.len(), 2);
        let mut server_out = vec![];
        while let Some(dgram) = server_dgrams.next() {
            if let Some(dgram) = server.process(Some(dgram), now()).dgram() {
                server_out.push(dgram);
            }
        }
        while let Some(dgram) = server.process(Option::<Datagram>::None, now()).dgram() {
            server_out.push(dgram);
        }
        assert_eq!(
            server.process(Option::<Datagram>::None, now()).dgram(),
            None
        );

        // proxy
        println!("==== proxy");
        for dgram in server_out {
            proxy_session
                .as_ref()
                .unwrap()
                .send_datagram(dgram.as_ref(), None)
                .unwrap();
        }
        let mut proxy_out = vec![];
        while let Some(dgram) = proxy.process(Vec::<Datagram>::new(), now()).dgram() {
            proxy_out.push(dgram);
        }
        assert_eq!(proxy.process(Option::<Datagram>::None, now()).dgram(), None);

        // client_outer
        println!("==== client_outer");
        client_outer.process_multiple_input(proxy_out, now());

        // client_inner
        println!("==== client_inner");
        let mut events = client_outer.events();
        while let Some(event) = events.next() {
            match event {
                Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Datagram {
                    session_id,
                    datagram,
                }) => {
                    assert_eq!(session_id, connect_udp_session_id);
                    client_inner.process_input(
                        Datagram::new(server_addr, client_inner_addr, Tos::default(), datagram),
                        now(),
                    );
                }
                _ => {}
            }
        }
    }
}
