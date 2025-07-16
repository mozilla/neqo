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
    ConnectUdpServerEvent, ConnectUdpSessionAcceptAction, Http3Client, Http3ClientEvent,
    Http3Parameters, Http3Server, Http3ServerEvent, Http3State,
};
use test_fixture::{
    anti_replay, fixture_init, now, CountingConnectionIdGenerator, DEFAULT_ADDR, DEFAULT_ALPN_H3,
    DEFAULT_KEYS, DEFAULT_SERVER_NAME,
};
#[test]
fn connect() {
    fixture_init();
    let mut client_outer = Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR,
        DEFAULT_ADDR,
        Http3Parameters::default().webtransport(true),
        now(),
    )
    .expect("create a default client");

    let mut client_inner = Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR,
        DEFAULT_ADDR,
        Http3Parameters::default().webtransport(true),
        now(),
    )
    .expect("create a default client");

    let mut proxy = Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN_H3,
        anti_replay(),
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        Http3Parameters::default().connect(true),
        None,
    )
    .expect("create a proxy");

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

    // Connect client_outer and proxy.
    //
    // TODO: deduplicate this? we don't have a helper for it?

    let out = client_outer.process_output(now());
    let out2 = client_outer.process_output(now());
    assert_eq!(client_outer.state(), Http3State::Initializing);

    _ = proxy.process(out.dgram(), now());
    let out = proxy.process(out2.dgram(), now());
    let out = client_outer.process(out.dgram(), now());
    let out = proxy.process(out.dgram(), now());
    let out = client_outer.process(out.dgram(), now());
    let out = proxy.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());

    let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
    assert!(client_outer.events().any(authentication_needed));
    client_outer.authenticated(AuthenticationStatus::Ok, now());

    let mut out = client_outer.process(out.dgram(), now()).dgram();
    let connected = |e| matches!(e, Http3ClientEvent::StateChange(Http3State::Connected));
    assert!(client_outer.events().any(connected));

    assert_eq!(client_outer.state(), Http3State::Connected);

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
        .connect_udp_create_session(now(), "https://[2001:db8::1:1:1:1]:443/", &[])
        .unwrap();
    let out = client_outer.process_output(now()).dgram().unwrap();
    let out = proxy.process(Some(out), now()).dgram().unwrap();

    let mut new_session = false;
    let mut events  = proxy.events();
    while let Some(event) = events.next(){
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
                new_session = true;
            }
            Http3ServerEvent::StateChange { .. } => {}
            e => panic!("Unexpected event: {:?}", e),
        }
    }
    assert!(proxy.events().next().is_none());
    assert!(new_session);
}
