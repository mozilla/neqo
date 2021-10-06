// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::event::Provider;

use neqo_crypto::AuthenticationStatus;
use neqo_http3::{Http3Client, Http3ClientEvent, Http3Parameters, Http3Server, Http3State};
use neqo_transport::ConnectionParameters;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use test_fixture::*;

pub fn default_http3_client(webtransport: bool) -> Http3Client {
    fixture_init();
    Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        addr(),
        addr(),
        ConnectionParameters::default(),
        Http3Parameters::default().webtransport(webtransport),
        now(),
    )
    .expect("create a default client")
}

pub fn default_http3_server(webtransport: bool) -> Http3Server {
    Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN_H3,
        anti_replay(),
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        Http3Parameters::default().webtransport(webtransport),
        None,
    )
    .expect("create a server")
}

// Perform only Quic transport handshake.
fn connect_with(client: &mut Http3Client, server: &mut Http3Server) {
    assert_eq!(client.state(), Http3State::Initializing);
    let out = client.process(None, now());
    assert_eq!(client.state(), Http3State::Initializing);

    let out = server.process(out.dgram(), now());
    let out = client.process(out.dgram(), now());
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());

    let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
    assert!(client.events().any(authentication_needed));
    client.authenticated(AuthenticationStatus::Ok, now());

    let out = client.process(out.dgram(), now());
    let connected = |e| matches!(e, Http3ClientEvent::StateChange(Http3State::Connected));
    assert!(client.events().any(connected));

    assert_eq!(client.state(), Http3State::Connected);
    let out = server.process(out.dgram(), now());

    // Exchange H3 setttings
    let out = client.process(out.dgram(), now());
    let out = server.process(out.dgram(), now());
    let _ = client.process(out.dgram(), now());
}

fn check_wt_event(client: &mut Http3Client, wt_enable_client: bool, wt_enable_server: bool) {
    let wt_event = client.events().find_map(|e| {
        if let Http3ClientEvent::WebTransportNegotiated(neg) = e {
            Some(neg)
        } else {
            None
        }
    });

    assert_eq!(wt_event.is_some(), wt_enable_client);
    if let Some(wt) = wt_event {
        assert_eq!(wt, wt_enable_client && wt_enable_server);
    }
}

fn connect(wt_enable_client: bool, wt_enable_server: bool) -> (Http3Client, Http3Server) {
    let mut client = default_http3_client(wt_enable_client);
    let mut server = default_http3_server(wt_enable_server);
    connect_with(&mut client, &mut server);
    (client, server)
}

#[test]
fn negotiate_wt() {
    let (mut client, _server) = connect(true, true);
    assert!(client.webtransport_enabled());
    check_wt_event(&mut client, true, true);

    let (mut client, _server) = connect(true, false);
    assert!(!client.webtransport_enabled());
    check_wt_event(&mut client, true, false);

    let (mut client, _server) = connect(false, true);
    assert!(!client.webtransport_enabled());
    check_wt_event(&mut client, false, true);

    let (mut client, _server) = connect(false, false);
    assert!(!client.webtransport_enabled());
    check_wt_event(&mut client, false, false);
}

fn zero_rtt(client_org: bool, server_org: bool, client_resumed: bool, server_resumed: bool) {
    let (mut client, mut server) = connect(client_org, server_org);
    assert_eq!(client.webtransport_enabled(), client_org && server_org);

    // exchane token
    let out = server.process(None, now());
    // We do not have a token so we need to wait for a resumption token timer to trigger.
    let _ = client.process(out.dgram(), now() + Duration::from_millis(250));
    assert_eq!(client.state(), Http3State::Connected);
    let token = client
        .events()
        .find_map(|e| {
            if let Http3ClientEvent::ResumptionToken(token) = e {
                Some(token)
            } else {
                None
            }
        })
        .unwrap();

    let mut client = default_http3_client(client_resumed);
    let mut server = default_http3_server(server_resumed);
    client
        .enable_resumption(now(), &token)
        .expect("Set resumption token.");
    assert_eq!(client.state(), Http3State::ZeroRtt);
    let out = client.process(None, now());

    assert_eq!(client.state(), Http3State::ZeroRtt);
    let out = server.process(out.dgram(), now());
    let out = client.process(out.dgram(), now());
    let out = server.process(out.dgram(), now());
    let out = client.process(out.dgram(), now());
    let out = server.process(out.dgram(), now());
    let out = client.process(out.dgram(), now());
    let _ = server.process(out.dgram(), now());

    assert_eq!(&client.state(), &Http3State::Connected);
    assert_eq!(
        client.webtransport_enabled(),
        client_resumed && server_resumed
    );
    check_wt_event(&mut client, client_resumed, server_resumed);
}

#[test]
fn zero_rtt_wt_settings() {
    zero_rtt(true, true, true, true);
    zero_rtt(true, true, true, false);
    zero_rtt(true, true, false, true);
    zero_rtt(true, true, false, false);

    zero_rtt(true, false, true, false);
    zero_rtt(true, false, true, true);
    zero_rtt(true, false, false, false);
    zero_rtt(true, false, false, true);

    zero_rtt(false, false, false, false);
    zero_rtt(false, false, false, true);
    zero_rtt(false, false, true, false);
    zero_rtt(false, false, true, true);

    zero_rtt(false, true, false, true);
    zero_rtt(false, true, false, false);
    zero_rtt(false, true, true, false);
    zero_rtt(false, true, true, true);
}
