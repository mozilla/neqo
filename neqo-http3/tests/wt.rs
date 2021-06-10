// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::event::Provider;
use neqo_crypto::AuthenticationStatus;
use neqo_http3::server_events::Http3ServerEvent;
use neqo_http3::server_events::{WtRequestStream, WtStream};
use neqo_http3::{Http3Client, Http3ClientEvent, Http3Parameters, Http3Server, Http3State};
use neqo_qpack::QpackSettings;
use neqo_transport::{ConnectionParameters, StreamType};
use std::cell::RefCell;
use std::mem;
use std::rc::Rc;
use std::time::Duration;
use test_fixture::*;

const DEFAULT_SETTINGS: QpackSettings = QpackSettings {
    max_table_size_encoder: 65536,
    max_table_size_decoder: 65536,
    max_blocked_streams: 100,
};

pub fn default_http3_client(enable_wt: bool) -> Http3Client {
    fixture_init();
    Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        addr(),
        addr(),
        ConnectionParameters::default(),
        &Http3Parameters {
            qpack_settings: DEFAULT_SETTINGS,
            enable_wt,
            max_concurrent_push_streams: 5,
        },
        now(),
    )
    .expect("create a default client")
}

pub fn default_http3_server(enabled_wt: bool) -> Http3Server {
    Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN_H3,
        anti_replay(),
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_SETTINGS,
        enabled_wt,
        None,
    )
    .expect("create a server")
}

fn exchange_packets(client: &mut Http3Client, server: &mut Http3Server) {
    let mut out = None;
    loop {
        out = client.process(out, now()).dgram();
        out = server.process(out, now()).dgram();
        if out.is_none() {
            break;
        }
    }
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
    // Exchange H3 setttings
    let out = server.process(out.dgram(), now());
    let out = client.process(out.dgram(), now());
    let out = server.process(out.dgram(), now());
    let out = client.process(out.dgram(), now());
    let _ = server.process(out.dgram(), now());
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
    assert!(client.web_transport_enabled());
    check_wt_event(&mut client, true, true);

    let (mut client, _server) = connect(true, false);
    assert!(!client.web_transport_enabled());
    check_wt_event(&mut client, true, false);

    let (mut client, _server) = connect(false, true);
    assert!(!client.web_transport_enabled());
    check_wt_event(&mut client, false, true);

    let (mut client, _server) = connect(false, false);
    assert!(!client.web_transport_enabled());
    check_wt_event(&mut client, false, false);
}

fn zero_rtt(client_org: bool, server_org: bool, client_resumed: bool, server_resumed: bool) {
    let (mut client, mut server) = connect(client_org, server_org);
    assert_eq!(client.web_transport_enabled(), client_org && server_org);

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

    exchange_packets(&mut client, &mut server);

    assert_eq!(&client.state(), &Http3State::Connected);
    assert_eq!(
        client.web_transport_enabled(),
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

struct WtTest {
    client: Http3Client,
    server: Http3Server,
}

impl WtTest {
    pub fn new() -> Self {
        let (client, server) = connect(true, true);
        Self { client, server }
    }

    fn create_wt_session(&mut self) -> (u64, WtRequestStream) {
        let wt_session_id = self
            .client
            .create_web_transport(now(), "something.com", "/", "something.com")
            .unwrap();
        self.exchange_packets();

        let mut wt_server_session = None;
        while let Some(event) = self.server.next_event() {
            match event {
                Http3ServerEvent::WebTransportNewSession {
                    mut request,
                    headers,
                } => {
                    assert!(
                        headers
                            .iter()
                            .any(|h| h.name() == ":method" && h.value() == "CONNECT")
                            && headers
                                .iter()
                                .any(|h| h.name() == ":protocol" && h.value() == "webtransport")
                    );
                    request.response(true).unwrap();
                    wt_server_session = Some(request);
                }
                Http3ServerEvent::Data { .. } => {
                    panic!("There should not be ane data events!");
                }
                _ => {}
            }
        }

        self.exchange_packets();

        let wt_session_negotiated_event = |e| matches!(e, Http3ClientEvent::WebTransportSessionNegotiated { stream_id, success } if stream_id == wt_session_id && success);
        assert!(self.client.events().any(wt_session_negotiated_event));

        (wt_session_id, wt_server_session.unwrap())
    }

    fn exchange_packets(&mut self) {
        let mut out = None;
        loop {
            out = self.client.process(out, now()).dgram();
            out = self.server.process(out, now()).dgram();
            if out.is_none() {
                break;
            }
        }
    }

    fn create_wt_stream_client(&mut self, wt_session_id: u64, stream_type: StreamType) -> u64 {
        let wt_stream_id = self
            .client
            .web_transport_create_new_stream(wt_session_id, stream_type)
            .unwrap();
        // TODO investigate why this is needed.
        self.exchange_packets();
        wt_stream_id
    }

    fn send_data_client(&mut self, wt_stream_id: u64, data: &[u8]) {
        assert_eq!(
            self.client
                .web_transport_send_data(wt_stream_id, data)
                .unwrap(),
            data.len()
        );
        self.exchange_packets();
    }

    fn receive_data_client(
        &mut self,
        expected_stream_id: u64,
        new_stream: bool,
        expected_data: &[u8],
    ) {
        let mut new_stream_received = false;
        let mut data_received = false;
        while let Some(event) = self.client.next_event() {
            match event {
                Http3ClientEvent::WebTransportNewStream { stream_id } => {
                    assert_eq!(stream_id, expected_stream_id);
                    new_stream_received = true;
                }
                Http3ClientEvent::WebTransportDataReadable { stream_id } => {
                    assert_eq!(stream_id, expected_stream_id);
                    // TODO fix multiple stream-readable events
                    if !data_received {
                        let mut buf = [0; 100];
                        let (amount, fin) = self
                            .client
                            .web_transport_read_data(now(), stream_id, &mut buf)
                            .unwrap();
                        assert_eq!(fin, false);
                        assert_eq!(amount, expected_data.len());
                        assert_eq!(&buf[..expected_data.len()], expected_data);
                        data_received = true;
                    }
                }
                _ => {}
            }
        }
        assert!(data_received);
        assert_eq!(new_stream, new_stream_received);
    }

    fn create_wt_stream_server(
        &mut self,
        wt_server_session: &mut WtRequestStream,
        stream_type: StreamType,
    ) -> WtStream {
        wt_server_session.create_stream(stream_type).unwrap()
    }

    fn send_data_server(&mut self, wt_stream: &mut WtStream, data: &[u8]) {
        assert_eq!(wt_stream.send_data(data).unwrap(), data.len());
        self.exchange_packets();
        self.exchange_packets();
    }

    fn receive_data_server(
        &mut self,
        stream_id: u64,
        new_stream: bool,
        expected_data: &[u8],
    ) -> WtStream {
        self.exchange_packets();
        let mut new_stream_received = false;
        let mut data_received = false;
        let mut wt_stream = None;
        while let Some(event) = self.server.next_event() {
            match event {
                Http3ServerEvent::WebTransportNewStream { request } => {
                    assert_eq!(stream_id, request.stream_id());
                    new_stream_received = true;
                }
                Http3ServerEvent::WebTransportStreamData { data, fin, request } => {
                    assert_eq!(data, expected_data);
                    assert_eq!(fin, false);
                    data_received = true;
                    wt_stream = Some(request);
                }
                _ => {}
            }
        }
        assert!(data_received);
        assert_eq!(new_stream, new_stream_received);
        wt_stream.unwrap()
    }
}

#[test]
fn wt_session() {
    let mut wt = WtTest::new();
    mem::drop(wt.create_wt_session());
}

#[test]
fn wt_client_stream_uni() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let (wt_session, _) = wt.create_wt_session();
    let wt_stream = wt.create_wt_stream_client(wt_session, StreamType::UniDi);
    wt.send_data_client(wt_stream, BUF_CLIENT);
    wt.receive_data_server(wt_stream, true, BUF_CLIENT);
}

#[test]
fn wt_client_stream_bidi() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let (wt_session, _) = wt.create_wt_session();
    let wt_client_stream = wt.create_wt_stream_client(wt_session, StreamType::BiDi);
    wt.send_data_client(wt_client_stream, BUF_CLIENT);
    let mut wt_server_stream = wt.receive_data_server(wt_client_stream, true, BUF_CLIENT);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_client_stream, false, BUF_SERVER);
}

#[test]
fn wt_server_stream_uni() {
    const BUF_SERVER: &[u8] = &[2; 30];

    let mut wt = WtTest::new();
    let (_, mut wt_session) = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::UniDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER);
}

#[test]
fn wt_server_stream_bidi() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let (_, mut wt_session) = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::BiDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER);
    wt.send_data_client(wt_server_stream.stream_id(), BUF_CLIENT);
    mem::drop(wt.receive_data_server(wt_server_stream.stream_id(), false, BUF_CLIENT));
}
