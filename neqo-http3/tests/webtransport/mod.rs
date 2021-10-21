// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod negotiation;
mod sessions;

use neqo_common::event::Provider;
use neqo_crypto::AuthenticationStatus;
use neqo_http3::{
    Error, Http3Client, Http3ClientEvent, Http3Parameters, Http3Server, Http3ServerEvent,
    Http3State, WebTransportEvent, WebTransportRequest, WebTransportServerEvent,
};
use neqo_transport::{AppError, ConnectionParameters, StreamId};
use std::cell::RefCell;
use std::rc::Rc;
use test_fixture::{
    addr, anti_replay, fixture_init, now, CountingConnectionIdGenerator, DEFAULT_ALPN_H3,
    DEFAULT_KEYS, DEFAULT_SERVER_NAME,
};

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

fn connect(wt_enable_client: bool, wt_enable_server: bool) -> (Http3Client, Http3Server) {
    let mut client = default_http3_client(wt_enable_client);
    let mut server = default_http3_server(wt_enable_server);
    connect_with(&mut client, &mut server);
    (client, server)
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

    fn negotiate_wt_session(&mut self, accept: bool) -> (StreamId, Option<WebTransportRequest>) {
        let wt_session_id = self
            .client
            .webtransport_create_session(now(), &("https", "something.com", "/"), &[])
            .unwrap();
        self.exchange_packets();

        let mut wt_server_session = None;
        while let Some(event) = self.server.next_event() {
            match event {
                Http3ServerEvent::WebTransport(
                    WebTransportServerEvent::WebTransportNewSession {
                        mut session,
                        headers,
                    },
                ) => {
                    assert!(
                        headers
                            .iter()
                            .any(|h| h.name() == ":method" && h.value() == "CONNECT")
                            && headers
                                .iter()
                                .any(|h| h.name() == ":protocol" && h.value() == "webtransport")
                    );
                    session.response(accept).unwrap();
                    wt_server_session = Some(session);
                }
                Http3ServerEvent::Data { .. } => {
                    panic!("There should not be ane data events!");
                }
                _ => {}
            }
        }

        self.exchange_packets();
        (wt_session_id, wt_server_session)
    }

    fn create_wt_session(&mut self) -> WebTransportRequest {
        let (wt_session_id, wt_server_session) = self.negotiate_wt_session(true);
        let wt_session_negotiated_event = |e| {
            matches!(
                e,
                Http3ClientEvent::WebTransport(WebTransportEvent::WebTransportSession(stream_id)) if stream_id == wt_session_id
            )
        };
        assert!(self.client.events().any(wt_session_negotiated_event));

        let wt_server_session = wt_server_session.unwrap();
        assert_eq!(wt_session_id, wt_server_session.stream_id());
        wt_server_session
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

    pub fn cancel_session_client(&mut self, wt_stream_id: StreamId) {
        self.client
            .cancel_fetch(wt_stream_id, Error::HttpNoError.code())
            .unwrap();
        self.exchange_packets();
    }

    fn session_closed_client(
        e: &Http3ClientEvent,
        id: StreamId,
        expected_error: &Option<AppError>,
    ) -> bool {
        if let Http3ClientEvent::WebTransport(WebTransportEvent::WebTransportSessionClosed {
            stream_id,
            error,
        }) = e
        {
            *stream_id == id && error == expected_error
        } else {
            false
        }
    }

    pub fn check_session_closed_event_client(
        &mut self,
        wt_session_id: StreamId,
        expected_error: Option<AppError>,
    ) {
        let mut event_found = false;

        while let Some(event) = self.client.next_event() {
            event_found = WtTest::session_closed_client(&event, wt_session_id, &expected_error);
            if event_found {
                break;
            }
        }
        assert!(event_found);
    }

    pub fn cancel_session_server(&mut self, wt_session: &mut WebTransportRequest) {
        wt_session.cancel_fetch(Error::HttpNoError.code()).unwrap();
        self.exchange_packets();
    }

    fn session_closed_server(
        e: &Http3ServerEvent,
        id: StreamId,
        expected_error: &Option<AppError>,
    ) -> bool {
        if let Http3ServerEvent::WebTransport(
            WebTransportServerEvent::WebTransportSessionClosed { session, error },
        ) = e
        {
            session.stream_id() == id && error == expected_error
        } else {
            false
        }
    }

    pub fn check_session_closed_event_server(
        &mut self,
        wt_session: &mut WebTransportRequest,
        expected_error: Option<AppError>,
    ) {
        let event = self.server.next_event().unwrap();
        assert!(WtTest::session_closed_server(
            &event,
            wt_session.stream_id(),
            &expected_error
        ));
    }
}
