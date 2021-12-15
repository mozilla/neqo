// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::webtransport::WtTest;
use neqo_common::event::Provider;
use neqo_http3::{
    features::extended_connect::SessionCloseReason, Error, Header, Http3ClientEvent,
    Http3ServerEvent, WebTransportEvent, WebTransportServerEvent,
};
use std::mem;
use test_fixture::now;

#[test]
fn wt_session() {
    let mut wt = WtTest::new();
    mem::drop(wt.create_wt_session());
}

#[test]
fn wt_session_reject() {
    let mut wt = WtTest::new();
    let (wt_session_id, _wt_session) = wt.negotiate_wt_session(false);

    wt.check_session_closed_event_client(wt_session_id, SessionCloseReason::Status(404));
}

#[test]
fn wt_session_close_client() {
    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    wt.cancel_session_client(wt_session.stream_id());
    wt.check_session_closed_event_server(
        &mut wt_session,
        SessionCloseReason::Error(Error::HttpNoError.code()),
    );
}

#[test]
fn wt_session_close_server() {
    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    wt.cancel_session_server(&mut wt_session);
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        SessionCloseReason::Error(Error::HttpNoError.code()),
    );
}

#[test]
fn wt_session_close_server_close_send() {
    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    wt_session.stream_close_send().unwrap();
    wt.exchange_packets();
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        SessionCloseReason::Error(Error::HttpGeneralProtocolStream.code()),
    );
}

#[test]
fn wt_session_close_server_stop_sending() {
    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    wt_session
        .stream_stop_sending(Error::HttpNoError.code())
        .unwrap();
    wt.exchange_packets();
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        SessionCloseReason::Error(Error::HttpNoError.code()),
    );
}

#[test]
fn wt_session_close_server_reset() {
    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    wt_session
        .stream_reset_send(Error::HttpNoError.code())
        .unwrap();
    wt.exchange_packets();
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        SessionCloseReason::Error(Error::HttpNoError.code()),
    );
}

#[test]
fn wt_session_respone_with_1xx() {
    let mut wt = WtTest::new();

    let wt_session_id = wt
        .client
        .webtransport_create_session(now(), &("https", "something.com", "/"), &[])
        .unwrap();
    wt.exchange_packets();

    let mut wt_server_session = None;
    while let Some(event) = wt.server.next_event() {
        match event {
            Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
                session,
                headers,
            }) => {
                assert!(
                    headers
                        .iter()
                        .any(|h| h.name() == ":method" && h.value() == "CONNECT")
                        && headers
                            .iter()
                            .any(|h| h.name() == ":protocol" && h.value() == "webtransport")
                );
                wt_server_session = Some(session);
            }
            _ => {}
        }
    }

    let mut wt_server_session = wt_server_session.unwrap();

    // Send interim response.
    wt_server_session
        .send_headers(&[Header::new(":status", "111")])
        .unwrap();
    wt_server_session.response(true).unwrap();

    wt.exchange_packets();

    let wt_session_negotiated_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::Session{
                stream_id,
                status
            }) if stream_id == wt_session_id && status == 200
        )
    };
    assert!(wt.client.events().any(wt_session_negotiated_event));

    assert_eq!(wt_session_id, wt_server_session.stream_id());
}

#[test]
fn wt_session_respone_200_with_fin() {
    let mut wt = WtTest::new();

    let wt_session_id = wt
        .client
        .webtransport_create_session(now(), &("https", "something.com", "/"), &[])
        .unwrap();
    wt.exchange_packets();
    let mut wt_server_session = None;
    while let Some(event) = wt.server.next_event() {
        match event {
            Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
                session,
                headers,
            }) => {
                assert!(
                    headers
                        .iter()
                        .any(|h| h.name() == ":method" && h.value() == "CONNECT")
                        && headers
                            .iter()
                            .any(|h| h.name() == ":protocol" && h.value() == "webtransport")
                );
                wt_server_session = Some(session);
            }
            _ => {}
        }
    }

    let mut wt_server_session = wt_server_session.unwrap();
    wt_server_session.response(true).unwrap();
    wt_server_session.stream_close_send().unwrap();

    wt.exchange_packets();

    let wt_session_close_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::SessionClosed{
                stream_id,
                reason
            }) if stream_id == wt_session_id && reason == SessionCloseReason::Clean
        )
    };
    assert!(wt.client.events().any(wt_session_close_event));

    assert_eq!(wt_session_id, wt_server_session.stream_id());
}
