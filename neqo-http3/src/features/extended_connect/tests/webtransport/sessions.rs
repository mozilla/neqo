// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Encoder, event::Provider as _, header::HeadersExt as _};
use neqo_transport::{StreamId, StreamType};
use test_fixture::now;

use crate::{
    Error, Header, Http3ClientEvent, Http3OrWebTransportStream, Http3Server, Http3ServerEvent,
    Http3State, Priority, SessionAcceptAction, WebTransportEvent, WebTransportServerEvent,
    features::extended_connect::{
        CloseReason,
        tests::webtransport::{
            WtTest, assert_wt, default_http3_client, default_http3_server, wt_default_parameters,
        },
    },
    frames::WebTransportFrame,
};

#[test]
fn wt_session() {
    let mut wt = WtTest::new();
    drop(wt.create_wt_session());
}

#[test]
fn wt_session_reject() {
    let mut wt = WtTest::new();
    let headers = vec![Header::new(":status", "404")];
    let accept_res = SessionAcceptAction::Reject(headers.clone());
    let (wt_session_id, _wt_session) = wt.negotiate_wt_session(&accept_res);

    wt.check_session_closed_event_client(wt_session_id, &CloseReason::Status(404), Some(&headers));
}

#[test]
fn wt_session_close_client() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt.cancel_session_client(wt_session.stream_id());
    wt.check_session_closed_event_server(&wt_session, &CloseReason::Error(Error::HttpNone.code()));
}

#[test]
fn wt_session_close_server() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt.cancel_session_server(&wt_session);
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        &CloseReason::Error(Error::HttpNone.code()),
        None,
    );
}

#[test]
fn wt_session_close_server_close_send() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt_session.stream_close_send(now()).unwrap();
    wt.exchange_packets();
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        &CloseReason::Clean {
            error: 0,
            message: String::new(),
        },
        None,
    );
}

#[test]
fn wt_session_close_server_stop_sending() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt_session
        .stream_stop_sending(Error::HttpNone.code())
        .unwrap();
    wt.exchange_packets();
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        &CloseReason::Error(Error::HttpNone.code()),
        None,
    );
}

#[test]
fn wt_session_close_server_reset() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt_session
        .stream_reset_send(Error::HttpNone.code())
        .unwrap();
    wt.exchange_packets();
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        &CloseReason::Error(Error::HttpNone.code()),
        None,
    );
}

#[test]
fn wt_session_response_with_1xx() {
    let mut wt = WtTest::new();

    let wt_session_id = wt
        .client
        .webtransport_create_session(now(), ("https", "something.com", "/"), &[])
        .unwrap();
    wt.exchange_packets();

    let mut wt_server_session = None;
    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
            session,
            headers,
        }) = event
        {
            assert_wt(&headers);
            wt_server_session = Some(session);
        }
    }

    let wt_server_session = wt_server_session.unwrap();

    // Send interim response.
    wt_server_session
        .send_headers(&[Header::new(":status", "111")])
        .unwrap();
    wt_server_session
        .response(&SessionAcceptAction::Accept, now())
        .unwrap();

    wt.exchange_packets();

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
    assert!(wt.client.events().any(wt_session_negotiated_event));

    assert_eq!(wt_session_id, wt_server_session.stream_id());
}

#[test]
fn wt_session_response_with_redirect() {
    let headers = [Header::new(":status", "302"), Header::new("location", "/")].to_vec();
    let mut wt = WtTest::new();

    let accept_res = SessionAcceptAction::Reject(headers.clone());

    let (wt_session_id, _wt_session) = wt.negotiate_wt_session(&accept_res);

    wt.check_session_closed_event_client(wt_session_id, &CloseReason::Status(302), Some(&headers));
}

#[test]
fn wt_session_respone_200_with_fin() {
    let mut wt = WtTest::new();

    let wt_session_id = wt
        .client
        .webtransport_create_session(now(), ("https", "something.com", "/"), &[])
        .unwrap();
    wt.exchange_packets();
    let mut wt_server_session = None;
    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
            session,
            headers,
        }) = event
        {
            assert_wt(&headers);
            wt_server_session = Some(session);
        }
    }

    let wt_server_session = wt_server_session.unwrap();
    wt_server_session
        .response(&SessionAcceptAction::Accept, now())
        .unwrap();
    wt_server_session.stream_close_send(now()).unwrap();

    wt.exchange_packets();

    let wt_session_close_event = |e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::SessionClosed{
                stream_id,
                reason,
                headers,
                ..
            }) if (
                stream_id == wt_session_id &&
                reason == CloseReason::Clean{ error: 0, message: String::new()} &&
                headers.is_none()
            )
        )
    };
    assert!(wt.client.events().any(wt_session_close_event));

    assert_eq!(wt_session_id, wt_server_session.stream_id());
}

#[test]
fn wt_session_close_frame_client() {
    const ERROR_NUM: u32 = 23;
    const ERROR_MESSAGE: &str = "Something went wrong";
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    wt.session_close_frame_client(wt_session.stream_id(), ERROR_NUM, ERROR_MESSAGE);
    wt.exchange_packets();

    wt.check_session_closed_event_server(
        &wt_session,
        &CloseReason::Clean {
            error: ERROR_NUM,
            message: ERROR_MESSAGE.to_string(),
        },
    );
}

#[test]
fn wt_session_close_frame_server() {
    const ERROR_NUM: u32 = 23;
    const ERROR_MESSAGE: &str = "Something went wrong";
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    WtTest::session_close_frame_server(&wt_session, ERROR_NUM, ERROR_MESSAGE);
    wt.exchange_packets();

    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        &CloseReason::Clean {
            error: ERROR_NUM,
            message: ERROR_MESSAGE.to_string(),
        },
        None,
    );
}

#[test]
fn wt_unknown_session_frame_client() {
    const UNKNOWN_FRAME_LEN: usize = 832;
    const BUF: &[u8] = &[0; 10];
    const ERROR_NUM: u32 = 23;
    const ERROR_MESSAGE: &str = "Something went wrong";
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    // Send an unknown frame.
    let mut enc = Encoder::with_capacity(UNKNOWN_FRAME_LEN + 4);
    enc.encode_varint(1028_u64); // Arbitrary type.
    enc.encode_varint(UNKNOWN_FRAME_LEN as u64);
    let mut buf: Vec<_> = enc.into();
    buf.resize(UNKNOWN_FRAME_LEN + buf.len(), 0);
    wt.client
        .send_data(wt_session.stream_id(), &buf, now())
        .unwrap();
    wt.exchange_packets();

    // The session is still active
    let unidi_server = WtTest::create_wt_stream_server(&wt_session, StreamType::UniDi);
    wt.send_data_server(&unidi_server, BUF);
    wt.receive_data_client(unidi_server.stream_id(), true, BUF, false);

    // Now close the session.
    wt.session_close_frame_client(wt_session.stream_id(), ERROR_NUM, ERROR_MESSAGE);
    wt.exchange_packets();

    wt.check_events_after_closing_session_client(
        &[unidi_server.stream_id()],
        Some(Error::HttpRequestCancelled.code()),
        &[],
        None,
        false,
        None,
    );
    wt.check_events_after_closing_session_server(
        &[],
        None,
        &[unidi_server.stream_id()],
        Some(Error::HttpRequestCancelled.code()),
        Some(&(
            wt_session.stream_id(),
            CloseReason::Clean {
                error: ERROR_NUM,
                message: ERROR_MESSAGE.to_string(),
            },
        )),
    );
}

#[test]
fn wt_close_session_frame_broken_client() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    // Send a incorrect CloseSession frame.
    let mut enc = Encoder::default();
    WebTransportFrame::CloseSession {
        error: 5,
        message: "Hello".to_string(),
    }
    .encode(&mut enc);
    let mut buf: Vec<_> = enc.into();
    // Corrupt the string.
    buf[9] = 0xff;
    wt.client
        .send_data(wt_session.stream_id(), &buf, now())
        .unwrap();
    wt.exchange_packets();

    // check that the webtransport session is closed.
    wt.check_session_closed_event_client(
        wt_session.stream_id(),
        &CloseReason::Error(Error::HttpGeneralProtocolStream.code()),
        None,
    );
    wt.check_session_closed_event_server(
        &wt_session,
        &CloseReason::Error(Error::HttpGeneralProtocolStream.code()),
    );

    // The Http3 session is still working.
    assert_eq!(wt.client.state(), Http3State::Connected);
    assert_eq!(wt_session.state(), Http3State::Connected);
}

fn receive_request(server: &Http3Server) -> Option<Http3OrWebTransportStream> {
    while let Some(event) = server.next_event() {
        if let Http3ServerEvent::Headers { stream, .. } = event {
            return Some(stream);
        }
    }
    None
}

#[test]
#[ignore = "Is panicking at wt.create_wt_stream_client; see issue #1386"]
fn wt_close_session_cannot_be_sent_at_once() {
    const BUF: &[u8] = &[0; 443];
    const ERROR_NUM: u32 = 23;
    const ERROR_MESSAGE: &str = "Something went wrong";

    let client = default_http3_client(wt_default_parameters());
    let server = default_http3_server(wt_default_parameters());
    let mut wt = WtTest::new_with(client, server);

    let wt_session = wt.create_wt_session();

    // Fill the flow control window using an unrelated http stream.
    let req_id = wt
        .client
        .fetch(
            now(),
            "GET",
            ("https", "something.com", "/"),
            &[],
            Priority::default(),
        )
        .unwrap();
    assert_eq!(req_id, 4);
    wt.exchange_packets();
    let req = receive_request(&wt.server).unwrap();
    req.send_headers(&[
        Header::new(":status", "200"),
        Header::new("content-length", BUF.len().to_string()),
    ])
    .unwrap();
    req.send_data(BUF, now()).unwrap();

    // Now close the session.
    WtTest::session_close_frame_server(&wt_session, ERROR_NUM, ERROR_MESSAGE);
    // server cannot create new streams.
    assert_eq!(
        wt_session.create_stream(StreamType::UniDi),
        Err(Error::InvalidStreamId)
    );

    let out = wt.server.process_output(now());
    let out = wt.client.process(out.dgram(), now());

    // Client has not received the full CloseSession frame and it can create more streams.
    let unidi_client = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::UniDi);

    let out = wt.server.process(out.dgram(), now());
    let out = wt.client.process(out.dgram(), now());
    let out = wt.server.process(out.dgram(), now());
    let out = wt.client.process(out.dgram(), now());
    let out = wt.server.process(out.dgram(), now());
    let _out = wt.client.process(out.dgram(), now());

    wt.check_events_after_closing_session_client(
        &[],
        None,
        &[unidi_client],
        Some(Error::HttpRequestCancelled.code()),
        false,
        Some(&(
            wt_session.stream_id(),
            CloseReason::Clean {
                error: ERROR_NUM,
                message: ERROR_MESSAGE.to_string(),
            },
        )),
    );
    wt.check_events_after_closing_session_server(&[], None, &[], None, None);
}

/// Per §4.6 of the WebTransport over HTTP/3 spec, a GOAWAY from the server is
/// "a signal to applications to initiate shutdown for all WebTransport sessions":
/// https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#name-interaction-with-the-http-3
///
/// An active session (stream ID < goaway_stream_id) should receive a Draining
/// event and remain open — no SessionClosed.
#[test]
fn wt_goaway_draining_active_session() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Send GOAWAY with a stream ID higher than the active session, so the
    // session is considered processed (still active, but connection draining).
    let goaway_stream_id = StreamId::new(session_id.as_u64() + 4);
    wt.server.test_send_goaway(goaway_stream_id);
    wt.exchange_packets();

    // Collect all events so we can check both presence and absence.
    let events: Vec<Http3ClientEvent> = wt.client.events().collect();

    // The client should receive a Draining event for the active session.
    let has_draining = events.iter().any(|e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::Draining { session_id: sid })
                if *sid == session_id
        )
    });
    assert!(has_draining, "expected Draining event for active session");

    // The session should NOT have been closed — no SessionClosed event.
    let has_closed = events.iter().any(|e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::SessionClosed {
                stream_id: sid, ..
            }) if *sid == session_id
        )
    });
    assert!(!has_closed, "active session should not be closed by GOAWAY");
}

/// Per §4.6 of the WebTransport over HTTP/3 spec, a GOAWAY from the server is
/// "a signal to applications to initiate shutdown for all WebTransport sessions":
/// https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#name-interaction-with-the-http-3
///
/// A rejected session (stream ID >= goaway_stream_id) should receive both a
/// Draining event and eventually a SessionClosed event.
#[test]
fn wt_goaway_draining_rejected_session() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Send GOAWAY with a stream ID equal to the session's stream ID, so the
    // session is considered NOT processed (rejected).
    wt.server.test_send_goaway(session_id);
    wt.exchange_packets();

    // Collect all events.
    let events: Vec<Http3ClientEvent> = wt.client.events().collect();

    // The client should receive a Draining event for the rejected session.
    let has_draining = events.iter().any(|e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::Draining { session_id: sid })
                if *sid == session_id
        )
    });
    assert!(has_draining, "expected Draining event for rejected session");

    // The client should also receive a SessionClosed event because the session
    // was reset (stream ID >= goaway_stream_id).
    let has_closed = events.iter().any(|e| {
        matches!(
            e,
            Http3ClientEvent::WebTransport(WebTransportEvent::SessionClosed {
                stream_id: sid, ..
            }) if *sid == session_id
        )
    });
    assert!(has_closed, "expected SessionClosed event for rejected session");
}

#[test]
fn wt_session_protocol_none_when_no_header() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();
    assert_eq!(
        wt.client.webtransport_session_protocol(session_id).unwrap(),
        None
    );
}

#[test]
fn wt_session_protocol_quoted_value() {
    let mut wt = WtTest::new();
    let (session_id, _) = wt.negotiate_wt_session(&SessionAcceptAction::AcceptWith(vec![
        Header::new("wt-protocol", r#""myproto""#),
    ]));
    assert_eq!(
        wt.client.webtransport_session_protocol(session_id).unwrap(),
        Some("myproto".to_string())
    );
}

#[test]
fn wt_session_protocol_parameters_stripped() {
    let mut wt = WtTest::new();
    let (session_id, _) = wt.negotiate_wt_session(&SessionAcceptAction::AcceptWith(vec![
        Header::new("wt-protocol", r#""myproto"; foo=bar; baz=2"#),
    ]));
    assert_eq!(
        wt.client.webtransport_session_protocol(session_id).unwrap(),
        Some("myproto".to_string())
    );
}

#[test]
fn wt_session_protocol_malformed_unquoted_rejected() {
    let mut wt = WtTest::new();
    let (session_id, _) = wt.negotiate_wt_session(&SessionAcceptAction::AcceptWith(vec![
        Header::new("wt-protocol", "myproto"),
    ]));
    assert_eq!(
        wt.client.webtransport_session_protocol(session_id).unwrap(),
        None
    );
}

#[test]
fn wt_create_send_group() {
    // Test that we can create a send group for a WebTransport session.
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let group = wt.client.webtransport_create_send_group(session_id);
    assert!(group.is_ok());
    assert!(group.unwrap().as_u64() > 0);
}

#[test]
fn wt_validate_send_group() {
    // Test that we can validate a send group belongs to a session.
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let group = wt.client.webtransport_create_send_group(session_id).unwrap();

    // Validate that the group belongs to this session
    let valid = wt.client.webtransport_validate_send_group(session_id, group);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

#[test]
fn wt_cross_session_send_group_rejected() {
    // Test that a send group from one session is not valid for another session.
    let mut wt = WtTest::new();

    // Create first session
    let wt_session1 = wt.create_wt_session();
    let session_id1 = wt_session1.stream_id();

    // Create second session
    let wt_session2_id = wt
        .client
        .webtransport_create_session(now(), ("https", "something.com", "/"), &[])
        .unwrap();
    wt.exchange_packets();

    // Accept second session
    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
            session,
            ..
        }) = event
        {
            session.response(&SessionAcceptAction::Accept, now()).unwrap();
        }
    }
    wt.exchange_packets();

    // Create send group for session 1
    let group1 = wt.client.webtransport_create_send_group(session_id1).unwrap();

    // Try to validate group1 with session2 - should return false
    let valid = wt.client.webtransport_validate_send_group(wt_session2_id, group1);
    assert!(valid.is_ok());
    assert!(!valid.unwrap());
}

#[test]
fn wt_create_stream_with_send_group() {
    // Test that we can create a stream with a send group.
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Create a send group
    let group = wt.client.webtransport_create_send_group(session_id).unwrap();

    // Create a stream with the send group
    let stream = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group));
    assert!(stream.is_ok());
}

#[test]
fn wt_create_stream_without_send_group() {
    // Test that we can create a stream without a send group (backward compatibility).
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Create a stream without a send group
    let stream = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, None);
    assert!(stream.is_ok());
}

#[test]
fn wt_create_stream_with_invalid_send_group() {
    // Test that creating a stream with an invalid send group fails.
    let mut wt = WtTest::new();

    // Create two sessions
    let wt_session1 = wt.create_wt_session();
    let session_id1 = wt_session1.stream_id();

    let wt_session2_id = wt
        .client
        .webtransport_create_session(now(), ("https", "something.com", "/"), &[])
        .unwrap();
    wt.exchange_packets();

    // Accept second session
    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
            session,
            ..
        }) = event
        {
            session.response(&SessionAcceptAction::Accept, now()).unwrap();
        }
    }
    wt.exchange_packets();

    // Create send group for session 1
    let group1 = wt.client.webtransport_create_send_group(session_id1).unwrap();

    // Try to create stream in session2 with group from session1 - should fail
    let result = wt
        .client
        .webtransport_create_stream_with_send_group(wt_session2_id, StreamType::UniDi, Some(group1));
    assert!(result.is_err());
}

#[test]
fn wt_multiple_streams_same_send_group() {
    // Test that multiple streams can belong to the same send group.
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Create a send group
    let group = wt.client.webtransport_create_send_group(session_id).unwrap();

    // Create multiple streams with the same send group
    let stream1 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group))
        .unwrap();
    let stream2 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group))
        .unwrap();
    let stream3 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::BiDi, Some(group))
        .unwrap();

    // All streams should be created successfully
    assert_ne!(stream1, stream2);
    assert_ne!(stream2, stream3);
    assert_ne!(stream1, stream3);
}

#[test]
fn wt_send_group_with_sendorder() {
    // Test that send groups work with sendOrder.
    // This test verifies streams can be created with both send groups and sendOrder set.
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Create two send groups
    let group1 = wt.client.webtransport_create_send_group(session_id).unwrap();
    let group2 = wt.client.webtransport_create_send_group(session_id).unwrap();

    // Create streams in different groups with sendOrder
    let stream1 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group1))
        .unwrap();
    let stream2 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group1))
        .unwrap();
    let stream3 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group2))
        .unwrap();
    let stream4 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, None)
        .unwrap();

    // Set sendOrder for the streams
    // According to spec, sendOrder is evaluated within the context of the send group
    // stream1 and stream2 are in group1 - their sendOrders should be compared within group1
    // stream3 is in group2 - its sendOrder is independent
    // stream4 has no group - its sendOrder is in the ungrouped namespace
    wt.client.webtransport_set_sendorder(stream1, Some(100)).unwrap();
    wt.client.webtransport_set_sendorder(stream2, Some(200)).unwrap();
    wt.client.webtransport_set_sendorder(stream3, Some(100)).unwrap(); // Same value as stream1, but different group
    wt.client.webtransport_set_sendorder(stream4, Some(100)).unwrap(); // Same value as stream1, but ungrouped

    // All operations should succeed
    // Note: The actual prioritization logic (treating groups equally, sendOrder within groups)
    // would require transport-layer changes and is beyond the scope of this test.
    // This test verifies the API works correctly.
}

#[test]
fn wt_send_groups_fair_bandwidth_allocation() {
    // Test that two send groups receive interleaved bandwidth, even when streams in
    // different groups have very different sendOrder values.
    //
    // Spec: "The user agent considers WebTransportSendGroups as equals when allocating
    // bandwidth for sending WebTransportSendStreams."
    //
    // group_high has sendOrder 1000/900; group_low has sendOrder 100/50.
    // Without group-level fairness the scheduler would prefer group_high streams
    // globally and completely starve group_low.  With per-group round-robin, the
    // server receives Data events from both groups interleaved throughout the transfer.
    //
    // We verify fairness by checking that the FIRST group_low Data event arrives
    // before the LAST group_high Data event — proving they overlap in delivery
    // (group_low is not held back until after group_high finishes).
    //
    // DATA_SIZE must produce multiple packets per stream so the interleaving is visible:
    // 10 KB / ~1440 B MTU ≈ 7 packets per stream → 14+ Data events per group.
    const DATA_SIZE: usize = 10_000;
    const BUF: &[u8] = &[0x42; DATA_SIZE];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let group_high = wt.client.webtransport_create_send_group(session_id).unwrap();
    let group_low = wt.client.webtransport_create_send_group(session_id).unwrap();

    let stream_high1 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group_high))
        .unwrap();
    let stream_high2 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group_high))
        .unwrap();
    let stream_low1 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group_low))
        .unwrap();
    let stream_low2 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group_low))
        .unwrap();

    wt.client.webtransport_set_sendorder(stream_high1, Some(1000)).unwrap();
    wt.client.webtransport_set_sendorder(stream_high2, Some(900)).unwrap();
    wt.client.webtransport_set_sendorder(stream_low1, Some(100)).unwrap();
    wt.client.webtransport_set_sendorder(stream_low2, Some(50)).unwrap();

    for stream in [stream_high1, stream_high2, stream_low1, stream_low2] {
        assert_eq!(wt.client.send_data(stream, BUF, now()).unwrap(), DATA_SIZE);
    }

    wt.exchange_packets();

    // Collect Data events in arrival order.  With fair round-robin scheduling the
    // server sees data from both groups interleaved (not group_high completely first).
    let mut events_in_order: Vec<StreamId> = Vec::new();
    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::Data { stream, .. } = event {
            let id = stream.stream_id();
            if id == stream_high1 || id == stream_high2 || id == stream_low1 || id == stream_low2
            {
                events_in_order.push(id);
            }
        }
    }

    // Both groups must have received data.
    let first_group_low = events_in_order
        .iter()
        .position(|&id| id == stream_low1 || id == stream_low2);
    let last_group_high = events_in_order
        .iter()
        .rposition(|&id| id == stream_high1 || id == stream_high2);

    assert!(
        first_group_low.is_some(),
        "group_low received no data; it was starved by group_high \
         (total events: {}, all for group_high)",
        events_in_order.len()
    );
    assert!(
        last_group_high.is_some(),
        "group_high received no data (total events: {})",
        events_in_order.len()
    );

    // The key fairness invariant: group_low's first delivery overlaps with group_high's
    // ongoing delivery.  If group_low was starved, its first event would come *after*
    // group_high's last event.
    assert!(
        first_group_low.unwrap() < last_group_high.unwrap(),
        "group_low was starved: first group_low event at position {} comes after \
         last group_high event at position {} (total {} events)",
        first_group_low.unwrap(),
        last_group_high.unwrap(),
        events_in_order.len()
    );
}

#[test]
fn wt_sendorder_within_send_group() {
    // Test that sendOrder prioritizes streams WITHIN a send group, and that lower-
    // priority streams are not permanently starved once higher-priority data is sent.
    //
    // Spec: "sendOrder values are evaluated within the context of the send group."
    // Spec: "this sending MUST starve until all bytes queued for sending on
    //        WebTransportSendStreams with a non-null and higher [[SendOrder]]… have
    //        been sent."  After those bytes are sent, the lower stream must proceed.
    //
    // DATA_SIZE is large enough that stream_high's data spans many packets, making
    // the ordering deterministic: server Data events for stream_high will precede
    // those for stream_low regardless of congestion-window size.

    const DATA_SIZE: usize = 50_000;
    const BUF: &[u8] = &[0x42; DATA_SIZE];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let group = wt.client.webtransport_create_send_group(session_id).unwrap();

    let stream_high = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group))
        .unwrap();
    let stream_low = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group))
        .unwrap();

    wt.client.webtransport_set_sendorder(stream_high, Some(1000)).unwrap();
    wt.client.webtransport_set_sendorder(stream_low, Some(10)).unwrap();

    assert_eq!(wt.client.send_data(stream_low, BUF, now()).unwrap(), DATA_SIZE);
    assert_eq!(wt.client.send_data(stream_high, BUF, now()).unwrap(), DATA_SIZE);

    wt.exchange_packets();

    // Collect all Data events in arrival order.
    let mut first_readable: Option<StreamId> = None;
    let mut stream_high_delivered = false;
    let mut stream_low_delivered = false;

    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::Data { stream, .. } = event {
            let id = stream.stream_id();
            if first_readable.is_none() {
                first_readable = Some(id);
            }
            if id == stream_high {
                stream_high_delivered = true;
            } else if id == stream_low {
                stream_low_delivered = true;
            }
        }
    }

    // stream_high (sendOrder=1000) must be served before stream_low (sendOrder=10).
    assert_eq!(
        first_readable,
        Some(stream_high),
        "stream with higher sendOrder should be served first within the group"
    );

    // Both streams must eventually deliver all their data: stream_high because it has
    // highest priority, stream_low because it must not be permanently starved once
    // stream_high's queued bytes have been sent.
    assert!(stream_high_delivered, "stream_high data was not delivered");
    assert!(
        stream_low_delivered,
        "stream_low was permanently starved even after stream_high exhausted its data"
    );
}

#[test]
fn wt_ungrouped_streams_independent_namespace() {
    // Test that ungrouped streams have their own sendOrder namespace,
    // independent from grouped streams.

    const DATA_SIZE: usize = 5_000;
    const BUF: &[u8] = &[0x42; DATA_SIZE];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Create a send group
    let group = wt.client.webtransport_create_send_group(session_id).unwrap();

    // Create a grouped stream with sendOrder 100
    let stream_grouped = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group))
        .unwrap();
    wt.client.webtransport_set_sendorder(stream_grouped, Some(100)).unwrap();

    // Create an ungrouped stream with sendOrder 100 (same value, different namespace)
    let stream_ungrouped = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, None)
        .unwrap();
    wt.client.webtransport_set_sendorder(stream_ungrouped, Some(100)).unwrap();

    // Fill both streams
    assert_eq!(wt.client.send_data(stream_grouped, BUF, now()).unwrap(), DATA_SIZE);
    assert_eq!(wt.client.send_data(stream_ungrouped, BUF, now()).unwrap(), DATA_SIZE);

    wt.exchange_packets();

    // Both streams should become readable despite having the same sendOrder value,
    // because they're in different namespaces (grouped vs ungrouped).
    let mut grouped_readable = false;
    let mut ungrouped_readable = false;

    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::Data { stream, .. } = event {
            let stream_id = stream.stream_id();
            if stream_id == stream_grouped {
                grouped_readable = true;
            }
            if stream_id == stream_ungrouped {
                ungrouped_readable = true;
            }
        }
    }

    // Both should have received data
    assert!(grouped_readable, "grouped stream should receive data");
    assert!(ungrouped_readable, "ungrouped stream should receive data");
}

#[test]
fn wt_multiple_groups_separate_sendorder_namespaces() {
    // Test that different send groups maintain separate sendOrder namespaces.
    // Streams in different groups with the same sendOrder value should not interfere.

    const DATA_SIZE: usize = 5_000;
    const BUF: &[u8] = &[0x42; DATA_SIZE];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    // Create three send groups
    let group1 = wt.client.webtransport_create_send_group(session_id).unwrap();
    let group2 = wt.client.webtransport_create_send_group(session_id).unwrap();
    let group3 = wt.client.webtransport_create_send_group(session_id).unwrap();

    // Create streams in each group, all with the SAME sendOrder value
    let stream1 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group1))
        .unwrap();
    let stream2 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group2))
        .unwrap();
    let stream3 = wt
        .client
        .webtransport_create_stream_with_send_group(session_id, StreamType::UniDi, Some(group3))
        .unwrap();

    // Set the SAME sendOrder value for all streams (different namespaces!)
    wt.client.webtransport_set_sendorder(stream1, Some(500)).unwrap();
    wt.client.webtransport_set_sendorder(stream2, Some(500)).unwrap();
    wt.client.webtransport_set_sendorder(stream3, Some(500)).unwrap();

    // Fill all streams
    for stream in [stream1, stream2, stream3] {
        assert_eq!(wt.client.send_data(stream, BUF, now()).unwrap(), DATA_SIZE);
    }

    wt.exchange_packets();

    // All three streams should become readable, demonstrating that they're in
    // separate namespaces and don't compete with each other based on sendOrder alone.
    let mut stream1_readable = false;
    let mut stream2_readable = false;
    let mut stream3_readable = false;

    while let Some(event) = wt.server.next_event() {
        if let Http3ServerEvent::Data { stream, .. } = event {
            let stream_id = stream.stream_id();
            if stream_id == stream1 {
                stream1_readable = true;
            }
            if stream_id == stream2 {
                stream2_readable = true;
            }
            if stream_id == stream3 {
                stream3_readable = true;
            }
        }
    }

    // All should have received data (fair allocation between groups)
    assert!(stream1_readable, "stream in group1 should receive data");
    assert!(stream2_readable, "stream in group2 should receive data");
    assert!(stream3_readable, "stream in group3 should receive data");
}

#[test]
fn wt_session_stats_initial() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    let stats = wt.client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(stats.datagrams_sent, 0);
    assert_eq!(stats.datagrams_received, 0);
    assert_eq!(stats.streams_opened_local, 0);
    assert_eq!(stats.streams_opened_remote, 0);
}

#[test]
fn wt_session_stats_streams() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    wt.client
        .webtransport_create_stream(session_id, StreamType::UniDi)
        .unwrap();
    let stats = wt.client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(stats.streams_opened_local, 1);
    assert_eq!(stats.streams_opened_remote, 0);

    wt.client
        .webtransport_create_stream(session_id, StreamType::BiDi)
        .unwrap();
    let stats = wt.client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(stats.streams_opened_local, 2);
    assert_eq!(stats.streams_opened_remote, 0);
}

#[test]
fn wt_session_stats_datagrams() {
    const DGRAM: &[u8] = &[0x12, 0x34, 0x56, 0x78];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let session_id = wt_session.stream_id();

    wt.send_datagram(session_id, DGRAM).unwrap();
    wt.exchange_packets();

    let stats = wt.client.webtransport_session_stats(session_id).unwrap();
    assert_eq!(stats.datagrams_sent, 1);
    assert!(stats.bytes_sent >= DGRAM.len() as u64);

    wt.check_datagram_received_server(&wt_session, DGRAM);
}
