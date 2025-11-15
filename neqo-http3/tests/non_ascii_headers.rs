// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{event::Provider as _, header::HeadersExt as _};
use neqo_http3::{Header, Http3ClientEvent, Http3ServerEvent, Priority};
use test_fixture::{default_http3_client, default_http3_server, exchange_packets, now};

#[test]
fn non_ascii_utf8_header_echo() {
    // Connect a client and a server.
    let mut client = default_http3_client();
    let mut server = default_http3_server();
    let out = test_fixture::connect_peers(&mut client, &mut server);
    assert_eq!(server.process(out, now()).dgram(), None);

    // Ignore all events so far.
    drop(server.events());
    drop(client.events());

    // Create a header with binary data
    let test_bytes: Vec<u8> = vec![0xE4]; // "ä" in extended ASCII (ISO-8859-1), invalid UTF-8
    let custom_header = Header::new("x-custom-data", &test_bytes);

    // Have client send a GET request with a custom header containing non-UTF-8 data
    let stream_id = client
        .fetch(
            now(),
            "GET",
            ("https", "something.com", "/"),
            &[custom_header],
            Priority::default(),
        )
        .unwrap();
    client.stream_close_send(stream_id, now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    // Server receives the request - loop through events to find Headers
    let mut received_stream = None;
    let mut received_headers = None;
    while let Some(event) = server.next_event() {
        if let Http3ServerEvent::Headers {
            stream,
            headers,
            fin: _,
        } = event
        {
            received_stream = Some(stream);
            received_headers = Some(headers);
            break;
        }
    }

    let stream = received_stream.expect("No Headers event received from server");
    let headers = received_headers.expect("No headers received");

    // Verify the server received the header with non-UTF-8 byte correctly
    let received_header = headers
        .find_header("x-custom-data")
        .expect("Custom header not found");
    assert_eq!(received_header.value(), test_bytes.as_slice());
    assert_eq!(received_header.value(), &[0xE4]);

    // Server echoes the value back in a different header
    stream
        .send_headers(&[
            Header::new(":status", "200"),
            Header::new("x-echoed-data", received_header.value()),
        ])
        .unwrap();
    stream.stream_close_send(now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    // Client receives the response
    let mut response_headers = None;
    while let Some(event) = client.next_event() {
        if let Http3ClientEvent::HeaderReady { headers, .. } = event {
            response_headers = Some(headers);
            break;
        }
    }

    let headers = response_headers.expect("No response headers received");

    // Verify the echoed header contains the original non-UTF-8 byte
    let echoed_header = headers
        .find_header("x-echoed-data")
        .expect("Echoed header not found");
    assert_eq!(echoed_header.value(), test_bytes.as_slice());
    assert_eq!(echoed_header.value(), &[0xE4]);
}

#[test]
fn non_ascii_emoji_header_echo() {
    // Connect a client and a server.
    let mut client = default_http3_client();
    let mut server = default_http3_server();
    let out = test_fixture::connect_peers(&mut client, &mut server);
    assert_eq!(server.process(out, now()).dgram(), None);

    // Ignore all events so far.
    drop(server.events());
    drop(client.events());

    // Create a header with non-ASCII but valid UTF-8 (emojis)
    let emoji_data = "🚀🌟💻";
    let custom_header = Header::new("x-emoji-data", emoji_data);

    // Have client send a GET request with a custom header containing emoji data
    let stream_id = client
        .fetch(
            now(),
            "GET",
            ("https", "something.com", "/"),
            &[custom_header],
            Priority::default(),
        )
        .unwrap();
    client.stream_close_send(stream_id, now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    // Server receives the request - loop through events to find Headers
    let mut received_stream = None;
    let mut received_headers = None;
    while let Some(event) = server.next_event() {
        if let Http3ServerEvent::Headers {
            stream,
            headers,
            fin: _,
        } = event
        {
            received_stream = Some(stream);
            received_headers = Some(headers);
            break;
        }
    }

    let stream = received_stream.expect("No Headers event received from server");
    let headers = received_headers.expect("No headers received");

    // Verify the server received the emoji header correctly
    let received_header = headers
        .find_header("x-emoji-data")
        .expect("Custom header not found");
    assert_eq!(received_header.value(), emoji_data.as_bytes());

    // Verify it's valid UTF-8 and matches the original
    assert_eq!(
        std::str::from_utf8(received_header.value()).unwrap(),
        emoji_data
    );

    // Server echoes the value back in a different header
    stream
        .send_headers(&[
            Header::new(":status", "200"),
            Header::new("x-echoed-emoji", received_header.value()),
        ])
        .unwrap();
    stream.stream_close_send(now()).unwrap();
    exchange_packets(&mut client, &mut server, false, None);

    // Client receives the response
    let mut response_headers = None;
    while let Some(event) = client.next_event() {
        if let Http3ClientEvent::HeaderReady { headers, .. } = event {
            response_headers = Some(headers);
            break;
        }
    }

    let headers = response_headers.expect("No response headers received");

    // Verify the echoed header contains the original emoji bytes
    let echoed_header = headers
        .find_header("x-echoed-emoji")
        .expect("Echoed header not found");
    assert_eq!(echoed_header.value(), emoji_data.as_bytes());

    // Verify it's still valid UTF-8 and matches
    assert_eq!(
        std::str::from_utf8(echoed_header.value()).unwrap(),
        emoji_data
    );
}
