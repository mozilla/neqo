// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_assignments)]

use neqo_common::Datagram;
use neqo_http3::{Http3Connection, Http3State};
use test_fixture::*;

fn new_stream_callback(
    request_headers: &[(String, String)],
    error: bool,
) -> (Vec<(String, String)>, Vec<u8>) {
    println!("Error: {}", error);

    assert_eq!(
        request_headers,
        &[
            (String::from(":method"), String::from("GET")),
            (String::from(":scheme"), String::from("https")),
            (String::from(":authority"), String::from("something.com")),
            (String::from(":path"), String::from("/"))
        ]
    );

    (
        vec![
            (String::from(":status"), String::from("200")),
            (String::from("content-length"), String::from("3")),
        ],
        b"123".to_vec(),
    )
}

fn connect() -> (Http3Connection, Http3Connection, Option<Datagram>) {
    let mut hconn_c = Http3Connection::new(default_client(), 100, 100, None);
    let mut hconn_s = Http3Connection::new(
        default_server(),
        100,
        100,
        Some(Box::new(new_stream_callback)),
    );

    assert_eq!(hconn_c.state(), Http3State::Initializing);
    assert_eq!(hconn_s.state(), Http3State::Initializing);
    let out = hconn_c.process(None, now()); // Initial
    let out = hconn_s.process(out.dgram(), now()); // Initial + Handshake
    let out = hconn_c.process(out.dgram(), now()); // Handshake
    assert_eq!(hconn_c.state(), Http3State::Connected);
    let out = hconn_s.process(out.dgram(), now()); // Handshake
    assert_eq!(hconn_s.state(), Http3State::Connected);
    let out = hconn_c.process(out.dgram(), now());
    let out = hconn_s.process(out.dgram(), now());
    // assert_eq!(hconn_s.settings_received, true);
    let out = hconn_c.process(out.dgram(), now());
    // assert_eq!(hconn_c.settings_received, true);

    (hconn_c, hconn_s, out.dgram())
}

#[test]
fn test_connect() {
    let (_hconn_c, _hconn_s, _d) = connect();
}

#[test]
fn test_fetch() {
    let (mut hconn_c, mut hconn_s, dgram) = connect();

    eprintln!("-----client");
    let req = hconn_c
        .fetch("GET", "https", "something.com", "/", &[])
        .unwrap();
    assert_eq!(req, 0);
    let out = hconn_c.process(dgram, now());
    eprintln!("-----server");
    let out = hconn_s.process(out.dgram(), now());

    eprintln!("-----client");
    let _ = hconn_c.process(out.dgram(), now());
    // TODO: some kind of client API needed to read result of fetch
    // TODO: assert result is as expected e.g. (200 "abc")
    // assert!(false);
}
