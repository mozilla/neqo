// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_assignments)]

use neqo_http3::HttpConn;
use neqo_transport::{Connection, Datagram, State};

use std::net::SocketAddr;

use neqo_crypto::init_db;

fn loopback() -> SocketAddr {
    "127.0.0.1:443".parse().unwrap()
}

fn connect() -> (HttpConn, HttpConn, (Vec<Datagram>, u64)) {
    init_db("../neqo-transport/db");

    let mut hconn_c = HttpConn::new(
        Connection::new_client("example.com", &["alpn"], loopback(), loopback()).unwrap(),
        100,
        100,
    );
    let mut hconn_s = HttpConn::new(
        Connection::new_server(&["key"], &["alpn"]).unwrap(),
        100,
        100,
    );

    assert_eq!(*hconn_c.state(), State::Init);
    assert_eq!(*hconn_s.state(), State::WaitInitial);
    let mut r = hconn_c.process(Vec::new(), 0);
    assert_eq!(*hconn_c.state(), State::WaitInitial);
    assert_eq!(*hconn_s.state(), State::WaitInitial);
    r = hconn_s.process(r.0, 0);
    assert_eq!(*hconn_c.state(), State::WaitInitial);
    assert_eq!(*hconn_s.state(), State::Handshaking);
    r = hconn_c.process(r.0, 0);
    assert_eq!(*hconn_c.state(), State::Connected);
    assert_eq!(*hconn_s.state(), State::Handshaking);
    r = hconn_s.process(r.0, 0);
    assert_eq!(*hconn_c.state(), State::Connected);
    assert_eq!(*hconn_s.state(), State::Connected);
    r = hconn_c.process(r.0, 0);
    r = hconn_s.process(r.0, 0);
    // assert_eq!(hconn_s.settings_received, true);
    r = hconn_c.process(r.0, 0);
    // assert_eq!(hconn_c.settings_received, true);

    (hconn_c, hconn_s, r)
}

#[test]
fn test_connect() {
    let (_hconn_c, _hconn_s, _r) = connect();
}

#[test]
fn test_fetch() {
    let (mut hconn_c, mut hconn_s, mut r) = connect();

    eprintln!("-----client");
    assert_eq!(
        hconn_c.fetch("GET", "https", "something.com", "/", &[]),
        Ok(())
    );
    r = hconn_c.process(r.0, 0);
    eprintln!("-----server");
    r = hconn_s.process(r.0, 0);
    // BUG: incoming fetch on stream 0 currently being interpreted as a
    // unicast push stream; need to handle bidi streams differently than uni
    // TODO: some kind of server API needed to create response

    eprintln!("-----client");
    r = hconn_c.process(r.0, 0);
    // TODO: some kind of client API needed to read result of fetch
    // TODO: assert result is as expected e.g. (200 "abc")
    // assert!(false);
}
