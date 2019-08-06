// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::{Datagram, Decoder};
use neqo_transport::{server::Server, Connection, FixedConnectionIdManager, State, QUIC_VERSION};
use test_fixture::{self, default_client, now};

// Different than the one in the fixture, which is a single connection.
fn default_server() -> Server {
    Server::new(
        now(),
        test_fixture::DEFAULT_KEYS,
        test_fixture::DEFAULT_ALPN,
        test_fixture::anti_replay(),
        FixedConnectionIdManager::make(7),
    )
}

fn assert_server_connected(server: &mut Server) {
    let server_connections = server.active_connections();
    assert_eq!(server_connections.len(), 1);
    for s in server_connections {
        assert_eq!(*s.borrow().state(), State::Connected);
    }
}

fn connect(client: &mut Connection, server: &mut Server) {
    let dgram = client.process(None, now()).dgram(); // ClientHello
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram(); // ServerHello...
    assert!(dgram.is_some());
    let dgram = client.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    assert_eq!(*client.state(), State::Connected);
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    assert_server_connected(server);
}

#[test]
fn single_client() {
    let mut server = default_server();
    let mut client = default_client();

    connect(&mut client, &mut server);
}

#[test]
fn retry() {
    let mut server = default_server();
    server.enable_retry(true);
    let mut client = default_client();

    let dgram = client.process(None, now()).dgram(); // Initial
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram(); // Retry
    assert!(dgram.is_some());

    let dgram = client.process(dgram, now()).dgram(); // Initial w/token
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram(); // Initial, HS
    assert!(dgram.is_some());
    let dgram = client.process(dgram, now()).dgram(); // HS (done)
    assert!(dgram.is_some());
    assert_eq!(*client.state(), State::Connected);
    let dgram = server.process(dgram, now()).dgram(); // (done)
    assert!(dgram.is_some());
    assert_server_connected(&mut server);
}

#[test]
fn version_negotiation() {
    let mut server = default_server();
    let mut client = default_client();

    // Any packet will do, but let's make something that looks real.
    let dgram = client.process(None, now()).dgram().expect("a datagram");
    let mut input = dgram.to_vec();
    input[1] ^= 0x12;
    let damaged = Datagram::new(dgram.source(), dgram.destination(), input.clone());
    let vn = server.process(Some(damaged), now()).dgram();

    let mut dec = Decoder::from(&input[5..]); // Skip past version.
    let dcid = dec.decode_vec(1).expect("client DCID").to_vec();
    let scid = dec.decode_vec(1).expect("client SCID").to_vec();

    // We should have received a VN packet.
    let vn = vn.expect("a vn packet");
    let mut dec = Decoder::from(&vn[1..]); // Skip first byte.

    assert_eq!(dec.decode_uint(4).expect("VN"), 0);
    assert_eq!(dec.decode_vec(1).expect("VN DCID"), &scid[..]);
    assert_eq!(dec.decode_vec(1).expect("VN SCID"), &dcid[..]);
    let mut found = false;
    while dec.remaining() > 0 {
        let v = dec.decode_uint(4).expect("supported version");
        found |= v == u64::from(QUIC_VERSION);
    }
    assert!(found, "valid version not found");
}
