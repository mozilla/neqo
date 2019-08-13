// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::{Datagram, Decoder};
use neqo_transport::{
    server::ActiveConnectionRef, server::Server, Connection, ConnectionError, Error,
    FixedConnectionIdManager, Output, State, StreamType, QUIC_VERSION,
};
use test_fixture::{self, assertions, default_client, now};

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

fn connected_server(server: &mut Server) -> ActiveConnectionRef {
    let server_connections = server.active_connections();
    assert_eq!(server_connections.len(), 1);
    assert_eq!(*server_connections[0].borrow().state(), State::Connected);
    server_connections[0].clone()
}

fn connect(client: &mut Connection, server: &mut Server) -> ActiveConnectionRef {
    server.require_retry(false);
    let dgram = client.process(None, now()).dgram(); // ClientHello
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram(); // ServerHello...
    assert!(dgram.is_some());
    // Ingest the server Certificate and authenticate.
    let _ = client.process(dgram, now()).dgram();
    // Drop any datagram the client sends here; it's just an ACK.
    client.authenticated(0, now());
    let dgram = client.process(None, now()).dgram();
    assert!(dgram.is_some());
    assert_eq!(*client.state(), State::Connected);
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some()); // ACK + NST
    connected_server(server)
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
    server.require_retry(true);
    let mut client = default_client();

    let dgram = client.process(None, now()).dgram(); // Initial
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram(); // Retry
    assert!(dgram.is_some());

    assertions::assert_retry(&dgram.as_ref().unwrap());

    let dgram = client.process(dgram, now()).dgram(); // Initial w/token
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram(); // Initial, HS
    assert!(dgram.is_some());
    let _ = client.process(dgram, now()).dgram(); // Ingest, drop any ACK.
    client.authenticated(0, now());
    let dgram = client.process(None, now()).dgram(); // Send Finished
    assert!(dgram.is_some());
    assert_eq!(*client.state(), State::Connected);
    let dgram = server.process(dgram, now()).dgram(); // (done)
    assert!(dgram.is_some()); // Note that this packet will be dropped...
    connected_server(&mut server);
}

// attempt a retry with 0-RTT, and have 0-RTT packets sent with the second ClientHello
#[test]
fn retry_0rtt() {
    let mut server = default_server();
    let mut client = default_client();

    let mut server_conn = connect(&mut client, &mut server);
    server_conn
        .borrow_mut()
        .send_ticket(now(), &[])
        .expect("ticket should go out");
    let dgram = server.process(None, now()).dgram();
    client.process_input(dgram.unwrap(), now()); // Consume ticket, ignore output.
    let token = client.resumption_token().expect("should get token");
    // Calling active_connections clears the set of active connections.
    assert_eq!(server.active_connections().len(), 1);

    server.require_retry(true);
    let mut client = default_client();
    client
        .set_resumption_token(now(), &token)
        .expect("should set token");

    let client_stream = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream, &[1, 2, 3]).unwrap();

    let dgram = client.process(None, now()).dgram(); // Initial w/0-RTT
    assert!(dgram.is_some());
    assertions::assert_coalesced_0rtt(dgram.as_ref().unwrap());
    let dgram = server.process(dgram, now()).dgram(); // Retry
    assert!(dgram.is_some());
    assertions::assert_retry(dgram.as_ref().unwrap());

    // After retry, there should be a token and still coalesced 0-RTT.
    let dgram = client.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    assertions::assert_coalesced_0rtt(dgram.as_ref().unwrap());

    let dgram = server.process(dgram, now()).dgram(); // Initial, HS
    assert!(dgram.is_some());
    let dgram = client.process(dgram, now()).dgram();
    // Note: the client doesn't need to authenticate the server here
    // as there is no certificate; authentication is based on the ticket.
    assert!(dgram.is_some());
    assert_eq!(*client.state(), State::Connected);
    let dgram = server.process(dgram, now()).dgram(); // (done)
    assert!(dgram.is_some());
    connected_server(&mut server);
    assert!(client.tls_info().unwrap().resumed());
}

#[test]
fn retry_bad_token() {
    // TODO(mt) - attempt a retry but get a bad token
}

#[test]
fn retry_bad_odcid() {
    // TODO(mt) - retry works, but the ODCID transport parameter is wrong
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

    let res = client.process(Some(vn), now());
    assert_eq!(res, Output::None);
    match client.state() {
        State::Closed(err) => {
            assert_eq!(*err, ConnectionError::Transport(Error::VersionNegotiation))
        }
        _ => panic!("Invalid client state"),
    }
}

#[test]
fn closed() {
    // TODO(mt) fully close a server connection and it should be dropped
}
