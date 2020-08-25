// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::*;
use crate::addr_valid::{AddressValidation, ValidateAddress};
use crate::cc::{CWND_INITIAL_PKTS, CWND_MIN, MAX_DATAGRAM_SIZE, PACING_BURST_SIZE};
use crate::frame::{CloseError, StreamType};
use crate::packet::PACKET_BIT_LONG;
use crate::path::PATH_MTU_V6;
use crate::recovery::ACK_ONLY_SIZE_LIMIT;
use crate::recovery::PTO_PACKET_COUNT;
use crate::send_stream::SEND_BUFFER_SIZE;
use crate::tracking::{ACK_DELAY, MAX_UNACKED_PKTS};
use std::convert::TryInto;

use neqo_crypto::{constants::TLS_CHACHA20_POLY1305_SHA256, AllowZeroRtt};
use std::mem;
use test_fixture::{self, assertions, fixture_init, loopback, now};

const AT_LEAST_PTO: Duration = Duration::from_secs(1);
const DEFAULT_STREAM_DATA: &[u8] = b"message";

// This is fabulous: because test_fixture uses the public API for Connection,
// it gets a different type to the ones that are referenced via super::*.
// Thus, this code can't use default_client() and default_server() from
// test_fixture because they produce different types.
//
// These are a direct copy of those functions.
pub fn default_client() -> Connection {
    fixture_init();
    Connection::new_client(
        test_fixture::DEFAULT_SERVER_NAME,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(3))),
        loopback(),
        loopback(),
        QuicVersion::default(),
    )
    .expect("create a default client")
}
pub fn default_server() -> Connection {
    fixture_init();

    let mut c = Connection::new_server(
        test_fixture::DEFAULT_KEYS,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(5))),
        QuicVersion::default(),
    )
    .expect("create a default server");
    c.server_enable_0rtt(&test_fixture::anti_replay(), AllowZeroRtt {})
        .expect("enable 0-RTT");
    c
}

/// If state is AuthenticationNeeded call authenticated(). This function will
/// consume all outstanding events on the connection.
pub fn maybe_authenticate(conn: &mut Connection) -> bool {
    let authentication_needed = |e| matches!(e, ConnectionEvent::AuthenticationNeeded);
    if conn.events().any(authentication_needed) {
        conn.authenticated(AuthenticationStatus::Ok, now());
        return true;
    }
    false
}

#[test]
fn test_conn_stream_create() {
    let mut client = default_client();

    let out = client.process(None, now());
    let mut server = default_server();
    let out = server.process(out.dgram(), now());

    let out = client.process(out.dgram(), now());
    let _ = server.process(out.dgram(), now());
    assert!(maybe_authenticate(&mut client));
    let out = client.process(None, now());

    // client now in State::Connected
    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 6);
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 4);

    let _ = server.process(out.dgram(), now());
    // server now in State::Connected
    assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 3);
    assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 7);
    assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 1);
    assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 5);
}

#[test]
fn test_conn_handshake() {
    qdebug!("---- client: generate CH");
    let mut client = default_client();
    let out = client.process(None, now());
    assert!(out.as_dgram_ref().is_some());
    assert_eq!(out.as_dgram_ref().unwrap().len(), PATH_MTU_V6);
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
    let mut server = default_server();
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    qdebug!("---- client: cert verification");
    let out = client.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());

    assert!(maybe_authenticate(&mut client));

    qdebug!("---- client: SH..FIN -> FIN");
    let out = client.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    assert_eq!(*client.state(), State::Connected);

    qdebug!("---- server: FIN -> ACKS");
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    assert_eq!(*server.state(), State::Confirmed);

    qdebug!("---- client: ACKS -> 0");
    let out = client.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    assert_eq!(*client.state(), State::Confirmed);
}

#[test]
fn handshake_failed_authentication() {
    qdebug!("---- client: generate CH");
    let mut client = default_client();
    let out = client.process(None, now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
    let mut server = default_server();
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    qdebug!("---- client: cert verification");
    let out = client.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    let authentication_needed = |e| matches!(e, ConnectionEvent::AuthenticationNeeded);
    assert!(client.events().any(authentication_needed));
    qdebug!("---- client: Alert(certificate_revoked)");
    client.authenticated(AuthenticationStatus::CertRevoked, now());

    qdebug!("---- client: -> Alert(certificate_revoked)");
    let out = client.process(None, now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    qdebug!("---- server: Alert(certificate_revoked)");
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    assert_error(&client, ConnectionError::Transport(Error::CryptoAlert(44)));
    assert_error(&server, ConnectionError::Transport(Error::PeerError(300)));
}

#[test]
#[allow(clippy::cognitive_complexity)]
// tests stream send/recv after connection is established.
fn test_conn_stream() {
    let mut client = default_client();
    let mut server = default_server();

    qdebug!("---- client");
    let out = client.process(None, now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    // -->> Initial[0]: CRYPTO[CH]

    qdebug!("---- server");
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    // <<-- Initial[0]: CRYPTO[SH] ACK[0]
    // <<-- Handshake[0]: CRYPTO[EE, CERT, CV, FIN]

    qdebug!("---- client");
    let out = client.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    // -->> Initial[1]: ACK[0]

    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());

    assert!(maybe_authenticate(&mut client));

    qdebug!("---- client");
    let out = client.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    assert_eq!(*client.state(), State::Connected);
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    // -->> Handshake[0]: CRYPTO[FIN], ACK[0]

    qdebug!("---- server");
    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_some());
    assert_eq!(*server.state(), State::Confirmed);
    qdebug!("Output={:0x?}", out.as_dgram_ref());
    // ACK and HANDSHAKE_DONE
    // -->> nothing

    qdebug!("---- client");
    // Send
    let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream_id, &[6; 100]).unwrap();
    client.stream_send(client_stream_id, &[7; 40]).unwrap();
    client.stream_send(client_stream_id, &[8; 4000]).unwrap();

    // Send to another stream but some data after fin has been set
    let client_stream_id2 = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream_id2, &[6; 60]).unwrap();
    client.stream_close_send(client_stream_id2).unwrap();
    client.stream_send(client_stream_id2, &[7; 50]).unwrap_err();
    // Sending this much takes a few datagrams.
    let mut datagrams = vec![];
    let mut out = client.process(out.dgram(), now());
    while let Some(d) = out.dgram() {
        datagrams.push(d);
        out = client.process(None, now());
    }
    assert_eq!(datagrams.len(), 4);
    assert_eq!(*client.state(), State::Confirmed);

    qdebug!("---- server");
    for (d_num, d) in datagrams.into_iter().enumerate() {
        let out = server.process(Some(d), now());
        assert_eq!(
            out.as_dgram_ref().is_some(),
            (d_num + 1) % (MAX_UNACKED_PKTS + 1) == 0
        );
        qdebug!("Output={:0x?}", out.as_dgram_ref());
    }
    assert_eq!(*server.state(), State::Confirmed);

    let mut buf = vec![0; 4000];

    let mut stream_ids = server.events().filter_map(|evt| match evt {
        ConnectionEvent::NewStream { stream_id, .. } => Some(stream_id),
        _ => None,
    });
    let stream_id = stream_ids.next().expect("should have a new stream event");
    let (received, fin) = server.stream_recv(stream_id.as_u64(), &mut buf).unwrap();
    assert_eq!(received, 4000);
    assert_eq!(fin, false);
    let (received, fin) = server.stream_recv(stream_id.as_u64(), &mut buf).unwrap();
    assert_eq!(received, 140);
    assert_eq!(fin, false);

    let stream_id = stream_ids
        .next()
        .expect("should have a second new stream event");
    let (received, fin) = server.stream_recv(stream_id.as_u64(), &mut buf).unwrap();
    assert_eq!(received, 60);
    assert_eq!(fin, true);
}

/// Drive the handshake between the client and server.
fn handshake(
    client: &mut Connection,
    server: &mut Connection,
    now: Instant,
    rtt: Duration,
) -> Instant {
    let mut a = client;
    let mut b = server;
    let mut now = now;

    let mut input = None;
    let is_done = |c: &mut Connection| match c.state() {
        State::Confirmed | State::Closing { .. } | State::Closed(..) => true,
        _ => false,
    };

    while !is_done(a) {
        let _ = maybe_authenticate(a);
        let had_input = input.is_some();
        let output = a.process(input, now).dgram();
        assert!(had_input || output.is_some());
        input = output;
        qtrace!("t += {:?}", rtt / 2);
        now += rtt / 2;
        mem::swap(&mut a, &mut b);
    }
    let _ = a.process(input, now);
    now
}

fn connect_with_rtt(
    client: &mut Connection,
    server: &mut Connection,
    now: Instant,
    rtt: Duration,
) -> Instant {
    let now = handshake(client, server, now, rtt);
    assert_eq!(*client.state(), State::Confirmed);
    assert_eq!(*client.state(), State::Confirmed);

    assert_eq!(client.loss_recovery.rtt(), rtt);
    assert_eq!(server.loss_recovery.rtt(), rtt);
    now
}

fn connect(client: &mut Connection, server: &mut Connection) {
    connect_with_rtt(client, server, now(), Duration::new(0, 0));
}

fn assert_error(c: &Connection, err: ConnectionError) {
    match c.state() {
        State::Closing { error, .. } | State::Draining { error, .. } | State::Closed(error) => {
            assert_eq!(*error, err);
        }
        _ => panic!("bad state {:?}", c.state()),
    }
}

#[test]
fn test_no_alpn() {
    fixture_init();
    let mut client = Connection::new_client(
        "example.com",
        &["bad-alpn"],
        Rc::new(RefCell::new(FixedConnectionIdManager::new(9))),
        loopback(),
        loopback(),
        QuicVersion::default(),
    )
    .unwrap();
    let mut server = default_server();

    handshake(&mut client, &mut server, now(), Duration::new(0, 0));
    // TODO (mt): errors are immediate, which means that we never send CONNECTION_CLOSE
    // and the client never sees the server's rejection of its handshake.
    //assert_error(&client, ConnectionError::Transport(Error::CryptoAlert(120)));
    assert_error(&server, ConnectionError::Transport(Error::CryptoAlert(120)));
}

#[test]
fn test_dup_server_flight1() {
    qdebug!("---- client: generate CH");
    let mut client = default_client();
    let out = client.process(None, now());
    assert!(out.as_dgram_ref().is_some());
    assert_eq!(out.as_dgram_ref().unwrap().len(), PATH_MTU_V6);
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
    let mut server = default_server();
    let out_to_rep = server.process(out.dgram(), now());
    assert!(out_to_rep.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out_to_rep.as_dgram_ref());

    qdebug!("---- client: cert verification");
    let out = client.process(Some(out_to_rep.as_dgram_ref().unwrap().clone()), now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    let out = server.process(out.dgram(), now());
    assert!(out.as_dgram_ref().is_none());

    assert!(maybe_authenticate(&mut client));

    qdebug!("---- client: SH..FIN -> FIN");
    let out = client.process(None, now());
    assert!(out.as_dgram_ref().is_some());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    assert_eq!(2, client.stats().packets_rx);
    assert_eq!(0, client.stats().dups_rx);

    qdebug!("---- Dup, ignored");
    let out = client.process(out_to_rep.dgram(), now());
    assert!(out.as_dgram_ref().is_none());
    qdebug!("Output={:0x?}", out.as_dgram_ref());

    // Four packets total received, 1 of them is a dup and one has been dropped because Initial keys
    // are dropped.
    assert_eq!(4, client.stats().packets_rx);
    assert_eq!(1, client.stats().dups_rx);
    assert_eq!(1, client.stats().dropped_rx);
}

fn exchange_ticket(client: &mut Connection, server: &mut Connection, now: Instant) -> Vec<u8> {
    server.send_ticket(now, &[]).expect("can send ticket");
    let ticket = server.process_output(now).dgram();
    assert!(ticket.is_some());
    client.process_input(ticket.unwrap(), now);
    assert_eq!(*client.state(), State::Confirmed);
    client.resumption_token().expect("should have token")
}

#[test]
fn connection_close() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let now = now();

    client.close(now, 42, "");

    let out = client.process(None, now);

    let frames = server.test_process_input(out.dgram().unwrap(), now);
    assert_eq!(frames.len(), 1);
    assert!(matches!(
        frames[0],
        (
            Frame::ConnectionClose {
                error_code: CloseError::Application(42),
                ..
            },
            PNSpace::ApplicationData,
        )
    ));
}

#[test]
fn resume() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let token = exchange_ticket(&mut client, &mut server, now());
    let mut client = default_client();
    client
        .enable_resumption(now(), &token[..])
        .expect("should set token");
    let mut server = default_server();
    connect(&mut client, &mut server);
    assert!(client.tls_info().unwrap().resumed());
    assert!(server.tls_info().unwrap().resumed());
}

#[test]
fn remember_smoothed_rtt() {
    let mut client = default_client();
    let mut server = default_server();

    const RTT1: Duration = Duration::from_millis(130);
    let now = connect_with_rtt(&mut client, &mut server, now(), RTT1);
    assert_eq!(client.loss_recovery.rtt(), RTT1);

    let token = exchange_ticket(&mut client, &mut server, now);
    let mut client = default_client();
    let mut server = default_server();
    client.enable_resumption(now, &token[..]).unwrap();
    assert_eq!(
        client.loss_recovery.rtt(),
        RTT1,
        "client should remember previous RTT"
    );

    const RTT2: Duration = Duration::from_millis(70);
    connect_with_rtt(&mut client, &mut server, now, RTT2);
    assert_eq!(
        client.loss_recovery.rtt(),
        RTT2,
        "previous RTT should be completely erased"
    );
}

#[test]
fn zero_rtt_negotiate() {
    // Note that the two servers in this test will get different anti-replay filters.
    // That's OK because we aren't testing anti-replay.
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let token = exchange_ticket(&mut client, &mut server, now());
    let mut client = default_client();
    client
        .enable_resumption(now(), &token[..])
        .expect("should set token");
    let mut server = default_server();
    connect(&mut client, &mut server);
    assert!(client.tls_info().unwrap().early_data_accepted());
    assert!(server.tls_info().unwrap().early_data_accepted());
}

#[test]
fn zero_rtt_send_recv() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let token = exchange_ticket(&mut client, &mut server, now());
    let mut client = default_client();
    client
        .enable_resumption(now(), &token[..])
        .expect("should set token");
    let mut server = default_server();

    // Send ClientHello.
    let client_hs = client.process(None, now());
    assert!(client_hs.as_dgram_ref().is_some());

    // Now send a 0-RTT packet.
    let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream_id, &[1, 2, 3]).unwrap();
    let client_0rtt = client.process(None, now());
    assert!(client_0rtt.as_dgram_ref().is_some());
    // 0-RTT packets on their own shouldn't be padded to 1200.
    assert!(client_0rtt.as_dgram_ref().unwrap().len() < 1200);

    let server_hs = server.process(client_hs.dgram(), now());
    assert!(server_hs.as_dgram_ref().is_some()); // ServerHello, etc...
    let server_process_0rtt = server.process(client_0rtt.dgram(), now());
    assert!(server_process_0rtt.as_dgram_ref().is_none());

    let server_stream_id = server
        .events()
        .find_map(|evt| match evt {
            ConnectionEvent::NewStream { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .expect("should have received a new stream event");
    assert_eq!(client_stream_id, server_stream_id.as_u64());
}

#[test]
fn zero_rtt_send_coalesce() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let token = exchange_ticket(&mut client, &mut server, now());
    let mut client = default_client();
    client
        .enable_resumption(now(), &token[..])
        .expect("should set token");
    let mut server = default_server();

    // Write 0-RTT before generating any packets.
    // This should result in a datagram that coalesces Initial and 0-RTT.
    let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream_id, &[1, 2, 3]).unwrap();
    let client_0rtt = client.process(None, now());
    assert!(client_0rtt.as_dgram_ref().is_some());

    assertions::assert_coalesced_0rtt(&client_0rtt.as_dgram_ref().unwrap()[..]);

    let server_hs = server.process(client_0rtt.dgram(), now());
    assert!(server_hs.as_dgram_ref().is_some()); // Should produce ServerHello etc...

    let server_stream_id = server
        .events()
        .find_map(|evt| match evt {
            ConnectionEvent::NewStream { stream_id } => Some(stream_id),
            _ => None,
        })
        .expect("should have received a new stream event");
    assert_eq!(client_stream_id, server_stream_id.as_u64());
}

#[test]
fn zero_rtt_before_resumption_token() {
    let mut client = default_client();
    assert!(client.stream_create(StreamType::BiDi).is_err());
}

#[test]
fn zero_rtt_send_reject() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let token = exchange_ticket(&mut client, &mut server, now());
    let mut client = default_client();
    client
        .enable_resumption(now(), &token[..])
        .expect("should set token");
    let mut server = Connection::new_server(
        test_fixture::DEFAULT_KEYS,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(10))),
        QuicVersion::default(),
    )
    .unwrap();
    // Using a freshly initialized anti-replay context
    // should result in the server rejecting 0-RTT.
    let ar =
        AntiReplay::new(now(), test_fixture::ANTI_REPLAY_WINDOW, 1, 3).expect("setup anti-replay");
    server
        .server_enable_0rtt(&ar, AllowZeroRtt {})
        .expect("enable 0-RTT");

    // Send ClientHello.
    let client_hs = client.process(None, now());
    assert!(client_hs.as_dgram_ref().is_some());

    // Write some data on the client.
    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    let msg = &[1, 2, 3];
    client.stream_send(stream_id, msg).unwrap();
    let client_0rtt = client.process(None, now());
    assert!(client_0rtt.as_dgram_ref().is_some());

    let server_hs = server.process(client_hs.dgram(), now());
    assert!(server_hs.as_dgram_ref().is_some()); // Should produce ServerHello etc...
    let server_ignored = server.process(client_0rtt.dgram(), now());
    assert!(server_ignored.as_dgram_ref().is_none());

    // The server shouldn't receive that 0-RTT data.
    let recvd_stream_evt = |e| matches!(e, ConnectionEvent::NewStream { .. });
    assert!(!server.events().any(recvd_stream_evt));

    // Client should get a rejection.
    let client_fin = client.process(server_hs.dgram(), now());
    let recvd_0rtt_reject = |e| e == ConnectionEvent::ZeroRttRejected;
    assert!(client.events().any(recvd_0rtt_reject));

    // Server consume client_fin
    let server_ack = server.process(client_fin.dgram(), now());
    assert!(server_ack.as_dgram_ref().is_some());
    let client_out = client.process(server_ack.dgram(), now());
    assert!(client_out.as_dgram_ref().is_none());

    // ...and the client stream should be gone.
    let res = client.stream_send(stream_id, msg);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

    // Open a new stream and send data. StreamId should start with 0.
    let stream_id_after_reject = client.stream_create(StreamType::UniDi).unwrap();
    assert_eq!(stream_id, stream_id_after_reject);
    let msg = &[1, 2, 3];
    client.stream_send(stream_id_after_reject, msg).unwrap();
    let client_after_reject = client.process(None, now());
    assert!(client_after_reject.as_dgram_ref().is_some());

    // The server should receive new stream
    let server_out = server.process(client_after_reject.dgram(), now());
    assert!(server_out.as_dgram_ref().is_none()); // suppress the ack
    let recvd_stream_evt = |e| matches!(e, ConnectionEvent::NewStream { .. });
    assert!(server.events().any(recvd_stream_evt));
}

#[test]
// Send fin even if a peer closes a reomte bidi send stream before sending any data.
fn report_fin_when_stream_closed_wo_data() {
    // Note that the two servers in this test will get different anti-replay filters.
    // That's OK because we aren't testing anti-replay.
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    // create a stream
    let stream_id = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream_id, &[0x00]).unwrap();
    let out = client.process(None, now());
    let _ = server.process(out.dgram(), now());

    assert_eq!(Ok(()), server.stream_close_send(stream_id));
    let out = server.process(None, now());
    let _ = client.process(out.dgram(), now());
    let stream_readable = |e| matches!(e, ConnectionEvent::RecvStreamReadable {..});
    assert!(client.events().any(stream_readable));
}

/// Connect with an RTT and then force both peers to be idle.
/// Getting the client and server to reach an idle state is surprisingly hard.
/// The server sends HANDSHAKE_DONE at the end of the handshake, and the client
/// doesn't immediately acknowledge it.  Reordering packets does the trick.
fn connect_rtt_idle(client: &mut Connection, server: &mut Connection, rtt: Duration) -> Instant {
    let mut now = connect_with_rtt(client, server, now(), rtt);
    let p1 = send_something(server, now);
    let p2 = send_something(server, now);
    now += rtt / 2;
    // Delivering p2 first at the client causes it to want to ACK.
    client.process_input(p2, now);
    // Delivering p1 should not have the client change its mind about the ACK.
    let ack = client.process(Some(p1), now).dgram();
    assert!(ack.is_some());
    assert_eq!(
        server.process(ack, now),
        Output::Callback(LOCAL_IDLE_TIMEOUT)
    );
    assert_eq!(
        client.process_output(now),
        Output::Callback(LOCAL_IDLE_TIMEOUT)
    );
    now
}

fn connect_force_idle(client: &mut Connection, server: &mut Connection) {
    connect_rtt_idle(client, server, Duration::new(0, 0));
}

#[test]
fn idle_timeout() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    // Still connected after 29 seconds. Idle timer not reset
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT - Duration::from_secs(1));
    assert!(matches!(client.state(), State::Confirmed));

    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT);

    // Not connected after LOCAL_IDLE_TIMEOUT seconds.
    assert!(matches!(client.state(), State::Closed(_)));
}

#[test]
fn asymmetric_idle_timeout() {
    const LOWER_TIMEOUT_MS: u64 = 1000;
    const LOWER_TIMEOUT: Duration = Duration::from_millis(LOWER_TIMEOUT_MS);
    // Sanity check the constant.
    assert!(LOWER_TIMEOUT < LOCAL_IDLE_TIMEOUT);

    let mut client = default_client();
    let mut server = default_server();

    // Overwrite the default at the server.
    server
        .tps
        .borrow_mut()
        .local
        .set_integer(tparams::IDLE_TIMEOUT, LOWER_TIMEOUT_MS);
    server.idle_timeout = IdleTimeout::new(LOWER_TIMEOUT);

    // Now connect and force idleness manually.
    connect(&mut client, &mut server);
    let p1 = send_something(&mut server, now());
    let p2 = send_something(&mut server, now());
    client.process_input(p2, now());
    let ack = client.process(Some(p1), now()).dgram();
    assert!(ack.is_some());
    // Now the server has its ACK and both should be idle.
    assert_eq!(server.process(ack, now()), Output::Callback(LOWER_TIMEOUT));
    assert_eq!(client.process(None, now()), Output::Callback(LOWER_TIMEOUT));
}

#[test]
fn tiny_idle_timeout() {
    const RTT: Duration = Duration::from_millis(500);
    const LOWER_TIMEOUT_MS: u64 = 100;
    const LOWER_TIMEOUT: Duration = Duration::from_millis(LOWER_TIMEOUT_MS);
    // We won't respect a value that is lower than 3*PTO, sanity check.
    assert!(LOWER_TIMEOUT < 3 * RTT);

    let mut client = default_client();
    let mut server = default_server();

    // Overwrite the default at the server.
    server
        .set_local_tparam(
            tparams::IDLE_TIMEOUT,
            TransportParameter::Integer(LOWER_TIMEOUT_MS),
        )
        .unwrap();
    server.idle_timeout = IdleTimeout::new(LOWER_TIMEOUT);

    // Now connect with an RTT and force idleness manually.
    let mut now = connect_with_rtt(&mut client, &mut server, now(), RTT);
    let p1 = send_something(&mut server, now);
    let p2 = send_something(&mut server, now);
    now += RTT / 2;
    client.process_input(p2, now);
    let ack = client.process(Some(p1), now).dgram();
    assert!(ack.is_some());

    // The client should be idle now, but with a different timer.
    if let Output::Callback(t) = client.process(None, now) {
        assert!(t > LOWER_TIMEOUT);
    } else {
        panic!("Client not idle");
    }

    // The server should go idle after the ACK, but again with a larger timeout.
    now += RTT / 2;
    if let Output::Callback(t) = client.process(ack, now) {
        assert!(t > LOWER_TIMEOUT);
    } else {
        panic!("Client not idle");
    }
}

#[test]
fn idle_send_packet1() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, b"hello").unwrap(), 5);

    let out = client.process(None, now + Duration::from_secs(10));
    let out = server.process(out.dgram(), now + Duration::from_secs(10));

    // Still connected after 39 seconds because idle timer reset by outgoing
    // packet
    let _ = client.process(
        out.dgram(),
        now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(9),
    );
    assert!(matches!(client.state(), State::Confirmed));

    // Not connected after 40 seconds.
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(10));

    assert!(matches!(client.state(), State::Closed(_)));
}

#[test]
fn idle_send_packet2() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, b"hello").unwrap(), 5);

    let _out = client.process(None, now + Duration::from_secs(10));

    assert_eq!(client.stream_send(2, b"there").unwrap(), 5);
    let _out = client.process(None, now + Duration::from_secs(20));

    // Still connected after 39 seconds.
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(9));
    assert!(matches!(client.state(), State::Confirmed));

    // Not connected after 40 seconds because timer not reset by second
    // outgoing packet
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(10));
    assert!(matches!(client.state(), State::Closed(_)));
}

#[test]
fn idle_recv_packet() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
    assert_eq!(client.stream_send(0, b"hello").unwrap(), 5);

    // Respond with another packet
    let out = client.process(None, now + Duration::from_secs(10));
    server.process_input(out.dgram().unwrap(), now + Duration::from_secs(10));
    assert_eq!(server.stream_send(0, b"world").unwrap(), 5);
    let out = server.process_output(now + Duration::from_secs(10));
    assert_ne!(out.as_dgram_ref(), None);

    let _ = client.process(out.dgram(), now + Duration::from_secs(20));
    assert!(matches!(client.state(), State::Confirmed));

    // Still connected after 49 seconds because idle timer reset by received
    // packet
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(19));
    assert!(matches!(client.state(), State::Confirmed));

    // Not connected after 50 seconds.
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(20));

    assert!(matches!(client.state(), State::Closed(_)));
}

#[test]
fn max_data() {
    let mut client = default_client();
    let mut server = default_server();

    const SMALL_MAX_DATA: usize = 16383;

    server
        .set_local_tparam(
            tparams::INITIAL_MAX_DATA,
            TransportParameter::Integer(SMALL_MAX_DATA.try_into().unwrap()),
        )
        .unwrap();

    connect(&mut client, &mut server);

    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    assert_eq!(client.events().count(), 2); // SendStreamWritable, StateChange(connected)
    assert_eq!(stream_id, 2);
    assert_eq!(
        client.stream_avail_send_space(stream_id).unwrap(),
        SMALL_MAX_DATA
    );
    assert_eq!(
        client
            .stream_send(stream_id, &[b'a'; RECV_BUFFER_SIZE])
            .unwrap(),
        SMALL_MAX_DATA
    );
    assert_eq!(client.events().count(), 0);

    assert_eq!(client.stream_send(stream_id, b"hello").unwrap(), 0);
    client
        .send_streams
        .get_mut(stream_id.into())
        .unwrap()
        .mark_as_sent(0, 4096, false);
    assert_eq!(client.events().count(), 0);
    client
        .send_streams
        .get_mut(stream_id.into())
        .unwrap()
        .mark_as_acked(0, 4096, false);
    assert_eq!(client.events().count(), 0);

    assert_eq!(client.stream_send(stream_id, b"hello").unwrap(), 0);
    // no event because still limited by conn max data
    assert_eq!(client.events().count(), 0);

    // Increase max data. Avail space now limited by stream credit
    client.handle_max_data(100_000_000);
    assert_eq!(
        client.stream_avail_send_space(stream_id).unwrap(),
        SEND_BUFFER_SIZE - SMALL_MAX_DATA
    );

    // Increase max stream data. Avail space now limited by tx buffer
    client
        .send_streams
        .get_mut(stream_id.into())
        .unwrap()
        .set_max_stream_data(100_000_000);
    assert_eq!(
        client.stream_avail_send_space(stream_id).unwrap(),
        SEND_BUFFER_SIZE - SMALL_MAX_DATA + 4096
    );

    let evts = client.events().collect::<Vec<_>>();
    assert_eq!(evts.len(), 1);
    assert!(matches!(evts[0], ConnectionEvent::SendStreamWritable{..}));
}

// Test that we split crypto data if they cannot fit into one packet.
// To test this we will use a long server certificate.
#[test]
fn crypto_frame_split() {
    let mut client = default_client();

    let mut server = Connection::new_server(
        test_fixture::LONG_CERT_KEYS,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(6))),
        QuicVersion::default(),
    )
    .expect("create a server");

    let client1 = client.process(None, now());
    assert!(client1.as_dgram_ref().is_some());

    // The entire server flight doesn't fit in a single packet because the
    // certificate is large, therefore the server will produce 2 packets.
    let server1 = server.process(client1.dgram(), now());
    assert!(server1.as_dgram_ref().is_some());
    let server2 = server.process(None, now());
    assert!(server2.as_dgram_ref().is_some());

    let client2 = client.process(server1.dgram(), now());
    // This is an ack.
    assert!(client2.as_dgram_ref().is_some());
    // The client might have the certificate now, so we can't guarantee that
    // this will work.
    let auth1 = maybe_authenticate(&mut client);
    assert_eq!(*client.state(), State::Handshaking);

    // let server process the ack for the first packet.
    let server3 = server.process(client2.dgram(), now());
    assert!(server3.as_dgram_ref().is_none());

    // Consume the second packet from the server.
    let client3 = client.process(server2.dgram(), now());

    // Check authentication.
    let auth2 = maybe_authenticate(&mut client);
    assert!(auth1 ^ auth2);
    // Now client has all data to finish handshake.
    assert_eq!(*client.state(), State::Connected);

    let client4 = client.process(server3.dgram(), now());
    // One of these will contain data depending on whether Authentication was completed
    // after the first or second server packet.
    assert!(client3.as_dgram_ref().is_some() ^ client4.as_dgram_ref().is_some());

    let _ = server.process(client3.dgram(), now());
    let _ = server.process(client4.dgram(), now());

    assert_eq!(*client.state(), State::Connected);
    assert_eq!(*server.state(), State::Confirmed);
}

#[test]
fn set_local_tparam() {
    let client = default_client();

    client
        .set_local_tparam(tparams::INITIAL_MAX_DATA, TransportParameter::Integer(55))
        .unwrap()
}

#[test]
// If we send a stop_sending to the peer, we should not accept more data from the peer.
fn do_not_accept_data_after_stop_sending() {
    // Note that the two servers in this test will get different anti-replay filters.
    // That's OK because we aren't testing anti-replay.
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    // create a stream
    let stream_id = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream_id, &[0x00]).unwrap();
    let out = client.process(None, now());
    let _ = server.process(out.dgram(), now());

    let stream_readable = |e| matches!(e, ConnectionEvent::RecvStreamReadable {..});
    assert!(server.events().any(stream_readable));

    // Send one more packet from client. The packet should arrive after the server
    // has already requested stop_sending.
    client.stream_send(stream_id, &[0x00]).unwrap();
    let out_second_data_frame = client.process(None, now());
    // Call stop sending.
    assert_eq!(
        Ok(()),
        server.stream_stop_sending(stream_id, Error::NoError.code())
    );

    // Receive the second data frame. The frame should be ignored and now
    // DataReadable events should be posted.
    let out = server.process(out_second_data_frame.dgram(), now());
    assert!(!server.events().any(stream_readable));

    let _ = client.process(out.dgram(), now());
    assert_eq!(
        Err(Error::FinalSizeError),
        client.stream_send(stream_id, &[0x00])
    );
}

#[test]
// Server sends stop_sending, the client simultaneous sends reset.
fn simultaneous_stop_sending_and_reset() {
    // Note that the two servers in this test will get different anti-replay filters.
    // That's OK because we aren't testing anti-replay.
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    // create a stream
    let stream_id = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream_id, &[0x00]).unwrap();
    let out = client.process(None, now());
    let _ = server.process(out.dgram(), now());

    let stream_readable = |e| matches!(e, ConnectionEvent::RecvStreamReadable {..});
    assert!(server.events().any(stream_readable));

    // The client resets the stream. The packet with reset should arrive after the server
    // has already requested stop_sending.
    client
        .stream_reset_send(stream_id, Error::NoError.code())
        .unwrap();
    let out_reset_frame = client.process(None, now());
    // Call stop sending.
    assert_eq!(
        Ok(()),
        server.stream_stop_sending(stream_id, Error::NoError.code())
    );

    // Receive the second data frame. The frame should be ignored and now
    // DataReadable events should be posted.
    let out = server.process(out_reset_frame.dgram(), now());
    assert!(!server.events().any(stream_readable));

    // The client gets the STOP_SENDING frame.
    let _ = client.process(out.dgram(), now());
    assert_eq!(
        Err(Error::InvalidStreamId),
        client.stream_send(stream_id, &[0x00])
    );
}

#[test]
fn test_client_fin_reorder() {
    let mut client = default_client();
    let mut server = default_server();

    // Send ClientHello.
    let client_hs = client.process(None, now());
    assert!(client_hs.as_dgram_ref().is_some());

    let server_hs = server.process(client_hs.dgram(), now());
    assert!(server_hs.as_dgram_ref().is_some()); // ServerHello, etc...

    let client_ack = client.process(server_hs.dgram(), now());
    assert!(client_ack.as_dgram_ref().is_some());

    let server_out = server.process(client_ack.dgram(), now());
    assert!(server_out.as_dgram_ref().is_none());

    assert!(maybe_authenticate(&mut client));
    assert_eq!(*client.state(), State::Connected);

    let client_fin = client.process(None, now());
    assert!(client_fin.as_dgram_ref().is_some());

    let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream_id, &[1, 2, 3]).unwrap();
    let client_stream_data = client.process(None, now());
    assert!(client_stream_data.as_dgram_ref().is_some());

    // Now stream data gets before client_fin
    let server_out = server.process(client_stream_data.dgram(), now());
    assert!(server_out.as_dgram_ref().is_none()); // the packet will be discarded

    assert_eq!(*server.state(), State::Handshaking);
    let server_out = server.process(client_fin.dgram(), now());
    assert!(server_out.as_dgram_ref().is_some());
}

#[test]
fn pto_works_basic() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let mut now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    // Send data on two streams
    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, b"hello").unwrap(), 5);
    assert_eq!(client.stream_send(2, b" world").unwrap(), 6);

    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 6);
    assert_eq!(client.stream_send(6, b"there!").unwrap(), 6);

    // Send a packet after some time.
    now += Duration::from_secs(10);
    let out = client.process(None, now);
    assert!(out.dgram().is_some());

    // Nothing to do, should return callback
    let out = client.process(None, now);
    assert!(matches!(out, Output::Callback(_)));

    // One second later, it should want to send PTO packet
    now += AT_LEAST_PTO;
    let out = client.process(None, now);

    let frames = server.test_process_input(out.dgram().unwrap(), now);

    assert!(frames.iter().all(|(_, sp)| *sp == PNSpace::ApplicationData));
    assert!(frames.iter().any(|(f, _)| *f == Frame::Ping));
    assert!(frames
        .iter()
        .any(|(f, _)| matches!(f, Frame::Stream { stream_id, .. } if stream_id.as_u64() == 2)));
    assert!(frames
        .iter()
        .any(|(f, _)| matches!(f, Frame::Stream { stream_id, .. } if stream_id.as_u64() == 6)));
}

#[test]
fn pto_works_full_cwnd() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let res = client.process(None, now());
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    // Send lots of data.
    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    let (dgrams, now) = fill_cwnd(&mut client, 2, now());
    assert_full_cwnd(&dgrams, POST_HANDSHAKE_CWND);

    // Fill the CWND after waiting for a PTO.
    let (dgrams, now) = fill_cwnd(&mut client, 2, now + AT_LEAST_PTO);
    assert_eq!(dgrams.len(), 2); // Two packets in the PTO.

    // All (2) datagrams contain one PING frame and at least one STREAM frame.
    for d in dgrams {
        assert_eq!(d.len(), PATH_MTU_V6);
        let frames = server.test_process_input(d, now);
        assert_eq!(
            frames
                .iter()
                .filter(|i| matches!(i, (Frame::Ping, PNSpace::ApplicationData)))
                .count(),
            1
        );
        assert!(
            frames
                .iter()
                .filter(|i| matches!(i, (Frame::Stream { .. }, PNSpace::ApplicationData)))
                .count()
                >= 1
        );
    }
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn pto_works_ping() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    // Send "zero" pkt
    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, b"zero").unwrap(), 4);
    let pkt0 = client.process(None, now + Duration::from_secs(10));
    assert!(matches!(pkt0, Output::Datagram(_)));

    // Send "one" pkt
    assert_eq!(client.stream_send(2, b"one").unwrap(), 3);
    let pkt1 = client.process(None, now + Duration::from_secs(10));

    // Send "two" pkt
    assert_eq!(client.stream_send(2, b"two").unwrap(), 3);
    let pkt2 = client.process(None, now + Duration::from_secs(10));

    // Send "three" pkt
    assert_eq!(client.stream_send(2, b"three").unwrap(), 5);
    let pkt3 = client.process(None, now + Duration::from_secs(10));

    // Nothing to do, should return callback
    let out = client.process(None, now + Duration::from_secs(10));
    // Check callback delay is what we expect
    assert!(matches!(out, Output::Callback(x) if x == Duration::from_millis(45)));

    // Process these by server, skipping pkt0
    let srv0_pkt1 = server.process(pkt1.dgram(), now + Duration::from_secs(10));
    // ooo, ack client pkt 1
    assert!(matches!(srv0_pkt1, Output::Datagram(_)));

    // process pkt2 (no ack yet)
    let srv2 = server.process(
        pkt2.dgram(),
        now + Duration::from_secs(10) + Duration::from_millis(20),
    );
    assert!(matches!(srv2, Output::Callback(_)));

    // process pkt3 (acked)
    let srv2 = server.process(
        pkt3.dgram(),
        now + Duration::from_secs(10) + Duration::from_millis(20),
    );
    // ack client pkt 2 & 3
    assert!(matches!(srv2, Output::Datagram(_)));

    // client processes ack
    let pkt4 = client.process(
        srv2.dgram(),
        now + Duration::from_secs(10) + Duration::from_millis(40),
    );
    // client resends data from pkt0
    assert!(matches!(pkt4, Output::Datagram(_)));

    // server sees ooo pkt0 and generates ack
    let srv_pkt2 = server.process(
        pkt0.dgram(),
        now + Duration::from_secs(10) + Duration::from_millis(40),
    );
    assert!(matches!(srv_pkt2, Output::Datagram(_)));

    // Orig data is acked
    let pkt5 = client.process(
        srv_pkt2.dgram(),
        now + Duration::from_secs(10) + Duration::from_millis(40),
    );
    assert!(matches!(pkt5, Output::Callback(_)));

    // PTO expires. No unacked data. Only send PING.
    let pkt6 = client.process(
        None,
        now + Duration::from_secs(10) + Duration::from_millis(110),
    );

    let frames = server.test_process_input(
        pkt6.dgram().unwrap(),
        now + Duration::from_secs(10) + Duration::from_millis(110),
    );

    assert_eq!(frames[0], (Frame::Ping, PNSpace::ApplicationData));
}

#[test]
fn pto_initial() {
    const INITIAL_PTO: Duration = Duration::from_millis(300);
    let mut now = now();

    qdebug!("---- client: generate CH");
    let mut client = default_client();
    let pkt1 = client.process(None, now).dgram();
    assert!(pkt1.is_some());
    assert_eq!(pkt1.clone().unwrap().len(), PATH_MTU_V6);

    let delay = client.process(None, now).callback();
    assert_eq!(delay, INITIAL_PTO);

    // Resend initial after PTO.
    now += delay;
    let pkt2 = client.process(None, now).dgram();
    assert!(pkt2.is_some());
    assert_eq!(pkt2.unwrap().len(), PATH_MTU_V6);

    let pkt3 = client.process(None, now).dgram();
    assert!(pkt3.is_some());
    assert_eq!(pkt3.unwrap().len(), PATH_MTU_V6);

    let delay = client.process(None, now).callback();
    // PTO has doubled.
    assert_eq!(delay, INITIAL_PTO * 2);

    // Server process the first initial pkt.
    let mut server = default_server();
    let out = server.process(pkt1, now).dgram();
    assert!(out.is_some());

    // Client receives ack for the first initial packet as well a Handshake packet.
    // After the handshake packet the initial keys and the crypto stream for the initial
    // packet number space will be discarded.
    // Here only an ack for the Handshake packet will be sent.
    let out = client.process(out, now).dgram();
    assert!(out.is_some());

    // We do not have PTO for the resent initial packet any more, but
    // the Handshake PTO timer should be armed.  As the RTT is apparently
    // the same as the initial PTO value, and there is only one sample,
    // the PTO will be 3x the INITIAL PTO.
    let delay = client.process(None, now).callback();
    assert_eq!(delay, INITIAL_PTO * 3);
}

/// A complete handshake that involves a PTO in the Handshake space.
#[test]
fn pto_handshake_complete() {
    let mut now = now();
    // start handshake
    let mut client = default_client();
    let mut server = default_server();

    let pkt = client.process(None, now).dgram();
    let cb = client.process(None, now).callback();
    assert_eq!(cb, Duration::from_millis(300));

    now += Duration::from_millis(10);
    let pkt = server.process(pkt, now).dgram();

    now += Duration::from_millis(10);
    let pkt = client.process(pkt, now).dgram();

    let cb = client.process(None, now).callback();
    // The client now has a single RTT estimate (20ms), so
    // the handshake PTO is set based on that.
    assert_eq!(cb, Duration::from_millis(60));

    now += Duration::from_millis(10);
    let pkt = server.process(pkt, now).dgram();
    assert!(pkt.is_none());

    now += Duration::from_millis(10);
    client.authenticated(AuthenticationStatus::Ok, now);

    qdebug!("---- client: SH..FIN -> FIN");
    let pkt1 = client.process(None, now).dgram();
    assert!(pkt1.is_some());

    let cb = client.process(None, now).callback();
    assert_eq!(cb, Duration::from_millis(60));

    // Wait for PTO to expire and resend a handshake packet
    now += Duration::from_millis(60);
    let pkt2 = client.process(None, now).dgram();
    assert!(pkt2.is_some());

    // Get a second PTO packet.
    let pkt3 = client.process(None, now).dgram();
    assert!(pkt3.is_some());

    // PTO has been doubled.
    let cb = client.process(None, now).callback();
    assert_eq!(cb, Duration::from_millis(120));

    now += Duration::from_millis(10);
    // Server receives the first packet.
    // The output will be a Handshake packet with an ack and a app pn space packet with
    // HANDSHAKE_DONE.
    let pkt = server.process(pkt1, now).dgram();
    assert!(pkt.is_some());

    // Check that the PTO packets (pkt2, pkt3) are Handshake packets.
    // The server discarded the Handshake keys already, therefore they are dropped.
    let dropped_before = server.stats().dropped_rx;
    let frames = server.test_process_input(pkt2.unwrap(), now);
    assert_eq!(1, server.stats().dropped_rx - dropped_before);
    assert!(frames.is_empty());

    let dropped_before = server.stats().dropped_rx;
    let frames = server.test_process_input(pkt3.unwrap(), now);
    assert_eq!(1, server.stats().dropped_rx - dropped_before);
    assert!(frames.is_empty());

    now += Duration::from_millis(10);
    // Client receive ack for the first packet
    let cb = client.process(pkt, now).callback();
    // Ack delay timer for the packet carrying HANDSHAKE_DONE.
    assert_eq!(cb, ACK_DELAY);

    // Let the ack timer expire.
    now += cb;
    let out = client.process(None, now).dgram();
    assert!(out.is_some());
    let cb = client.process(None, now).callback();
    // The handshake keys are discarded, but now we're back to the idle timeout.
    // We don't send another PING because the handshake space is done and there
    // is nothing to probe for.
    assert_eq!(cb, LOCAL_IDLE_TIMEOUT - ACK_DELAY);
}

/// Test that PTO in the Handshake space contains the right frames.
#[test]
fn pto_handshake_frames() {
    let mut now = now();
    qdebug!("---- client: generate CH");
    let mut client = default_client();
    let pkt = client.process(None, now);

    now += Duration::from_millis(10);
    qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
    let mut server = default_server();
    let pkt = server.process(pkt.dgram(), now);

    now += Duration::from_millis(10);
    qdebug!("---- client: cert verification");
    let pkt = client.process(pkt.dgram(), now);

    now += Duration::from_millis(10);
    let _pkt = server.process(pkt.dgram(), now);

    now += Duration::from_millis(10);
    client.authenticated(AuthenticationStatus::Ok, now);

    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, b"zero").unwrap(), 4);
    qdebug!("---- client: SH..FIN -> FIN and 1RTT packet");
    let pkt1 = client.process(None, now).dgram();
    assert!(pkt1.is_some());

    // Get PTO timer.
    let out = client.process(None, now);
    assert_eq!(out, Output::Callback(Duration::from_millis(60)));

    // Wait for PTO to expire and resend a handshake packet.
    now += Duration::from_millis(60);
    let pkt2 = client.process(None, now).dgram();
    assert!(pkt2.is_some());

    now += Duration::from_millis(10);
    let frames = server.test_process_input(pkt2.unwrap(), now);

    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], (Frame::Ping, PNSpace::Handshake));
    assert!(matches!(
        frames[1],
        (Frame::Crypto { .. }, PNSpace::Handshake)
    ));
}

/// In the case that the Handshake takes too many packets, the server might
/// be stalled on the anti-amplification limit.  If a Handshake ACK from the
/// client is lost, the client has to keep the PTO timer armed or the server
/// might be unable to send anything, causing a deadlock.
#[test]
fn handshake_ack_pto() {
    const RTT: Duration = Duration::from_millis(10);
    let mut now = now();
    let mut client = default_client();
    let mut server = default_server();
    // This is a greasing transport parameter, and large enough that the
    // server needs to send two Handshake packets.
    let big = TransportParameter::Bytes(vec![0; PATH_MTU_V6]);
    server.set_local_tparam(0xce16, big).unwrap();

    let c1 = client.process(None, now).dgram();

    now += RTT / 2;
    let s1 = server.process(c1, now).dgram();
    assert!(s1.is_some());
    let s2 = server.process(None, now).dgram();
    assert!(s1.is_some());

    // Now let the client have the Initial, but drop the first coalesced Handshake packet.
    now += RTT / 2;
    let (initial, _) = split_datagram(s1.unwrap());
    client.process_input(initial, now);
    let c2 = client.process(s2, now).dgram();
    assert!(c2.is_some()); // This is an ACK.  Drop it.
    let delay = client.process(None, now).callback();
    assert_eq!(delay, RTT * 3);

    // Wait for the PTO and ensure that the client generates a packet.
    now += delay;
    let c3 = client.process(None, now).dgram();
    assert!(c3.is_some());

    now += RTT / 2;
    let frames = server.test_process_input(c3.unwrap(), now);
    assert_eq!(frames, vec![(Frame::Ping, PNSpace::Handshake)]);

    // Now complete the handshake as cheaply as possible.
    let dgram = server.process(None, now).dgram();
    client.process_input(dgram.unwrap(), now);
    maybe_authenticate(&mut client);
    let dgram = client.process(None, now).dgram();
    assert_eq!(*client.state(), State::Connected);
    let dgram = server.process(dgram, now).dgram();
    assert_eq!(*server.state(), State::Confirmed);
    client.process_input(dgram.unwrap(), now);
    assert_eq!(*client.state(), State::Confirmed);
}

#[test]
// Absent path PTU discovery, max v6 packet size should be PATH_MTU_V6.
fn verify_pkt_honors_mtu() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    // Try to send a large stream and verify first packet is correctly sized
    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, &[0xbb; 2000]).unwrap(), 2000);
    let pkt0 = client.process(None, now);
    assert!(matches!(pkt0, Output::Datagram(_)));
    assert_eq!(pkt0.as_dgram_ref().unwrap().len(), PATH_MTU_V6);
}

/// This fills the congestion window from a single source.
/// As the pacer will interfere with this, this moves time forward
/// as `Output::Callback` is received.  Because it is hard to tell
/// from the return value whether a timeout is an ACK delay, PTO, or
/// pacing, this looks at the congestion window to tell when to stop.
/// Returns a list of datagrams and the new time.
fn fill_cwnd(src: &mut Connection, stream: u64, mut now: Instant) -> (Vec<Datagram>, Instant) {
    const BLOCK_SIZE: usize = 4_096;
    let mut total_dgrams = Vec::new();

    qtrace!(
        "fill_cwnd starting cwnd: {}",
        src.loss_recovery.cwnd_avail()
    );

    loop {
        let bytes_sent = src.stream_send(stream, &[0x42; BLOCK_SIZE]).unwrap();
        qtrace!("fill_cwnd wrote {} bytes", bytes_sent);
        if bytes_sent < BLOCK_SIZE {
            break;
        }
    }

    loop {
        let pkt = src.process_output(now);
        qtrace!(
            "fill_cwnd cwnd remaining={}, output: {:?}",
            src.loss_recovery.cwnd_avail(),
            pkt
        );
        match pkt {
            Output::Datagram(dgram) => {
                total_dgrams.push(dgram);
            }
            Output::Callback(t) => {
                if src.loss_recovery.cwnd_avail() < ACK_ONLY_SIZE_LIMIT {
                    break;
                }
                now += t;
            }
            _ => panic!(),
        }
    }

    (total_dgrams, now)
}

// Receive multiple packets and generate an ack-only packet.
fn ack_bytes<D>(
    dest: &mut Connection,
    stream: u64,
    in_dgrams: D,
    now: Instant,
) -> (Vec<Datagram>, Vec<Frame>)
where
    D: IntoIterator<Item = Datagram>,
    D::IntoIter: ExactSizeIterator,
{
    let mut srv_buf = [0; 4_096];
    let mut recvd_frames = Vec::new();

    let in_dgrams = in_dgrams.into_iter();
    qdebug!([dest], "ack_bytes {} datagrams", in_dgrams.len());
    for dgram in in_dgrams {
        recvd_frames.extend(dest.test_process_input(dgram, now));
    }

    loop {
        let (bytes_read, _fin) = dest.stream_recv(stream, &mut srv_buf).unwrap();
        qtrace!([dest], "ack_bytes read {} bytes", bytes_read);
        if bytes_read == 0 {
            break;
        }
    }

    let mut tx_dgrams = Vec::new();
    while let Output::Datagram(dg) = dest.process_output(now) {
        tx_dgrams.push(dg);
    }

    assert!((tx_dgrams.len() == 1) || (tx_dgrams.len() == 2));

    (
        tx_dgrams,
        recvd_frames.into_iter().map(|(f, _e)| f).collect(),
    )
}

/// This magic number is the size of the client's CWND after the handshake completes.
/// This includes the initial congestion window, as increased as a result
/// receiving acknowledgments for Initial and Handshake packets, which is
/// at least one full packet (the first Initial) and a little extra.
///
/// As we change how we build packets, or even as NSS changes,
/// this number might be different.  The tests that depend on this
/// value could fail as a result of variations, so it's OK to just
/// change this value, but it is good to first understand where the
/// change came from.
const POST_HANDSHAKE_CWND: usize = PATH_MTU_V6 * (CWND_INITIAL_PKTS + 1) + 75;

/// Determine the number of packets required to fill the CWND.
const fn cwnd_packets(data: usize) -> usize {
    (data + ACK_ONLY_SIZE_LIMIT - 1) / PATH_MTU_V6
}

/// Determine the size of the last packet.
/// The minimal size of a packet is `ACK_ONLY_SIZE_LIMIT`.
fn last_packet(cwnd: usize) -> usize {
    if (cwnd % PATH_MTU_V6) > ACK_ONLY_SIZE_LIMIT {
        cwnd % PATH_MTU_V6
    } else {
        PATH_MTU_V6
    }
}

/// Assert that the set of packets fill the CWND.
fn assert_full_cwnd(packets: &[Datagram], cwnd: usize) {
    assert_eq!(packets.len(), cwnd_packets(cwnd));
    let (last, rest) = packets.split_last().unwrap();
    assert!(rest.iter().all(|d| d.len() == PATH_MTU_V6));
    assert_eq!(last.len(), last_packet(cwnd));
}

#[test]
/// Verify initial CWND is honored.
fn cc_slow_start() {
    let mut client = default_client();
    let mut server = default_server();

    server
        .set_local_tparam(
            tparams::INITIAL_MAX_DATA,
            TransportParameter::Integer(65536),
        )
        .unwrap();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    // Try to send a lot of data
    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    let (c_tx_dgrams, _) = fill_cwnd(&mut client, 2, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);
    assert!(client.loss_recovery.cwnd_avail() < ACK_ONLY_SIZE_LIMIT);
}

#[test]
/// Verify that CC moves to cong avoidance when a packet is marked lost.
fn cc_slow_start_to_cong_avoidance_recovery_period() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, now) = fill_cwnd(&mut client, 0, now());
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);
    // Predict the packet number of the last packet sent.
    // We have already sent one packet in `connect_force_idle` (an ACK),
    // so this will be equal to the number of packets in this flight.
    let flight1_largest = PacketNumber::try_from(c_tx_dgrams.len()).unwrap();

    // Server: Receive and generate ack
    let (s_tx_dgram, _recvd_frames) = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // Client: Process ack
    for dgram in s_tx_dgram {
        let recvd_frames = client.test_process_input(dgram, now);

        // Verify that server-sent frame was what we thought.
        if let (
            Frame::Ack {
                largest_acknowledged,
                ..
            },
            PNSpace::ApplicationData,
        ) = recvd_frames[0]
        {
            assert_eq!(largest_acknowledged, flight1_largest);
        } else {
            panic!("Expected an application ACK");
        }
    }

    // Client: send more
    let (mut c_tx_dgrams, now) = fill_cwnd(&mut client, 0, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND * 2);
    let flight2_largest = flight1_largest + u64::try_from(c_tx_dgrams.len()).unwrap();

    // Server: Receive and generate ack again, but drop first packet
    c_tx_dgrams.remove(0);
    let (s_tx_dgram, _recvd_frames) = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // Client: Process ack
    for dgram in s_tx_dgram {
        let recvd_frames = client.test_process_input(dgram, now);

        // Verify that server-sent frame was what we thought.
        if let (
            Frame::Ack {
                largest_acknowledged,
                ..
            },
            PNSpace::ApplicationData,
        ) = recvd_frames[0]
        {
            assert_eq!(largest_acknowledged, flight2_largest);
        } else {
            panic!("Expected an application ACK");
        }
    }

    // If we just triggered cong avoidance, these should be equal
    assert_eq!(client.loss_recovery.cwnd(), client.loss_recovery.ssthresh());
}

#[test]
/// Verify that CC stays in recovery period when packet sent before start of
/// recovery period is acked.
fn cc_cong_avoidance_recovery_period_unchanged() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (mut c_tx_dgrams, now) = fill_cwnd(&mut client, 0, now());
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Drop 0th packet. When acked, this should put client into CARP.
    c_tx_dgrams.remove(0);

    let c_tx_dgrams2 = c_tx_dgrams.split_off(5);

    // Server: Receive and generate ack
    let (s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams, now);
    for dgram in s_tx_dgram {
        client.test_process_input(dgram, now);
    }

    // If we just triggered cong avoidance, these should be equal
    let cwnd1 = client.loss_recovery.cwnd();
    assert_eq!(cwnd1, client.loss_recovery.ssthresh());

    // Generate ACK for more received packets
    let (s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams2, now);

    // ACK more packets but they were sent before end of recovery period
    for dgram in s_tx_dgram {
        client.test_process_input(dgram, now);
    }

    // cwnd should not have changed since ACKed packets were sent before
    // recovery period expired
    let cwnd2 = client.loss_recovery.cwnd();
    assert_eq!(cwnd1, cwnd2);
}

#[test]
/// Verify that CC moves out of recovery period when packet sent after start
/// of recovery period is acked.
fn cc_cong_avoidance_recovery_period_to_cong_avoidance() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (mut c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now());

    // Drop 0th packet. When acked, this should put client into CARP.
    c_tx_dgrams.remove(0);

    // Server: Receive and generate ack
    let (s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // Client: Process ack
    for dgram in s_tx_dgram {
        client.test_process_input(dgram, now);
    }

    // Should be in CARP now.

    now += Duration::from_millis(10); // Time passes. CARP -> CA

    // Now make sure that we increase congestion window according to the
    // accurate byte counting version of congestion avoidance.
    // Check over several increases to be sure.
    let mut expected_cwnd = client.loss_recovery.cwnd();
    for i in 0..5 {
        println!("{}", i);
        // Client: Send more data
        let (mut c_tx_dgrams, next_now) = fill_cwnd(&mut client, 0, now);
        now = next_now;

        let c_tx_size: usize = c_tx_dgrams.iter().map(|d| d.len()).sum();
        println!(
            "client sending {} bytes into cwnd of {}",
            c_tx_size,
            client.loss_recovery.cwnd()
        );
        assert_eq!(c_tx_size, expected_cwnd);

        // Until we process all the packets, the congestion window remains the same.
        // Note that we need the client to process ACK frames in stages, so split the
        // datagrams into two, ensuring that we allow for an ACK for each batch.
        let most = c_tx_dgrams.len() - MAX_UNACKED_PKTS - 1;
        let (s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams.drain(..most), now);
        for dgram in s_tx_dgram {
            assert_eq!(client.loss_recovery.cwnd(), expected_cwnd);
            client.process_input(dgram, now);
        }
        let (s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams, now);
        for dgram in s_tx_dgram {
            assert_eq!(client.loss_recovery.cwnd(), expected_cwnd);
            client.process_input(dgram, now);
        }
        expected_cwnd += MAX_DATAGRAM_SIZE;
        assert_eq!(client.loss_recovery.cwnd(), expected_cwnd);
    }
}

fn induce_persistent_congestion(
    client: &mut Connection,
    server: &mut Connection,
    mut now: Instant,
) -> Instant {
    // Note: wait some arbitrary time that should be longer than pto
    // timer. This is rather brittle.
    now += AT_LEAST_PTO;

    qtrace!([client], "first PTO");
    let (c_tx_dgrams, next_now) = fill_cwnd(client, 0, now);
    now = next_now;
    assert_eq!(c_tx_dgrams.len(), 2); // Two PTO packets

    qtrace!([client], "second PTO");
    now += AT_LEAST_PTO * 2;
    let (c_tx_dgrams, next_now) = fill_cwnd(client, 0, now);
    now = next_now;
    assert_eq!(c_tx_dgrams.len(), 2); // Two PTO packets

    qtrace!([client], "third PTO");
    now += AT_LEAST_PTO * 4;
    let (c_tx_dgrams, next_now) = fill_cwnd(client, 0, now);
    now = next_now;
    assert_eq!(c_tx_dgrams.len(), 2); // Two PTO packets

    // Generate ACK
    let (s_tx_dgram, _) = ack_bytes(server, 0, c_tx_dgrams, now);

    // An ACK for the third PTO causes persistent congestion.
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    assert_eq!(client.loss_recovery.cwnd(), CWND_MIN);
    now
}

#[test]
/// Verify transition to persistent congestion state if conditions are met.
fn cc_slow_start_to_persistent_congestion_no_acks() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now());
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Server: Receive and generate ack
    now += Duration::from_millis(100);
    let (_s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // ACK lost.

    induce_persistent_congestion(&mut client, &mut server, now);
}

#[test]
/// Verify transition to persistent congestion state if conditions are met.
fn cc_slow_start_to_persistent_congestion_some_acks() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now());
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Server: Receive and generate ack
    now += Duration::from_millis(100);
    let (s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    now += Duration::from_millis(100);
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    // send bytes that will be lost
    let (_c_tx_dgrams, next_now) = fill_cwnd(&mut client, 0, now);
    now = next_now + Duration::from_millis(100);

    induce_persistent_congestion(&mut client, &mut server, now);
}

#[test]
/// Verify persistent congestion moves to slow start after recovery period
/// ends.
fn cc_persistent_congestion_to_slow_start() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now());
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Server: Receive and generate ack
    now += Duration::from_millis(10);
    let (_s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // ACK lost.

    now = induce_persistent_congestion(&mut client, &mut server, now);

    // New part of test starts here

    now += Duration::from_millis(10);

    // Send packets from after start of CARP
    let (c_tx_dgrams, next_now) = fill_cwnd(&mut client, 0, now);
    assert_eq!(c_tx_dgrams.len(), 2);

    // Server: Receive and generate ack
    now = next_now + Duration::from_millis(100);
    let (s_tx_dgram, _) = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // No longer in CARP. (pkts acked from after start of CARP)
    // Should be in slow start now.
    for dgram in s_tx_dgram {
        client.test_process_input(dgram, now);
    }

    // ACKing 2 packets should let client send 4.
    let (c_tx_dgrams, _) = fill_cwnd(&mut client, 0, now);
    assert_eq!(c_tx_dgrams.len(), 4);
}

fn check_discarded(peer: &mut Connection, pkt: Datagram, dropped: usize, dups: usize) {
    // Make sure to flush any saved datagrams before doing this.
    let _ = peer.process_output(now());

    let before = peer.stats();
    let out = peer.process(Some(pkt), now());
    assert!(out.as_dgram_ref().is_none());
    let after = peer.stats();
    assert_eq!(dropped, after.dropped_rx - before.dropped_rx);
    assert_eq!(dups, after.dups_rx - before.dups_rx);
}

#[test]
fn discarded_initial_keys() {
    qdebug!("---- client: generate CH");
    let mut client = default_client();
    let init_pkt_c = client.process(None, now()).dgram();
    assert!(init_pkt_c.is_some());
    assert_eq!(init_pkt_c.as_ref().unwrap().len(), PATH_MTU_V6);

    qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
    let mut server = default_server();
    let init_pkt_s = server.process(init_pkt_c.clone(), now()).dgram();
    assert!(init_pkt_s.is_some());

    qdebug!("---- client: cert verification");
    let out = client.process(init_pkt_s.clone(), now()).dgram();
    assert!(out.is_some());

    // The client has received handshake packet. It will remove the Initial keys.
    // We will check this by processing init_pkt_s a second time.
    // The initial packet should be dropped. The packet contains a Handshake packet as well, which
    // will be marked as dup.
    check_discarded(&mut client, init_pkt_s.unwrap(), 1, 1);

    assert!(maybe_authenticate(&mut client));

    // The server has not removed the Initial keys yet, because it has not yet received a Handshake
    // packet from the client.
    // We will check this by processing init_pkt_c a second time.
    // The dropped packet is padding. The Initial packet has been mark dup.
    check_discarded(&mut server, init_pkt_c.clone().unwrap(), 1, 1);

    qdebug!("---- client: SH..FIN -> FIN");
    let out = client.process(None, now()).dgram();
    assert!(out.is_some());

    // The server will process the first Handshake packet.
    // After this the Initial keys will be dropped.
    let out = server.process(out, now()).dgram();
    assert!(out.is_some());

    // Check that the Initial keys are dropped at the server
    // We will check this by processing init_pkt_c a third time.
    // The Initial packet has been dropped and padding that follows it.
    // There is no dups, everything has been dropped.
    check_discarded(&mut server, init_pkt_c.unwrap(), 1, 0);
}

/// Send something on a stream from `sender` to `receiver`.
/// Return the resulting datagram.
#[must_use]
fn send_something(sender: &mut Connection, now: Instant) -> Datagram {
    let stream_id = sender.stream_create(StreamType::UniDi).unwrap();
    assert!(sender.stream_send(stream_id, DEFAULT_STREAM_DATA).is_ok());
    assert!(sender.stream_close_send(stream_id).is_ok());
    qdebug!([sender], "send_something on {}", stream_id);
    let dgram = sender.process(None, now).dgram();
    dgram.expect("should have something to send")
}

/// Send something on a stream from `sender` to `receiver`.
/// Return any ACK that might result.
fn send_and_receive(
    sender: &mut Connection,
    receiver: &mut Connection,
    now: Instant,
) -> Option<Datagram> {
    let dgram = send_something(sender, now);
    receiver.process(Some(dgram), now).dgram()
}

#[test]
fn key_update_client() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let mut now = now();

    assert_eq!(client.get_epochs(), (Some(3), Some(3))); // (write, read)
    assert_eq!(server.get_epochs(), (Some(3), Some(3)));

    // TODO(mt) this needs to wait for handshake confirmation,
    // but for now, we can do this immediately.
    assert!(client.initiate_key_update().is_ok());
    assert!(client.initiate_key_update().is_err());

    // Initiating an update should only increase the write epoch.
    assert_eq!(
        Output::Callback(LOCAL_IDLE_TIMEOUT),
        client.process(None, now)
    );
    assert_eq!(client.get_epochs(), (Some(4), Some(3)));

    // Send something to propagate the update.
    assert!(send_and_receive(&mut client, &mut server, now).is_none());

    // The server should now be waiting to discharge read keys.
    assert_eq!(server.get_epochs(), (Some(4), Some(3)));
    let res = server.process(None, now);
    if let Output::Callback(t) = res {
        assert!(t < LOCAL_IDLE_TIMEOUT);
    } else {
        panic!("server should now be waiting to clear keys");
    }

    // Without having had time to purge old keys, more updates are blocked.
    // The spec would permits it at this point, but we are more conservative.
    assert!(client.initiate_key_update().is_err());
    // The server can't update until it receives an ACK for a packet.
    assert!(server.initiate_key_update().is_err());

    // Waiting now for at least a PTO should cause the server to drop old keys.
    // But at this point the client hasn't received a key update from the server.
    // It will be stuck with old keys.
    now += AT_LEAST_PTO;
    let dgram = client.process(None, now).dgram();
    assert!(dgram.is_some()); // Drop this packet.
    assert_eq!(client.get_epochs(), (Some(4), Some(3)));
    let _ = server.process(None, now);
    assert_eq!(server.get_epochs(), (Some(4), Some(4)));

    // Even though the server has updated, it hasn't received an ACK yet.
    assert!(server.initiate_key_update().is_err());

    // Now get an ACK from the server.
    // The previous PTO packet (see above) was dropped, so we should get an ACK here.
    let dgram = send_and_receive(&mut client, &mut server, now);
    assert!(dgram.is_some());
    let res = client.process(dgram, now);
    // This is the first packet that the client has received from the server
    // with new keys, so its read timer just started.
    if let Output::Callback(t) = res {
        assert!(t < LOCAL_IDLE_TIMEOUT);
    } else {
        panic!("client should now be waiting to clear keys");
    }

    assert!(client.initiate_key_update().is_err());
    assert_eq!(client.get_epochs(), (Some(4), Some(3)));
    // The server can't update until it gets something from the client.
    assert!(server.initiate_key_update().is_err());

    now += AT_LEAST_PTO;
    let _ = client.process(None, now);
    assert_eq!(client.get_epochs(), (Some(4), Some(4)));
}

#[test]
fn key_update_consecutive() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);
    let now = now();

    assert!(server.initiate_key_update().is_ok());
    assert_eq!(server.get_epochs(), (Some(4), Some(3)));

    // Server sends something.
    // Send twice and drop the first to induce an ACK from the client.
    let _ = send_something(&mut server, now); // Drop this.

    // Another packet from the server will cause the client to ACK and update keys.
    let dgram = send_and_receive(&mut server, &mut client, now);
    assert!(dgram.is_some());
    assert_eq!(client.get_epochs(), (Some(4), Some(3)));

    // Have the server process the ACK.
    if let Output::Callback(_) = server.process(dgram, now) {
        assert_eq!(server.get_epochs(), (Some(4), Some(3)));
        // Now move the server temporarily into the future so that it
        // rotates the keys.  The client stays in the present.
        let _ = server.process(None, now + AT_LEAST_PTO);
        assert_eq!(server.get_epochs(), (Some(4), Some(4)));
    } else {
        panic!("server should have a timer set");
    }

    // Now update keys on the server again.
    assert!(server.initiate_key_update().is_ok());
    assert_eq!(server.get_epochs(), (Some(5), Some(4)));

    let dgram = send_something(&mut server, now + AT_LEAST_PTO);

    // However, as the server didn't wait long enough to update again, the
    // client hasn't rotated its keys, so the packet gets dropped.
    check_discarded(&mut client, dgram, 1, 0);
}

// Key updates can't be initiated too early.
#[test]
fn key_update_before_confirmed() {
    let mut client = default_client();
    assert!(client.initiate_key_update().is_err());
    let mut server = default_server();
    assert!(server.initiate_key_update().is_err());

    // Client Initial
    let dgram = client.process(None, now()).dgram();
    assert!(dgram.is_some());
    assert!(client.initiate_key_update().is_err());

    // Server Initial + Handshake
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    assert!(server.initiate_key_update().is_err());

    // Client Handshake
    client.process_input(dgram.unwrap(), now());
    assert!(client.initiate_key_update().is_err());

    assert!(maybe_authenticate(&mut client));
    assert!(client.initiate_key_update().is_err());

    let dgram = client.process(None, now()).dgram();
    assert!(dgram.is_some());
    assert!(client.initiate_key_update().is_err());

    // Server HANDSHAKE_DONE
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    assert!(server.initiate_key_update().is_ok());

    // Client receives HANDSHAKE_DONE
    let dgram = client.process(dgram, now()).dgram();
    assert!(dgram.is_none());
    assert!(client.initiate_key_update().is_ok());
}

#[test]
fn ack_are_not_cc() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Create a stream
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets, so that cc window is filled.
    let (c_tx_dgrams, now) = fill_cwnd(&mut client, 0, now());
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // The server hasn't received any of these packets yet, the server
    // won't ACK, but if it sends an ack-eliciting packet instead.
    qdebug!([server], "Sending ack-eliciting");
    assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 1);
    server.stream_send(1, b"dropped").unwrap();
    let dropped_packet = server.process(None, now).dgram();
    assert!(dropped_packet.is_some()); // Now drop this one.

    // Now the server sends a packet that will force an ACK,
    // because the client will detect a gap.
    server.stream_send(1, b"sent").unwrap();
    let ack_eliciting_packet = server.process(None, now).dgram();
    assert!(ack_eliciting_packet.is_some());

    // The client can ack the server packet even if cc windows is full.
    qdebug!([client], "Process ack-eliciting");
    let ack_pkt = client.process(ack_eliciting_packet, now).dgram();
    assert!(ack_pkt.is_some());
    qdebug!([server], "Handle ACK");
    let frames = server.test_process_input(ack_pkt.unwrap(), now);
    assert_eq!(frames.len(), 1);
    assert!(matches!(
        frames[0],
        (Frame::Ack { .. }, PNSpace::ApplicationData)
    ));
}

#[test]
fn after_fin_is_read_conn_events_for_stream_should_be_removed() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let id = server.stream_create(StreamType::BiDi).unwrap();
    server.stream_send(id, &[6; 10]).unwrap();
    server.stream_close_send(id).unwrap();
    let out = server.process(None, now()).dgram();
    assert!(out.is_some());

    let _ = client.process(out, now());

    // read from the stream before checking connection events.
    let mut buf = vec![0; 4000];
    let (_, fin) = client.stream_recv(id, &mut buf).unwrap();
    assert_eq!(fin, true);

    // Make sure we do not have RecvStreamReadable events for the stream when fin has been read.
    let readable_stream_evt =
        |e| matches!(e, ConnectionEvent::RecvStreamReadable { stream_id } if stream_id == id);
    assert!(!client.events().any(readable_stream_evt));
}

#[test]
fn after_stream_stop_sending_is_called_conn_events_for_stream_should_be_removed() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let id = server.stream_create(StreamType::BiDi).unwrap();
    server.stream_send(id, &[6; 10]).unwrap();
    server.stream_close_send(id).unwrap();
    let out = server.process(None, now()).dgram();
    assert!(out.is_some());

    let _ = client.process(out, now());

    // send stop seending.
    client
        .stream_stop_sending(id, Error::NoError.code())
        .unwrap();

    // Make sure we do not have RecvStreamReadable events for the stream after stream_stop_sending
    // has been called.
    let readable_stream_evt =
        |e| matches!(e, ConnectionEvent::RecvStreamReadable { stream_id } if stream_id == id);
    assert!(!client.events().any(readable_stream_evt));
}

// During the handshake, an application close should be sanitized.
#[test]
fn early_application_close() {
    let mut client = default_client();
    let mut server = default_server();

    // One flight each.
    let dgram = client.process(None, now()).dgram();
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some());

    server.close(now(), 77, String::from(""));
    assert!(server.state().closed());
    let dgram = server.process(None, now()).dgram();
    assert!(dgram.is_some());

    let frames = client.test_process_input(dgram.unwrap(), now());
    assert!(matches!(
        frames[0],
        (
            Frame::ConnectionClose {
                error_code: CloseError::Transport(code),
                ..
            },
            PNSpace::Initial,
        ) if code == Error::ApplicationError.code()
    ));
    assert!(client.state().closed());
}

#[test]
fn bad_tls_version() {
    let mut client = default_client();
    // Do a bad, bad thing.
    client
        .crypto
        .tls
        .set_option(neqo_crypto::Opt::Tls13CompatMode, true)
        .unwrap();
    let mut server = default_server();
    let dgram = client.process(None, now()).dgram();
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram();
    assert_eq!(
        *server.state(),
        State::Closed(ConnectionError::Transport(Error::ProtocolViolation))
    );
    assert!(dgram.is_some());
    let frames = client.test_process_input(dgram.unwrap(), now());
    assert!(matches!(
        frames[0],
        (
            Frame::ConnectionClose {
                error_code: CloseError::Transport(_),
                ..
            },
            PNSpace::Initial,
        )
    ));
}

#[test]
fn pace() {
    const RTT: Duration = Duration::from_millis(1000);
    const DATA: &[u8] = &[0xcc; 4_096];
    let mut client = default_client();
    let mut server = default_server();
    let mut now = connect_rtt_idle(&mut client, &mut server, RTT);

    // Now fill up the pipe and watch it trickle out.
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    loop {
        let written = client.stream_send(stream, DATA).unwrap();
        if written < DATA.len() {
            break;
        }
    }
    let mut count = 0;
    // We should get a burst at first.
    for _ in 0..PACING_BURST_SIZE {
        let dgram = client.process_output(now).dgram();
        assert!(dgram.is_some());
        count += 1;
    }
    let gap = client.process_output(now).callback();
    assert_ne!(gap, Duration::new(0, 0));
    for _ in PACING_BURST_SIZE..cwnd_packets(POST_HANDSHAKE_CWND) {
        assert_eq!(client.process_output(now).callback(), gap);
        now += gap;
        let dgram = client.process_output(now).dgram();
        assert!(dgram.is_some());
        count += 1;
    }
    assert_eq!(count, cwnd_packets(POST_HANDSHAKE_CWND));
    let fin = client.process_output(now).callback();
    assert_ne!(fin, Duration::new(0, 0));
    assert_ne!(fin, gap);
}

#[test]
fn loss_recovery_crash() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);
    let now = now();

    // The server sends something, but we will drop this.
    let _ = send_something(&mut server, now);

    // Then send something again, but let it through.
    let ack = send_and_receive(&mut server, &mut client, now);
    assert!(ack.is_some());

    // Have the server process the ACK.
    let cb = server.process(ack, now).callback();
    assert!(cb > Duration::from_secs(0));

    // Now we leap into the future.  The server should regard the first
    // packet as lost based on time alone.
    let dgram = server.process(None, now + AT_LEAST_PTO).dgram();
    assert!(dgram.is_some());

    // This crashes.
    let _ = send_something(&mut server, now + AT_LEAST_PTO);
}

// If we receive packets after the PTO timer has fired, we won't clear
// the PTO state, but we might need to acknowledge those packets.
// This shouldn't happen, but we found that some implementations do this.
#[test]
fn ack_after_pto() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let mut now = now();

    // The client sends and is forced into a PTO.
    let _ = send_something(&mut client, now);

    // Jump forward to the PTO and drain the PTO packets.
    now += AT_LEAST_PTO;
    for _ in 0..PTO_PACKET_COUNT {
        let dgram = client.process(None, now).dgram();
        assert!(dgram.is_some());
    }
    assert!(client.process(None, now).dgram().is_none());

    // The server now needs to send something that will cause the
    // client to want to acknowledge it.  A little out of order
    // delivery is just the thing.
    // Note: The server can't ACK anything here, but none of what
    // the client has sent so far has been transferred.
    let _ = send_something(&mut server, now);
    let dgram = send_something(&mut server, now);

    // The client is now after a PTO, but if it receives something
    // that demands acknowledgment, it will send just the ACK.
    let ack = client.process(Some(dgram), now).dgram();
    assert!(ack.is_some());

    // Make sure that the packet only contained ACK frames.
    let frames = server.test_process_input(ack.unwrap(), now);
    assert_eq!(frames.len(), 1);
    for (frame, space) in frames {
        assert_eq!(space, PNSpace::ApplicationData);
        assert!(matches!(frame, Frame::Ack { .. }));
    }
}

/// Test the interaction between the loss recovery timer
/// and the closing timer.
#[test]
fn closing_timers_interation() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let mut now = now();

    // We're going to induce time-based loss recovery so that timer is set.
    let _p1 = send_something(&mut client, now);
    let p2 = send_something(&mut client, now);
    let ack = server.process(Some(p2), now).dgram();
    assert!(ack.is_some()); // This is an ACK.

    // After processing the ACK, we should be on the loss recovery timer.
    let cb = client.process(ack, now).callback();
    assert_ne!(cb, Duration::from_secs(0));
    now += cb;

    // Rather than let the timer pop, close the connection.
    client.close(now, 0, "");
    let client_close = client.process(None, now).dgram();
    assert!(client_close.is_some());
    // This should now report the end of the closing period, not a
    // zero-duration wait driven by the (now defunct) loss recovery timer.
    let client_close_timer = client.process(None, now).callback();
    assert_ne!(client_close_timer, Duration::from_secs(0));
}

#[test]
fn closing_and_draining() {
    const APP_ERROR: AppError = 7;
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    // Save a packet from the client for later.
    let p1 = send_something(&mut client, now());

    // Close the connection.
    client.close(now(), APP_ERROR, "");
    let client_close = client.process(None, now()).dgram();
    assert!(client_close.is_some());
    let client_close_timer = client.process(None, now()).callback();
    assert_ne!(client_close_timer, Duration::from_secs(0));

    // The client will spit out the same packet in response to anything it receives.
    let p3 = send_something(&mut server, now());
    let client_close2 = client.process(Some(p3), now()).dgram();
    assert_eq!(
        client_close.as_ref().unwrap().len(),
        client_close2.as_ref().unwrap().len()
    );

    // After this time, the client should transition to closed.
    let end = client.process(None, now() + client_close_timer);
    assert_eq!(end, Output::None);
    assert_eq!(
        *client.state(),
        State::Closed(ConnectionError::Application(APP_ERROR))
    );

    // When the server receives the close, it too should generate CONNECTION_CLOSE.
    let server_close = server.process(client_close, now()).dgram();
    assert!(server.state().closed());
    assert!(server_close.is_some());
    // .. but it ignores any further close packets.
    let server_close_timer = server.process(client_close2, now()).callback();
    assert_ne!(server_close_timer, Duration::from_secs(0));
    // Even a legitimate packet without a close in it.
    let server_close_timer2 = server.process(Some(p1), now()).callback();
    assert_eq!(server_close_timer, server_close_timer2);

    let end = server.process(None, now() + server_close_timer);
    assert_eq!(end, Output::None);
    assert_eq!(
        *server.state(),
        State::Closed(ConnectionError::Transport(Error::PeerApplicationError(
            APP_ERROR
        )))
    );
}

/// When we declare a packet as lost, we keep it around for a while for another loss period.
/// Those packets should not affect how we report the loss recovery timer.
/// As the loss recovery timer based on RTT we use that to drive the state.
#[test]
fn lost_but_kept_and_lr_timer() {
    const RTT: Duration = Duration::from_secs(1);
    let mut client = default_client();
    let mut server = default_server();
    let mut now = connect_with_rtt(&mut client, &mut server, now(), RTT);

    // Two packets (p1, p2) are sent at around t=0.  The first is lost.
    let _p1 = send_something(&mut client, now);
    let p2 = send_something(&mut client, now);

    // At t=RTT/2 the server receives the packet and ACKs it.
    now += RTT / 2;
    let ack = server.process(Some(p2), now).dgram();
    assert!(ack.is_some());
    // The client also sends another two packets (p3, p4), again losing the first.
    let _p3 = send_something(&mut client, now);
    let p4 = send_something(&mut client, now);

    // At t=RTT the client receives the ACK and goes into timed loss recovery.
    // The client doesn't call p1 lost at this stage, but it will soon.
    now += RTT / 2;
    let res = client.process(ack, now);
    // The client should be on a loss recovery timer as p1 is missing.
    let lr_timer = res.callback();
    // Loss recovery timer should be RTT/8, but only check for 0 or >=RTT/2.
    assert_ne!(lr_timer, Duration::from_secs(0));
    assert!(lr_timer < (RTT / 2));
    // The server also receives and acknowledges p4, again sending an ACK.
    let ack = server.process(Some(p4), now).dgram();
    assert!(ack.is_some());

    // At t=RTT*3/2 the client should declare p1 to be lost.
    now += RTT / 2;
    // So the client will send the data from p1 again.
    let res = client.process(None, now);
    assert!(res.dgram().is_some());
    // When the client processes the ACK, it should engage the
    // loss recovery timer for p3, not p1 (even though it still tracks p1).
    let res = client.process(ack, now);
    let lr_timer2 = res.callback();
    assert_eq!(lr_timer, lr_timer2);
}

/// Split the first packet off a coalesced packet.
fn split_packet(buf: &[u8]) -> (&[u8], Option<&[u8]>) {
    if buf[0] & 0x80 == 0 {
        // Short header: easy.
        return (buf, None);
    }
    let mut dec = Decoder::from(buf);
    let first = dec.decode_byte().unwrap();
    assert_ne!(first & 0b0011_0000, 0b0011_0000, "retry not supported");
    dec.skip(4); // Version.
    dec.skip_vec(1); // DCID
    dec.skip_vec(1); // SCID
    if first & 0b0011_0000 == 0 {
        dec.skip_vvec(); // Initial token
    }
    dec.skip_vvec(); // The rest of the packet.
    let p1 = &buf[..dec.offset()];
    let p2 = if dec.remaining() > 0 {
        Some(dec.decode_remainder())
    } else {
        None
    };
    (p1, p2)
}

/// Split the first datagram off a coalesced datagram.
fn split_datagram(d: Datagram) -> (Datagram, Option<Datagram>) {
    let (a, b) = split_packet(&d[..]);
    (
        Datagram::new(d.source(), d.destination(), a),
        b.map(|b| Datagram::new(d.source(), d.destination(), b)),
    )
}

/// We should not be setting the loss recovery timer based on packets
/// that are sent prior to the largest acknowledged.
/// Testing this requires that we construct a case where one packet
/// number space causes the loss recovery timer to be engaged.  At the same time,
/// there is a packet in another space that hasn't been acknowledged AND
/// that packet number space has not received acknowledgments for later packets.
#[test]
fn loss_time_past_largest_acked() {
    const RTT: Duration = Duration::from_secs(10);
    const INCR: Duration = Duration::from_millis(1);
    let mut client = default_client();
    let mut server = default_server();

    let mut now = now();

    // Start the handshake.
    let c_in = client.process(None, now).dgram();
    now += RTT / 2;
    let s_hs1 = server.process(c_in, now).dgram();

    // Get some spare server handshake packets for the client to ACK.
    // This involves a time machine, so be a little cautious.
    // This test uses an RTT of 10s, but our server starts
    // with a much lower RTT estimate, so the PTO at this point should
    // be much smaller than an RTT and so the server shouldn't see
    // time go backwards.
    let s_pto = server.process(None, now).callback();
    assert_ne!(s_pto, Duration::from_secs(0));
    assert!(s_pto < RTT);
    let s_hs2 = server.process(None, now + s_pto).dgram();
    assert!(s_hs2.is_some());
    let s_hs3 = server.process(None, now + s_pto).dgram();
    assert!(s_hs3.is_some());

    // Get some Handshake packets from the client.
    // We need one to be left unacknowledged before one that is acknowledged.
    // So that the client engages the loss recovery timer.
    // This is complicated by the fact that it is hard to cause the client
    // to generate an ack-eliciting packet.  For that, we use the Finished message.
    // Reordering delivery ensures that the later packet is also acknowledged.
    now += RTT / 2;
    let c_hs1 = client.process(s_hs1, now).dgram();
    assert!(c_hs1.is_some()); // This comes first, so it's useless.
    maybe_authenticate(&mut client);
    let c_hs2 = client.process(None, now).dgram();
    assert!(c_hs2.is_some()); // This one will elicit an ACK.

    // The we need the outstanding packet to be sent after the
    // application data packet, so space these out a tiny bit.
    let _p1 = send_something(&mut client, now + INCR);
    let c_hs3 = client.process(s_hs2, now + (INCR * 2)).dgram();
    assert!(c_hs3.is_some()); // This will be left outstanding.
    let c_hs4 = client.process(s_hs3, now + (INCR * 3)).dgram();
    assert!(c_hs4.is_some()); // This will be acknowledged.

    // Process c_hs2 and c_hs4, but skip c_hs3.
    // Then get an ACK for the client.
    now += RTT / 2;
    // Deliver c_hs4 first, but don't generate a packet.
    server.process_input(c_hs4.unwrap(), now);
    let s_ack = server.process(c_hs2, now).dgram();
    assert!(s_ack.is_some());
    // This includes an ACK, but it also includes HANDSHAKE_DONE,
    // which we need to remove because that will cause the Handshake loss
    // recovery state to be dropped.
    let (s_hs_ack, _s_ap_ack) = split_datagram(s_ack.unwrap());

    // Now the client should start its loss recovery timer based on the ACK.
    now += RTT / 2;
    let c_ack = client.process(Some(s_hs_ack), now).dgram();
    assert!(c_ack.is_none());
    // The client should now have the loss recovery timer active.
    let lr_time = client.process(None, now).callback();
    assert_ne!(lr_time, Duration::from_secs(0));
    assert!(lr_time < (RTT / 2));

    // Skipping forward by the loss recovery timer should cause the client to
    // mark packets as lost and retransmit, after which we should be on the PTO
    // timer.
    now += lr_time;
    let delay = client.process(None, now).callback();
    assert_ne!(delay, Duration::from_secs(0));
    assert!(delay > lr_time);
}

#[test]
fn unknown_version() {
    let mut client = default_client();
    // Start the handshake.
    let _ = client.process(None, now()).dgram();

    let mut unknown_version_packet = vec![0x80, 0x1a, 0x1a, 0x1a, 0x1a];
    unknown_version_packet.resize(1200, 0x0);
    let _ = client.process(
        Some(Datagram::new(
            loopback(),
            loopback(),
            unknown_version_packet,
        )),
        now(),
    );
    assert_eq!(1, client.stats().dropped_rx);
}

/// Run a single ChaCha20-Poly1305 test and get a PTO.
#[test]
fn chacha20poly1305() {
    let mut server = default_server();
    let mut client = Connection::new_client(
        test_fixture::DEFAULT_SERVER_NAME,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        loopback(),
        loopback(),
        QuicVersion::default(),
    )
    .expect("create a default client");
    client.set_ciphers(&[TLS_CHACHA20_POLY1305_SHA256]).unwrap();
    connect_force_idle(&mut client, &mut server);
}

/// Test that a client can handle a stateless reset correctly.
#[test]
fn stateless_reset_client() {
    let mut client = default_client();
    let mut server = default_server();
    server
        .set_local_tparam(
            tparams::STATELESS_RESET_TOKEN,
            TransportParameter::Bytes(vec![77; 16]),
        )
        .unwrap();
    connect_force_idle(&mut client, &mut server);

    client.process_input(Datagram::new(loopback(), loopback(), vec![77; 21]), now());
    assert!(matches!(client.state(), State::Draining { .. }));
}

/// Test that a server can send 0.5 RTT application data.
#[test]
fn send_05rtt() {
    let mut client = default_client();
    let mut server = default_server();

    let c1 = client.process(None, now()).dgram();
    assert!(c1.is_some());
    let s1 = server.process(c1, now()).dgram().unwrap();

    // The server should accept writes at this point.
    let s2 = send_something(&mut server, now());

    // Complete the handshake at the client.
    client.process_input(s1, now());
    maybe_authenticate(&mut client);
    assert_eq!(*client.state(), State::Connected);

    // The client should receive the 0.5-RTT data now.
    client.process_input(s2, now());
    let mut buf = vec![0; DEFAULT_STREAM_DATA.len() + 1];
    let stream_id = client
        .events()
        .find_map(|e| {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                Some(stream_id)
            } else {
                None
            }
        })
        .unwrap();
    let (l, ended) = client.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(&buf[..l], DEFAULT_STREAM_DATA);
    assert!(ended);
}

/// Test that a client buffers 0.5-RTT data when it arrives early.
#[test]
fn reorder_05rtt() {
    let mut client = default_client();
    let mut server = default_server();

    let c1 = client.process(None, now()).dgram();
    assert!(c1.is_some());
    let s1 = server.process(c1, now()).dgram().unwrap();

    // The server should accept writes at this point.
    let s2 = send_something(&mut server, now());

    // We can't use the standard facility to complete the handshake, so
    // drive it as aggressively as possible.
    client.process_input(s2, now());
    assert_eq!(client.stats().saved_datagrams, 1);

    // After processing the first packet, the client should go back and
    // process the 0.5-RTT packet data, which should make data available.
    client.process_input(s1, now());
    // We can't use `maybe_authenticate` here as that consumes events.
    client.authenticated(AuthenticationStatus::Ok, now());
    assert_eq!(*client.state(), State::Connected);

    let mut buf = vec![0; DEFAULT_STREAM_DATA.len() + 1];
    let stream_id = client
        .events()
        .find_map(|e| {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                Some(stream_id)
            } else {
                None
            }
        })
        .unwrap();
    let (l, ended) = client.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(&buf[..l], DEFAULT_STREAM_DATA);
    assert!(ended);
}

#[test]
fn reorder_05rtt_with_0rtt() {
    const RTT: Duration = Duration::from_millis(100);

    let mut client = default_client();
    let mut server = default_server();
    let mut now = connect_with_rtt(&mut client, &mut server, now(), RTT);

    // Include RTT in sending the ticket or the ticket age reported by the
    // client is wrong, which causes the server to reject 0-RTT.
    now += RTT / 2;
    server.send_ticket(now, &[]).unwrap();
    let ticket = server.process_output(now).dgram().unwrap();
    now += RTT / 2;
    client.process_input(ticket, now);
    let token = client.resumption_token().unwrap();
    let mut client = default_client();
    client.enable_resumption(now, &token[..]).unwrap();
    let mut server = default_server();

    // Send ClientHello and some 0-RTT.
    let c1 = send_something(&mut client, now);
    assertions::assert_coalesced_0rtt(&c1[..]);
    // Drop the 0-RTT from the coalesced datagram, so that the server
    // acknowledges the next 0-RTT packet.
    let (c1, _) = split_datagram(c1);
    let c2 = send_something(&mut client, now);

    // Handle the first packet and send 0.5-RTT in response.  Drop the response.
    now += RTT / 2;
    let _ = server.process(Some(c1), now).dgram().unwrap();
    // The gap in 0-RTT will result in this 0.5 RTT containing an ACK.
    server.process_input(c2, now);
    let s2 = send_something(&mut server, now);

    // Save the 0.5 RTT.
    now += RTT / 2;
    client.process_input(s2, now);
    assert_eq!(client.stats().saved_datagrams, 1);

    // Now PTO at the client and cause the server to re-send handshake packets.
    now += AT_LEAST_PTO;
    let c3 = client.process(None, now).dgram();

    now += RTT / 2;
    let s3 = server.process(c3, now).dgram().unwrap();
    assertions::assert_no_1rtt(&s3[..]);

    // The client should be able to process the 0.5 RTT now.
    // This should contain an ACK, so we are processing an ACK from the past.
    now += RTT / 2;
    client.process_input(s3, now);
    maybe_authenticate(&mut client);
    let c4 = client.process(None, now).dgram();
    assert_eq!(*client.state(), State::Connected);
    assert_eq!(client.loss_recovery.rtt(), RTT);

    now += RTT / 2;
    server.process_input(c4.unwrap(), now);
    assert_eq!(*server.state(), State::Confirmed);
    assert_eq!(server.loss_recovery.rtt(), RTT);
}

/// Test that a server that coalesces 0.5 RTT with handshake packets
/// doesn't cause the client to drop application data.
#[test]
fn coalesce_05rtt() {
    const RTT: Duration = Duration::from_millis(100);
    let mut client = default_client();
    let mut server = default_server();
    let mut now = now();

    // The first exchange doesn't offer a chance for the server to send.
    // So drop the server flight and wait for the PTO.
    let c1 = client.process(None, now).dgram();
    assert!(c1.is_some());
    now += RTT / 2;
    let s1 = server.process(c1, now).dgram();
    assert!(s1.is_some());

    // Drop the server flight.  Then send some data.
    let stream_id = server.stream_create(StreamType::UniDi).unwrap();
    assert!(server.stream_send(stream_id, DEFAULT_STREAM_DATA).is_ok());
    assert!(server.stream_close_send(stream_id).is_ok());

    // Now after a PTO the client can send another packet.
    // The server should then send its entire flight again,
    // including the application data, which it sends in a 1-RTT packet.
    now += AT_LEAST_PTO;
    let c2 = client.process(None, now).dgram();
    assert!(c2.is_some());
    now += RTT / 2;
    let s2 = server.process(c2, now).dgram();
    assert!(s2.is_some());

    // The client should process the datagram.  It can't process the 1-RTT
    // packet until authentication completes though.  So it saves it.
    now += RTT / 2;
    assert_eq!(client.stats().dropped_rx, 0);
    let _ = client.process(s2, now).dgram();
    // This packet will contain an ACK, but we can ignore it.
    assert_eq!(client.stats().dropped_rx, 0);
    assert_eq!(client.stats().packets_rx, 3);
    assert_eq!(client.stats().saved_datagrams, 1);

    // After (successful) authentication, the packet is processed.
    maybe_authenticate(&mut client);
    let c3 = client.process(None, now).dgram();
    assert!(c3.is_some());
    assert_eq!(client.stats().dropped_rx, 0);
    assert_eq!(client.stats().packets_rx, 4);
    assert_eq!(client.stats().saved_datagrams, 1);

    // Allow the handshake to complete.
    now += RTT / 2;
    let s3 = server.process(c3, now).dgram();
    assert!(s3.is_some());
    assert_eq!(*server.state(), State::Confirmed);
    now += RTT / 2;
    let _ = client.process(s3, now).dgram();
    assert_eq!(*client.state(), State::Confirmed);

    assert_eq!(client.stats().dropped_rx, 0);
}

#[test]
fn reorder_handshake() {
    const RTT: Duration = Duration::from_millis(100);
    let mut client = default_client();
    let mut server = default_server();
    let mut now = now();

    let c1 = client.process(None, now).dgram();
    assert!(c1.is_some());

    now += RTT / 2;
    let s1 = server.process(c1, now).dgram();
    assert!(s1.is_some());

    // Drop the Initial packet from this.
    let (_, s_hs) = split_datagram(s1.unwrap());
    assert!(s_hs.is_some());

    // Pass just the handshake packet in and the client can't handle it.
    now += RTT / 2;
    let res = client.process(s_hs, now);
    assert_ne!(res.callback(), Duration::new(0, 0));
    assert_eq!(client.stats().saved_datagrams, 1);
    assert_eq!(client.stats().packets_rx, 1);

    // Get the server to try again.
    // Though we currently allow the server to arm its PTO timer, use
    // a second client Initial packet to cause it to send again.
    now += AT_LEAST_PTO;
    let c2 = client.process(None, now).dgram();
    now += RTT / 2;
    let s2 = server.process(c2, now).dgram();
    assert!(s2.is_some());

    let (s_init, s_hs) = split_datagram(s2.unwrap());
    assert!(s_hs.is_some());

    // Processing the Handshake packet first should save it.
    now += RTT / 2;
    client.process_input(s_hs.unwrap(), now);
    assert_eq!(client.stats().saved_datagrams, 2);
    assert_eq!(client.stats().packets_rx, 2);

    client.process_input(s_init, now);
    // Each saved packet should now be "received" again.
    assert_eq!(client.stats().packets_rx, 5);
    maybe_authenticate(&mut client);
    let c3 = client.process(None, now).dgram();
    assert!(c3.is_some());

    // Note that though packets were saved and processed very late,
    // they don't cause the RTT to change.
    now += RTT / 2;
    let s3 = server.process(c3, now).dgram();
    assert_eq!(*server.state(), State::Confirmed);
    assert_eq!(server.loss_recovery.rtt(), RTT);

    now += RTT / 2;
    client.process_input(s3.unwrap(), now);
    assert_eq!(*client.state(), State::Confirmed);
    assert_eq!(client.loss_recovery.rtt(), RTT);
}

#[test]
fn reorder_1rtt() {
    const RTT: Duration = Duration::from_millis(100);
    const PACKETS: usize = 6; // Many, but not enough to overflow cwnd.
    let mut client = default_client();
    let mut server = default_server();
    let mut now = now();

    let c1 = client.process(None, now).dgram();
    assert!(c1.is_some());

    now += RTT / 2;
    let s1 = server.process(c1, now).dgram();
    assert!(s1.is_some());

    now += RTT / 2;
    client.process_input(s1.unwrap(), now);
    maybe_authenticate(&mut client);
    let c2 = client.process(None, now).dgram();
    assert!(c2.is_some());

    // Now get a bunch of packets from the client.
    // Give them to the server before giving it `c2`.
    for _ in 0..PACKETS {
        let d = send_something(&mut client, now);
        server.process_input(d, now + RTT / 2);
    }
    // The server has now received those packets, and saved them.
    // The two extra received are Initial + the junk we use for padding.
    assert_eq!(server.stats().packets_rx, PACKETS + 2);
    assert_eq!(server.stats().saved_datagrams, PACKETS);
    assert_eq!(server.stats().dropped_rx, 1);

    now += RTT / 2;
    let s2 = server.process(c2, now).dgram();
    // The server has now received those packets, and saved them.
    // The two additional are an Initial ACK and Handshake.
    assert_eq!(server.stats().packets_rx, PACKETS * 2 + 4);
    assert_eq!(server.stats().saved_datagrams, PACKETS);
    assert_eq!(server.stats().dropped_rx, 1);
    assert_eq!(*server.state(), State::Confirmed);
    assert_eq!(server.loss_recovery.rtt(), RTT);

    now += RTT / 2;
    client.process_input(s2.unwrap(), now);
    assert_eq!(client.loss_recovery.rtt(), RTT);

    // All the stream data that was sent should now be available.
    let packets = server
        .events()
        .filter_map(|e| {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
                let mut buf = vec![0; DEFAULT_STREAM_DATA.len() + 1];
                let (recvd, fin) = server.stream_recv(stream_id, &mut buf).unwrap();
                assert_eq!(recvd, DEFAULT_STREAM_DATA.len());
                assert!(fin);
                Some(())
            } else {
                None
            }
        })
        .count();
    assert_eq!(packets, PACKETS);
}

#[test]
fn server_receive_unknown_first_packet() {
    let mut server = default_server();

    let mut unknown_version_packet = vec![0x80, 0x1a, 0x1a, 0x1a, 0x1a];
    unknown_version_packet.resize(1200, 0x0);

    assert_eq!(
        server.process(
            Some(Datagram::new(
                loopback(),
                loopback(),
                unknown_version_packet,
            )),
            now(),
        ),
        Output::None
    );

    assert_eq!(1, server.stats().dropped_rx);
}

fn create_vn(initial_pkt: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut dec = Decoder::from(&initial_pkt[5..]); // Skip past version.
    let dcid = dec.decode_vec(1).expect("client DCID");
    let scid = dec.decode_vec(1).expect("client SCID");

    let mut encoder = Encoder::default();
    encoder.encode_byte(PACKET_BIT_LONG);
    encoder.encode(&[0; 4]); // Zero version == VN.
    encoder.encode_vec(1, dcid);
    encoder.encode_vec(1, scid);

    for v in versions {
        encoder.encode_uint(4, *v);
    }
    encoder.into()
}

#[test]
fn version_negotiation_current_version() {
    let mut client = default_client();
    // Start the handshake.
    let initial_pkt = client
        .process(None, now())
        .dgram()
        .expect("a datagram")
        .to_vec();

    let vn = create_vn(
        &initial_pkt,
        &[0x1a1_a1a1a, QuicVersion::default().as_u32()],
    );

    let dgram = Datagram::new(loopback(), loopback(), vn);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, Duration::from_millis(300));
    assert_eq!(*client.state(), State::WaitInitial);
    assert_eq!(1, client.stats().dropped_rx);
}

#[test]
fn version_negotiation_only_reserved() {
    let mut client = default_client();
    // Start the handshake.
    let initial_pkt = client
        .process(None, now())
        .dgram()
        .expect("a datagram")
        .to_vec();

    let vn = create_vn(&initial_pkt, &[0x1a1a_1a1a, 0x2a2a_2a2a]);

    let dgram = Datagram::new(loopback(), loopback(), vn);
    assert_eq!(client.process(Some(dgram), now()), Output::None);
    match client.state() {
        State::Closed(err) => {
            assert_eq!(*err, ConnectionError::Transport(Error::VersionNegotiation))
        }
        _ => panic!("Invalid client state"),
    }
}

#[test]
fn version_negotiation_corrupted() {
    let mut client = default_client();
    // Start the handshake.
    let initial_pkt = client
        .process(None, now())
        .dgram()
        .expect("a datagram")
        .to_vec();

    let vn = create_vn(&initial_pkt, &[0x1a1a_1a1a, 0x2a2a_2a2a]);

    let dgram = Datagram::new(loopback(), loopback(), &vn[..vn.len() - 1]);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, Duration::from_millis(300));
    assert_eq!(*client.state(), State::WaitInitial);
    assert_eq!(1, client.stats().dropped_rx);
}

#[test]
fn version_negotiation_empty() {
    let mut client = default_client();
    // Start the handshake.
    let initial_pkt = client
        .process(None, now())
        .dgram()
        .expect("a datagram")
        .to_vec();

    let vn = create_vn(&initial_pkt, &[]);

    let dgram = Datagram::new(loopback(), loopback(), vn);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, Duration::from_millis(300));
    assert_eq!(*client.state(), State::WaitInitial);
    assert_eq!(1, client.stats().dropped_rx);
}

#[test]
fn version_negotiation_not_supported() {
    let mut client = default_client();
    // Start the handshake.
    let initial_pkt = client
        .process(None, now())
        .dgram()
        .expect("a datagram")
        .to_vec();

    let vn = create_vn(&initial_pkt, &[0x1a1a_1a1a, 0x2a2a_2a2a, 0xff00_0001]);

    assert_eq!(
        client.process(Some(Datagram::new(loopback(), loopback(), vn)), now(),),
        Output::None
    );
    match client.state() {
        State::Closed(err) => {
            assert_eq!(*err, ConnectionError::Transport(Error::VersionNegotiation))
        }
        _ => panic!("Invalid client state"),
    }
}

#[test]
fn stream_data_blocked_generates_max_stream_data() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let now = now();

    // Try to say we're blocked beyond the initial data window
    server
        .flow_mgr
        .borrow_mut()
        .stream_data_blocked(3.into(), RECV_BUFFER_SIZE as u64 * 4);

    let out = server.process(None, now);
    assert!(out.as_dgram_ref().is_some());

    let frames = client.test_process_input(out.dgram().unwrap(), now);
    assert!(frames
        .iter()
        .any(|(f, _)| matches!(f, Frame::StreamDataBlocked { .. })));

    let out = client.process_output(now);
    assert!(out.as_dgram_ref().is_some());

    let frames = server.test_process_input(out.dgram().unwrap(), now);
    // Client should have sent a MaxStreamData frame with just the initial
    // window value.
    assert!(frames.iter().any(
        |(f, _)| matches!(f, Frame::MaxStreamData { maximum_stream_data, .. }
				   if *maximum_stream_data == RECV_BUFFER_SIZE as u64)
    ));
}

/// Check that a resumed connection uses a token on Initial packets.
#[test]
fn address_validation_token_resume() {
    const RTT: Duration = Duration::from_millis(10);

    let mut client = default_client();
    let mut server = default_server();
    let validation = AddressValidation::new(now(), ValidateAddress::Always).unwrap();
    let validation = Rc::new(RefCell::new(validation));
    server.set_validation(Rc::clone(&validation));
    let mut now = connect_with_rtt(&mut client, &mut server, now(), RTT);

    let token = exchange_ticket(&mut client, &mut server, now);
    let mut client = default_client();
    client.enable_resumption(now, &token[..]).unwrap();
    let mut server = default_server();

    // Grab an Initial packet from the client.
    let dgram = client.process(None, now).dgram();
    assertions::assert_initial(dgram.as_ref().unwrap(), true);

    // Now try to complete the handshake after giving time for a client PTO.
    now += AT_LEAST_PTO;
    connect_with_rtt(&mut client, &mut server, now, RTT);
    assert!(client.crypto.tls.info().unwrap().resumed());
    assert!(server.crypto.tls.info().unwrap().resumed());
}

fn can_resume(mut token: Option<Vec<u8>>, initial_has_token: bool) {
    let mut client = default_client();
    client
        .enable_resumption(now(), token.take().as_ref().unwrap())
        .unwrap();
    let initial = client.process_output(now()).dgram();
    assertions::assert_initial(initial.as_ref().unwrap(), initial_has_token);
}

#[test]
fn two_tickets() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    // Send two tickets and then bundle those into a packet.
    server.send_ticket(now(), &[]).expect("send ticket1");
    server.send_ticket(now(), &[]).expect("send ticket2");
    let pkt = send_something(&mut server, now());

    client.process_input(pkt, now());
    let token1 = client.resumption_token();
    assert!(token1.is_some());
    let token2 = client.resumption_token();
    assert!(token2.is_some());
    assert_ne!(token1, token2);
    assert!(client.resumption_token().is_none());

    can_resume(token1, false);
    can_resume(token2, false);
}

#[test]
fn two_tickets_and_tokens() {
    let mut client = default_client();
    let mut server = default_server();
    let validation = AddressValidation::new(now(), ValidateAddress::Always).unwrap();
    let validation = Rc::new(RefCell::new(validation));
    server.set_validation(Rc::clone(&validation));
    connect(&mut client, &mut server);

    // Send two tickets with tokens and then bundle those into a packet.
    server.send_ticket(now(), &[]).expect("send ticket1");
    server.send_ticket(now(), &[]).expect("send ticket2");
    let pkt = send_something(&mut server, now());

    client.process_input(pkt, now());
    let token1 = client.resumption_token();
    let token2 = client.resumption_token();
    assert_ne!(token1, token2);
    assert!(client.resumption_token().is_none());

    can_resume(token1, true);
    can_resume(token2, true);
}

#[test]
fn corrupted_initial() {
    let mut client = default_client();
    let mut server = default_server();
    let d = client.process(None, now()).dgram().unwrap();
    let mut corrupted = Vec::from(&d[..]);
    // Find the last non-zero value and corrupt that.
    let (idx, _) = corrupted
        .iter()
        .enumerate()
        .rev()
        .find(|(_, &v)| v != 0)
        .unwrap();
    corrupted[idx] ^= 0x76;
    let dgram = Datagram::new(d.source(), d.destination(), corrupted);
    server.process_input(dgram, now());
    // The server should have received two packets,
    // the first should be dropped, the second saved.
    assert_eq!(server.stats().packets_rx, 2);
    assert_eq!(server.stats().dropped_rx, 1);
    // assert_eq!(server.stats().saved_datagram, 1);
}
