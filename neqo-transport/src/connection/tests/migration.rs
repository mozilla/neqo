// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::{Connection, Output, State, StreamType};
use super::{
    connect_force_idle, default_client, default_server, maybe_authenticate, send_something,
};
use crate::path::{PATH_MTU_V4, PATH_MTU_V6};
use crate::tparams::PreferredAddress;
use crate::{
    CongestionControlAlgorithm, ConnectionError, EmptyConnectionIdGenerator, Error, QuicVersion,
};

use neqo_common::Datagram;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;
use test_fixture::{self, fixture_init, loopback, now};

// These tests generally use two paths:
// The connection is established on a path with the same IPv6 loopback address on both ends.
// Migrations move to a path with the same IPv4 loopback address on both ends.
// This simplifies validation as the same assertions can be used for client and server.
// The risk is that there is a place where source/destination local/remote is inverted.
fn loopback_v4() -> SocketAddr {
    let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    SocketAddr::new(localhost_v4, loopback().port())
}

fn change_path(d: &Datagram) -> Datagram {
    let v4 = loopback_v4();
    Datagram::new(v4, v4, &d[..])
}

fn new_port() -> SocketAddr {
    let lb = loopback();
    let (port, _) = lb.port().overflowing_add(1);
    SocketAddr::new(lb.ip(), port)
}

fn change_source_port(d: &Datagram) -> Datagram {
    Datagram::new(new_port(), loopback(), &d[..])
}

fn assert_v4_path(dgram: &Datagram, padded: bool) {
    assert_eq!(dgram.source(), loopback_v4());
    assert_eq!(dgram.destination(), loopback_v4());
    if padded {
        assert_eq!(dgram.len(), PATH_MTU_V4);
    }
}
fn assert_v6_path(dgram: &Datagram, padded: bool) {
    assert_eq!(dgram.source(), loopback());
    assert_eq!(dgram.destination(), loopback());
    if padded {
        assert_eq!(dgram.len(), PATH_MTU_V6);
    }
}

#[test]
fn rebinding_port() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let dgram = send_something(&mut client, now());
    let dgram = change_source_port(&dgram);

    server.process_input(dgram, now());
    // Have the server send something so that it generates a packet.
    let stream_id = server.stream_create(StreamType::UniDi).unwrap();
    server.stream_close_send(stream_id).unwrap();
    let dgram = server.process_output(now()).dgram();
    let dgram = dgram.unwrap();
    assert_eq!(dgram.source(), loopback());
    assert_eq!(dgram.destination(), new_port());
}

/// This simulates an attack where a valid packet is forwarded on
/// a different path.  This shows how both paths are probed and the
/// server eventually returns to the original path.
#[test]
fn path_forwarding_attack() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let dgram = send_something(&mut client, now());
    let dgram = change_path(&dgram);
    server.process_input(dgram, now());

    // The server now probes the new (primary) path.
    let new_probe = server.process_output(now()).dgram().unwrap();
    assert_eq!(server.stats().frame_tx.path_challenge, 1);
    assert_v4_path(&new_probe, false); // Can't be padded.

    // The server also probes the old path.
    let old_probe = server.process_output(now()).dgram().unwrap();
    assert_eq!(server.stats().frame_tx.path_challenge, 2);
    assert_v6_path(&old_probe, true);

    // New data from the server is sent on the new path, but that is
    // now constrained by the amplification limit.
    let stream_id = server.stream_create(StreamType::UniDi).unwrap();
    server.stream_close_send(stream_id).unwrap();
    assert!(server.process_output(now()).dgram().is_none());

    // The client should respond to the challenge on the new path.
    // The server couldn't pad, so the client is also amplification limited.
    let new_resp = client.process(Some(new_probe), now()).dgram().unwrap();
    assert_eq!(client.stats().frame_rx.path_challenge, 1);
    assert_eq!(client.stats().frame_tx.path_challenge, 1);
    assert_eq!(client.stats().frame_tx.path_response, 1);
    assert_v4_path(&new_resp, false);

    // The client also responds to probes on the old path.
    let old_resp = client.process(Some(old_probe), now()).dgram().unwrap();
    assert_eq!(client.stats().frame_rx.path_challenge, 2);
    assert_eq!(client.stats().frame_tx.path_challenge, 1);
    assert_eq!(client.stats().frame_tx.path_response, 2);
    assert_v6_path(&old_resp, true);

    // But the client still sends data on the old path.
    let client_data1 = send_something(&mut client, now());
    assert_v6_path(&client_data1, false); // Just data.

    // Receiving the PATH_RESPONSE from the client opens the amplification
    // limit enough for the server to respond.
    // This is padded because it includes PATH_CHALLENGE.
    let server_data1 = server.process(Some(new_resp), now()).dgram().unwrap();
    assert_v4_path(&server_data1, true);
    assert_eq!(server.stats().frame_tx.path_challenge, 3);

    // The client responds to this probe on the new path.
    client.process_input(server_data1, now());
    let stream_before = client.stats().frame_tx.stream;
    let padded_resp = send_something(&mut client, now());
    assert_eq!(stream_before, client.stats().frame_tx.stream);
    assert_v4_path(&padded_resp, true); // This is padded!

    // But new data from the client stays on the old path.
    let client_data2 = client.process_output(now()).dgram().unwrap();
    assert_v6_path(&client_data2, false);

    // The server keeps sending on the new path.
    let server_data2 = send_something(&mut server, now());
    assert_v4_path(&server_data2, false);

    // Until new data is received from the client on the old path.
    server.process_input(client_data2, now());
    // The server sends a probe on the "old" path.
    let server_data3 = send_something(&mut server, now());
    assert_v4_path(&server_data3, true);
    // But switches data transmission to the "new" path.
    let server_data4 = server.process_output(now()).dgram().unwrap();
    assert_v6_path(&server_data4, false);
}

#[test]
fn migrate_immediate() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    client
        .migrate(loopback_v4(), loopback_v4(), true, now())
        .unwrap();

    let client1 = send_something(&mut client, now());
    assert_v4_path(&client1, true); // Contains PATH_CHALLENGE.
    let client2 = send_something(&mut client, now());
    assert_v4_path(&client2, false); // Doesn't.

    let server_delayed = send_something(&mut server, now());

    // The server accepts the first packet and migrates (but probes).
    let server1 = server.process(Some(client1), now()).dgram().unwrap();
    assert_v4_path(&server1, true);
    let server2 = server.process_output(now()).dgram().unwrap();
    assert_v6_path(&server2, true);

    // The second packet has no real effect, it just elicits an ACK.
    let all_before = server.stats().frame_tx.all;
    let ack_before = server.stats().frame_tx.ack;
    let server3 = server.process(Some(client2), now()).dgram();
    assert!(server3.is_some());
    assert_eq!(server.stats().frame_tx.all, all_before + 1);
    assert_eq!(server.stats().frame_tx.ack, ack_before + 1);

    // Receiving a packet sent by the server before migration doesn't change path.
    client.process_input(server_delayed, now());
    let client3 = send_something(&mut client, now());
    assert_v4_path(&client3, false);
}

#[test]
fn migrate_immediate_fail() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let mut now = now();

    client
        .migrate(loopback_v4(), loopback_v4(), true, now)
        .unwrap();

    let probe = client.process_output(now).dgram().unwrap();
    assert_v4_path(&probe, true); // Contains PATH_CHALLENGE.

    for _ in 0..2 {
        let cb = client.process_output(now).callback();
        assert_ne!(cb, Duration::new(0, 0));
        now += cb;

        let before = client.stats().frame_tx;
        let probe = client.process_output(now).dgram().unwrap();
        assert_v4_path(&probe, true); // Contains PATH_CHALLENGE.
        let after = client.stats().frame_tx;
        assert_eq!(after.path_challenge, before.path_challenge + 1);
        assert_eq!(after.padding, before.padding + 1);
        assert_eq!(after.all, before.all + 2);

        // This might be a PTO, which will result in sending a probe.
        if let Some(probe) = client.process_output(now).dgram() {
            assert_v4_path(&probe, false); // Contains PATH_CHALLENGE.
            let after = client.stats().frame_tx;
            assert_eq!(after.ping, before.ping + 1);
            assert_eq!(after.all, before.all + 3);
        }
    }

    let pto = client.process_output(now).callback();
    assert_ne!(pto, Duration::new(0, 0));
    now += pto;

    // The client should fall back to the original path and
    let fallback = client.process_output(now).dgram();
    assert_v6_path(&fallback.unwrap(), false);
    assert_eq!(client.stats().frame_tx.retire_connection_id, 1);
}

/// Migrating to the same path shouldn't do anything special,
/// except that the path is probed.
#[test]
fn migrate_same() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let now = now();

    client.migrate(loopback(), loopback(), true, now).unwrap();

    let probe = client.process_output(now).dgram().unwrap();
    assert_v6_path(&probe, true); // Contains PATH_CHALLENGE.
    assert_eq!(client.stats().frame_tx.path_challenge, 1);

    let resp = server.process(Some(probe), now).dgram().unwrap();
    assert_v6_path(&resp, true);
    assert_eq!(server.stats().frame_tx.path_response, 1);
    assert_eq!(server.stats().frame_tx.path_challenge, 0);

    // Everything continues happily.
    client.process_input(resp, now);
    let contd = send_something(&mut client, now);
    assert_v6_path(&contd, false);
}

/// Migrating to the same path, if it fails, causes the connection to fail.
#[test]
fn migrate_same_fail() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let mut now = now();

    client.migrate(loopback(), loopback(), true, now).unwrap();

    let probe = client.process_output(now).dgram().unwrap();
    assert_v6_path(&probe, true); // Contains PATH_CHALLENGE.

    for _ in 0..2 {
        let cb = client.process_output(now).callback();
        assert_ne!(cb, Duration::new(0, 0));
        now += cb;

        let before = client.stats().frame_tx;
        let probe = client.process_output(now).dgram().unwrap();
        assert_v6_path(&probe, true); // Contains PATH_CHALLENGE.
        let after = client.stats().frame_tx;
        assert_eq!(after.path_challenge, before.path_challenge + 1);
        assert_eq!(after.padding, before.padding + 1);
        assert_eq!(after.all, before.all + 2);

        // This might be a PTO, which will result in sending a probe.
        if let Some(probe) = client.process_output(now).dgram() {
            assert_v6_path(&probe, false); // Contains PATH_CHALLENGE.
            let after = client.stats().frame_tx;
            assert_eq!(after.ping, before.ping + 1);
            assert_eq!(after.all, before.all + 3);
        }
    }

    let pto = client.process_output(now).callback();
    assert_ne!(pto, Duration::new(0, 0));
    now += pto;

    // The client should mark this path as failed and close immediately.
    let res = client.process_output(now);
    assert!(matches!(res, Output::None));
    assert!(matches!(
        client.state(),
        State::Closed(ConnectionError::Transport(Error::NoAvailablePath))
    ));
}

fn migration(mut client: Connection) {
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let now = now();

    client
        .migrate(loopback_v4(), loopback_v4(), false, now)
        .unwrap();

    let probe = client.process_output(now).dgram().unwrap();
    assert_v4_path(&probe, true); // Contains PATH_CHALLENGE.
    assert_eq!(client.stats().frame_tx.path_challenge, 1);

    let resp = server.process(Some(probe), now).dgram().unwrap();
    assert_v4_path(&resp, true);
    assert_eq!(server.stats().frame_tx.path_response, 1);
    assert_eq!(server.stats().frame_tx.path_challenge, 1);

    // Data continues to be exchanged on the new path.
    let client_data = send_something(&mut client, now);
    assert_v6_path(&client_data, false);
    server.process_input(client_data, now);
    let server_data = send_something(&mut server, now);
    assert_v6_path(&server_data, false);

    // Once the client receives the probe response, it migrates to the new path.
    client.process_input(resp, now);
    assert_eq!(client.stats().frame_rx.path_challenge, 1);
    let migrate_client = send_something(&mut client, now);
    assert_v4_path(&migrate_client, true); // Responds to server probe.

    // The server now sees the migration and will switch over.
    // However, it will probe the old path again, even though it has just
    // received a response to its last probe, because it needs to verify
    // that the migration is genuine.
    server.process_input(migrate_client, now);
    let stream_before = server.stats().frame_tx.stream;
    let probe_old_server = send_something(&mut server, now);
    // This is just the double-check probe; no STREAM frames.
    assert_v6_path(&probe_old_server, true);
    assert_eq!(server.stats().frame_tx.path_challenge, 2);
    assert_eq!(server.stats().frame_tx.stream, stream_before);

    // The server then sends data on the new path.
    let migrate_server = server.process_output(now).dgram().unwrap();
    assert_v4_path(&migrate_server, false);
    assert_eq!(server.stats().frame_tx.path_challenge, 2);
    assert_eq!(server.stats().frame_tx.stream, stream_before + 1);

    // The client receives these checks and responds to the probe, but uses the new path.
    client.process_input(migrate_server, now);
    client.process_input(probe_old_server, now);
    let old_probe_resp = send_something(&mut client, now);
    assert_v6_path(&old_probe_resp, true);
    let client_confirmation = client.process_output(now).dgram().unwrap();
    assert_v4_path(&client_confirmation, false);

    let server_confirmation = send_something(&mut server, now);
    assert_v4_path(&server_confirmation, false);
}

#[test]
fn migration_graceful() {
    migration(default_client());
}

/// A client should be able to migrate when it has a zero-length connection ID.
#[test]
fn migration_client_empty_cid() {
    fixture_init();
    let client = Connection::new_client(
        test_fixture::DEFAULT_SERVER_NAME,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(EmptyConnectionIdGenerator::default())),
        loopback(),
        loopback(),
        &CongestionControlAlgorithm::NewReno,
        QuicVersion::default(),
    )
    .unwrap();
    migration(client);
}

#[test]
fn preferred_address() {
    fn assert_toward_spa(d: &Datagram, full_mtu: bool) {
        assert_eq!(d.destination(), new_port());
        assert_eq!(d.source(), loopback());
        if full_mtu {
            assert_eq!(d.len(), PATH_MTU_V6);
        }
    }
    fn assert_from_spa(d: &Datagram, full_mtu: bool) {
        assert_eq!(d.destination(), loopback());
        assert_eq!(d.source(), new_port());
        if full_mtu {
            assert_eq!(d.len(), PATH_MTU_V6);
        }
    }

    let mut client = default_client();
    let mut server = default_server();
    server
        .set_preferred_address(&PreferredAddress::new(None, Some(new_port())))
        .unwrap();
    let now = now();

    // Drive the handshake in the most expeditious fashion.
    let dgram = client.process_output(now).dgram();
    let dgram = server.process(dgram, now).dgram();
    client.process_input(dgram.unwrap(), now);
    assert!(maybe_authenticate(&mut client));
    let dgram = client.process_output(now).dgram();
    let dgram = server.process(dgram, now).dgram();

    // The client is about to process HANDSHAKE_DONE.
    // It should start probing toward the server's preferred address.
    let probe = client.process(dgram, now).dgram().unwrap();
    assert_toward_spa(&probe, true);
    assert_eq!(client.stats().frame_tx.path_challenge, 1);
    assert_ne!(client.process_output(now).callback(), Duration::new(0, 0));

    // Data continues on the main path for the client.
    let data = send_something(&mut client, now);
    assert_v6_path(&data, false);

    // The server responds to the probe.
    let resp = server.process(Some(probe), now).dgram().unwrap();
    assert_from_spa(&resp, true);
    assert_eq!(server.stats().frame_tx.path_challenge, 1);
    assert_eq!(server.stats().frame_tx.path_response, 1);

    // Data continues on the main path for the server.
    server.process_input(data, now);
    let data = send_something(&mut server, now);
    assert_v6_path(&data, false);

    // Client gets the probe response back and it migrates.
    client.process_input(resp, now);
    client.process_input(data, now);
    let data = send_something(&mut client, now);
    assert_toward_spa(&data, true);
    assert_eq!(client.stats().frame_tx.stream, 2);
    assert_eq!(client.stats().frame_tx.path_response, 1);

    // The server sees the migration and probes the old path.
    let probe = server.process(Some(data), now).dgram().unwrap();
    assert_v6_path(&probe, true);
    assert_eq!(server.stats().frame_tx.path_challenge, 2);

    // But data now goes on the new path.
    let data = send_something(&mut server, now);
    assert_from_spa(&data, false);
}

#[test]
fn preferred_address_empty_cid() {
    fixture_init();

    let mut server = Connection::new_server(
        test_fixture::DEFAULT_KEYS,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(EmptyConnectionIdGenerator::default())),
        &CongestionControlAlgorithm::NewReno,
        QuicVersion::default(),
    )
    .unwrap();

    assert_eq!(
        server
            .set_preferred_address(&PreferredAddress::new(None, Some(new_port())))
            .unwrap_err(),
        Error::ConnectionIdsExhausted
    );
}

/// Test that migration isn't permitted if the connection isn't in the right state.
#[test]
fn no_migration() {
    let mut client = default_client();
    assert!(client
        .migrate(loopback(), loopback(), false, now())
        .is_err());

    let mut server = default_server();
    assert!(server
        .migrate(loopback(), loopback(), false, now())
        .is_err());
    connect_force_idle(&mut client, &mut server);

    assert!(server
        .migrate(loopback(), loopback(), false, now())
        .is_err());

    client.close(now(), 0, "closing");
    assert!(client
        .migrate(loopback(), loopback(), false, now())
        .is_err());
    let close = client.process(None, now()).dgram();

    let dgram = server.process(close, now()).dgram();
    assert!(server
        .migrate(loopback(), loopback(), false, now())
        .is_err());

    client.process_input(dgram.unwrap(), now());
    assert!(client
        .migrate(loopback(), loopback(), false, now())
        .is_err());
}
