// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use neqo_common::Datagram;
use test_fixture::{DEFAULT_ADDR, DEFAULT_ADDR_V4, fixture_init, now};

use super::{Connection, Output};
use crate::{
    ConnectionParameters, Pmtud, State, StreamType,
    connection::tests::{
        CountingConnectionIdGenerator, DEFAULT_RTT, connect, default_server, exchange_ticket,
        fill_stream, handshake, maybe_authenticate, new_client, new_server, resumed_server,
        send_something,
    },
    pmtud::{BASE_MTU, MAX_PROBE_MTU},
};

/// The handshake confirms a size above the base MTU, without any exchange after it.
#[test]
fn confirmed_during_handshake() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));
    let max_plpmtu = MAX_PROBE_MTU - Pmtud::header_size(DEFAULT_ADDR.ip());

    connect(&mut client, &mut server);

    assert_eq!(client.plpmtu(), max_plpmtu);
    assert_eq!(server.plpmtu(), max_plpmtu);
    // The largest planned probe goes out first and its acknowledgement confirms every smaller
    // size, so exactly one probe is spent on each side and the rest are pruned unsent.
    assert_eq!(client.stats().pmtud_tx, 1);
    assert_eq!(server.stats().pmtud_tx, 1);
    assert_eq!(client.stats().pmtud_ack, 1);
    assert_eq!(server.stats().pmtud_ack, 1);
    assert_eq!(client.stats().pmtud_lost, 0);
    assert_eq!(server.stats().pmtud_lost, 0);
    assert_eq!(client.stats().frame_tx.ping, 0);
    assert_eq!(server.stats().frame_tx.ping, 0);
}

/// The handshake completes even when no probe is acknowledged. Both sides stay at the base MTU.
#[test]
fn handshake_completes_without_any_probe() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));
    let base_plpmtu = BASE_MTU - Pmtud::header_size(DEFAULT_ADDR.ip());

    // Nothing above the base MTU gets through in either direction.
    exchange(&mut client, &mut server, base_plpmtu, now(), 10);

    assert_eq!(*client.state(), State::Confirmed);
    assert_eq!(*server.state(), State::Confirmed);
    assert_eq!(client.plpmtu(), base_plpmtu);
    assert_eq!(server.plpmtu(), base_plpmtu);
    // All six planned probes go out, none is acknowledged, and none is retried.
    assert_eq!(client.stats().pmtud_tx, 6);
    assert_eq!(client.stats().pmtud_ack, 0);
}

/// Every probe datagram reaches the size it probes for, whichever packet carries it.
#[test]
fn probe_datagrams_reach_their_size() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));
    connect(&mut client, &mut server);
    let token = exchange_ticket(&mut client, &mut server, now());

    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    client
        .enable_resumption(now(), token)
        .expect("should set token");
    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(stream_id, &[1; 32]).unwrap();

    // Drain the flight, so the client runs out of Initial-space ACKs ahead of its 0-RTT probes.
    let mut probes = 0;
    while let Some(d) = client.process_output(now()).dgram() {
        if d.len() > BASE_MTU - Pmtud::header_size(DEFAULT_ADDR.ip()) {
            probes += 1;
        }
    }
    assert_eq!(probes, 6);
}

/// A probe in an LH packet is expanded even when an SH packet is coalesced behind it.
#[test]
fn probe_expanded_past_coalesced_short_header() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));

    while let Some(d) = client.process_output(now()).dgram() {
        server.process_input(d, now());
    }
    // The server has 1-RTT keys but is not yet done, so this rides behind its Handshake probes.
    let stream_id = server.stream_create(StreamType::UniDi).unwrap();
    server.stream_send(stream_id, &[1; 512]).unwrap();

    let mut dgrams = Vec::new();
    while let Some(d) = server.process_output(now()).dgram() {
        dgrams.push(d);
    }
    assert_eq!(server.stats().pmtud_tx, 6);

    // A short header packet extends to the end of the datagram, so expanding a datagram that
    // ends in one would make the peer fold the padding into the ciphertext.
    for d in dgrams {
        client.process_input(d, now());
    }
    handshake(&mut client, &mut server, now(), Duration::new(0, 0));
    assert_eq!(*client.state(), State::Confirmed);
    let mut buf = [0; 512];
    assert_eq!(client.stream_recv(stream_id, &mut buf), Ok((512, false)));
}

/// A resuming client probes too, bounded by the `max_udp_payload_size` it remembered.
#[test]
fn zero_rtt_probes() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));
    connect(&mut client, &mut server);
    let token = exchange_ticket(&mut client, &mut server, now());

    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    client
        .enable_resumption(now(), token)
        .expect("should set token");
    let mut server = resumed_server(&client);

    // Give the client some 0-RTT data, which the probe budget has to leave room for.
    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(stream_id, &[1; 512]).unwrap();

    connect(&mut client, &mut server);
    assert!(client.tls_info().unwrap().early_data_accepted());
    // The largest probe gets through, so one is enough to confirm the maximum.
    assert_eq!(client.stats().pmtud_tx, 1);
    assert_eq!(
        client.plpmtu(),
        MAX_PROBE_MTU - Pmtud::header_size(DEFAULT_ADDR.ip())
    );
}

/// Pins the shape of a client's first flight:
///
/// * probes first, at descending, equally spaced sizes, each padded to the size it probes for;
/// * each probe carries exactly one CRYPTO frame, so that SNI slicing survive;
/// * the flight ends in minimum-sized packets that carry the complete `ClientHello`;
/// * all of it in one burst with no time passing.
#[test]
fn client_first_flight_shape() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let base_plpmtu = BASE_MTU - Pmtud::header_size(DEFAULT_ADDR.ip());

    let mut sizes = Vec::new();
    let mut crypto_frames = Vec::new();
    let delay = loop {
        let before = client.stats().frame_tx.crypto;
        match client.process_output(now()) {
            Output::Datagram(d) => {
                crypto_frames.push(client.stats().frame_tx.crypto - before);
                sizes.push(d.len());
            }
            Output::Callback(delay) => break delay,
            Output::None => panic!("the client should be waiting for the server"),
        }
    };

    // Six probes descending in steps of 37, which is the 1280-to-1500 range over the six probes
    // the initial congestion window affords, then the `ClientHello` itself in two minimum-sized
    // datagrams.
    assert_eq!(client.stats().pmtud_tx, 6);
    assert_eq!(
        sizes,
        [1452, 1415, 1378, 1341, 1304, 1267, base_plpmtu, base_plpmtu]
    );

    // The `ClientHello` is cut into two fragments for a minimum-sized packet: the SNI-sliced pair,
    // which is two CRYPTO frames, and a single frame with the rest.
    assert_eq!(crypto_frames, [2, 1, 2, 1, 2, 1, 2, 1]);
    assert_eq!(client.stats().frame_tx.ping, 0);
    assert_eq!(client.process_output(now() + delay).dgram(), None);
}

/// A client's probes carry copies of the `ClientHello`, so the server can complete the handshake
/// from the probes alone, even if every datagram carrying the real one is lost.
#[test]
fn client_probes_carry_clienthello() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));
    let base_plpmtu = BASE_MTU - Pmtud::header_size(DEFAULT_ADDR.ip());

    // Drop everything at the current size, so only the probes reach the server.
    let mut probes = 0;
    while let Some(d) = client.process_output(now()).dgram() {
        if d.len() > base_plpmtu {
            probes += 1;
            server.process_input(d, now());
        }
    }
    assert_eq!(probes, 6);

    // The server got a complete ClientHello out of them.
    assert_eq!(server.stats().frame_rx.crypto, 9);
    assert_eq!(*server.state(), State::Handshaking);
    assert!(server.process_output(now()).dgram().is_some());
}

/// Test that one can reach the largest probed MTU with GSO enabled.
#[test]
fn gso_with_max_mtu() {
    neqo_common::log::init(None);
    fixture_init();
    let mut client = Connection::new_client(
        test_fixture::DEFAULT_SERVER_NAME,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR_V4,
        DEFAULT_ADDR_V4,
        ConnectionParameters::default()
            .pmtud(true)
            .pmtud_iface_mtu(false),
        now(),
    )
    .expect("create a default client");

    let mut server = default_server();

    connect(&mut client, &mut server);

    let max_plpmtu = MAX_PROBE_MTU - Pmtud::header_size(DEFAULT_ADDR_V4.ip());
    assert_eq!(client.plpmtu(), max_plpmtu);

    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    fill_stream(&mut client, stream_id);
    let pkts = client
        .process_multiple_output(now(), 2.try_into().unwrap())
        .dgram()
        .unwrap();
    assert_eq!(pkts.datagram_size().get(), max_plpmtu);
}

/// Simulates VPN by changing the source address of a datagram to an IPv6 VPN endpoint.
fn via_vpn(d: &Datagram) -> Datagram {
    // Use an IPv6 address since the default test connection uses IPv6.
    const VPN_ADDR: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        12345,
    );
    Datagram::new(VPN_ADDR, d.destination(), d.tos(), &d[..])
}

/// Exchange packets in both directions for `rounds` timer expiries, dropping anything larger than
/// `mtu` in either direction. Both sides keep a stream busy, so full-size packets keep flowing.
fn exchange(
    client: &mut Connection,
    server: &mut Connection,
    mtu: usize,
    mut now: Instant,
    rounds: usize,
) -> Instant {
    for _ in 0..rounds {
        for c in [&mut *client, &mut *server] {
            if let Ok(stream_id) = c.stream_create(StreamType::UniDi) {
                fill_stream(c, stream_id);
            }
        }
        while let Some(d) = client.process_output(now).dgram() {
            if d.len() <= mtu {
                server.process_input(d, now);
            }
        }
        while let Some(d) = server.process_output(now).dgram() {
            if d.len() <= mtu {
                client.process_input(d, now);
            }
        }
        maybe_authenticate(client);
        now += DEFAULT_RTT;
    }
    now
}

/// Tests what happens when a client starts going through a VPN, i.e., its packets arrive at the
/// server from a different IP address, and the VPN's MTU is smaller than the one both sides
/// confirmed on the original path.
///
/// Scenario:
/// 1. Connection established; both sides confirm a size above the base MTU
/// 2. VPN is brought up; all traffic now flows through it, with an MTU of 1400
/// 3. Server sees packets from a new IP and sends a `PATH_CHALLENGE`, and probes the new path
/// 4. The client cannot probe for anything smaller -- probing only ever goes up -- so it detects
///    that its confirmed size is being black holed and falls back to the base MTU.
///
/// The server's own PLPMTU is not asserted here: whether it ends up on the new path or keeps the
/// old one depends on migration details this test does not model faithfully, since it feeds
/// datagrams to each side regardless of the address they were sent to.
#[test]
fn vpn_migration_triggers_pmtud() {
    fixture_init();
    let mut now = now();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));
    let header_size = Pmtud::header_size(
        client
            .paths
            .primary()
            .unwrap()
            .borrow()
            .local_address()
            .ip(),
    );
    let base_plpmtu = BASE_MTU - header_size;
    let initial_path_mtu = MAX_PROBE_MTU - header_size;
    let vpn_path_mtu = 1400 - header_size;

    connect(&mut client, &mut server);

    // Settle PMTUD on the initial path, which carries everything that was probed for.
    now = exchange(&mut client, &mut server, initial_path_mtu, now, 5);
    assert_eq!(client.plpmtu(), initial_path_mtu);
    assert_eq!(server.plpmtu(), initial_path_mtu);

    // VPN is now brought up; the client sends data, but from the server's perspective it now
    // arrives from the VPN tunnel endpoint address.
    let c1 = send_something(&mut client, now);
    let c1_via_vpn = via_vpn(&c1);

    // Server receives a packet from the "new" source IP, which triggers path validation.
    let server_pmtud_tx_before = server.stats().pmtud_tx;
    let before_challenge = server.stats().frame_tx.path_challenge;
    let s1 = server.process(Some(c1_via_vpn), now).dgram();
    assert!(s1.is_some(), "Server should respond");
    assert_eq!(server.stats().frame_tx.path_challenge, before_challenge + 1);

    // Client receives the PATH_CHALLENGE.
    let s1 = s1.unwrap();
    let s1_to_client = Datagram::new(s1.source(), c1.source(), s1.tos(), &s1[..]);
    let before_response = client.stats().frame_tx.path_response;
    let c2 = client.process(Some(s1_to_client), now).dgram();
    assert!(c2.is_some(), "Client should respond with PATH_RESPONSE");
    assert_eq!(client.stats().frame_tx.path_response, before_response + 1);

    // Server receives PATH_RESPONSE via VPN.
    let c2 = c2.unwrap();
    let c2_via_vpn = via_vpn(&c2);
    server.process_input(c2_via_vpn, now);

    // Now everything has to fit through the VPN.
    exchange(&mut client, &mut server, vpn_path_mtu, now, 10);

    // The server probed the path it now sees the client on.
    assert_eq!(server.stats().pmtud_tx, server_pmtud_tx_before + 1);

    // The client stopped using a size the VPN cannot carry.
    assert_eq!(client.stats().pmtud_black_hole, 1);
    assert_eq!(client.plpmtu(), base_plpmtu);
    assert!(
        base_plpmtu < vpn_path_mtu,
        "the fallback fits through the VPN"
    );
}

/// A server may answer before the whole `ClientHello` flight has arrived, which leaves it an
/// anti-amplification budget of only three times what it has seen. Its own flight has to fit in
/// what probing leaves of that, or it is split across datagrams that only later arrivals unlock.
///
/// Two things keep it whole: [`Path::pmtud_probe`] holds the flight back from the budget, and
/// coalescing means the `ServerHello` costs no datagram of its own. Either alone suffices for the
/// flight sizes here, so this guards the outcome rather than one of the two mechanisms.
#[test]
fn probes_do_not_starve_the_server_flight() {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));

    let mut flight = Vec::new();
    while let Some(d) = client.process_output(now()).dgram() {
        flight.push(d);
    }
    assert!(flight.len() > 2, "a flight of probes: {}", flight.len());

    // Only the first two datagrams arrive before the server answers.
    for d in flight.into_iter().take(2) {
        server.process_input(d, now());
    }
    while let Some(d) = server.process_output(now()).dgram() {
        client.process_input(d, now());
    }

    // The client assembled a complete flight from that, without the rest of its own arriving.
    assert!(maybe_authenticate(&mut client));

    // The flight went out whole: one CRYPTO frame for each of Initial and Handshake, plus the copy
    // each probe carries. Starved of anti-amplification budget it is split across two frames
    // instead, and the last probe waits for the rest of the peer's flight to unlock more.
    assert_eq!(
        server.stats().frame_tx.crypto,
        server.stats().pmtud_tx + 2,
        "{} probes",
        server.stats().pmtud_tx
    );
}
