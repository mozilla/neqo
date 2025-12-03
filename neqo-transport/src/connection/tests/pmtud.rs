// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    rc::Rc,
};

use neqo_common::Datagram;
use test_fixture::{fixture_init, now, DEFAULT_ADDR_V4};

use super::Connection;
use crate::{
    connection::tests::{
        connect, default_server, fill_stream, new_client, new_server, send_something,
        CountingConnectionIdGenerator, DEFAULT_RTT,
    },
    ConnectionParameters, Output, StreamType,
};

/// Test that one can reach the maximum MTU with GSO enabled.
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

    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    // Increase MTU to the max.
    loop {
        fill_stream(&mut client, stream_id);
        let mut pkts = client
            .process_multiple_output(now(), 2.try_into().unwrap())
            .dgram()
            .unwrap();
        if pkts.datagram_size().get() == 65507 {
            // Success. It reached the maximum IPv4 UDP MTU.
            break;
        }
        assert!(pkts.datagram_size().get() < 65507);

        server.process_multiple_input(pkts.iter_mut(), now());
        let ack = server.process_output(now()).dgram();
        client.process_input(ack.unwrap(), now());
    }
}

/// Simulates VPN by changing the source address of a datagram to an IPv6 VPN endpoint.
fn via_vpn(d: &Datagram) -> Datagram {
    // Use an IPv6 address since the default test connection uses IPv6.
    const VPN_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 12345);
    Datagram::new(VPN_ADDR, d.destination(), d.tos(), &d[..])
}

/// Exchanges packets between sender and receiver until PMTUD settles,
/// dropping any packets larger than `path_mtu` to simulate the MTU limit.
fn exchange_until_mtu_probed(
    sender: &mut Connection,
    receiver: &mut Connection,
    path_mtu: usize,
    mut now: std::time::Instant,
) -> std::time::Instant {
    if let Ok(stream_id) = sender.stream_create(StreamType::UniDi) {
        fill_stream(sender, stream_id);
    }
    loop {
        match sender.process_output(now) {
            Output::Datagram(d) => {
                if d.len() <= path_mtu {
                    receiver.process_input(d, now);
                }
            }
            Output::Callback(t) => {
                // Get ACKs from receiver.
                while let Some(d) = receiver.process_output(now).dgram() {
                    if d.len() <= path_mtu {
                        sender.process_input(d, now);
                    }
                }
                if t >= DEFAULT_RTT {
                    break; // PMTUD has settled (waiting for PTO or raise timer).
                }
                now += t;
            }
            Output::None => break,
        }
    }
    now
}

/// Tests that when a client goes through a VPN (packets arrive from different IP),
/// the server initiates a path challenge, and both client and server run PMTUD
/// to discover the VPN's lower MTU.
///
/// Scenario:
/// 1. Connection established, both sides discover initial MTU (1500)
/// 2. VPN is brought up - all traffic now flows through VPN with lower MTU (1400)
/// 3. Server sees packets from new IP, sends `PATH_CHALLENGE`, creates new path, runs PMTUD
/// 4. Client receives `PATH_CHALLENGE`, which triggers PMTUD on its path
/// 5. Both sides discover the VPN's lower MTU
#[test]
fn vpn_migration_triggers_pmtud() {
    const INITIAL_PATH_MTU: usize = 1500;
    const VPN_PATH_MTU: usize = 1400;

    fixture_init();
    let mut now = now();
    let mut client = new_client(ConnectionParameters::default().pmtud(true));
    let mut server = new_server(ConnectionParameters::default().pmtud(true));
    connect(&mut client, &mut server);

    // Verify initial PMTU for IPv6 (1232 = 1280 - 48 byte header).
    let initial_client_pmtu = client.plpmtu();
    let initial_server_pmtu = server.plpmtu();
    assert_eq!(initial_client_pmtu, 1232, "Client initial PMTU should be IPv6 default");
    assert_eq!(initial_server_pmtu, 1232, "Server initial PMTU should be IPv6 default");

    // Drive PMTUD on the initial path to discover the full MTU (1500).
    now = exchange_until_mtu_probed(&mut client, &mut server, INITIAL_PATH_MTU, now);
    now = exchange_until_mtu_probed(&mut server, &mut client, INITIAL_PATH_MTU, now);

    // Verify both sides discovered a larger MTU on the initial path.
    let client_pmtu_after_initial = client.plpmtu();
    let server_pmtu_after_initial = server.plpmtu();
    assert!(
        client_pmtu_after_initial > initial_client_pmtu,
        "Client should have discovered larger MTU on initial path: {client_pmtu_after_initial} > {initial_client_pmtu}"
    );
    assert!(
        server_pmtu_after_initial > initial_server_pmtu,
        "Server should have discovered larger MTU on initial path: {server_pmtu_after_initial} > {initial_server_pmtu}"
    );

    // --- VPN is now brought up ---
    // Client sends data, but from the server's perspective, it now arrives
    // from the VPN tunnel endpoint address.
    let c1 = send_something(&mut client, now);
    let c1_via_vpn = via_vpn(&c1);

    // Server receives packet from "new" source IP (VPN endpoint).
    // This triggers path validation (PATH_CHALLENGE) on a new path.
    let before_challenge = server.stats().frame_tx.path_challenge;
    let s1 = server.process(Some(c1_via_vpn), now).dgram();
    assert!(s1.is_some(), "Server should respond");
    let after_challenge = server.stats().frame_tx.path_challenge;
    assert_eq!(
        after_challenge,
        before_challenge + 1,
        "Server should send PATH_CHALLENGE"
    );

    // Client receives the PATH_CHALLENGE. This triggers PMTUD restart on its path.
    let s1 = s1.unwrap();
    let s1_to_client = Datagram::new(s1.source(), c1.source(), s1.tos(), &s1[..]);
    let client_pmtud_tx_before_challenge = client.stats().pmtud_tx;
    let before_response = client.stats().frame_tx.path_response;
    let c2 = client.process(Some(s1_to_client), now).dgram();
    assert!(c2.is_some(), "Client should respond with PATH_RESPONSE");
    let after_response = client.stats().frame_tx.path_response;
    assert_eq!(
        after_response,
        before_response + 1,
        "Client should send PATH_RESPONSE"
    );

    // Server receives PATH_RESPONSE via VPN.
    let c2 = c2.unwrap();
    let c2_via_vpn = via_vpn(&c2);
    server.process_input(c2_via_vpn, now);

    // Allow time for path validation to complete.
    now += DEFAULT_RTT * 2;

    // Record PMTUD probe counts before driving traffic on VPN path.
    let server_pmtud_tx_before = server.stats().pmtud_tx;

    // Drive PMTUD probing for both sides on the VPN path with smaller MTU.
    let now = exchange_until_mtu_probed(&mut client, &mut server, VPN_PATH_MTU, now);
    exchange_until_mtu_probed(&mut server, &mut client, VPN_PATH_MTU, now);

    // Verify server sent PMTUD probes on the new path.
    let server_pmtud_tx_after = server.stats().pmtud_tx;
    assert!(
        server_pmtud_tx_after > server_pmtud_tx_before,
        "Server should have sent PMTUD probes on VPN path (before: {server_pmtud_tx_before}, after: {server_pmtud_tx_after})"
    );

    // Verify client sent PMTUD probes after receiving PATH_CHALLENGE.
    let client_pmtud_tx_after = client.stats().pmtud_tx;
    assert!(
        client_pmtud_tx_after > client_pmtud_tx_before_challenge,
        "Client should have sent PMTUD probes after PATH_CHALLENGE (before: {client_pmtud_tx_before_challenge}, after: {client_pmtud_tx_after})"
    );

    // Verify both sides' PMTU reflects the VPN path's smaller MTU.
    let server_pmtu_on_vpn = server.plpmtu();
    let client_pmtu_on_vpn = client.plpmtu();
    assert!(
        server_pmtu_on_vpn <= VPN_PATH_MTU,
        "Server PMTU {server_pmtu_on_vpn} should be <= VPN path MTU {VPN_PATH_MTU}"
    );
    assert!(
        client_pmtu_on_vpn <= VPN_PATH_MTU,
        "Client PMTU {client_pmtu_on_vpn} should be <= VPN path MTU {VPN_PATH_MTU}"
    );
}
