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
    ConnectionParameters, Output, Pmtud, StreamType,
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
    const VPN_ADDR: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        12345,
    );
    Datagram::new(VPN_ADDR, d.destination(), d.tos(), &d[..])
}

/// Exchanges packets between sender and receiver until PMTUD settles,
/// dropping any packets larger than `mtu`.
fn drive_pmtud(
    sender: &mut Connection,
    receiver: &mut Connection,
    mtu: usize,
    mut now: std::time::Instant,
) -> std::time::Instant {
    if let Ok(stream_id) = sender.stream_create(StreamType::UniDi) {
        fill_stream(sender, stream_id);
    }
    loop {
        match sender.process_output(now) {
            Output::Datagram(d) => {
                if d.len() <= mtu {
                    receiver.process_input(d, now);
                }
            }
            Output::Callback(t) => {
                // Get ACKs from receiver.
                while let Some(d) = receiver.process_output(now).dgram() {
                    if d.len() <= mtu {
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
    let initial_path_mtu = 1500 - header_size;
    let vpn_path_mtu = 1400 - header_size;

    connect(&mut client, &mut server);
    assert_eq!(client.plpmtu(), 1232, "PMTU should be IPv6 default");
    assert_eq!(server.plpmtu(), 1232, "PMTU should be IPv6 default");

    // Drive PMTUD on the initial path.
    now = drive_pmtud(&mut client, &mut server, initial_path_mtu, now);
    now = drive_pmtud(&mut server, &mut client, initial_path_mtu, now);
    assert_eq!(client.plpmtu(), initial_path_mtu);
    assert_eq!(server.plpmtu(), initial_path_mtu);

    // VPN is now brought up; client sends data, but from the server's perspective, it now arrives
    // from the VPN tunnel endpoint address.
    let c1 = send_something(&mut client, now);
    let c1_via_vpn = via_vpn(&c1);

    // Server receives packet from "new" source IP (VPN endpoint).
    // This triggers path validation (PATH_CHALLENGE) on a new path.
    let before_challenge = server.stats().frame_tx.path_challenge;
    let s1 = server.process(Some(c1_via_vpn), now).dgram();
    assert!(s1.is_some(), "Server should respond");
    assert_eq!(server.stats().frame_tx.path_challenge, before_challenge + 1);

    // Client receives the PATH_CHALLENGE. This triggers PMTUD restart on its path.
    let s1 = s1.unwrap();
    let s1_to_client = Datagram::new(s1.source(), c1.source(), s1.tos(), &s1[..]);
    let client_pmtud_tx_before_challenge = client.stats().pmtud_tx;
    let before_response = client.stats().frame_tx.path_response;
    let c2 = client.process(Some(s1_to_client), now).dgram();
    assert!(c2.is_some(), "Client should respond with PATH_RESPONSE");
    assert_eq!(client.stats().frame_tx.path_response, before_response + 1);

    // Server receives PATH_RESPONSE via VPN.
    let c2 = c2.unwrap();
    let c2_via_vpn = via_vpn(&c2);
    server.process_input(c2_via_vpn, now);

    // Record PMTUD probe counts before driving traffic on VPN path.
    let server_pmtud_tx_before = server.stats().pmtud_tx;

    // Drive PMTUD probing for both sides on the VPN path with smaller MTU.
    let now = drive_pmtud(&mut client, &mut server, vpn_path_mtu, now);
    drive_pmtud(&mut server, &mut client, vpn_path_mtu, now);

    // Verify server and client sent PMTUD probes on the new path.
    assert!(server.stats().pmtud_tx > server_pmtud_tx_before);
    assert!(client.stats().pmtud_tx > client_pmtud_tx_before_challenge);

    // Verify both sides' PMTU reflects the VPN path's smaller MTU.
    // vpn_path_mtu is 1400; the largest IPv6 search table entry <= 1400 is 1380.
    let expected_vpn_mtu = 1380 - header_size;
    assert_eq!(server.plpmtu(), expected_vpn_mtu);
    assert_eq!(client.plpmtu(), expected_vpn_mtu);
}
