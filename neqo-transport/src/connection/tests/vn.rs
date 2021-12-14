// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::{ConnectionError, Output, State};
use super::{connect, default_client, default_server, new_client, new_server};
use crate::packet::PACKET_BIT_LONG;
use crate::{tparams::TransportParameter, ConnectionParameters, Error, QuicVersion};

use neqo_common::{Datagram, Decoder, Encoder};
use std::mem;
use std::time::Duration;
use test_fixture::{self, addr, assertions, now};

// The expected PTO duration after the first Initial is sent.
const INITIAL_PTO: Duration = Duration::from_millis(300);

#[test]
fn unknown_version() {
    let mut client = default_client();
    // Start the handshake.
    mem::drop(client.process(None, now()).dgram());

    let mut unknown_version_packet = vec![0x80, 0x1a, 0x1a, 0x1a, 0x1a];
    unknown_version_packet.resize(1200, 0x0);
    mem::drop(client.process(
        Some(Datagram::new(addr(), addr(), unknown_version_packet)),
        now(),
    ));
    assert_eq!(1, client.stats().dropped_rx);
}

#[test]
fn server_receive_unknown_first_packet() {
    let mut server = default_server();

    let mut unknown_version_packet = vec![0x80, 0x1a, 0x1a, 0x1a, 0x1a];
    unknown_version_packet.resize(1200, 0x0);

    assert_eq!(
        server.process(
            Some(Datagram::new(addr(), addr(), unknown_version_packet,)),
            now(),
        ),
        Output::None
    );

    assert_eq!(1, server.stats().dropped_rx);
}

fn create_vn(initial_pkt: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut dec = Decoder::from(&initial_pkt[5..]); // Skip past version.
    let dst_cid = dec.decode_vec(1).expect("client DCID");
    let src_cid = dec.decode_vec(1).expect("client SCID");

    let mut encoder = Encoder::default();
    encoder.encode_byte(PACKET_BIT_LONG);
    encoder.encode(&[0; 4]); // Zero version == VN.
    encoder.encode_vec(1, src_cid);
    encoder.encode_vec(1, dst_cid);

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
        &[0x1a1a_1a1a, QuicVersion::default().as_u32()],
    );

    let dgram = Datagram::new(addr(), addr(), vn);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, INITIAL_PTO);
    assert_eq!(*client.state(), State::WaitInitial);
    assert_eq!(1, client.stats().dropped_rx);
}

#[test]
fn version_negotiation_version0() {
    let mut client = default_client();
    // Start the handshake.
    let initial_pkt = client
        .process(None, now())
        .dgram()
        .expect("a datagram")
        .to_vec();

    let vn = create_vn(&initial_pkt, &[0, 0x1a1a_1a1a]);

    let dgram = Datagram::new(addr(), addr(), vn);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, INITIAL_PTO);
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

    let dgram = Datagram::new(addr(), addr(), vn);
    assert_eq!(client.process(Some(dgram), now()), Output::None);
    match client.state() {
        State::Closed(err) => {
            assert_eq!(*err, ConnectionError::Transport(Error::VersionNegotiation));
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

    let dgram = Datagram::new(addr(), addr(), &vn[..vn.len() - 1]);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, INITIAL_PTO);
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

    let dgram = Datagram::new(addr(), addr(), vn);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, INITIAL_PTO);
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
    let dgram = Datagram::new(addr(), addr(), vn);
    assert_eq!(client.process(Some(dgram), now()), Output::None);
    match client.state() {
        State::Closed(err) => {
            assert_eq!(*err, ConnectionError::Transport(Error::VersionNegotiation));
        }
        _ => panic!("Invalid client state"),
    }
}

#[test]
fn version_negotiation_bad_cid() {
    let mut client = default_client();
    // Start the handshake.
    let mut initial_pkt = client
        .process(None, now())
        .dgram()
        .expect("a datagram")
        .to_vec();

    initial_pkt[6] ^= 0xc4;
    let vn = create_vn(&initial_pkt, &[0x1a1a_1a1a, 0x2a2a_2a2a, 0xff00_0001]);

    let dgram = Datagram::new(addr(), addr(), vn);
    let delay = client.process(Some(dgram), now()).callback();
    assert_eq!(delay, INITIAL_PTO);
    assert_eq!(*client.state(), State::WaitInitial);
    assert_eq!(1, client.stats().dropped_rx);
}

#[test]
fn compatible_upgrade() {
    let mut client = default_client();
    let mut server = default_server();

    connect(&mut client, &mut server);
    assert_eq!(client.version(), QuicVersion::Version2);
    assert_eq!(server.version(), QuicVersion::Version2);
}

/// When the first packet from the client is gigantic, the server might generate acknowledgment packets in
/// version 1.  Both client and server need to handle that gracefully.
#[test]
fn compatible_upgrade_large_initial() {
    let params = ConnectionParameters::default().versions(
        QuicVersion::Version1,
        vec![QuicVersion::Version2, QuicVersion::Version1],
    );
    let mut client = new_client(params.clone());
    client
        .set_local_tparam(
            0x0845_de37_00ac_a5f9,
            TransportParameter::Bytes(vec![0; 2048]),
        )
        .unwrap();
    let mut server = new_server(params);

    // Client Initial should take 2 packets.
    // Each should elicit a Version 1 ACK from the server.
    let dgram = client.process_output(now()).dgram();
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    // The following uses the QuicVersion from *outside* this crate.
    assertions::assert_version(dgram.as_ref().unwrap(), QuicVersion::Version1.as_u32());
    client.process_input(dgram.unwrap(), now());

    connect(&mut client, &mut server);
    assert_eq!(client.version(), QuicVersion::Version2);
    assert_eq!(server.version(), QuicVersion::Version2);
    // Only handshake padding is "dropped".
    assert_eq!(client.stats().dropped_rx, 1);
    assert_eq!(server.stats().dropped_rx, 1);
}

/// A server that supports versions 1 and 2 might prefer version 1 and that's OK.
#[test]
fn compatible_downgrade() {
    let mut client = default_client();
    let mut server = new_server(ConnectionParameters::default().versions(
        QuicVersion::Version2,
        vec![QuicVersion::Version1, QuicVersion::Version2],
    ));

    connect(&mut client, &mut server);
    assert_eq!(client.version(), QuicVersion::Version1);
    assert_eq!(server.version(), QuicVersion::Version1);
}

/// Test that connecting with only one version works.
/// This only works at the client end as our Connection doesn't generate
/// a Version Negotiation packet.
fn one_version_only(version: QuicVersion) {
    let mut client = new_client(ConnectionParameters::default().versions(version, vec![version]));
    let mut server = default_server();

    connect(&mut client, &mut server);
    assert_eq!(client.version(), version);
    assert_eq!(server.version(), version);
}

#[test]
fn just_v1_client() {
    one_version_only(QuicVersion::Version1);
}

#[test]
fn just_v2_client() {
    one_version_only(QuicVersion::Version2);
}
