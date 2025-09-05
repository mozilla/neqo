// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod common;
use common::assert_dscp;
use neqo_common::{Datagram, Decoder, Encoder, Role};
use neqo_crypto::Aead;
use neqo_transport::{
    CloseReason, ConnectionParameters, Error, State, StreamType, Version, MIN_INITIAL_PACKET_SIZE,
};
use test_fixture::{
    default_client, default_server,
    header_protection::{self, decode_initial_header, initial_aead_and_hp},
    new_client, new_server, now, split_datagram, CountingConnectionIdGenerator, DEFAULT_ALPN,
};

#[test]
fn connect() {
    let (client, server) = test_fixture::connect();
    assert_dscp(&client.stats());
    assert_dscp(&server.stats());
}

#[test]
fn gso() {
    let (mut client, _server) = test_fixture::connect();

    let stream_id2 = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(stream_id2, &[42; 2048]).unwrap();
    client.stream_close_send(stream_id2).unwrap();

    let out = client
        .process_multiple_output(now(), 64.try_into().expect(">0"))
        .dgram()
        .unwrap();

    assert_eq!(out.datagram_size(), 1232);
    assert!(out.data().len() > out.datagram_size());
}

#[test]
fn truncate_long_packet() {
    neqo_common::log::init(None);
    let now = now();

    // This test needs to alter the server handshake, so turn off MLKEM.
    let mut client =
        new_client::<CountingConnectionIdGenerator>(ConnectionParameters::default().mlkem(false));
    let mut server = new_server::<CountingConnectionIdGenerator>(
        DEFAULT_ALPN,
        ConnectionParameters::default().mlkem(false),
    );

    let out = client.process_output(now).dgram().unwrap();
    let out = server.process(Some(out), now);

    // This will truncate the Handshake packet from the server.
    let dupe = out.as_dgram_ref().unwrap().clone();
    // Count the padding in the packet, plus 1.
    let tail = dupe.iter().rev().take_while(|b| **b == 0).count() + 1;
    let truncated = Datagram::new(
        dupe.source(),
        dupe.destination(),
        dupe.tos(),
        &dupe[..(dupe.len() - tail)],
    );
    let hs_probe = client.process(Some(truncated), now).dgram();
    assert!(hs_probe.is_some());

    // Now feed in the untruncated packet.
    let out = client.process(out.dgram(), now);
    assert!(out.as_dgram_ref().is_some()); // Throw this ACK away.
    assert!(test_fixture::maybe_authenticate(&mut client));
    let out = client.process_output(now);
    assert!(out.as_dgram_ref().is_some());

    assert!(client.state().connected());
    let out = server.process(out.dgram(), now);
    assert!(out.as_dgram_ref().is_some());
    assert!(server.state().connected());
}

/// Test that reordering parts of the server Initial doesn't change things.
#[test]
fn reorder_server_initial() {
    // A simple ACK frame for a single packet with packet number 0.
    const ACK_FRAME: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x00];

    // This test predicts the precise format of an ACK frame, so turn off MLKEM
    // and packet number randomization.
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default()
            .versions(Version::Version1, vec![Version::Version1])
            .mlkem(false)
            .randomize_first_pn(false),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now());
    let (_, client_dcid, _, _) =
        decode_initial_header(client_initial.as_dgram_ref().unwrap(), Role::Client).unwrap();
    let client_dcid = client_dcid.to_owned();

    let server_packet = server.process(client_initial.dgram(), now()).dgram();
    let (server_initial, server_hs) = split_datagram(server_packet.as_ref().unwrap());
    let (protected_header, _, _, payload) =
        decode_initial_header(&server_initial, Role::Server).unwrap();

    // Now decrypt the packet.
    let (aead, hp) = initial_aead_and_hp(&client_dcid, Role::Server);
    let (header, pn) = header_protection::remove(&hp, protected_header, payload);
    let pn_len = header.len() - protected_header.len();
    let mut buf = vec![0; payload.len()];
    let mut plaintext = aead
        .decrypt(pn, &header, &payload[pn_len..], &mut buf)
        .unwrap()
        .to_owned();

    // Now we need to find the frames.  Make some really strong assumptions.
    let mut dec = Decoder::new(&plaintext[..]);
    assert_eq!(dec.decode(ACK_FRAME.len()), Some(ACK_FRAME));
    assert_eq!(dec.decode_varint(), Some(0x06)); // CRYPTO
    assert_eq!(dec.decode_varint(), Some(0x00)); // offset
    dec.skip_vvec(); // Skip over the payload.
    let end = dec.offset();

    // Move the ACK frame after the CRYPTO frame.
    plaintext[..end].rotate_left(ACK_FRAME.len());

    // And rebuild a packet.
    let mut packet = header.clone();
    packet.resize(MIN_INITIAL_PACKET_SIZE, 0);
    aead.encrypt(pn, &header, &plaintext, &mut packet[header.len()..])
        .unwrap();
    header_protection::apply(&hp, &mut packet, protected_header.len()..header.len());
    let reordered = Datagram::new(
        server_initial.source(),
        server_initial.destination(),
        server_initial.tos(),
        packet,
    );

    // Now a connection can be made successfully.
    // Though we modified the server's Initial packet, we get away with it.
    // TLS only authenticates the content of the CRYPTO frame, which was untouched.
    client.process_input(reordered, now());
    client.process_input(server_hs.unwrap(), now());
    assert!(test_fixture::maybe_authenticate(&mut client));
    let finished = client.process_output(now());
    assert_eq!(*client.state(), State::Connected);

    let done = server.process(finished.dgram(), now());
    assert_eq!(*server.state(), State::Confirmed);

    client.process_input(done.dgram().unwrap(), now());
    assert_eq!(*client.state(), State::Confirmed);
}

#[cfg(test)]
fn set_payload(server_packet: Option<&Datagram>, client_dcid: &[u8], payload: &[u8]) -> Datagram {
    let (server_initial, _server_hs) = split_datagram(server_packet.as_ref().unwrap());
    let (protected_header, _, _, orig_payload) =
        decode_initial_header(&server_initial, Role::Server).unwrap();

    // Now decrypt the packet.
    let (aead, hp) = initial_aead_and_hp(client_dcid, Role::Server);
    let (mut header, pn) = header_protection::remove(&hp, protected_header, orig_payload);
    // Re-encode the packet number as four bytes, so we have enough material for the header
    // protection sample if payload is empty.
    let pn_len = usize::from(header[0] & 0b0000_0011) + 1;
    let len_pos = header.len()
        - pn_len
        - Encoder::varint_len(u64::try_from(pn_len + orig_payload.len()).unwrap());
    header.truncate(len_pos);
    let mut enc = Encoder::new_borrowed_vec(&mut header);
    enc.encode_varint(u64::try_from(4 + payload.len() + Aead::expansion()).unwrap());
    enc.encode_uint(4, pn);
    header[0] = header[0] & 0xfc | 0b0000_0011; // Set the packet number length to 4.

    // And build a packet containing the given payload.
    let mut packet = header.clone();
    packet.resize(header.len() + payload.len() + Aead::expansion(), 0);
    aead.encrypt(pn, &header, payload, &mut packet[header.len()..])
        .unwrap();
    header_protection::apply(&hp, &mut packet, protected_header.len()..header.len());
    Datagram::new(
        server_initial.source(),
        server_initial.destination(),
        server_initial.tos(),
        packet,
    )
}

/// Test that the stack treats a packet without any frames as a protocol violation.
#[test]
fn packet_without_frames() {
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default().versions(Version::Version1, vec![Version::Version1]),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now());
    let client_initial_clone = client_initial.as_dgram_ref().unwrap().clone();
    let (_, client_dcid, _, _) =
        decode_initial_header(&client_initial_clone, Role::Client).unwrap();

    let server_packet = server.process(client_initial.dgram(), now()).dgram();
    let modified = set_payload(server_packet.as_ref(), client_dcid, &[]);
    client.process_input(modified, now());
    assert_eq!(
        client.state(),
        &State::Closed(CloseReason::Transport(Error::ProtocolViolation))
    );
}

/// Test that the stack permits a packet containing only padding.
#[test]
fn packet_with_only_padding() {
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default().versions(Version::Version1, vec![Version::Version1]),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now());
    let client_initial_clone = client_initial.as_dgram_ref().unwrap().clone();
    let (_, client_dcid, _, _) =
        decode_initial_header(&client_initial_clone, Role::Client).unwrap();

    let server_packet = server.process(client_initial.dgram(), now()).dgram();
    let modified = set_payload(server_packet.as_ref(), client_dcid, &[0]);
    client.process_input(modified, now());
    assert_eq!(client.state(), &State::WaitVersion);
}

/// Overflow the crypto buffer.
#[expect(clippy::similar_names, reason = "scid simiar to dcid.")]
#[test]
fn overflow_crypto() {
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default().versions(Version::Version1, vec![Version::Version1]),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now()).dgram();
    let (_, client_dcid, _, _) =
        decode_initial_header(client_initial.as_ref().unwrap(), Role::Client).unwrap();
    let client_dcid = client_dcid.to_owned();

    let server_packet = server.process(client_initial, now()).dgram();
    let (server_initial, _) = split_datagram(server_packet.as_ref().unwrap());

    // Now decrypt the server packet to get AEAD and HP instances.
    // We won't be using the packet, but making new ones.
    let (aead, hp) = initial_aead_and_hp(&client_dcid, Role::Server);
    let (_, server_dcid, server_scid, _) =
        decode_initial_header(&server_initial, Role::Server).unwrap();

    // Send in 100 packets, each with 1000 bytes of crypto frame data each,
    // eventually this will overrun the buffer we keep for crypto data.
    let mut payload = Encoder::with_capacity(1024);
    for pn in 0..100_u64 {
        payload.truncate(0);
        payload
            .encode_varint(0x06_u64) // CRYPTO frame type.
            .encode_varint(pn * 1000 + 1) // offset
            .encode_varint(1000_u64); // length
        let plen = payload.len();
        payload.pad_to(plen + 1000, 44);

        let mut packet = Encoder::with_capacity(MIN_INITIAL_PACKET_SIZE);
        packet
            .encode_byte(0xc1) // Initial with packet number length of 2.
            .encode_uint(4, Version::Version1.wire_version())
            .encode_vec(1, server_dcid)
            .encode_vec(1, server_scid)
            .encode_vvec(&[]) // token
            .encode_varint(u64::try_from(2 + payload.len() + Aead::expansion()).unwrap()); // length
        let pn_offset = packet.len();
        packet.encode_uint(2, pn);

        let mut packet = Vec::from(packet);
        let header = packet.clone();
        packet.resize(header.len() + payload.len() + Aead::expansion(), 0);
        aead.encrypt(pn, &header, payload.as_ref(), &mut packet[header.len()..])
            .unwrap();
        header_protection::apply(&hp, &mut packet, pn_offset..(pn_offset + 2));
        packet.resize(MIN_INITIAL_PACKET_SIZE, 0); // Initial has to be MIN_INITIAL_PACKET_SIZE bytes!

        let dgram = Datagram::new(
            server_initial.source(),
            server_initial.destination(),
            server_initial.tos(),
            packet,
        );
        client.process_input(dgram, now());
        if let State::Closing { error, .. } | State::Closed(error) = client.state() {
            assert!(
                matches!(error, CloseReason::Transport(Error::CryptoBufferExceeded)),
                "the connection need to abort on crypto buffer"
            );
            assert!(pn > 64, "at least 64000 bytes of data is buffered");
            return;
        }
    }
    panic!("Unable to overflow the crypto buffer: {:?}", client.state());
}

#[test]
fn handshake_mlkem768x25519() {
    let mut client = default_client();
    let mut server = default_server();

    client
        .set_groups(&[neqo_crypto::TLS_GRP_KEM_MLKEM768X25519])
        .unwrap();
    client.send_additional_key_shares(0).unwrap();

    test_fixture::handshake(&mut client, &mut server);
    assert_eq!(*client.state(), State::Confirmed);
    assert_eq!(*server.state(), State::Confirmed);
    assert_eq!(
        client.tls_info().unwrap().key_exchange(),
        neqo_crypto::TLS_GRP_KEM_MLKEM768X25519
    );
    assert_eq!(
        server.tls_info().unwrap().key_exchange(),
        neqo_crypto::TLS_GRP_KEM_MLKEM768X25519
    );
}

#[test]
fn client_initial_packet_number() {
    // Check that the initial packet number is randomized (i.e, > 0) if the `randomize_first_pn`
    // connection parameter is set, and that it is zero when not.
    for randomize in [true, false] {
        // This test needs to decrypt the CI, so turn off MLKEM.
        let mut client = new_client::<CountingConnectionIdGenerator>(
            ConnectionParameters::default()
                .versions(Version::Version1, vec![Version::Version1])
                .mlkem(false)
                .randomize_first_pn(randomize),
        );

        let client_initial = client.process_output(now());
        let (protected_header, client_dcid, _, payload) =
            decode_initial_header(client_initial.as_dgram_ref().unwrap(), Role::Client).unwrap();
        let (_, hp) = initial_aead_and_hp(client_dcid, Role::Client);
        let (_, pn) = header_protection::remove(&hp, protected_header, payload);
        assert!(
            randomize && pn > 0 || !randomize && pn == 0,
            "randomize {randomize} = {pn}"
        );
    }
}

#[test]
fn server_initial_packet_number() {
    // Check that the initial packet number is randomized (i.e, > 0) if the `randomize_first_pn`
    // connection parameter is set, and that it is zero when not.
    for randomize in [true, false] {
        // This test needs to decrypt the CI, so turn off MLKEM.
        let mut client = new_client::<CountingConnectionIdGenerator>(
            ConnectionParameters::default()
                .versions(Version::Version1, vec![Version::Version1])
                .mlkem(false),
        );
        let mut server = new_server::<CountingConnectionIdGenerator>(
            DEFAULT_ALPN,
            ConnectionParameters::default()
                .versions(Version::Version1, vec![Version::Version1])
                .randomize_first_pn(randomize),
        );

        let client_initial = client.process_output(now()).dgram();
        let (_protected_header, client_dcid, _scid, _payload) =
            decode_initial_header(client_initial.as_ref().unwrap(), Role::Client).unwrap();

        let (_, hp) = initial_aead_and_hp(client_dcid, Role::Server);

        let server_initial = server.process(client_initial, now()).dgram();
        let (protected_header, _dcid, _scid, payload) =
            decode_initial_header(server_initial.as_ref().unwrap(), Role::Server).unwrap();

        let (_, pn) = header_protection::remove(&hp, protected_header, payload);
        println!();
        assert!(
            randomize && pn > 0 || !randomize && pn == 0,
            "randomize {randomize} = {pn}"
        );
    }
}
