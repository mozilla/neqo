// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, rc::Rc, time::Duration};

use neqo_common::{event::Provider as _, qdebug};
use neqo_crypto::{AllowZeroRtt, AntiReplay};
use test_fixture::{assertions, now};

use super::{
    super::Connection, connect, default_client, default_server, exchange_ticket, new_server,
    resumed_server, CountingConnectionIdGenerator,
};
use crate::{
    events::ConnectionEvent, ConnectionParameters, Error, StreamType, Version,
    MIN_INITIAL_PACKET_SIZE,
};

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
        .enable_resumption(now(), token)
        .expect("should set token");
    let mut server = resumed_server(&client);
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
        .enable_resumption(now(), token)
        .expect("should set token");
    let mut server = resumed_server(&client);

    // Send ClientHello.
    let client_hs1 = client.process_output(now());
    let client_hs2 = client.process_output(now());
    assert!(client_hs1.as_dgram_ref().is_some() && client_hs2.as_dgram_ref().is_some());

    // Wait
    let delay = client.process_output(now()).callback();

    // Now send a 0-RTT packet.
    let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream_id, &[1, 2, 3]).unwrap();
    let client_0rtt = client.process_output(now() + delay);
    assert!(client_0rtt.as_dgram_ref().is_some());
    // 0-RTT packets on their own shouldn't be padded to MIN_INITIAL_PACKET_SIZE.
    assert!(client_0rtt.as_dgram_ref().unwrap().len() < MIN_INITIAL_PACKET_SIZE);

    _ = server.process(client_hs1.dgram(), now());
    let server_hs = server.process(client_hs2.dgram(), now());
    assert!(server_hs.as_dgram_ref().is_some()); // ServerHello, etc...

    let all_frames = server.stats().frame_tx.all();
    let ack_frames = server.stats().frame_tx.ack;
    let server_process_0rtt = server.process(client_0rtt.dgram(), now());
    assert!(server_process_0rtt.dgram().is_some());
    assert_eq!(server.stats().frame_tx.all(), all_frames + 1);
    assert_eq!(server.stats().frame_tx.ack, ack_frames + 1);

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
        .enable_resumption(now(), token)
        .expect("should set token");
    let mut server = resumed_server(&client);

    // Write 0-RTT before generating any packets.
    // This should result in a datagram that coalesces Initial and 0-RTT.
    let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(client_stream_id, &[1, 2, 3]).unwrap();
    let client_init = client.process_output(now());
    assert!(client_init.as_dgram_ref().is_some());
    let client_0rtt = client.process_output(now());
    assert!(client_0rtt.as_dgram_ref().is_some());

    assertions::assert_coalesced_0rtt(&client_0rtt.as_dgram_ref().unwrap()[..]);

    _ = server.process(client_init.dgram(), now());
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
    const MESSAGE: &[u8] = &[1, 2, 3];

    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let token = exchange_ticket(&mut client, &mut server, now());
    let mut client = default_client();
    client
        .enable_resumption(now(), token)
        .expect("should set token");
    let mut server = Connection::new_server(
        test_fixture::DEFAULT_KEYS,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        ConnectionParameters::default().versions(client.version(), Version::all()),
    )
    .unwrap();
    // Using a freshly initialized anti-replay context
    // should result in the server rejecting 0-RTT.
    let ar =
        AntiReplay::new(now(), test_fixture::ANTI_REPLAY_WINDOW, 1, 3).expect("setup anti-replay");
    server
        .server_enable_0rtt(&ar, AllowZeroRtt {})
        .expect("enable 0-RTT");

    // Write some data on the client.
    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(stream_id, MESSAGE).unwrap();

    // Send ClientHello.
    let client_hs = client.process_output(now());
    assert!(client_hs.as_dgram_ref().is_some());

    let client_0rtt = client.process_output(now());
    assert!(client_0rtt.as_dgram_ref().is_some());

    let server_hs = server.process(client_hs.dgram(), now());
    assert!(server_hs.as_dgram_ref().is_some()); // Should produce ServerHello etc...
    let server_hs2 = server.process(client_0rtt.dgram(), now());

    // The server shouldn't receive that 0-RTT data.
    let recvd_stream_evt = |e| matches!(e, ConnectionEvent::NewStream { .. });
    assert!(!server.events().any(recvd_stream_evt));

    _ = client.process(server_hs.dgram(), now());
    let dgram = client.process(server_hs2.dgram(), now()).dgram();
    let dgram = server.process(dgram, now()).dgram();

    // Client should get a rejection.
    let client_fin = client.process(dgram, now());
    let recvd_0rtt_reject = |e| e == ConnectionEvent::ZeroRttRejected;
    assert!(client.events().any(recvd_0rtt_reject));

    // Server consume client_fin
    let server_ack = server.process(client_fin.dgram(), now());
    assert!(server_ack.as_dgram_ref().is_some());
    let client_out = client.process(server_ack.dgram(), now());
    assert!(client_out.as_dgram_ref().is_none());

    // ...and the client stream should be gone.
    let res = client.stream_send(stream_id, MESSAGE);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), Error::InvalidStreamId);

    // Open a new stream and send data. StreamId should start with 0.
    let stream_id_after_reject = client.stream_create(StreamType::UniDi).unwrap();
    assert_eq!(stream_id, stream_id_after_reject);
    client.stream_send(stream_id_after_reject, MESSAGE).unwrap();
    let client_after_reject = client.process_output(now()).dgram();
    assert!(client_after_reject.is_some());

    // The server should receive new stream
    server.process_input(client_after_reject.unwrap(), now());
    assert!(server.events().any(recvd_stream_evt));
}

#[test]
fn zero_rtt_update_flow_control() {
    const LOW: u64 = 3;
    const HIGH: u64 = 10;
    #[allow(clippy::cast_possible_truncation)]
    const MESSAGE: &[u8] = &[0; HIGH as usize];

    let mut client = default_client();
    let mut server = new_server(
        ConnectionParameters::default()
            .max_stream_data(StreamType::UniDi, true, LOW)
            .max_stream_data(StreamType::BiDi, true, LOW),
    );
    connect(&mut client, &mut server);

    let token = exchange_ticket(&mut client, &mut server, now());
    let mut client = default_client();
    client
        .enable_resumption(now(), token)
        .expect("should set token");
    let mut server = new_server(
        ConnectionParameters::default()
            .max_stream_data(StreamType::UniDi, true, HIGH)
            .max_stream_data(StreamType::BiDi, true, HIGH)
            .versions(client.version, Version::all()),
    );

    // Stream limits should be low for 0-RTT.
    let client_hs1 = client.process_output(now()).dgram();
    let client_hs2 = client.process_output(now()).dgram();
    let uni_stream = client.stream_create(StreamType::UniDi).unwrap();
    assert!(!client.stream_send_atomic(uni_stream, MESSAGE).unwrap());
    let bidi_stream = client.stream_create(StreamType::BiDi).unwrap();
    assert!(!client.stream_send_atomic(bidi_stream, MESSAGE).unwrap());

    // Now get the server transport parameters.
    _ = server.process(client_hs1, now()).dgram();
    let server_hs = server.process(client_hs2, now()).dgram();
    let client_hs3 = client.process(server_hs, now()).dgram();
    let server_hs2 = server.process(client_hs3, now()).dgram();
    client.process_input(server_hs2.unwrap(), now());

    // The streams should report a writeable event.
    let mut uni_stream_event = false;
    let mut bidi_stream_event = false;
    for e in client.events() {
        if let ConnectionEvent::SendStreamWritable { stream_id } = e {
            if stream_id.is_uni() {
                uni_stream_event = true;
            } else {
                bidi_stream_event = true;
            }
        }
    }
    assert!(uni_stream_event);
    assert!(bidi_stream_event);
    // But no MAX_STREAM_DATA frame was received.
    assert_eq!(client.stats().frame_rx.max_stream_data, 0);

    // And the new limit applies.
    assert!(client.stream_send_atomic(uni_stream, MESSAGE).unwrap());
    assert!(client.stream_send_atomic(bidi_stream, MESSAGE).unwrap());
}

#[test]
fn zero_rtt_loss_accepted() {
    // This test requires a wider anti-replay window than other tests
    // because the dropped 0-RTT packets add a bunch of delay.
    const WINDOW: Duration = Duration::from_secs(20);
    for i in 0..5 {
        let mut client = default_client();
        let mut server = default_server();
        connect(&mut client, &mut server);

        let mut now = now();
        let earlier = now;

        let token = exchange_ticket(&mut client, &mut server, now);

        now += WINDOW;
        let mut client = default_client();
        client.enable_resumption(now, token).unwrap();
        let mut server = resumed_server(&client);
        let anti_replay = AntiReplay::new(earlier, WINDOW, 1, 3).unwrap();
        server
            .server_enable_0rtt(&anti_replay, AllowZeroRtt {})
            .unwrap();

        // Make CI/0-RTT
        let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
        client.stream_send(client_stream_id, &[1, 2, 3]).unwrap();
        let mut ci = client.process_output(now);
        assert!(ci.as_dgram_ref().is_some());
        let mut c0rtt = client.process_output(now);
        assert!(c0rtt.as_dgram_ref().is_some());
        assertions::assert_coalesced_0rtt(&c0rtt.as_dgram_ref().unwrap()[..]);

        // Drop CI/0-RTT a number of times
        qdebug!("Drop CI/0-RTT {i} extra times");
        for _ in 0..i {
            now += client.process_output(now).callback();
            ci = client.process_output(now);
            assert!(ci.as_dgram_ref().is_some());
            c0rtt = client.process_output(now);
            assert!(c0rtt.as_dgram_ref().is_some());
        }

        // Process CI/0-RTT
        _ = server.process(ci.dgram(), now);
        let si = server.process(c0rtt.dgram(), now);
        assert!(si.as_dgram_ref().is_some());

        let server_stream_id = server
            .events()
            .find_map(|evt| match evt {
                ConnectionEvent::NewStream { stream_id } => Some(stream_id),
                _ => None,
            })
            .expect("should have received a new stream event");
        assert_eq!(client_stream_id, server_stream_id.as_u64());

        // 0-RTT should be accepted
        client.process_input(si.dgram().unwrap(), now);
        let recvd_0rtt_reject = |e| e == ConnectionEvent::ZeroRttRejected;
        assert!(
            !client.events().any(recvd_0rtt_reject),
            "rejected 0-RTT after {i} extra dropped packets"
        );
    }
}
