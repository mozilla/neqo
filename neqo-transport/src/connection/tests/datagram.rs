// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, num::NonZeroUsize, rc::Rc, time::Duration};

use neqo_common::{event::Provider as _, to_u64};
use static_assertions::const_assert;

use super::{
    AT_LEAST_PTO, assert_error, connect_force_idle, default_server, new_client, new_server, now,
};
use crate::{
    CloseReason, Connection, ConnectionParameters, Error, MIN_INITIAL_PACKET_SIZE, Pmtud, StreamId,
    StreamType,
    connection::tests::DEFAULT_ADDR,
    datagram_queue::DatagramQueueOutcome,
    events::{ConnectionEvent, OutgoingDatagramOutcome},
    frame::FrameType,
    packet,
    quic_datagrams::MAX_DATAGRAM_SIZE,
    send_stream::{RetransmissionPriority, TransmissionPriority},
    streams::SendGroupId,
};

/// Minimum overhead for a short header packet carrying a DATAGRAM frame:
/// - 8 bytes: minimum connection ID length (from `CountingConnectionIdGenerator`)
/// - 1 byte: short header (header form, spin, reserved, key phase, PN length)
/// - 1 byte: minimum packet number encoding
/// - 1 byte: DATAGRAM frame type
/// - 16 bytes: AEAD authentication tag
const MIN_DATAGRAM_PACKET_OVERHEAD: usize = 8 + 1 + 1 + 1 + 16;
const DATAGRAM_LEN_MTU: usize =
    Pmtud::default_plpmtu(DEFAULT_ADDR.ip()) - MIN_DATAGRAM_PACKET_OVERHEAD;
const DATA_MTU: &[u8] = &[1; DATAGRAM_LEN_MTU];
const DATA_BIGGER_THAN_MTU: &[u8] = &[0; 2 * DATAGRAM_LEN_MTU];
const_assert!(DATA_BIGGER_THAN_MTU.len() > DATAGRAM_LEN_MTU);
const DATAGRAM_LEN_SMALLER_THAN_MTU: u64 = to_u64(MIN_INITIAL_PACKET_SIZE);
const_assert!(DATAGRAM_LEN_SMALLER_THAN_MTU < to_u64(DATAGRAM_LEN_MTU));
const DATA_SMALLER_THAN_MTU: &[u8] = &[0; MIN_INITIAL_PACKET_SIZE];
const_assert!(DATA_SMALLER_THAN_MTU.len() < DATAGRAM_LEN_MTU);
const DATA_SMALLER_THAN_MTU_2: &[u8] = &[0; MIN_INITIAL_PACKET_SIZE / 2];
const_assert!(DATA_SMALLER_THAN_MTU_2.len() < DATA_SMALLER_THAN_MTU.len());

struct InsertDatagram<'a> {
    data: &'a [u8],
}

impl crate::connection::test_internal::FrameWriter for InsertDatagram<'_> {
    fn write_frames(&mut self, builder: &mut packet::Builder<&mut Vec<u8>>) {
        builder.encode_varint(FrameType::Datagram);
        builder.encode(self.data);
    }
}

struct InsertEmptyDatagram;

impl crate::connection::test_internal::FrameWriter for InsertEmptyDatagram {
    fn write_frames(&mut self, builder: &mut packet::Builder<&mut Vec<u8>>) {
        builder.encode_varint(FrameType::DatagramWithLen);
        builder.encode_vvec(&[]);
    }
}

fn connect_datagram() -> (Connection, Connection) {
    let mut client = new_client(ConnectionParameters::default().datagram_size(MAX_DATAGRAM_SIZE));
    let mut server = new_server(ConnectionParameters::default().datagram_size(MAX_DATAGRAM_SIZE));
    connect_force_idle(&mut client, &mut server);
    (client, server)
}

#[test]
fn mtu_limit() {
    let (client, server) = connect_datagram();

    assert_eq!(
        client.max_datagram_size(),
        Ok((DATAGRAM_LEN_MTU).try_into().unwrap())
    );
    assert_eq!(
        server.max_datagram_size(),
        Ok((DATAGRAM_LEN_MTU).try_into().unwrap())
    );
}

#[test]
fn limit_data_size() {
    let (mut client, mut server) = connect_datagram();

    // Datagram can be queued because they are smaller than allowed by the peer,
    // but they cannot be sent.
    assert_eq!(
        server.enqueue_datagram(
            StreamId::new(0),
            DATA_BIGGER_THAN_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );

    let dgram_dropped_s = server.stats().datagram_tx.dropped_too_big;
    let dgram_sent_s = server.stats().frame_tx.datagram;
    assert!(server.process_output(now()).dgram().is_none());
    assert_eq!(
        server.stats().datagram_tx.dropped_too_big,
        dgram_dropped_s + 1
    );
    assert_eq!(server.stats().frame_tx.datagram, dgram_sent_s);
    assert!(matches!(
        server.next_event().unwrap(),
        ConnectionEvent::OutgoingDatagramOutcome { id, outcome } if id == 1 && outcome == OutgoingDatagramOutcome::DroppedTooBig
    ));

    // The same test for the client side.
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_BIGGER_THAN_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );
    let dgram_sent_c = client.stats().frame_tx.datagram;
    assert!(client.process_output(now()).dgram().is_none());
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent_c);
    assert!(matches!(
        client.next_event().unwrap(),
        ConnectionEvent::OutgoingDatagramOutcome { id, outcome } if id == 1 && outcome == OutgoingDatagramOutcome::DroppedTooBig
    ));
}

#[test]
fn after_dgram_dropped_continue_writing_frames() {
    let (mut client, _) = connect_datagram();

    // Both are queued: the first is too big for any packet and will be
    // dropped when the write loop reaches it, but that must not stop the
    // second, smaller one from being written in the same call.
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_BIGGER_THAN_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_SMALLER_THAN_MTU.to_vec(),
            Some(2),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );

    let datagram_dropped = |e| {
        matches!(
        e,
        ConnectionEvent::OutgoingDatagramOutcome { id, outcome } if id == 1 && outcome == OutgoingDatagramOutcome::DroppedTooBig)
    };

    let dgram_dropped_c = client.stats().datagram_tx.dropped_too_big;
    let dgram_sent_c = client.stats().frame_tx.datagram;

    assert!(client.process_output(now()).dgram().is_some());
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent_c + 1);
    assert_eq!(
        client.stats().datagram_tx.dropped_too_big,
        dgram_dropped_c + 1
    );
    assert!(client.events().any(datagram_dropped));
}

#[test]
fn datagram_acked() {
    let (mut client, mut server) = connect_datagram();

    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_SMALLER_THAN_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );
    let out = client.process_output(now()).dgram();
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    let dgram_received = server.stats().frame_rx.datagram;
    server.process_input(out.unwrap(), now());
    assert_eq!(server.stats().frame_rx.datagram, dgram_received + 1);
    let now = now() + AT_LEAST_PTO;
    // Ack should be sent
    let ack_sent = server.stats().frame_tx.ack;
    let out = server.process_output(now).dgram();
    assert_eq!(server.stats().frame_tx.ack, ack_sent + 1);

    assert!(matches!(
        server.next_event().unwrap(),
        ConnectionEvent::Datagram(data) if data == DATA_SMALLER_THAN_MTU
    ));

    client.process_input(out.unwrap(), now);
    assert!(matches!(
        client.next_event().unwrap(),
        ConnectionEvent::OutgoingDatagramOutcome { id, outcome } if id == 1 && outcome == OutgoingDatagramOutcome::Acked
    ));
}

fn send_packet_and_get_server_event(
    client: &mut Connection,
    server: &mut Connection,
) -> ConnectionEvent {
    let out = client.process_output(now()).dgram();
    server.process_input(out.unwrap(), now());
    let mut events: Vec<_> = server
        .events()
        .filter_map(|evt| match evt {
            ConnectionEvent::RecvStreamReadable { .. } | ConnectionEvent::Datagram { .. } => {
                Some(evt)
            }
            _ => None,
        })
        .collect();
    // We should only get one event - either RecvStreamReadable or Datagram.
    assert_eq!(events.len(), 1);
    events.remove(0)
}

/// Write a datagram that is big enough to fill a packet, but then see that
/// normal priority stream data is sent first.
#[test]
fn datagram_after_stream_data() {
    let (mut client, mut server) = connect_datagram();

    // Write a datagram first.
    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );

    // Create a stream with normal priority and send some data.
    let stream_id = client.stream_create(StreamType::BiDi).unwrap();
    client
        .stream_send(stream_id, &[6; MIN_INITIAL_PACKET_SIZE])
        .unwrap();

    assert!(
        matches!(send_packet_and_get_server_event(&mut client, &mut server), ConnectionEvent::RecvStreamReadable { stream_id: s } if s == stream_id)
    );
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent);

    if let ConnectionEvent::Datagram(data) =
        &send_packet_and_get_server_event(&mut client, &mut server)
    {
        assert_eq!(data, DATA_MTU);
    } else {
        panic!();
    }
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);
}

#[test]
fn datagram_before_stream_data() {
    let (mut client, mut server) = connect_datagram();

    // Create a stream with low priority and send some data before datagram.
    let stream_id = client.stream_create(StreamType::BiDi).unwrap();
    client
        .stream_priority(
            stream_id,
            TransmissionPriority::Low,
            RetransmissionPriority::default(),
        )
        .unwrap();
    client
        .stream_send(stream_id, &[6; MIN_INITIAL_PACKET_SIZE])
        .unwrap();

    // Write a datagram.
    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );

    if let ConnectionEvent::Datagram(data) =
        &send_packet_and_get_server_event(&mut client, &mut server)
    {
        assert_eq!(data, DATA_MTU);
    } else {
        panic!();
    }
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    assert!(
        matches!(send_packet_and_get_server_event(&mut client, &mut server), ConnectionEvent::RecvStreamReadable { stream_id: s } if s == stream_id)
    );
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);
}

#[test]
fn datagram_lost() {
    let (mut client, _) = connect_datagram();

    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_SMALLER_THAN_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );
    let _out = client.process_output(now()).dgram(); // This packet will be lost.
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    // Wait for PTO
    let now = now() + AT_LEAST_PTO;
    let dgram_sent2 = client.stats().frame_tx.datagram;
    let pings_sent = client.stats().frame_tx.ping;
    let dgram_lost = client.stats().datagram_tx.lost;
    let out = client.process_output(now).dgram();
    assert!(out.is_some()); // PING probing
    // Datagram is not sent again.
    assert_eq!(client.stats().frame_tx.ping, pings_sent + 1);
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent2);
    assert_eq!(client.stats().datagram_tx.lost, dgram_lost + 1);

    assert!(matches!(
        client.next_event().unwrap(),
        ConnectionEvent::OutgoingDatagramOutcome { id, outcome } if id == 1 && outcome == OutgoingDatagramOutcome::Lost
    ));
}

#[test]
fn datagram_sent_once() {
    let (mut client, _) = connect_datagram();

    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(
        client.enqueue_datagram(
            StreamId::new(0),
            DATA_SMALLER_THAN_MTU.to_vec(),
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );
    let _out = client.process_output(now()).dgram();
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    // Call process_output again should not send any new Datagram.
    assert!(client.process_output(now()).dgram().is_none());
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);
}

#[test]
fn dgram_too_big() {
    let mut client =
        new_client(ConnectionParameters::default().datagram_size(DATAGRAM_LEN_SMALLER_THAN_MTU));
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let out = server
        .test_write_frames(InsertDatagram { data: DATA_MTU }, now())
        .dgram()
        .unwrap();
    client.process_input(out, now());

    assert_error(&client, &CloseReason::Transport(Error::ProtocolViolation));
}

#[test]
fn dgram_unsupported() {
    let mut client = new_client(ConnectionParameters::default().datagram_size(0));
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // The client advertised max_datagram_frame_size=0, so any DATAGRAM frame,
    // including an empty one, is a connection error (RFC 9221, Section 3).
    let out = server
        .test_write_frames(InsertEmptyDatagram, now())
        .dgram()
        .unwrap();
    client.process_input(out, now());

    assert_error(&client, &CloseReason::Transport(Error::ProtocolViolation));
}

fn send_datagram(sender: &mut Connection, receiver: &mut Connection, data: Vec<u8>) {
    let dgram_sent = sender.stats().frame_tx.datagram;
    assert_eq!(
        sender.enqueue_datagram(
            StreamId::new(0),
            data,
            Some(1),
            now(),
            SendGroupId::new(0),
            0
        ),
        DatagramQueueOutcome::Ok
    );
    let out = sender.process_output(now()).dgram().unwrap();
    assert_eq!(sender.stats().frame_tx.datagram, dgram_sent + 1);

    let dgram_received = receiver.stats().frame_rx.datagram;
    receiver.process_input(out, now());
    assert_eq!(receiver.stats().frame_rx.datagram, dgram_received + 1);
}

#[test]
fn multiple_datagram_events() {
    const DATA_SIZE: usize = MIN_INITIAL_PACKET_SIZE;
    const FIRST_DATAGRAM: &[u8] = &[0; DATA_SIZE];
    const SECOND_DATAGRAM: &[u8] = &[1; DATA_SIZE];
    const THIRD_DATAGRAM: &[u8] = &[2; DATA_SIZE];
    const FOURTH_DATAGRAM: &[u8] = &[3; DATA_SIZE];

    let mut client = new_client(ConnectionParameters::default().datagram_size(to_u64(DATA_SIZE)));
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    send_datagram(&mut server, &mut client, FIRST_DATAGRAM.to_vec());
    send_datagram(&mut server, &mut client, SECOND_DATAGRAM.to_vec());
    send_datagram(&mut server, &mut client, THIRD_DATAGRAM.to_vec());

    let mut datagrams = client.events().filter_map(|evt| {
        if let ConnectionEvent::Datagram(d) = evt {
            Some(d)
        } else {
            None
        }
    });
    assert_eq!(datagrams.next().unwrap(), FIRST_DATAGRAM);
    assert_eq!(datagrams.next().unwrap(), SECOND_DATAGRAM);
    assert_eq!(datagrams.next().unwrap(), THIRD_DATAGRAM);
    assert!(datagrams.next().is_none());

    // New events can be queued.
    send_datagram(&mut server, &mut client, FOURTH_DATAGRAM.to_vec());
    let mut datagrams = client.events().filter_map(|evt| {
        if let ConnectionEvent::Datagram(d) = evt {
            Some(d)
        } else {
            None
        }
    });
    assert_eq!(datagrams.next().unwrap(), FOURTH_DATAGRAM);
    assert!(datagrams.next().is_none());
}

/// Datagrams that are close to the capacity of the packet need special
/// handling.  They need to use the packet-filling frame type and
/// they cannot allow other frames to follow.
fn datagram_overfill(client: &mut Connection, server: &mut Connection, gap: usize) {
    /// This `FrameWriter` should not be invoked.
    struct PanickingFrameWriter {}
    impl crate::connection::test_internal::FrameWriter for PanickingFrameWriter {
        fn write_frames(&mut self, builder: &mut packet::Builder<&mut Vec<u8>>) {
            panic!(
                "builder invoked with {} bytes remaining",
                builder.remaining()
            );
        }
    }

    // Work out how much space we have for a datagram.
    let space = {
        let p = client.paths.primary().unwrap();
        let path = p.borrow();
        // Minimum overhead is connection ID length, 1 byte short header, 1 byte packet number,
        // 1 byte for the DATAGRAM frame type, and 16 bytes for the AEAD.
        path.plpmtu() - path.remote_cid().unwrap().len() - 19
    };
    assert!(space >= 64); // Unlikely, but this test depends on the datagram being this large.

    // This should not be called.
    if client.test_frame_writer.is_none() {
        client.test_frame_writer = Some(Box::new(PanickingFrameWriter {}));
    }

    // This will completely fill available space, so the packet is completely full.
    send_datagram(client, server, vec![9; space - gap]);
}

#[test]
#[should_panic(expected = "test_frame_writer set on full packet")]
fn datagram_fill_gap0() {
    let (mut client, mut server) = connect_datagram();
    datagram_overfill(&mut client, &mut server, 0);
}

#[test]
#[should_panic(expected = "test_frame_writer set on full packet")]
fn datagram_fill_gap1() {
    let (mut client, mut server) = connect_datagram();
    datagram_overfill(&mut client, &mut server, 1);
}

#[test]
#[should_panic(expected = "test_frame_writer set on full packet")]
fn datagram_fill_gap2() {
    let (mut client, mut server) = connect_datagram();
    datagram_overfill(&mut client, &mut server, 2);
}

#[test]
#[should_panic(expected = "test_frame_writer set on full packet")]
fn datagram_fill_gap3() {
    let (mut client, mut server) = connect_datagram();
    datagram_overfill(&mut client, &mut server, 3);
}

#[test]
fn datagram_fill_gap4() {
    struct TrackingFrameWriter {
        called: Rc<RefCell<bool>>,
    }
    impl crate::connection::test_internal::FrameWriter for TrackingFrameWriter {
        fn write_frames(&mut self, builder: &mut packet::Builder<&mut Vec<u8>>) {
            assert_eq!(builder.remaining(), 2);
            *self.called.borrow_mut() = true;
        }
    }

    let (mut client, mut server) = connect_datagram();

    // Four bytes free is enough space for another frame.
    let called = Rc::new(RefCell::new(false));
    client.test_frame_writer = Some(Box::new(TrackingFrameWriter {
        called: Rc::clone(&called),
    }));
    datagram_overfill(&mut client, &mut server, 4);
    assert!(*called.borrow());
}

#[test]
fn per_session_queues_round_robin_across_sessions() {
    let (mut client, mut server) = connect_datagram();
    let now = now();

    // Two unrelated "sessions" (opaque `StreamId` tags), each enqueuing two
    // datagrams. If they were served in enqueue order rather than
    // round-robin, session A's two datagrams would both arrive before
    // either of session B's.
    let session_a = StreamId::new(0);
    let session_b = StreamId::new(4);
    _ = client.enqueue_datagram(
        session_a,
        vec![b'A'; 4],
        Some(1),
        now,
        SendGroupId::new(0),
        0,
    );
    _ = client.enqueue_datagram(
        session_b,
        vec![b'B'; 4],
        Some(2),
        now,
        SendGroupId::new(0),
        0,
    );
    _ = client.enqueue_datagram(
        session_a,
        vec![b'A'; 4],
        Some(3),
        now,
        SendGroupId::new(0),
        0,
    );
    _ = client.enqueue_datagram(
        session_b,
        vec![b'B'; 4],
        Some(4),
        now,
        SendGroupId::new(0),
        0,
    );

    let out = client
        .process_output(now)
        .dgram()
        .expect("four small datagrams fit in one packet");
    server.process_input(out, now);

    let payloads: Vec<Vec<u8>> = server
        .events()
        .filter_map(|e| match e {
            ConnectionEvent::Datagram(data) => Some(data),
            _ => None,
        })
        .collect();
    assert_eq!(
        payloads,
        vec![vec![b'A'; 4], vec![b'B'; 4], vec![b'A'; 4], vec![b'B'; 4]],
        "sessions must be served round-robin, not one drained before the other starts"
    );
}

#[test]
fn expire_datagrams_expires_stale_entries_across_every_session() {
    let (mut client, _server) = connect_datagram();
    let now = now();

    let session_a = StreamId::new(0);
    let session_b = StreamId::new(4);
    client.set_datagram_max_age(session_a, Some(Duration::from_millis(5)), now);
    client.set_datagram_max_age(session_b, Some(Duration::from_millis(5)), now);
    _ = client.enqueue_datagram(session_a, vec![1], Some(1), now, SendGroupId::new(0), 0);
    _ = client.enqueue_datagram(session_b, vec![2], Some(2), now, SendGroupId::new(0), 0);

    let later = now + Duration::from_millis(10);
    let mut expired = client.expire_datagrams(later);
    expired.sort_unstable();
    assert_eq!(expired, vec![Some(1), Some(2)]);
    assert_eq!(
        client.datagram_queue_capacity(session_a).queued_datagrams,
        0
    );
    assert_eq!(
        client.datagram_queue_capacity(session_b).queued_datagrams,
        0
    );
}

#[test]
fn expire_session_datagrams_leaves_other_sessions_alone() {
    let (mut client, _server) = connect_datagram();
    let now = now();

    let session_a = StreamId::new(0);
    let session_b = StreamId::new(4);
    client.set_datagram_max_age(session_a, Some(Duration::from_millis(5)), now);
    client.set_datagram_max_age(session_b, Some(Duration::from_millis(5)), now);
    _ = client.enqueue_datagram(session_a, vec![1], Some(1), now, SendGroupId::new(0), 0);
    _ = client.enqueue_datagram(session_b, vec![2], Some(2), now, SendGroupId::new(0), 0);

    let later = now + Duration::from_millis(10);
    assert_eq!(
        client.expire_session_datagrams(session_a, later),
        vec![Some(1)],
        "a session-scoped sweep must not report another session's datagrams"
    );
    assert_eq!(
        client.datagram_queue_capacity(session_b).queued_datagrams,
        1,
        "nor expire them"
    );
    assert_eq!(
        client.expire_session_datagrams(session_b, later),
        vec![Some(2)]
    );
}

#[test]
fn expire_session_datagrams_on_an_unknown_session_is_empty() {
    let (mut client, _server) = connect_datagram();
    let now = now();

    assert!(
        client
            .expire_session_datagrams(StreamId::new(8), now)
            .is_empty()
    );
}

#[test]
fn drop_session_datagrams_removes_only_that_sessions_entries() {
    let (mut client, _server) = connect_datagram();
    let now = now();

    let session_a = StreamId::new(0);
    let session_b = StreamId::new(4);
    _ = client.enqueue_datagram(session_a, vec![1], Some(1), now, SendGroupId::new(0), 0);
    _ = client.enqueue_datagram(session_b, vec![2], Some(2), now, SendGroupId::new(0), 0);

    assert_eq!(client.drop_session_datagrams(session_a), vec![Some(1)]);
    assert_eq!(
        client.datagram_queue_capacity(session_a).queued_datagrams,
        0
    );
    assert_eq!(
        client.datagram_queue_capacity(session_b).queued_datagrams,
        1,
        "session B's queue must be untouched by session A's teardown"
    );
}

#[test]
fn datagram_queue_expiry_drives_next_delay() {
    let (mut client, _server) = connect_datagram();
    let now = now();
    let session = StreamId::new(0);

    client.set_datagram_max_age(session, Some(Duration::from_millis(5)), now);
    let outcome =
        client.enqueue_datagram(session, vec![1, 2, 3], Some(1), now, SendGroupId::new(0), 0);
    assert_eq!(outcome, DatagramQueueOutcome::Ok);

    assert_eq!(
        client.next_delay(now, false),
        Duration::from_millis(5),
        "the queued datagram's max-age must drive the callback timer, \
         shorter than every other pending timer on a freshly idle connection"
    );
}

#[test]
fn process_timer_expires_a_stale_datagram_with_no_packets_pending() {
    let (mut client, _server) = connect_datagram();
    let now = now();
    let session = StreamId::new(0);

    client.set_datagram_max_age(session, Some(Duration::from_millis(5)), now);
    _ = client.enqueue_datagram(session, vec![1, 2, 3], Some(1), now, SendGroupId::new(0), 0);
    assert_eq!(client.datagram_queue_capacity(session).queued_datagrams, 1);

    client.process_timer(now + Duration::from_millis(10));

    assert_eq!(
        client.datagram_queue_capacity(session).queued_datagrams,
        0,
        "expiry must not wait on there being packets ready to build"
    );
}

#[test]
fn expiring_a_blocked_session_queue_signals_space_available() {
    // Expiry, not a send, is how one of these queues is expected to shed
    // load: a sender waiting above the high water mark for a queue that then
    // ages out entirely would otherwise wait forever, since no send will ever
    // revisit an empty queue.
    let (mut client, _server) = connect_datagram();
    let now = now();
    let session = StreamId::new(0);

    client.set_datagram_high_water_mark(session, Some(NonZeroUsize::new(1).unwrap()));
    client.set_datagram_max_age(session, Some(Duration::from_millis(5)), now);
    assert_eq!(
        client.enqueue_datagram(session, vec![1], Some(1), now, SendGroupId::new(0), 0),
        DatagramQueueOutcome::AboveWatermark
    );

    client.process_timer(now + Duration::from_millis(10));

    assert!(
        client
            .events()
            .any(|e| matches!(e, ConnectionEvent::OutgoingDatagramSpaceAvailable)),
        "a queue emptied by expiry must resume the sender"
    );
}

#[test]
fn shrinking_max_age_signals_space_available() {
    // Same for the expiry that `set_datagram_max_age` runs on the spot.
    let (mut client, _server) = connect_datagram();
    let now = now();
    let session = StreamId::new(0);

    client.set_datagram_high_water_mark(session, Some(NonZeroUsize::new(1).unwrap()));
    assert_eq!(
        client.enqueue_datagram(session, vec![1], Some(1), now, SendGroupId::new(0), 0),
        DatagramQueueOutcome::AboveWatermark
    );

    client.set_datagram_max_age(
        session,
        Some(Duration::from_millis(1)),
        now + Duration::from_millis(10),
    );

    assert!(
        client
            .events()
            .any(|e| matches!(e, ConnectionEvent::OutgoingDatagramSpaceAvailable)),
        "a queue emptied by a shrunken max age must resume the sender"
    );
}
