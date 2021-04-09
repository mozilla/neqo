// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::{Connection, ConnectionParameters, Output, ACK_RATIO_SCALE};
use super::{
    assert_full_cwnd, connect_rtt_idle, cwnd_packets, default_client, default_server, fill_cwnd,
    fill_stream, new_client, new_server, send_something, AT_LEAST_PTO, DEFAULT_RTT,
    FORCE_IDLE_CLIENT_1RTT_PACKETS, POST_HANDSHAKE_CWND,
};
use crate::cc::{CWND_MIN, MAX_DATAGRAM_SIZE};
use crate::packet::PacketNumber;
use crate::recovery::{ACK_ONLY_SIZE_LIMIT, PACKET_THRESHOLD};
use crate::sender::PACING_BURST_SIZE;
use crate::stats::MAX_PTO_COUNTS;
use crate::stream_id::StreamType;
use crate::tracking::DEFAULT_ACK_PACKET_TOLERANCE;

use neqo_common::{qdebug, qinfo, qtrace, Datagram};
use std::convert::TryFrom;
use std::mem;
use std::time::{Duration, Instant};

// Get the current congestion window for the connection.
fn cwnd(c: &Connection) -> usize {
    c.paths.primary().borrow().sender().cwnd()
}
fn cwnd_avail(c: &Connection) -> usize {
    c.paths.primary().borrow().sender().cwnd_avail()
}

fn induce_persistent_congestion(
    client: &mut Connection,
    server: &mut Connection,
    stream: u64,
    mut now: Instant,
) -> Instant {
    // Note: wait some arbitrary time that should be longer than pto
    // timer. This is rather brittle.
    qtrace!([client], "induce_persistent_congestion");
    now += AT_LEAST_PTO;

    let mut pto_counts = [0; MAX_PTO_COUNTS];
    assert_eq!(client.stats.borrow().pto_counts, pto_counts);

    qtrace!([client], "first PTO");
    let (c_tx_dgrams, next_now) = fill_cwnd(client, stream, now);
    now = next_now;
    assert_eq!(c_tx_dgrams.len(), 2); // Two PTO packets

    pto_counts[0] = 1;
    assert_eq!(client.stats.borrow().pto_counts, pto_counts);

    qtrace!([client], "second PTO");
    now += AT_LEAST_PTO * 2;
    let (c_tx_dgrams, next_now) = fill_cwnd(client, stream, now);
    now = next_now;
    assert_eq!(c_tx_dgrams.len(), 2); // Two PTO packets

    pto_counts[0] = 0;
    pto_counts[1] = 1;
    assert_eq!(client.stats.borrow().pto_counts, pto_counts);

    qtrace!([client], "third PTO");
    now += AT_LEAST_PTO * 4;
    let (c_tx_dgrams, next_now) = fill_cwnd(client, stream, now);
    now = next_now;
    assert_eq!(c_tx_dgrams.len(), 2); // Two PTO packets

    pto_counts[1] = 0;
    pto_counts[2] = 1;
    assert_eq!(client.stats.borrow().pto_counts, pto_counts);

    // Generate ACK
    let s_tx_dgram = ack_bytes(server, stream, c_tx_dgrams, now);

    // An ACK for the third PTO causes persistent congestion.
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    assert_eq!(cwnd(client), CWND_MIN);
    now
}

// Receive multiple packets and generate an ack-only packet.
fn ack_bytes<D>(dest: &mut Connection, stream: u64, in_dgrams: D, now: Instant) -> Vec<Datagram>
where
    D: IntoIterator<Item = Datagram>,
    D::IntoIter: ExactSizeIterator,
{
    let mut srv_buf = [0; 4_096];

    let in_dgrams = in_dgrams.into_iter();
    qdebug!([dest], "ack_bytes {} datagrams", in_dgrams.len());
    for dgram in in_dgrams {
        dest.process_input(dgram, now);
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
    tx_dgrams
}

#[test]
/// Verify initial CWND is honored.
fn cc_slow_start() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Try to send a lot of data
    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    let (c_tx_dgrams, _) = fill_cwnd(&mut client, stream_id, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);
    assert!(cwnd_avail(&client) < ACK_ONLY_SIZE_LIMIT);
}

#[test]
/// Verify that CC moves to cong avoidance when a packet is marked lost.
fn cc_slow_start_to_cong_avoidance_recovery_period() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);
    // Predict the packet number of the last packet sent.
    // We have already sent packets in `connect_rtt_idle`,
    // so include a fudge factor.
    let flight1_largest =
        PacketNumber::try_from(c_tx_dgrams.len() + FORCE_IDLE_CLIENT_1RTT_PACKETS).unwrap();

    // Server: Receive and generate ack
    now += DEFAULT_RTT / 2;
    let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams, now);
    assert_eq!(
        server.stats().frame_tx.largest_acknowledged,
        flight1_largest
    );

    // Client: Process ack
    now += DEFAULT_RTT / 2;
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }
    assert_eq!(
        client.stats().frame_rx.largest_acknowledged,
        flight1_largest
    );

    // Client: send more
    let (mut c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND * 2);
    let flight2_largest = flight1_largest + u64::try_from(c_tx_dgrams.len()).unwrap();

    // Server: Receive and generate ack again, but drop first packet
    now += DEFAULT_RTT / 2;
    c_tx_dgrams.remove(0);
    let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams, now);
    assert_eq!(
        server.stats().frame_tx.largest_acknowledged,
        flight2_largest
    );

    // Client: Process ack
    now += DEFAULT_RTT / 2;
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }
    assert_eq!(
        client.stats().frame_rx.largest_acknowledged,
        flight2_largest
    );
}

#[test]
/// Verify that CC stays in recovery period when packet sent before start of
/// recovery period is acked.
fn cc_cong_avoidance_recovery_period_unchanged() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (mut c_tx_dgrams, now) = fill_cwnd(&mut client, 0, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Drop 0th packet. When acked, this should put client into CARP.
    c_tx_dgrams.remove(0);

    let c_tx_dgrams2 = c_tx_dgrams.split_off(5);

    // Server: Receive and generate ack
    let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams, now);
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    let cwnd1 = cwnd(&client);

    // Generate ACK for more received packets
    let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams2, now);

    // ACK more packets but they were sent before end of recovery period
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    // cwnd should not have changed since ACKed packets were sent before
    // recovery period expired
    let cwnd2 = cwnd(&client);
    assert_eq!(cwnd1, cwnd2);
}

#[test]
/// Ensure that a single packet is sent after entering recovery, even
/// when that exceeds the available congestion window.
fn single_packet_on_recovery() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Drop a few packets, up to the reordering threshold.
    for _ in 0..PACKET_THRESHOLD {
        let _dropped = send_something(&mut client, now);
    }
    let delivered = send_something(&mut client, now);

    // Now fill the congestion window.
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
    let (_, now) = fill_cwnd(&mut client, 0, now);
    assert!(cwnd_avail(&client) < ACK_ONLY_SIZE_LIMIT);

    // Acknowledge just one packet and cause one packet to be declared lost.
    // The length is the amount of credit the client should have.
    let ack = server.process(Some(delivered), now).dgram();
    assert!(ack.is_some());

    // The client should see the loss and enter recovery.
    // As there are many outstanding packets, there should be no available cwnd.
    client.process_input(ack.unwrap(), now);
    assert_eq!(cwnd_avail(&client), 0);

    // The client should send one packet, ignoring the cwnd.
    let dgram = client.process_output(now).dgram();
    assert!(dgram.is_some());
}

#[test]
/// Verify that CC moves out of recovery period when packet sent after start
/// of recovery period is acked.
fn cc_cong_avoidance_recovery_period_to_cong_avoidance() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Create stream 0
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets
    let (mut c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now);

    // Drop 0th packet. When acked, this should put client into CARP.
    c_tx_dgrams.remove(0);

    // Server: Receive and generate ack
    now += DEFAULT_RTT / 2;
    let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // Client: Process ack
    now += DEFAULT_RTT / 2;
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    // Should be in CARP now.
    now += DEFAULT_RTT / 2;
    qinfo!("moving to congestion avoidance {}", cwnd(&client));

    // Now make sure that we increase congestion window according to the
    // accurate byte counting version of congestion avoidance.
    // Check over several increases to be sure.
    let mut expected_cwnd = cwnd(&client);
    // Fill cwnd.
    let (mut c_tx_dgrams, next_now) = fill_cwnd(&mut client, 0, now);
    now = next_now;
    for i in 0..5 {
        qinfo!("iteration {}", i);

        let c_tx_size: usize = c_tx_dgrams.iter().map(|d| d.len()).sum();
        qinfo!(
            "client sending {} bytes into cwnd of {}",
            c_tx_size,
            cwnd(&client)
        );
        assert_eq!(c_tx_size, expected_cwnd);

        // As acks arrive we will continue filling cwnd and save all packets
        // from this cycle will be stored in next_c_tx_dgrams.
        let mut next_c_tx_dgrams: Vec<Datagram> = Vec::new();

        // Until we process all the packets, the congestion window remains the same.
        // Note that we need the client to process ACK frames in stages, so split the
        // datagrams into two, ensuring that we allow for an ACK for each batch.
        let most = c_tx_dgrams.len() - usize::try_from(DEFAULT_ACK_PACKET_TOLERANCE).unwrap() - 1;
        let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams.drain(..most), now);
        for dgram in s_tx_dgram {
            assert_eq!(cwnd(&client), expected_cwnd);
            client.process_input(dgram, now);
            // make sure to fill cwnd again.
            let (mut new_pkts, next_now) = fill_cwnd(&mut client, 0, now);
            now = next_now;
            next_c_tx_dgrams.append(&mut new_pkts);
        }
        let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams, now);
        for dgram in s_tx_dgram {
            assert_eq!(cwnd(&client), expected_cwnd);
            client.process_input(dgram, now);
            // make sure to fill cwnd again.
            let (mut new_pkts, next_now) = fill_cwnd(&mut client, 0, now);
            now = next_now;
            next_c_tx_dgrams.append(&mut new_pkts);
        }
        expected_cwnd += MAX_DATAGRAM_SIZE;
        assert_eq!(cwnd(&client), expected_cwnd);
        c_tx_dgrams = next_c_tx_dgrams;
    }
}

#[test]
/// Verify transition to persistent congestion state if conditions are met.
fn cc_slow_start_to_persistent_congestion_no_acks() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Create stream 0
    let stream = client.stream_create(StreamType::BiDi).unwrap();

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Server: Receive and generate ack
    now += DEFAULT_RTT / 2;
    mem::drop(ack_bytes(&mut server, 0, c_tx_dgrams, now));

    // ACK lost.
    induce_persistent_congestion(&mut client, &mut server, stream, now);
}

#[test]
/// Verify transition to persistent congestion state if conditions are met.
fn cc_slow_start_to_persistent_congestion_some_acks() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Create stream 0
    let stream = client.stream_create(StreamType::BiDi).unwrap();

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Server: Receive and generate ack
    now += Duration::from_millis(100);
    let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    now += Duration::from_millis(100);
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    // send bytes that will be lost
    let (_, next_now) = fill_cwnd(&mut client, 0, now);
    now = next_now + Duration::from_millis(100);

    induce_persistent_congestion(&mut client, &mut server, stream, now);
}

#[test]
/// Verify persistent congestion moves to slow start after recovery period
/// ends.
fn cc_persistent_congestion_to_slow_start() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Create stream 0
    let stream = client.stream_create(StreamType::BiDi).unwrap();

    // Buffer up lot of data and generate packets
    let (c_tx_dgrams, mut now) = fill_cwnd(&mut client, 0, now);
    assert_full_cwnd(&c_tx_dgrams, POST_HANDSHAKE_CWND);

    // Server: Receive and generate ack
    now += Duration::from_millis(10);
    mem::drop(ack_bytes(&mut server, 0, c_tx_dgrams, now));

    // ACK lost.

    now = induce_persistent_congestion(&mut client, &mut server, stream, now);

    // New part of test starts here

    now += Duration::from_millis(10);

    // Send packets from after start of CARP
    let (c_tx_dgrams, next_now) = fill_cwnd(&mut client, 0, now);
    assert_eq!(c_tx_dgrams.len(), 2);

    // Server: Receive and generate ack
    now = next_now + Duration::from_millis(100);
    let s_tx_dgram = ack_bytes(&mut server, 0, c_tx_dgrams, now);

    // No longer in CARP. (pkts acked from after start of CARP)
    // Should be in slow start now.
    for dgram in s_tx_dgram {
        client.process_input(dgram, now);
    }

    // ACKing 2 packets should let client send 4.
    let (c_tx_dgrams, _) = fill_cwnd(&mut client, 0, now);
    assert_eq!(c_tx_dgrams.len(), 4);
}

#[test]
fn ack_are_not_cc() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Create a stream
    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);

    // Buffer up lot of data and generate packets, so that cc window is filled.
    let (c_tx_dgrams, now) = fill_cwnd(&mut client, 0, now);
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
    let prev_ack_count = server.stats().frame_rx.ack;
    server.process_input(ack_pkt.unwrap(), now);
    assert_eq!(server.stats().frame_rx.ack, prev_ack_count + 1);
}

#[test]
fn pace() {
    const DATA: &[u8] = &[0xcc; 4_096];
    let mut client = default_client();
    let mut server = default_server();
    let mut now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

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
    // The first packet is not subject to pacing as there are no bytes in flight.
    // After that we allow the burst to continue up to a number of packets (2).
    for _ in 0..=PACING_BURST_SIZE {
        let dgram = client.process_output(now).dgram();
        assert!(dgram.is_some());
        count += 1;
    }
    let gap = client.process_output(now).callback();
    assert_ne!(gap, Duration::new(0, 0));
    for _ in (1 + PACING_BURST_SIZE)..cwnd_packets(POST_HANDSHAKE_CWND) {
        match client.process_output(now) {
            Output::Callback(t) => assert_eq!(t, gap),
            Output::Datagram(_) => {
                // The last packet might not be paced.
                count += 1;
                break;
            }
            Output::None => panic!(),
        }
        now += gap;
        let dgram = client.process_output(now).dgram();
        assert!(dgram.is_some());
        count += 1;
    }
    let dgram = client.process_output(now).dgram();
    assert!(dgram.is_none());
    assert_eq!(count, cwnd_packets(POST_HANDSHAKE_CWND));
    let fin = client.process_output(now).callback();
    assert_ne!(fin, Duration::new(0, 0));
    assert_ne!(fin, gap);
}

/// With the default RTT here (100ms) and default ratio (4), endpoints won't send
/// `ACK_FREQUENCY` as the ACK delay isn't different enough from the default.
#[test]
fn ack_rate_default() {
    let mut client = default_client();
    let mut server = default_server();
    let _ = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    assert_eq!(client.stats().frame_tx.ack_frequency, 0);
    assert_eq!(server.stats().frame_tx.ack_frequency, 0);
}

/// This function is like the combination of `fill_cwnd` and `ack_bytes`.
/// However, it acknowledges everything inline and preserves an RTT.
fn increase_cwnd(
    sender: &mut Connection,
    receiver: &mut Connection,
    stream: u64,
    mut now: Instant,
) -> Instant {
    fill_stream(sender, stream);
    loop {
        let pkt = sender.process_output(now);
        match pkt {
            Output::Datagram(dgram) => {
                receiver.process_input(dgram, now + DEFAULT_RTT / 2);
            }
            Output::Callback(t) => {
                if t < DEFAULT_RTT {
                    now += t;
                } else {
                    break; // We're on PTO now.
                }
            }
            Output::None => panic!(),
        }
    }

    // Now acknowledge all those packets at once.
    now += DEFAULT_RTT / 2;
    let ack = receiver.process_output(now).dgram();
    now += DEFAULT_RTT / 2;
    sender.process_input(ack.unwrap(), now);
    now
}

/// When the congestion window increases, the rate doesn't change.
#[test]
fn ack_rate_slow_start() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Increase the congestion window a few times.
    let stream = client.stream_create(StreamType::UniDi).unwrap();
    let now = increase_cwnd(&mut client, &mut server, stream, now);
    let now = increase_cwnd(&mut client, &mut server, stream, now);
    let _ = increase_cwnd(&mut client, &mut server, stream, now);

    // The client should not have sent an ACK_FREQUENCY frame, even
    // though the value would have updated.
    assert_eq!(client.stats().frame_tx.ack_frequency, 0);
    assert_eq!(server.stats().frame_rx.ack_frequency, 0);
}

/// When the congestion window decreases, a frame is sent.
#[test]
fn ack_rate_exit_slow_start() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    // Increase the congestion window a few times, enough that after a loss,
    // there are enough packets in the window to increase the packet
    // count in ACK_FREQUENCY frames.
    let stream = client.stream_create(StreamType::UniDi).unwrap();
    let now = increase_cwnd(&mut client, &mut server, stream, now);
    let now = increase_cwnd(&mut client, &mut server, stream, now);

    // Now fill the congestion window and drop the first packet.
    let (mut pkts, mut now) = fill_cwnd(&mut client, stream, now);
    pkts.remove(0);

    // After acknowledging the other packets the client will notice the loss.
    now += DEFAULT_RTT / 2;
    let mut acks = ack_bytes(&mut server, stream, pkts, now);
    assert!(!acks.is_empty());

    // Receiving the ACK will cause the client to reduce its congestion window
    // and to send ACK_FREQUENCY.
    now += DEFAULT_RTT / 2;
    assert_eq!(client.stats().frame_tx.ack_frequency, 0);
    let af = client.process(acks.pop(), now).dgram();
    assert!(af.is_some());
    assert_eq!(client.stats().frame_tx.ack_frequency, 1);
}

/// When the congestion window collapses, `ACK_FREQUENCY` is updated.
#[test]
fn ack_rate_persistent_congestion() {
    // Use a configuration that results in the value being set after exiting
    // the handshake.
    const RTT: Duration = Duration::from_millis(3);
    let mut client = new_client(ConnectionParameters::default().ack_ratio(ACK_RATIO_SCALE));
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, RTT);

    // The client should have sent a frame.
    assert_eq!(client.stats().frame_tx.ack_frequency, 1);

    // Now crash the congestion window.
    let stream = client.stream_create(StreamType::UniDi).unwrap();
    let (dgrams, mut now) = fill_cwnd(&mut client, stream, now);
    now += RTT / 2;
    mem::drop(ack_bytes(&mut server, stream, dgrams, now));

    let now = induce_persistent_congestion(&mut client, &mut server, stream, now);

    // The client sends a second ACK_FREQUENCY frame with an increased rate.
    let af = client.process_output(now).dgram();
    assert!(af.is_some());
    assert_eq!(client.stats().frame_tx.ack_frequency, 2);
}

/// Validate that the configuration works for the client.
#[test]
fn ack_rate_client_one_rtt() {
    // This has to be chosen so that the resulting ACK delay is between 1ms and 50ms.
    // We also have to avoid values between 20..30ms (approximately). The default
    // maximum ACK delay is 25ms and an ACK_FREQUENCY frame won't be sent when the
    // change to the maximum ACK delay is too small.
    const RTT: Duration = Duration::from_millis(3);
    let mut client = new_client(ConnectionParameters::default().ack_ratio(ACK_RATIO_SCALE));
    let mut server = default_server();
    let mut now = connect_rtt_idle(&mut client, &mut server, RTT);

    // A single packet from the client will cause the server to engage its delayed
    // acknowledgment timer, which should now be equal to RTT.
    let d = send_something(&mut client, now);
    now += RTT / 2;
    let delay = server.process(Some(d), now).callback();
    assert_eq!(delay, RTT);

    assert_eq!(client.stats().frame_tx.ack_frequency, 1);
}

/// Validate that the configuration works for the server.
#[test]
fn ack_rate_server_half_rtt() {
    const RTT: Duration = Duration::from_millis(10);
    let mut client = default_client();
    let mut server = new_server(ConnectionParameters::default().ack_ratio(ACK_RATIO_SCALE * 2));
    let mut now = connect_rtt_idle(&mut client, &mut server, RTT);

    let d = send_something(&mut server, now);
    now += RTT / 2;
    let delay = client.process(Some(d), now).callback();
    assert_eq!(delay, RTT / 2);

    assert_eq!(server.stats().frame_tx.ack_frequency, 1);
}
