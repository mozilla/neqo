// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use test_fixture::{DEFAULT_ADDR_V4, assertions, now};

use super::{
    super::ConnectionParameters, DEFAULT_RTT, ack_bytes, connect, connect_rtt_idle, default_client,
    default_server, fill_cwnd, increase_cwnd, induce_persistent_congestion, new_client, new_server,
    send_something, send_with_extra,
};
use crate::{
    CloseReason, Error,
    connection::tests::{assert_error, assert_path_challenge_min_len},
    frame::FrameType,
    packet,
    rtt::GRANULARITY,
    stream_id::StreamType,
    tparams::{
        TransportParameter,
        TransportParameterId::{MaxAckDelay, MinAckDelay},
    },
};

/// With the default RTT here (100ms) and default ratio (4), endpoints won't send
/// `ACK_FREQUENCY` as the ACK delay isn't different enough from the default.
#[test]
fn ack_rate_default() {
    let mut client = default_client();
    let mut server = default_server();
    _ = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    assert_eq!(client.stats().frame_tx.ack_frequency, 0);
    assert_eq!(server.stats().frame_tx.ack_frequency, 0);
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
    _ = increase_cwnd(&mut client, &mut server, stream, now);

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
    let ack = ack_bytes(&mut server, stream, pkts, now);

    // Receiving the ACK will cause the client to reduce its congestion window
    // and to send ACK_FREQUENCY.
    now += DEFAULT_RTT / 2;
    assert_eq!(client.stats().frame_tx.ack_frequency, 0);
    let af = client.process(Some(ack), now).dgram();
    assert!(af.is_some());
    assert_eq!(client.stats().frame_tx.ack_frequency, 1);
}

/// When the congestion window collapses, `ACK_FREQUENCY` is updated.
#[test]
fn ack_rate_persistent_congestion() {
    // Use a configuration that results in the value being set after exiting
    // the handshake.
    const RTT: Duration = Duration::from_millis(3);
    let mut client = new_client(
        ConnectionParameters::default().ack_ratio(ConnectionParameters::ACK_RATIO_SCALE),
    );
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, RTT);

    // The client should have sent a frame.
    assert_eq!(client.stats().frame_tx.ack_frequency, 1);

    // Now crash the congestion window.
    let stream = client.stream_create(StreamType::UniDi).unwrap();
    let (dgrams, mut now) = fill_cwnd(&mut client, stream, now);
    now += RTT / 2;
    drop(ack_bytes(&mut server, stream, dgrams, now));

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
    let mut client = new_client(
        ConnectionParameters::default().ack_ratio(ConnectionParameters::ACK_RATIO_SCALE),
    );
    let mut server = default_server();
    let mut now = connect_rtt_idle(&mut client, &mut server, RTT);

    // A single packet from the client will cause the server to engage its delayed
    // acknowledgment timer, which should now be equal to RTT.
    // The first packet will elicit an immediate ACK however, so do this twice.
    let d = send_something(&mut client, now);
    now += RTT / 2;
    let ack = server.process(Some(d), now).dgram();
    assert!(ack.is_some());
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
    let mut server = new_server(
        ConnectionParameters::default().ack_ratio(ConnectionParameters::ACK_RATIO_SCALE * 2),
    );
    let mut now = connect_rtt_idle(&mut client, &mut server, RTT);

    // The server now sends something.
    let d = send_something(&mut server, now);
    now += RTT / 2;
    // The client now will acknowledge immediately because it has been more than
    // an RTT since it last sent an acknowledgment.
    let ack = client.process(Some(d), now);
    assert!(ack.as_dgram_ref().is_some());
    let d = send_something(&mut server, now);
    now += RTT / 2;
    let delay = client.process(Some(d), now).callback();
    assert_eq!(delay, RTT / 2);

    assert_eq!(server.stats().frame_tx.ack_frequency, 1);
}

/// ACK delay calculations are path-specific,
/// so check that they can be sent on new paths.
#[test]
fn migrate_ack_delay() {
    // Have the client send ACK_FREQUENCY frames at a normal-ish rate.
    let mut client = new_client(
        ConnectionParameters::default().ack_ratio(ConnectionParameters::ACK_RATIO_SCALE),
    );
    let mut server = default_server();
    let mut now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);

    client
        .migrate(Some(DEFAULT_ADDR_V4), Some(DEFAULT_ADDR_V4), true, now)
        .unwrap();

    let client1 = send_something(&mut client, now);
    assertions::assert_v4_path(&client1, true); // Contains PATH_CHALLENGE.
    assert_path_challenge_min_len(&client, &client1, now);
    let client2 = send_something(&mut client, now);
    assertions::assert_v4_path(&client2, false); // Doesn't.  Is dropped.
    now += DEFAULT_RTT / 2;
    server.process_input(client1, now);

    let stream = client.stream_create(StreamType::UniDi).unwrap();
    let now = increase_cwnd(&mut client, &mut server, stream, now);
    let now = increase_cwnd(&mut client, &mut server, stream, now);
    let now = increase_cwnd(&mut client, &mut server, stream, now);

    // Now lose a packet and force the client to update
    let (mut pkts, mut now) = fill_cwnd(&mut client, stream, now);
    pkts.remove(0);
    now += DEFAULT_RTT / 2;
    let ack = ack_bytes(&mut server, stream, pkts, now);

    // After noticing this new loss, the client sends ACK_FREQUENCY.
    // It has sent a few before (as we dropped `client2`), so ignore those.
    let ad_before = client.stats().frame_tx.ack_frequency;
    let af = client.process(Some(ack), now).dgram();
    assert!(af.is_some());
    assert_eq!(client.stats().frame_tx.ack_frequency, ad_before + 1);
}

struct AckFrequencyWriter {
    delay: u64,
}

impl crate::connection::test_internal::FrameWriter for AckFrequencyWriter {
    fn write_frames(&mut self, builder: &mut packet::Builder<&mut Vec<u8>>) {
        builder
            .encode_varint(FrameType::AckFrequency)
            .encode_varint(0_u64) // Sequence Number
            .encode_varint(1_u64) // Ack-Eliciting Threshold
            .encode_varint(self.delay) // Requested Max Ack Delay, in microseconds
            .encode_byte(0); // Ignore Order
    }
}

#[test]
fn ack_frequency_below_min_ack_delay() {
    // We advertise `GRANULARITY` as our `min_ack_delay`.
    let smallest = u64::try_from(GRANULARITY.as_micros()).unwrap();

    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);
    let dgram = send_with_extra(
        &mut server,
        AckFrequencyWriter {
            delay: smallest - 1,
        },
        now(),
    );
    client.process_input(dgram, now());
    assert_error(&client, &CloseReason::Transport(Error::ProtocolViolation));

    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);
    let dgram = send_with_extra(&mut server, AckFrequencyWriter { delay: smallest }, now());
    client.process_input(dgram, now());
    assert_eq!(client.state().error(), None);
    assert!(client.state().connected());
}

/// A peer's `min_ack_delay` can exceed the cap we put on the delay we request.
#[test]
fn large_min_ack_delay() {
    let mut server = default_server();
    server
        .set_local_tparam(MaxAckDelay, TransportParameter::Integer(100))
        .unwrap();
    server
        .set_local_tparam(MinAckDelay, TransportParameter::Integer(60_000))
        .unwrap();
    let mut client = default_client();

    connect(&mut client, &mut server);

    assert_ne!(client.stats().frame_tx.ack_frequency, 0);
    assert_eq!(
        server.stats().frame_rx.ack_frequency,
        client.stats().frame_tx.ack_frequency
    );
    assert_eq!(server.state().error(), None);
    assert!(client.state().connected());
}
