// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::{IdleTimeout, Output, State, LOCAL_IDLE_TIMEOUT};
use super::{
    connect, connect_force_idle, connect_with_rtt, default_client, default_server, send_something,
};
use crate::frame::StreamType;
use crate::tparams::{self, TransportParameter};

use std::time::Duration;
use test_fixture::{self, now};

#[test]
fn idle_timeout() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    // Still connected after 29 seconds. Idle timer not reset
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT - Duration::from_secs(1));
    assert!(matches!(client.state(), State::Confirmed));

    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT);

    // Not connected after LOCAL_IDLE_TIMEOUT seconds.
    assert!(matches!(client.state(), State::Closed(_)));
}

#[test]
fn asymmetric_idle_timeout() {
    const LOWER_TIMEOUT_MS: u64 = 1000;
    const LOWER_TIMEOUT: Duration = Duration::from_millis(LOWER_TIMEOUT_MS);
    // Sanity check the constant.
    assert!(LOWER_TIMEOUT < LOCAL_IDLE_TIMEOUT);

    let mut client = default_client();
    let mut server = default_server();

    // Overwrite the default at the server.
    server
        .tps
        .borrow_mut()
        .local
        .set_integer(tparams::IDLE_TIMEOUT, LOWER_TIMEOUT_MS);
    server.idle_timeout = IdleTimeout::new(LOWER_TIMEOUT);

    // Now connect and force idleness manually.
    connect(&mut client, &mut server);
    let p1 = send_something(&mut server, now());
    let p2 = send_something(&mut server, now());
    client.process_input(p2, now());
    let ack = client.process(Some(p1), now()).dgram();
    assert!(ack.is_some());
    // Now the server has its ACK and both should be idle.
    assert_eq!(server.process(ack, now()), Output::Callback(LOWER_TIMEOUT));
    assert_eq!(client.process(None, now()), Output::Callback(LOWER_TIMEOUT));
}

#[test]
fn tiny_idle_timeout() {
    const RTT: Duration = Duration::from_millis(500);
    const LOWER_TIMEOUT_MS: u64 = 100;
    const LOWER_TIMEOUT: Duration = Duration::from_millis(LOWER_TIMEOUT_MS);
    // We won't respect a value that is lower than 3*PTO, sanity check.
    assert!(LOWER_TIMEOUT < 3 * RTT);

    let mut client = default_client();
    let mut server = default_server();

    // Overwrite the default at the server.
    server
        .set_local_tparam(
            tparams::IDLE_TIMEOUT,
            TransportParameter::Integer(LOWER_TIMEOUT_MS),
        )
        .unwrap();
    server.idle_timeout = IdleTimeout::new(LOWER_TIMEOUT);

    // Now connect with an RTT and force idleness manually.
    let mut now = connect_with_rtt(&mut client, &mut server, now(), RTT);
    let p1 = send_something(&mut server, now);
    let p2 = send_something(&mut server, now);
    now += RTT / 2;
    client.process_input(p2, now);
    let ack = client.process(Some(p1), now).dgram();
    assert!(ack.is_some());

    // The client should be idle now, but with a different timer.
    if let Output::Callback(t) = client.process(None, now) {
        assert!(t > LOWER_TIMEOUT);
    } else {
        panic!("Client not idle");
    }

    // The server should go idle after the ACK, but again with a larger timeout.
    now += RTT / 2;
    if let Output::Callback(t) = client.process(ack, now) {
        assert!(t > LOWER_TIMEOUT);
    } else {
        panic!("Client not idle");
    }
}

#[test]
fn idle_send_packet1() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, b"hello").unwrap(), 5);

    let out = client.process(None, now + Duration::from_secs(10));
    let out = server.process(out.dgram(), now + Duration::from_secs(10));

    // Still connected after 39 seconds because idle timer reset by outgoing
    // packet
    let _ = client.process(
        out.dgram(),
        now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(9),
    );
    assert!(matches!(client.state(), State::Confirmed));

    // Not connected after 40 seconds.
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(10));

    assert!(matches!(client.state(), State::Closed(_)));
}

#[test]
fn idle_send_packet2() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
    assert_eq!(client.stream_send(2, b"hello").unwrap(), 5);

    let _out = client.process(None, now + Duration::from_secs(10));

    assert_eq!(client.stream_send(2, b"there").unwrap(), 5);
    let _out = client.process(None, now + Duration::from_secs(20));

    // Still connected after 39 seconds.
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(9));
    assert!(matches!(client.state(), State::Confirmed));

    // Not connected after 40 seconds because timer not reset by second
    // outgoing packet
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(10));
    assert!(matches!(client.state(), State::Closed(_)));
}

#[test]
fn idle_recv_packet() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let now = now();

    let res = client.process(None, now);
    assert_eq!(res, Output::Callback(LOCAL_IDLE_TIMEOUT));

    assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
    assert_eq!(client.stream_send(0, b"hello").unwrap(), 5);

    // Respond with another packet
    let out = client.process(None, now + Duration::from_secs(10));
    server.process_input(out.dgram().unwrap(), now + Duration::from_secs(10));
    assert_eq!(server.stream_send(0, b"world").unwrap(), 5);
    let out = server.process_output(now + Duration::from_secs(10));
    assert_ne!(out.as_dgram_ref(), None);

    let _ = client.process(out.dgram(), now + Duration::from_secs(20));
    assert!(matches!(client.state(), State::Confirmed));

    // Still connected after 49 seconds because idle timer reset by received
    // packet
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(19));
    assert!(matches!(client.state(), State::Confirmed));

    // Not connected after 50 seconds.
    let _ = client.process(None, now + LOCAL_IDLE_TIMEOUT + Duration::from_secs(20));

    assert!(matches!(client.state(), State::Closed(_)));
}
