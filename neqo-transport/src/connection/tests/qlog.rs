// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Tests for what a trace says, as opposed to what the connection does. These
//! check the things a reader of a trace has to be able to rely on: that a packet
//! reports its own size, that everything received is accounted for, and that
//! events do not go backwards in time.

use std::time::{Duration, Instant};

use neqo_common::Datagram;
use test_fixture::{now, strip_padding};

use super::{
    super::State, Connection, ConnectionParameters, default_client, maybe_authenticate,
    new_server_with_qlog, send_something,
};
use crate::saved::SavedDatagrams;

/// Every event's time, in order of appearance.
fn times(trace: &str) -> Vec<f64> {
    trace
        .lines()
        .filter_map(|l| {
            l.split_once(r#"{"time":"#)?
                .1
                .split_once(',')?
                .0
                .parse()
                .ok()
        })
        .collect()
}

const RTT: Duration = Duration::from_millis(100);

fn handshake_but_for_the_last_flight(
    client: &mut Connection,
    server: &mut Connection,
    t: &mut Instant,
) -> Datagram {
    let c1 = client.process_output(*t).dgram().map(strip_padding);
    let c2 = client.process_output(*t).dgram().map(strip_padding);

    *t += RTT / 2;
    server.process_input(c1.unwrap(), *t);
    let s1 = server.process(c2, *t).dgram().map(strip_padding);

    *t += RTT / 2;
    let dgram = client.process(s1, *t).dgram().map(strip_padding);
    *t += RTT / 2;
    let dgram = server.process(dgram, *t).dgram().map(strip_padding);

    *t += RTT / 2;
    client.process_input(dgram.unwrap(), *t);
    maybe_authenticate(client);
    strip_padding(
        client
            .process_output(*t)
            .dgram()
            .expect("a final client flight"),
    )
}

/// Fill the server's store with 1-RTT datagrams it has no keys for yet.
fn fill_saved_datagrams(client: &mut Connection, server: &mut Connection, t: Instant) {
    for _ in 0..SavedDatagrams::CAPACITY {
        let d = send_something(client, t);
        server.process_input(strip_padding(d), t);
    }
    assert_eq!(server.stats().saved_datagrams, SavedDatagrams::CAPACITY);
}

#[test]
fn event_times_do_not_go_backwards() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    let mut t = now();
    let last = handshake_but_for_the_last_flight(&mut client, &mut server, &mut t);

    fill_saved_datagrams(&mut client, &mut server, t);

    t += RTT;
    _ = server.process(Some(last), t).dgram();
    assert_eq!(*server.state(), State::Confirmed);
    drop(server);

    let trace = contents.to_string();
    let times = times(&trace);
    assert!(times.len() > 10, "too few events in {trace}");
    assert!(times.is_sorted(), "time went backwards in {trace}");
}
