// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![warn(clippy::pedantic)]

use std::time::Duration;

use neqo_common::{qdebug, Datagram, IpTosEcn};
use test_fixture::now;

use crate::{
    connection::tests::{connect_force_idle, default_client, default_server, send_something},
    ecn::ECN_TEST_COUNT,
};

fn assert_ecn_enabled(d: &Datagram) {
    assert_eq!(IpTosEcn::from(d.tos()), IpTosEcn::Ect0);
}

fn assert_ecn_disabled(d: &Datagram) {
    assert_eq!(IpTosEcn::from(d.tos()), IpTosEcn::default());
}

fn connect_and_send_something_marked(ecn: IpTosEcn) -> Datagram {
    let now = now();
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    for _ in 0..ECN_TEST_COUNT {
        let mut client_pkt = send_something(&mut client, now);
        // Change the ECN bits on the packet to `ecn`.
        client_pkt.set_tos(ecn.into());
        server.process_input(&client_pkt, now);
    }
    qdebug!("XXX burst done");

    // Client should now process ACKs with incorrect ECN counts and disable ECN.
    while let Some(server_pkt) = server.process_output(now).dgram() {
        client.process_input(&server_pkt, now);
    }
    qdebug!("XXX ACK processed");

    // Return another client packet for the caller to check.
    send_something(&mut client, now)
}

#[test]
fn disables_when_bleached() {
    let pkt = connect_and_send_something_marked(IpTosEcn::default());
    assert_ecn_disabled(&pkt);
}

#[test]
fn disables_when_remarked() {
    let pkt = connect_and_send_something_marked(IpTosEcn::Ect1);
    assert_ecn_disabled(&pkt);
}

#[test]
fn stay_enabled_under_ce() {
    let pkt = connect_and_send_something_marked(IpTosEcn::Ce);
    assert_ecn_enabled(&pkt);
}

#[test]
fn disables_on_loss() {
    let mut now = now();
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    for _ in 0..ECN_TEST_COUNT {
        send_something(&mut client, now);
    }

    // First PTO.
    //
    // We're only marking two packets lost on a PTO, so we need another one
    // to trigger ECN disablement.
    let delay = client.process_output(now).callback();
    now += delay;
    qdebug!("XXX {:?} PTO 1", delay);
    send_something(&mut client, now);
    send_something(&mut client, now);

    // // Second PTO. Somewhere in this second batch, ECN will be disabled.
    // let delay = client.process_output(now).callback();
    // now += delay;
    // qdebug!("XXX {:?} PTO 2", delay);
    // send_something(&mut client, now);

    let mut delay = client.process_output(now).callback();
    while delay > Duration::from_secs(0) {
        now += delay;
        qdebug!("XXX delay {:?} ", delay);
        delay = client.process_output(now).callback();
    }

    send_something(&mut client, now);
    send_something(&mut client, now);

    let mut delay = client.process_output(now).callback();
    while delay > Duration::from_secs(0) {
        now += delay;
        qdebug!("XXX delay {:?} ", delay);
        delay = client.process_output(now).callback();
    }

    send_something(&mut client, now);
    send_something(&mut client, now);

    // ECN should now be disabled.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_disabled(&client_pkt);
}
