// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![warn(clippy::pedantic)]

use neqo_common::{qwarn, Datagram, IpTosEcn};
use test_fixture::now;

use super::{connect_force_idle_with_modifier, send_something_with_modifier, DatagramModifier};
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

fn connect_and_send_something_with_modifier(mut modifier: impl DatagramModifier) -> Datagram {
    let now = now();
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle_with_modifier(&mut client, &mut server, &mut modifier);

    // Right after the handshake, the ECN validation should still be in progress.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_enabled(&client_pkt);

    for _ in 0..ECN_TEST_COUNT {
        let client_pkt = send_something_with_modifier(&mut client, now, &mut modifier);
        server.process_input(&client_pkt, now);
    }

    // Client should now process ACKs with incorrect ECN counts and disable ECN.
    while let Some(server_pkt) = server.process_output(now).dgram() {
        client.process_input(&server_pkt, now);
    }

    // Return another client packet for the caller to check.
    send_something(&mut client, now)
}

fn set_tos(mut d: Datagram, ecn: IpTosEcn) -> neqo_common::Datagram {
    qwarn!("Setting ECN to {:?}", ecn);
    d.set_tos(ecn.into());
    d
}

#[test]
fn disables_when_bleached() {
    let pkt = connect_and_send_something_with_modifier(|d| Some(set_tos(d, IpTosEcn::default())));
    assert_ecn_disabled(&pkt);
}

#[test]
fn disables_when_remarked() {
    let pkt = connect_and_send_something_with_modifier(|d| Some(set_tos(d, IpTosEcn::Ect1)));
    assert_ecn_disabled(&pkt);
}

#[test]
fn stay_enabled_under_ce() {
    let pkt = connect_and_send_something_with_modifier(|d| Some(set_tos(d, IpTosEcn::Ce)));
    assert_ecn_enabled(&pkt);
}

#[test]
fn disables_on_loss() {
    let now = now();
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Right after the handshake, the ECN validation should still be in progress.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_enabled(&client_pkt);

    for _ in 0..ECN_TEST_COUNT {
        send_something(&mut client, now);
    }

    // ECN should now be disabled.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_disabled(&client_pkt);
}
