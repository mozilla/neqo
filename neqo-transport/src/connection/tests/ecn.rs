// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![warn(clippy::pedantic)]

use neqo_common::IpTos;
use test_fixture::now;

use crate::{
    connection::tests::{connect_force_idle, default_client, default_server},
    StreamType,
};

#[test]
fn disables_when_bleached() {
    const DATA_CLIENT: &[u8] = &[2; 8000];
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    assert!(client.paths.primary().borrow().is_ecn_enabled());

    let stream_id = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream_id, DATA_CLIENT).unwrap();

    while let Some(mut client_pkt) = client.process_output(now()).dgram() {
        // Bleach the ECN bits on the packet.
        client_pkt.set_tos(IpTos::default());
        server.process_input(&client_pkt, now());
    }

    // Client should now process ACKs with incorrect ECN counts and disable ECN.
    while let Some(server_pkt) = server.process_output(now()).dgram() {
        client.process_input(&server_pkt, now());
    }

    assert!(!client.paths.primary().borrow().is_ecn_enabled());
}
