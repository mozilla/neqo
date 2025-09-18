// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, rc::Rc};

use test_fixture::{fixture_init, now, DEFAULT_ADDR_V4};

use super::Connection;
use crate::{
    connection::tests::{connect, default_server, fill_stream, CountingConnectionIdGenerator},
    ConnectionParameters, StreamType,
};

/// Test that one can reach the maximum MTU with GSO enabled.
#[test]
fn gso_with_max_mtu() {
    neqo_common::log::init(None);
    fixture_init();
    let mut client = Connection::new_client(
        test_fixture::DEFAULT_SERVER_NAME,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR_V4,
        DEFAULT_ADDR_V4,
        ConnectionParameters::default()
            .pmtud(true)
            .pmtud_iface_mtu(false),
        now(),
    )
    .expect("create a default client");

    let mut server = default_server();

    connect(&mut client, &mut server);

    let stream_id = client.stream_create(StreamType::UniDi).unwrap();
    // Increase MTU to the max.
    loop {
        fill_stream(&mut client, stream_id);
        let mut pkts = client
            .process_multiple_output(now(), 2.try_into().unwrap())
            .dgram()
            .unwrap();
        if pkts.datagram_size() == 65507 {
            // Success. It reached the maximum IPv4 UDP MTU.
            break;
        }
        assert!(pkts.datagram_size() < 65507);

        server.process_multiple_input(pkts.iter_mut(), now());
        let ack = server.process_output(now()).dgram();
        client.process_input(ack.unwrap(), now());
    }
}
