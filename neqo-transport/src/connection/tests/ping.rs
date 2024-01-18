// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{connect, default_client, default_server};

use test_fixture::{self, now};

#[test]
fn ping() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);

    let now = now();

    let tx_ping_before = client.stats().frame_tx.ping;
    client.send_ping();
    let out = client.process(None, now);
    assert!(out.clone().dgram().is_some());
    assert_eq!(client.stats().frame_tx.ping, tx_ping_before + 1);

    let rx_ping_before = server.stats().frame_rx.ping;
    server.process_input(&out.dgram().unwrap(), now);
    assert_eq!(server.stats().frame_rx.ping, rx_ping_before + 1);
}
