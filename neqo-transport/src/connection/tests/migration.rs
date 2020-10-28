// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::StreamType;
use super::{connect_force_idle, default_client, default_server, send_something};

use neqo_common::Datagram;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use test_fixture::{self, loopback, now};

fn loopback_v4() -> SocketAddr {
    let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    SocketAddr::new(localhost_v4, loopback().port())
}

fn change_path(d: &Datagram) -> Datagram {
    let v4 = loopback_v4();
    Datagram::new(v4, v4, &d[..])
}

fn new_port() -> SocketAddr {
    let lb = loopback();
    let (port, _) = lb.port().overflowing_add(1);
    SocketAddr::new(lb.ip(), port)
}

fn change_source_port(d: &Datagram) -> Datagram {
    Datagram::new(new_port(), loopback(), &d[..])
}

#[test]
fn rebinding_address() {
    fn assert_new_path(dgram: &Datagram) {
        assert_eq!(dgram.source(), loopback_v4());
        assert_eq!(dgram.destination(), loopback_v4());
    }
    fn assert_old_path(dgram: &Datagram) {
        assert_eq!(dgram.source(), loopback());
        assert_eq!(dgram.destination(), loopback());
    }

    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let dgram = send_something(&mut client, now());
    let dgram = change_path(&dgram);
    server.process_input(dgram, now());

    // The server now probes the new (primary) path.
    let new_probe = server.process_output(now()).dgram().unwrap();
    assert_eq!(server.stats().frame_tx.path_challenge, 1);
    assert_new_path(&new_probe);

    // The server also probes the old path.
    let old_probe = server.process_output(now()).dgram().unwrap();
    assert_eq!(server.stats().frame_tx.path_challenge, 2);
    assert_old_path(&old_probe);

    // New data from the server is sent on the new path.
    let server_data = send_something(&mut server, now());
    assert_new_path(&server_data);

    // The client should respond to the challenge on the new path.
    let new_resp = client.process(Some(new_probe), now()).dgram().unwrap();
    assert_eq!(client.stats().frame_rx.path_challenge, 1);
    assert_eq!(client.stats().frame_tx.path_challenge, 1);
    assert_eq!(client.stats().frame_tx.path_response, 1);
    assert_new_path(&new_resp);

    // The client also responds to probes on the old path.
    let old_resp = client.process(Some(old_probe), now()).dgram().unwrap();
    assert_eq!(client.stats().frame_rx.path_challenge, 2);
    assert_eq!(client.stats().frame_tx.path_challenge, 2);
    assert_eq!(client.stats().frame_tx.path_response, 2);
    assert_old_path(&old_resp);

    // But the client still sends data on the old path.
    let client_data1 = send_something(&mut client, now());
    assert_old_path(&client_data1);

    // Even after it receives a non-probing packet on the new path.
    client.process_input(server_data, now());
    let client_data2 = send_something(&mut client, now());
    assert_new_path(&client_data2);
}

#[test]
fn rebinding_port() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let dgram = send_something(&mut client, now());
    let dgram = change_source_port(&dgram);

    server.process_input(dgram, now());
    // Have the server send something so that it generates a packet.
    let stream_id = server.stream_create(StreamType::UniDi).unwrap();
    server.stream_close_send(stream_id).unwrap();
    let dgram = server.process_output(now()).dgram();
    let dgram = dgram.unwrap();
    assert_eq!(dgram.source(), loopback());
    assert_eq!(dgram.destination(), new_port());
}
