// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::StreamType;
use super::{connect_force_idle, default_client, default_server, send_something};
use crate::path::PATH_MTU_V4;

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
#[ignore] // This test fails because we don't send NEW_CONNECTION_ID yet.
fn rebinding_address() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let dgram = send_something(&mut client, now());
    let dgram = change_path(&dgram);
    let dgram = server.process(Some(dgram), now()).dgram();
    let dgram = dgram.unwrap();
    assert_eq!(dgram.source(), loopback_v4());
    assert_eq!(dgram.destination(), loopback_v4());
    assert_eq!(dgram.len(), PATH_MTU_V4);
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
