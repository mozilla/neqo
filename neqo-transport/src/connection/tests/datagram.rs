// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{
    assert_error, connect_force_idle, default_client, default_server, new_client, new_server,
    AT_LEAST_PTO,
};
use crate::events::ConnectionEvent;
use crate::{Connection, ConnectionError, ConnectionParameters, Error};
use neqo_common::event::Provider;
use std::convert::TryFrom;
use std::time::Duration;
use test_fixture::now;

const DATAGRAM_LEN_MAX: u64 = 65535;
const DATAGRAM_LEN_MTU: u64 = 1310;
const DATA_MTU: &[u8] = &[1; 1310];
const DATA_BIGGER_THAN_MTU: &[u8] = &[0; 2620];
const DATAGRAM_LEN_SMALLER_THAN_MTU: u64 = 1200;
const DATA_SMALLER_THAN_MTU: &[u8] = &[0; 1200];

#[test]
fn datagram_disabled_both() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    assert_eq!(client.max_dgram_size(), Err(Error::NotAvailable));
    assert_eq!(server.max_dgram_size(), Err(Error::NotAvailable));
    assert_eq!(
        client.send_dgram(DATA_SMALLER_THAN_MTU),
        Err(Error::NotAvailable)
    );
    assert_eq!(server.stats().frame_tx.datagram, 0);
    assert_eq!(
        server.send_dgram(DATA_SMALLER_THAN_MTU),
        Err(Error::NotAvailable)
    );
    assert_eq!(server.stats().frame_tx.datagram, 0);
}

#[test]
fn datagram_enabled_on_client() {
    let mut client = new_client(
        ConnectionParameters::default().max_datagram_frame_size(DATAGRAM_LEN_SMALLER_THAN_MTU),
    );
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    assert_eq!(client.max_dgram_size(), Err(Error::NotAvailable));
    assert_eq!(server.max_dgram_size(), Ok(DATAGRAM_LEN_SMALLER_THAN_MTU));
    assert_eq!(
        client.send_dgram(DATA_SMALLER_THAN_MTU),
        Err(Error::NotAvailable)
    );
    let dgram_sent = server.stats().frame_tx.datagram;
    assert_eq!(server.send_dgram(DATA_SMALLER_THAN_MTU), Ok(false));
    let out = server.process_output(now()).dgram().unwrap();
    assert_eq!(server.stats().frame_tx.datagram, dgram_sent + 1);

    client.process_input(out, now());
    let datagram =
        |e| matches!(e, ConnectionEvent::Datagram(data) if data == DATA_SMALLER_THAN_MTU);
    assert!(client.events().any(datagram));
}

#[test]
fn datagram_enabled_on_server() {
    let mut client = default_client();
    let mut server = new_server(
        ConnectionParameters::default().max_datagram_frame_size(DATAGRAM_LEN_SMALLER_THAN_MTU),
    );
    connect_force_idle(&mut client, &mut server);

    assert_eq!(client.max_dgram_size(), Ok(DATAGRAM_LEN_SMALLER_THAN_MTU));
    assert_eq!(server.max_dgram_size(), Err(Error::NotAvailable));
    assert_eq!(
        server.send_dgram(&DATA_SMALLER_THAN_MTU),
        Err(Error::NotAvailable)
    );
    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(client.send_dgram(DATA_SMALLER_THAN_MTU), Ok(false));
    let out = client.process_output(now()).dgram().unwrap();
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    server.process_input(out, now());
    let datagram =
        |e| matches!(e, ConnectionEvent::Datagram(data) if data == DATA_SMALLER_THAN_MTU);
    assert!(server.events().any(datagram));
}

fn create_and_connect_with_dgrams() -> (Connection, Connection) {
    let mut client =
        new_client(ConnectionParameters::default().max_datagram_frame_size(DATAGRAM_LEN_MAX));
    let mut server =
        new_server(ConnectionParameters::default().max_datagram_frame_size(DATAGRAM_LEN_MAX));
    connect_force_idle(&mut client, &mut server);
    (client, server)
}

#[test]
fn mtu_limit() {
    let (client, server) = create_and_connect_with_dgrams();

    assert_eq!(client.max_dgram_size(), Ok(DATAGRAM_LEN_MTU));
    assert_eq!(server.max_dgram_size(), Ok(DATAGRAM_LEN_MTU));
}

#[test]
fn limit_data_size() {
    let (mut client, mut server) = create_and_connect_with_dgrams();

    assert!(u64::try_from(DATA_BIGGER_THAN_MTU.len()).unwrap() > DATAGRAM_LEN_MTU);
    assert_eq!(
        client.send_dgram(DATA_BIGGER_THAN_MTU),
        Err(Error::TooMuchData)
    );
    assert_eq!(
        server.send_dgram(DATA_BIGGER_THAN_MTU),
        Err(Error::TooMuchData)
    );
}

#[test]
fn datagram_acked() {
    let (mut client, mut server) = create_and_connect_with_dgrams();

    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(client.send_dgram(DATA_SMALLER_THAN_MTU), Ok(false));
    let out = client.process_output(now()).dgram();
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    let dgram_received = server.stats().frame_rx.datagram;
    server.process_input(out.unwrap(), now());
    assert_eq!(server.stats().frame_rx.datagram, dgram_received + 1);
    let now = now() + Duration::from_millis(1);
    // Ack should be sent
    let ack_sent = server.stats().frame_tx.ack;
    let out = server.process_output(now).dgram();
    assert_eq!(server.stats().frame_tx.ack, ack_sent + 1);

    let datagram =
        |e| matches!(e, ConnectionEvent::Datagram(data) if data == DATA_SMALLER_THAN_MTU);
    assert!(server.events().any(datagram));

    client.process_input(out.unwrap(), now);
    let datagram_acked = |e| matches!(e, ConnectionEvent::DatagramAcked);
    assert!(client.events().any(datagram_acked));
}

#[test]
fn datagram_lost() {
    let (mut client, _) = create_and_connect_with_dgrams();

    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(client.send_dgram(DATA_SMALLER_THAN_MTU), Ok(false));
    let _out = client.process_output(now()).dgram(); // This packet will be lost.
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    // Wait for PTO
    let now = now() + AT_LEAST_PTO;
    let dgram_sent = client.stats().frame_tx.datagram;
    let out = client.process_output(now).dgram();
    assert!(out.is_some()); //PING probing
                            // Datagram is not sent again.
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent);

    let datagram_lost = |e| matches!(e, ConnectionEvent::DatagramLost);
    assert!(client.events().any(datagram_lost));
}

#[test]
fn datagram_sent_once() {
    let (mut client, _) = create_and_connect_with_dgrams();

    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(client.send_dgram(DATA_SMALLER_THAN_MTU), Ok(false));
    let _out = client.process_output(now()).dgram();
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    // Call process_output again should not send any new Datagram.
    let dgram_sent = client.stats().frame_tx.datagram;
    assert!(client.process_output(now()).dgram().is_none());
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent);
}

#[test]
fn dgram_no_allowed() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    server.set_max_dgram_size(DATAGRAM_LEN_MTU);
    assert_eq!(server.max_dgram_size(), Ok(DATAGRAM_LEN_MTU));
    assert_eq!(server.send_dgram(DATA_MTU), Ok(false));

    let out = server.process_output(now()).dgram().unwrap();
    client.process_input(out, now());

    assert_error(
        &client,
        &ConnectionError::Transport(Error::ProtocolViolation),
    );
}

#[test]
fn dgram_too_big() {
    let mut client = new_client(
        ConnectionParameters::default().max_datagram_frame_size(DATAGRAM_LEN_SMALLER_THAN_MTU),
    );
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    server.set_max_dgram_size(DATAGRAM_LEN_MTU);
    assert!(DATAGRAM_LEN_MTU > DATAGRAM_LEN_SMALLER_THAN_MTU);
    assert_eq!(server.max_dgram_size(), Ok(DATAGRAM_LEN_MTU));
    assert_eq!(server.send_dgram(DATA_MTU), Ok(false));

    let out = server.process_output(now()).dgram().unwrap();
    client.process_input(out, now());

    assert_error(
        &client,
        &ConnectionError::Transport(Error::ProtocolViolation),
    );
}

#[test]
fn overwrite_datagram() {
    let (mut client, mut server) = create_and_connect_with_dgrams();

    let dgram_sent = client.stats().frame_tx.datagram;
    assert_eq!(client.send_dgram(DATA_SMALLER_THAN_MTU), Ok(false));
    // overwrite datagram
    assert_eq!(client.send_dgram(DATA_MTU), Ok(true));
    let out = client.process_output(now()).dgram();
    assert_eq!(client.stats().frame_tx.datagram, dgram_sent + 1);

    server.process_input(out.unwrap(), now());
    let datagram = |e| matches!(e, ConnectionEvent::Datagram(data) if data == DATA_MTU);
    assert!(server.events().any(datagram));
}
