// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Tests for what a trace says, as opposed to what the connection does.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use serde_json::Value;

use super::{
    ConnectionParameters, connect, default_client, default_server, new_client_with_qlog,
    new_server, new_server_with_qlog,
};
use crate::{
    stateless_reset::Token as Srt,
    tparams::{PreferredAddress, TransportParameter, TransportParameterId::StatelessResetToken},
};

/// The events of a JSON-SEQ trace, i.e. every record but the header.
fn events(trace: &str) -> Vec<Value> {
    trace
        .split('\u{1e}')
        .filter(|r| !r.trim().is_empty())
        .map(|r| serde_json::from_str::<Value>(r).expect("valid JSON"))
        .filter(|ev| ev.get("name").is_some())
        .collect()
}

fn named<'a>(events: &'a [Value], name: &'a str) -> impl Iterator<Item = &'a Value> {
    events.iter().filter(move |ev| ev["name"] == name)
}

/// The `parameters_set` event that `initiator` logged.
fn parameters_set<'a>(events: &'a [Value], initiator: &str) -> Option<&'a Value> {
    named(events, "quic:parameters_set").find(|ev| ev["data"]["initiator"] == initiator)
}

/// Every value of `key`, at any depth.
fn values_of<'a>(v: &'a Value, key: &str, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(map) => {
            out.extend(map.get(key));
            map.values().for_each(|v| values_of(v, key, out));
        }
        Value::Array(vs) => vs.iter().for_each(|v| values_of(v, key, out)),
        _ => {}
    }
}

#[test]
fn transport_parameters_are_logged_for_both_peers() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let mut server = default_server();
    connect(&mut client, &mut server);
    drop(client);

    let trace = contents.to_string();
    let events = events(&trace);
    assert!(parameters_set(&events, "local").is_some(), "trace: {trace}");
    assert!(
        parameters_set(&events, "remote").is_some(),
        "trace: {trace}"
    );
}

#[test]
fn server_logs_its_original_destination_connection_id() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    connect(&mut client, &mut server);
    drop(server);

    let trace = contents.to_string();
    let events = events(&trace);
    let local = parameters_set(&events, "local").expect("the server's own parameters");
    let odcid = local["data"]["original_destination_connection_id"].as_str();
    assert!(odcid.is_some_and(|v| !v.is_empty()), "trace: {trace}");
}

#[test]
fn stateless_reset_token_is_not_logged() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    // Both address families, as only then is the preferred address logged.
    let spa = PreferredAddress::new(
        Some(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443)),
        Some(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        )),
    );
    let mut server = new_server(ConnectionParameters::default().preferred_address(spa));
    server
        .set_local_tparam(
            StatelessResetToken,
            TransportParameter::Bytes(vec![77; Srt::LEN]),
        )
        .unwrap();
    connect(&mut client, &mut server);
    drop(client);

    let trace = contents.to_string();
    let events = events(&trace);
    // The transport parameter, the preferred address and NEW_CONNECTION_ID all carry one.
    assert!(
        named(&events, "quic:parameters_set")
            .any(|ev| ev["data"].get("preferred_address").is_some()),
        "trace: {trace}"
    );
    assert!(
        named(&events, "quic:packet_received").any(|ev| ev["data"]["frames"]
            .as_array()
            .is_some_and(|fs| fs.iter().any(|f| f["frame_type"] == "new_connection_id"))),
        "trace: {trace}"
    );
    let mut logged = Vec::new();
    for ev in &events {
        values_of(ev, "stateless_reset_token", &mut logged);
    }
    assert!(logged.len() > 2, "trace: {trace}");
    assert!(logged.iter().all(|t| *t == ""), "trace: {trace}");
}
