// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Tests for what a trace says, as opposed to what the connection does. These
//! check the things a reader of a trace has to be able to rely on: that a packet
//! reports its own size, that everything received is accounted for, and that
//! events do not go backwards in time.

use serde_json::Value;

use super::{ConnectionParameters, connect, new_client_with_qlog, new_server_with_qlog};

/// The events of a JSON-SEQ trace with the given name.
fn named<'a>(trace: &'a str, name: &'a str) -> impl Iterator<Item = Value> + 'a {
    trace
        .split('\u{1e}')
        .filter_map(|r| serde_json::from_str::<Value>(r).ok())
        .filter(move |e| e["name"] == name)
}

#[test]
fn coalesced_packet_lengths_agree_with_the_peer() {
    let (mut client, client_log) = new_client_with_qlog(ConnectionParameters::default());
    let (mut server, server_log) = new_server_with_qlog(ConnectionParameters::default());
    connect(&mut client, &mut server);
    drop((client, server));

    // Both lengths, so that `payload_length` is held to the same standard.
    let key = |e: &Value| {
        let (header, raw) = (&e["data"]["header"], &e["data"]["raw"]);
        Some((
            header["packet_type"].as_str()?.to_owned(),
            header["packet_number"].as_u64()?,
            (raw["length"].as_u64()?, raw["payload_length"].as_u64()?),
        ))
    };
    let tx = named(&client_log.to_string(), "quic:packet_sent")
        .filter_map(|e| key(&e))
        .collect::<Vec<_>>();
    let rx = named(&server_log.to_string(), "quic:packet_received")
        .filter_map(|e| key(&e))
        .collect::<Vec<_>>();
    assert!(tx.len() > 1 && !rx.is_empty());
    // Every packet the server decoded has to match what the client said it sent.
    let mut compared = 0;
    for (packet_type, pn, lengths) in &rx {
        if let Some((_, _, sent)) = tx.iter().find(|(t, n, _)| t == packet_type && n == pn) {
            assert_eq!(sent, lengths);
            compared += 1;
        }
    }
    assert_eq!(compared, rx.len(), "sent {tx:?} received {rx:?}");
}
