// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Tests for what a trace says, as opposed to what the connection does. These
//! check the things a reader of a trace has to be able to rely on: that a packet
//! reports its own size, that everything received is accounted for, and that
//! events do not go backwards in time.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use neqo_common::{Datagram, Decoder};
use test_fixture::{datagram, now, strip_padding};

use super::{
    super::State, Connection, ConnectionParameters, connect, default_client, default_server,
    maybe_authenticate, new_client_with_qlog, new_server_with_qlog, send_something,
};
use crate::{
    saved::SavedDatagrams,
    stateless_reset::Token as Srt,
    tparams::{TransportParameter, TransportParameterId::StatelessResetToken},
    version::Version,
};

/// The lines of a JSON-SEQ trace that are events, i.e. everything but the header.
fn events(trace: &str) -> impl Iterator<Item = &str> {
    trace
        .lines()
        .map(|l| l.trim_start_matches('\u{1e}'))
        .filter(|l| l.contains("\"name\":"))
}

fn named<'a>(trace: &'a str, name: &'a str) -> impl Iterator<Item = &'a str> {
    events(trace).filter(move |l| l.contains(&format!("\"name\":\"{name}\"")))
}

/// The value that follows `key`, up to the next `,`, `}` or `]`. Enough of a
/// parser for these traces, and avoids pulling in a JSON dependency.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = &line[line.find(key)? + key.len()..];
    let end = rest.find([',', '}', ']']).unwrap_or(rest.len());
    Some(rest[..end].trim_matches('"'))
}

fn number(line: &str, key: &str) -> Option<u64> {
    field(line, key)?.parse().ok()
}

/// The `raw` length of a packet event, anchored on the enclosing object.
fn raw_length(line: &str) -> Option<u64> {
    number(line, "\"raw\":{\"length\":")
}

/// As [`raw_length`], for the datagram events, whose `raw` is a list.
fn raw_list_length(line: &str) -> Option<u64> {
    number(line, "\"raw\":[{\"length\":")
}

/// Every event's time, in order of appearance.
fn times(trace: &str) -> Vec<f64> {
    events(trace)
        .filter_map(|l| field(l, "\"time\":").and_then(|t| t.parse().ok()))
        .collect()
}

#[test]
fn datagrams_sent_reports_the_padded_size() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let dgram = client.process_output(now()).dgram().expect("a datagram");
    let len = dgram.len();
    drop(client);

    let trace = contents.to_string();
    let sent = named(&trace, "transport:datagrams_sent")
        .next()
        .expect("a datagrams_sent event");
    assert_eq!(raw_list_length(sent), Some(len as u64));

    let packet = named(&trace, "transport:packet_sent")
        .next()
        .expect("a packet_sent event");
    assert!(
        raw_length(packet).unwrap() < len as u64,
        "expected the Initial to be padded out, trace: {trace}"
    );
}

#[test]
fn coalesced_packet_lengths_agree_with_the_peer() {
    let (mut client, client_log) = new_client_with_qlog(ConnectionParameters::default());
    let (mut server, server_log) = new_server_with_qlog(ConnectionParameters::default());
    connect(&mut client, &mut server);
    drop((client, server));

    let (sent, received) = (client_log.to_string(), server_log.to_string());
    let key = |l: &str| {
        Some((
            field(l, "\"packet_type\":")?.to_owned(),
            number(l, "\"packet_number\":")?,
            raw_length(l)?,
        ))
    };
    let tx = named(&sent, "transport:packet_sent")
        .filter_map(key)
        .collect::<Vec<_>>();
    let rx = named(&received, "transport:packet_received")
        .filter_map(key)
        .collect::<Vec<_>>();
    assert!(
        tx.len() > 1 && !rx.is_empty(),
        "sent {tx:?} received {rx:?}"
    );

    // Every packet the server decoded has to match what the client said it sent.
    let mut compared = 0;
    for (packet_type, pn, len) in &rx {
        if let Some((_, _, sent_len)) = tx.iter().find(|(t, n, _)| t == packet_type && n == pn) {
            assert_eq!(sent_len, len);
            compared += 1;
        }
    }
    assert_eq!(compared, rx.len(), "sent {tx:?} received {rx:?}");
}

#[test]
fn packets_name_their_datagram() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let mut server = default_server();
    connect(&mut client, &mut server);
    drop(client);

    let trace = contents.to_string();
    let datagrams = named(&trace, "transport:datagrams_sent")
        .filter_map(|l| number(l, "\"datagram_ids\":["))
        .collect::<Vec<_>>();
    assert!(!datagrams.is_empty(), "no datagrams_sent in {trace}");

    let mut per_datagram: HashMap<u64, usize> = HashMap::new();
    for packet in named(&trace, "transport:packet_sent") {
        let id = number(packet, "\"datagram_id\":").expect("a datagram_id");
        assert!(
            datagrams.contains(&id),
            "packet in unreported datagram {id}: {packet}"
        );
        *per_datagram.entry(id).or_default() += 1;
    }
    let shared = per_datagram.values().filter(|n| **n > 1).count();
    assert!(shared > 0, "expected coalescing during the handshake");
}

const RTT: Duration = Duration::from_millis(100);

fn handshake_but_for_the_last_flight(
    client: &mut Connection,
    server: &mut Connection,
    t: &mut Instant,
) -> Datagram {
    let c1 = client.process_output(*t).dgram().map(strip_padding);
    let c2 = client.process_output(*t).dgram().map(strip_padding);

    *t += RTT / 2;
    server.process_input(c1.unwrap(), *t);
    let s1 = server.process(c2, *t).dgram().map(strip_padding);

    *t += RTT / 2;
    let dgram = client.process(s1, *t).dgram().map(strip_padding);
    *t += RTT / 2;
    let dgram = server.process(dgram, *t).dgram().map(strip_padding);

    *t += RTT / 2;
    client.process_input(dgram.unwrap(), *t);
    maybe_authenticate(client);
    strip_padding(
        client
            .process_output(*t)
            .dgram()
            .expect("a final client flight"),
    )
}

/// Fill the server's store with 1-RTT datagrams it has no keys for yet.
fn fill_saved_datagrams(client: &mut Connection, server: &mut Connection, t: Instant) {
    for _ in 0..SavedDatagrams::CAPACITY {
        let d = send_something(client, t);
        server.process_input(strip_padding(d), t);
    }
    assert_eq!(server.stats().saved_datagrams, SavedDatagrams::CAPACITY);
}

#[test]
fn event_times_do_not_go_backwards() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    let mut t = now();
    let last = handshake_but_for_the_last_flight(&mut client, &mut server, &mut t);

    fill_saved_datagrams(&mut client, &mut server, t);

    t += RTT;
    _ = server.process(Some(last), t).dgram();
    assert_eq!(*server.state(), State::Confirmed);
    drop(server);

    let trace = contents.to_string();
    let times = times(&trace);
    assert!(times.len() > 10, "too few events in {trace}");
    for (a, b) in times.iter().zip(times.iter().skip(1)) {
        assert!(a <= b, "time went from {a} back to {b}, trace: {trace}");
    }
}

#[test]
fn dropping_a_datagram_is_reported() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    let mut t = now();
    _ = handshake_but_for_the_last_flight(&mut client, &mut server, &mut t);

    // One more than the store holds, so the last one is dropped.
    let mut last = 0;
    for _ in 0..=SavedDatagrams::CAPACITY {
        let d = strip_padding(send_something(&mut client, t));
        last = d.len();
        server.process_input(d, t + RTT / 2);
    }
    assert_eq!(server.stats().saved_datagrams, SavedDatagrams::CAPACITY);
    drop(server);

    let trace = contents.to_string();
    let buffered = named(&trace, "transport:packet_buffered").count();
    assert_eq!(buffered, SavedDatagrams::CAPACITY, "trace: {trace}");

    let dropped = named(&trace, "transport:packet_dropped")
        .filter_map(raw_length)
        .collect::<Vec<_>>();
    assert!(
        dropped.contains(&(last as u64)),
        "expected a dropped datagram of {last} bytes, got {dropped:?}, trace: {trace}"
    );
}

#[test]
fn transport_parameters_are_logged_for_both_peers() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let mut server = default_server();
    connect(&mut client, &mut server);
    drop(client);

    let trace = contents.to_string();
    let peers = named(&trace, "transport:parameters_set")
        .filter_map(|l| field(l, "\"owner\":").map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert!(peers.contains(&"local".to_owned()), "trace: {trace}");
    assert!(peers.contains(&"remote".to_owned()), "trace: {trace}");
}

#[test]
fn server_logs_its_original_destination_connection_id() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    connect(&mut client, &mut server);
    drop(server);

    let trace = contents.to_string();
    let local = named(&trace, "transport:parameters_set")
        .find(|l| field(l, "\"owner\":") == Some("local"))
        .expect("the server's own parameters");
    assert!(
        field(local, "\"original_destination_connection_id\":").is_some_and(|v| !v.is_empty()),
        "trace: {trace}"
    );
}

#[test]
fn stateless_reset_token_is_not_logged() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let mut server = default_server();
    server
        .set_local_tparam(
            StatelessResetToken,
            TransportParameter::Bytes(vec![77; Srt::LEN]),
        )
        .unwrap();
    connect(&mut client, &mut server);
    drop(client);

    let trace = contents.to_string();
    let logged = named(&trace, "transport:parameters_set")
        .filter_map(|l| field(l, "\"stateless_reset_token\":"))
        .collect::<Vec<_>>();
    assert_eq!(logged, vec![""], "trace: {trace}");
}

/// The DCID and SCID of the client's first Initial, to address a packet back at it.
fn client_cids(client: &mut Connection) -> (Vec<u8>, Vec<u8>) {
    let initial = client
        .process_output(now())
        .dgram()
        .expect("a datagram")
        .to_vec();
    // Skip the first byte and the version, then the length-prefixed DCID and SCID.
    let mut dec = Decoder::from(&initial[5..]);
    let dcid = dec.decode_vec(1).expect("client DCID").to_vec();
    let scid = dec.decode_vec(1).expect("client SCID").to_vec();
    (dcid, scid)
}

#[cfg(not(feature = "disable-encryption"))]
#[test]
fn an_accepted_retry_is_not_reported_as_dropped() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let (dcid, scid) = client_cids(&mut client);
    let mut server_scid = dcid.clone();
    server_scid[0] ^= 0xff;

    let retry =
        crate::packet::Builder::retry(Version::default(), &scid, &server_scid, &[0x01], &dcid)
            .expect("build retry");
    drop(client.process(Some(datagram(retry)), now()));
    assert_eq!(client.stats().dropped_rx, 0, "the Retry was accepted");
    drop(client);

    let trace = contents.to_string();
    assert_eq!(
        named(&trace, "transport:packet_dropped").count(),
        0,
        "trace: {trace}"
    );
}

#[cfg(not(feature = "disable-encryption"))]
#[test]
fn rejected_retry_is_reported_as_dropped() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let (dcid, scid) = client_cids(&mut client);
    let mut server_scid = dcid.clone();
    server_scid[0] ^= 0xff;

    let retry =
        crate::packet::Builder::retry(Version::default(), &scid, &server_scid, &[0x01], &dcid)
            .expect("build retry");
    let len = retry.len();
    // The first is accepted, so the second is an extra one and is discarded.
    drop(client.process(Some(datagram(retry.clone())), now()));
    assert_eq!(client.stats().dropped_rx, 0, "the first Retry was accepted");
    drop(client.process(Some(datagram(retry)), now()));
    assert_eq!(client.stats().dropped_rx, 1, "the second was rejected");
    drop(client);

    let trace = contents.to_string();
    let dropped = named(&trace, "transport:packet_dropped").collect::<Vec<_>>();
    assert_eq!(dropped.len(), 1, "trace: {trace}");
    assert_eq!(raw_length(dropped[0]), Some(len as u64), "trace: {trace}");
}

#[test]
fn received_datagram_is_reported_once() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    let ci = client.process_output(now()).dgram().expect("a datagram");
    let len = ci.len();

    server.process_input(ci, now());
    drop(server);

    let trace = contents.to_string();
    let received = named(&trace, "transport:datagrams_received")
        .filter_map(raw_list_length)
        .collect::<Vec<_>>();
    assert_eq!(received, vec![len as u64], "trace: {trace}");

    let packet = named(&trace, "transport:packet_received")
        .next()
        .expect("a packet_received event");
    assert!(raw_length(packet).unwrap() < len as u64, "{trace}");
}

#[test]
fn received_packets_name_their_datagram() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    connect(&mut client, &mut server);
    drop((client, server));

    let trace = contents.to_string();
    let datagrams = named(&trace, "transport:datagrams_received")
        .filter_map(|l| number(l, "\"datagram_ids\":["))
        .collect::<Vec<_>>();
    assert!(!datagrams.is_empty(), "no datagrams_received in {trace}");

    let mut per_datagram: HashMap<u64, usize> = HashMap::new();
    for packet in named(&trace, "transport:packet_received") {
        let id = number(packet, "\"datagram_id\":").expect("a datagram_id");
        assert!(
            datagrams.contains(&id),
            "packet in unreported datagram {id}: {packet}"
        );
        *per_datagram.entry(id).or_default() += 1;
    }
    let shared = per_datagram.values().filter(|n| **n > 1).count();
    assert!(shared > 0, "expected a coalesced datagram in {trace}");
}

#[test]
fn replayed_datagrams_are_not_counted_twice() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    let mut t = now();
    let last = handshake_but_for_the_last_flight(&mut client, &mut server, &mut t);

    fill_saved_datagrams(&mut client, &mut server, t);

    // Everything saved is replayed by handing over the flight that supplies the
    // keys, so only that one datagram arrives from here on.
    let before = named(&contents.to_string(), "transport:datagrams_received").count();
    t += RTT;
    _ = server.process(Some(last), t).dgram();
    assert_eq!(*server.state(), State::Confirmed);
    drop(server);

    let trace = contents.to_string();
    let received = named(&trace, "transport:datagrams_received").count();
    assert_eq!(
        received - before,
        1,
        "replay reported {} extra datagrams, trace: {trace}",
        received - before - 1
    );

    // Every datagram set aside is one that was reported as received.
    let ids = named(&trace, "transport:datagrams_received")
        .filter_map(|l| number(l, "\"datagram_ids\":["))
        .collect::<Vec<_>>();
    let buffered = named(&trace, "transport:packet_buffered")
        .filter_map(|l| number(l, "\"datagram_id\":"))
        .collect::<Vec<_>>();
    assert_eq!(buffered.len(), SavedDatagrams::CAPACITY, "trace: {trace}");
    for id in &buffered {
        assert!(ids.contains(id), "packet_buffered names {id}: {trace}");
    }
}

#[test]
fn rejected_version_negotiation_is_reported() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let (dcid, scid) = client_cids(&mut client);

    // Offering the version already in use has to be ignored, per RFC 9000.
    let vn = crate::packet::Builder::version_negotiation(
        &scid,
        &dcid,
        Version::default().wire_version(),
        &[Version::default()],
    );
    let len = vn.len();
    drop(client.process(Some(datagram(vn)), now()));
    assert_eq!(client.stats().dropped_rx, 1, "the VN was rejected");
    drop(client);

    let trace = contents.to_string();
    let dropped = named(&trace, "transport:packet_dropped").collect::<Vec<_>>();
    assert_eq!(dropped.len(), 1, "trace: {trace}");
    // Reported against the datagram it arrived in, at the size that arrived.
    assert_eq!(raw_length(dropped[0]), Some(len as u64), "trace: {trace}");
    assert!(
        number(dropped[0], "\"datagram_id\":").is_some(),
        "trace: {trace}"
    );
}

/// The sum of a trace's `raw` lengths, for the events named.
fn total(trace: &str, name: &str) -> u64 {
    named(trace, name).filter_map(raw_length).sum()
}

/// Every byte that arrives is accounted for, exactly once, by a packet event:
/// received, dropped, or set aside. This is what the datagram events are for, so it
/// is checked on both roles and across a close, where packets keep arriving but stop
/// being processed.
#[test]
fn every_received_byte_is_accounted_for() {
    let (mut client, client_log) = new_client_with_qlog(ConnectionParameters::default());
    let (mut server, server_log) = new_server_with_qlog(ConnectionParameters::default());
    connect(&mut client, &mut server);

    let d = send_something(&mut client, now());
    server.process_input(d, now());
    // Held back, so that it reaches the client only once it is closing.
    let late = send_something(&mut server, now());

    client.close(now(), 0, "done");
    assert!(matches!(client.state(), State::Closing { .. }));
    client.process_input(late, now());
    drop((client, server));

    for (role, trace) in [
        ("client", client_log.to_string()),
        ("server", server_log.to_string()),
    ] {
        let arrived = named(&trace, "transport:datagrams_received")
            .filter_map(raw_list_length)
            .sum::<u64>();
        let accounted = total(&trace, "transport:packet_received")
            + total(&trace, "transport:packet_dropped")
            + total(&trace, "transport:packet_buffered");
        let mut per: HashMap<u64, (u64, u64)> = HashMap::new();
        for e in named(&trace, "transport:datagrams_received") {
            if let (Some(id), Some(len)) = (number(e, "\"datagram_ids\":["), raw_list_length(e)) {
                per.entry(id).or_default().0 += len;
            }
        }
        for n in [
            "transport:packet_received",
            "transport:packet_dropped",
            "transport:packet_buffered",
        ] {
            for e in named(&trace, n) {
                if let (Some(id), Some(len)) = (number(e, "\"datagram_id\":"), raw_length(e)) {
                    per.entry(id).or_default().1 += len;
                }
            }
        }
        let off = per
            .iter()
            .filter(|(_, (a, b))| a != b)
            .map(|(id, (a, b))| (*id, *a, *b))
            .collect::<Vec<_>>();
        assert!(
            off.is_empty(),
            "{role}: (datagram, arrived, accounted) {off:?}"
        );
        assert_eq!(arrived, accounted, "{role}");
        assert!(arrived > 0, "{role} received nothing");
    }
}

/// Trailing bytes that cannot be used are reported as padding: they were sent and
/// received, so they took up bandwidth, but there is no telling padding from a packet
/// we cannot use, so no packet type is claimed for them.
#[test]
fn trailing_bytes_are_reported_as_padding() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    // A client Initial is padded out, so the server sees trailing bytes it cannot use.
    let ci = client.process_output(now()).dgram().expect("a datagram");
    let len = ci.len();
    server.process_input(ci, now());
    drop(server);

    let trace = contents.to_string();
    let initial = named(&trace, "transport:packet_received")
        .next()
        .expect("the Initial");
    let dropped = named(&trace, "transport:packet_dropped").collect::<Vec<_>>();
    assert_eq!(dropped.len(), 1, "trace: {trace}");
    // Named as padding, with no packet type invented for it.
    assert_eq!(field(dropped[0], "\"details\":"), Some("padding"));
    assert_eq!(field(dropped[0], "\"packet_type\":"), None);
    // And it covers exactly the bytes the Initial did not.
    assert_eq!(
        raw_length(initial).unwrap() + raw_length(dropped[0]).unwrap(),
        len as u64,
        "trace: {trace}"
    );
}
