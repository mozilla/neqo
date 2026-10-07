// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Tests for what a trace says, as opposed to what the connection does. These
//! check the things a reader of a trace has to be able to rely on: that a packet
//! reports its own size, that everything received is accounted for, and that
//! events do not go backwards in time.

use std::time::{Duration, Instant};

use neqo_common::{Datagram, Decoder};
use test_fixture::{datagram, now, strip_padding};

use super::{
    super::State, Connection, ConnectionParameters, connect, default_client, default_server,
    maybe_authenticate, new_client_with_qlog, new_server_with_qlog, send_something,
};
use crate::{saved::SavedDatagrams, version::Version};

/// The lines of a JSON-SEQ trace that are events, i.e. everything but the header.
fn events(trace: &str) -> impl Iterator<Item = &str> + Clone {
    trace
        .lines()
        .map(|l| l.trim_start_matches('\u{1e}'))
        .filter(|l| l.contains("\"name\":"))
}

fn named<'a>(trace: &'a str, name: &str) -> impl Iterator<Item = &'a str> + Clone + use<'a> {
    let name = format!("\"name\":\"{name}\"");
    events(trace).filter(move |l| l.contains(&name))
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

/// The `datagram_id` of a packet event.
fn datagram_id(line: &str) -> Option<u64> {
    number(line, "\"datagram_id\":")
}

/// As [`datagram_id`], for the datagram events, whose `datagram_ids` is a list.
fn datagram_ids(line: &str) -> Option<u64> {
    number(line, "\"datagram_ids\":[")
}

/// The datagram and packet events for `dir`, which is `"sent"` or `"received"`.
fn datagrams_and_packets<'a>(
    trace: &'a str,
    dir: &str,
) -> (
    impl Iterator<Item = &'a str> + Clone,
    impl Iterator<Item = &'a str>,
) {
    (
        named(trace, &format!("quic:datagrams_{dir}")),
        named(trace, &format!("quic:packet_{dir}")),
    )
}

/// The only datagram is reported with all of its `len` bytes, its packet with fewer.
fn reports_the_padded_size(trace: &str, dir: &str, len: usize) {
    let (datagrams, mut packets) = datagrams_and_packets(trace, dir);
    let len = u64::try_from(len).unwrap();
    let lengths = datagrams.filter_map(raw_list_length).collect::<Vec<_>>();
    assert_eq!(lengths, vec![len], "trace: {trace}");
    let packet = packets.next().expect("a packet event");
    assert!(raw_length(packet).unwrap() < len, "trace: {trace}");
}

#[test]
fn datagrams_sent_reports_the_padded_size() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let dgram = client.process_output(now()).dgram().expect("a datagram");
    drop(client);
    reports_the_padded_size(&contents.to_string(), "sent", dgram.len());
}

#[test]
fn packets_name_their_datagram() {
    let (mut client, client_log) = new_client_with_qlog(ConnectionParameters::default());
    let (mut server, server_log) = new_server_with_qlog(ConnectionParameters::default());
    connect(&mut client, &mut server);
    drop((client, server));

    // Both directions, because each side decides the `datagram_id` for what it logs.
    names_its_datagram(&client_log.to_string(), "sent");
    names_its_datagram(&server_log.to_string(), "received");
}

#[test]
fn datagram_ids_have_no_gaps() {
    let (mut client, contents) = new_client_with_qlog(ConnectionParameters::default());
    let mut server = default_server();
    connect(&mut client, &mut server);
    // Nothing to send, then something, so that an ID wasted on the first would show.
    assert!(client.process_output(now()).dgram().is_none());
    send_something(&mut client, now());
    drop(client);

    let trace = contents.to_string();
    let mut ids = events(&trace).filter_map(datagram_ids).collect::<Vec<_>>();
    ids.sort_unstable();
    assert_eq!(
        ids,
        (0..).take(ids.len()).collect::<Vec<_>>(),
        "trace: {trace}"
    );
}

/// Every packet names a datagram that was itself reported, and some datagram carried
/// more than one packet, so that coalescing is recoverable from the trace.
fn names_its_datagram(trace: &str, dir: &str) {
    let (datagrams, packets) = datagrams_and_packets(trace, dir);
    let reported = |id| datagrams.clone().any(|d| datagram_ids(d) == Some(id));
    let mut coalesced = false;
    let mut last = None;
    for packet in packets {
        let id = datagram_id(packet).expect("a datagram_id");
        assert!(reported(id), "packet in unreported datagram {id}: {packet}");
        // Packets of one datagram are logged together, so a repeat means coalescing.
        coalesced |= last == Some(id);
        last = Some(id);
    }
    assert!(coalesced, "expected a coalesced datagram in {trace}");
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
    let buffered = named(&trace, "quic:packet_buffered").count();
    assert_eq!(buffered, SavedDatagrams::CAPACITY, "trace: {trace}");
    assert!(
        named(&trace, "quic:packet_dropped")
            .filter_map(raw_length)
            .any(|len| len == last as u64)
    );
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
    assert_eq!(named(&trace, "quic:packet_dropped").count(), 0);
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
    let mut dropped = named(&trace, "quic:packet_dropped");
    assert_eq!(
        dropped.next().and_then(raw_length),
        Some(len as u64),
        "{trace}"
    );
    assert_eq!(dropped.next(), None, "trace: {trace}");
}

#[test]
fn received_datagram_is_reported_once() {
    let mut client = default_client();
    let (mut server, contents) = new_server_with_qlog(ConnectionParameters::default());
    let ci = client.process_output(now()).dgram().expect("a datagram");
    let len = ci.len();

    server.process_input(ci, now());
    drop(server);
    reports_the_padded_size(&contents.to_string(), "received", len);
}

/// The IDs of all datagrams reported as received.
fn received_ids(trace: &str) -> Vec<u64> {
    named(trace, "quic:datagrams_received")
        .filter_map(datagram_ids)
        .collect()
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
    let before = received_ids(&contents.to_string()).len();
    t += RTT;
    _ = server.process(Some(last), t).dgram();
    assert_eq!(*server.state(), State::Confirmed);
    drop(server);

    let trace = contents.to_string();
    let ids = received_ids(&trace);
    assert_eq!(ids.len() - before, 1);

    // Every datagram set aside is one that was reported as received.
    let buffered = named(&trace, "quic:packet_buffered")
        .filter_map(datagram_id)
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
    let dropped = named(&trace, "quic:packet_dropped").collect::<Vec<_>>();
    assert_eq!(dropped.len(), 1, "trace: {trace}");
    // Reported against the datagram it arrived in, at the size that arrived.
    assert_eq!(raw_length(dropped[0]), Some(len as u64), "trace: {trace}");
    assert!(number(dropped[0], "\"datagram_id\":").is_some());
}

#[test]
fn every_received_byte_is_accounted_for() {
    let (mut client, client_log) = new_client_with_qlog(ConnectionParameters::default());
    let (mut server, server_log) = new_server_with_qlog(ConnectionParameters::default());
    let mut t = now();
    let last = handshake_but_for_the_last_flight(&mut client, &mut server, &mut t);
    // Buffered by the server, and replayed when the flight below supplies the keys.
    fill_saved_datagrams(&mut client, &mut server, t);
    t += RTT;
    _ = server.process(Some(last), t).dgram();
    assert_eq!(*server.state(), State::Confirmed);

    // Held back, so that it reaches the client only once it is closing.
    let late = send_something(&mut server, t);
    client.close(t, 0, "done");
    assert!(matches!(client.state(), State::Closing { .. }));
    client.process_input(late, t);
    drop((client, server));

    let server_trace = server_log.to_string();
    assert!(named(&server_trace, "quic:packet_buffered").count() > 0);
    accounts_for_every_byte(&client_log.to_string());
    accounts_for_every_byte(&server_trace);
}

/// Every byte that arrived in a datagram is accounted for by that datagram's packet
/// events, and none is counted twice.
fn accounts_for_every_byte(trace: &str) {
    let mut datagrams = 0;
    for d in named(trace, "quic:datagrams_received") {
        let id = number(d, "\"datagram_ids\":[").expect("a datagram_id");
        let accounted = ["quic:packet_received", "quic:packet_dropped"]
            .into_iter()
            .flat_map(|name| named(trace, name))
            .filter(|p| number(p, "\"datagram_id\":") == Some(id))
            .filter_map(raw_length)
            .sum::<u64>();
        assert_eq!(raw_list_length(d), Some(accounted), "datagram {id}: {d}");
        datagrams += 1;
    }
    assert!(datagrams > 0, "nothing arrived in {trace}");
}

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
    let padding = named(&trace, "quic:packet_dropped")
        .next()
        .expect("the padding");
    // Named as padding, with no packet type invented for it.
    assert_eq!(field(padding, "\"details\":"), Some("padding"));
    assert_eq!(field(padding, "\"packet_type\":"), None);
    // This is the case the accounting rests on, so hold it to the sum as well: the
    // handshake tests strip padding, so nothing else covers it.
    assert!(raw_length(padding).unwrap() < len as u64);
    accounts_for_every_byte(&trace);
}
