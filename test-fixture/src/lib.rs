// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::pedantic)]

use neqo_common::{event::Provider, Datagram, Decoder};

use neqo_crypto::{init_db, random, AllowZeroRtt, AntiReplay, AuthenticationStatus};
use neqo_http3::{Http3Client, Http3Parameters, Http3Server};
use neqo_qpack::QpackSettings;
use neqo_transport::{
    Connection, ConnectionEvent, ConnectionId, ConnectionIdDecoder, ConnectionIdGenerator,
    ConnectionIdRef, ConnectionParameters, State,
};

use std::cell::RefCell;
use std::cmp::max;
use std::convert::TryFrom;
use std::mem;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use lazy_static::lazy_static;

pub mod assertions;

/// The path for the database used in tests.
pub const NSS_DB_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/db");

/// Initialize the test fixture.  Only call this if you aren't also calling a
/// fixture function that depends on setup.  Other functions in the fixture
/// that depend on this setup call the function for you.
pub fn fixture_init() {
    init_db(NSS_DB_PATH);
}

// This needs to be > 2ms to avoid it being rounded to zero.
// NSS operates in milliseconds and halves any value it is provided.
pub const ANTI_REPLAY_WINDOW: Duration = Duration::from_millis(10);

lazy_static! {
    static ref BASE_TIME: Instant = Instant::now();
}

fn earlier() -> Instant {
    fixture_init();
    *BASE_TIME
}

/// The current time for the test.  Which is in the future,
/// because 0-RTT tests need to run at least `ANTI_REPLAY_WINDOW` in the past.
/// # Panics
/// When the setup fails.
#[must_use]
pub fn now() -> Instant {
    earlier().checked_add(ANTI_REPLAY_WINDOW).unwrap()
}

// Create a default anti-replay context.
/// # Panics
/// When the setup fails.
#[must_use]
pub fn anti_replay() -> AntiReplay {
    AntiReplay::new(earlier(), ANTI_REPLAY_WINDOW, 1, 3).expect("setup anti-replay")
}

pub const DEFAULT_SERVER_NAME: &str = "example.com";
pub const DEFAULT_KEYS: &[&str] = &["key"];
pub const LONG_CERT_KEYS: &[&str] = &["A long cert"];
pub const DEFAULT_ALPN: &[&str] = &["alpn"];
pub const DEFAULT_ALPN_H3: &[&str] = &["h3"];

/// Create a default socket address.
#[must_use]
pub fn addr() -> SocketAddr {
    // These could be const functions, but they aren't...
    let v6ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    SocketAddr::new(v6ip, 443)
}

/// This connection ID generation scheme is the worst, but it doesn't produce collisions.
/// It produces a connection ID with a length byte, 4 counter bytes and random padding.
#[derive(Debug, Default)]
pub struct CountingConnectionIdGenerator {
    counter: u32,
}

impl ConnectionIdDecoder for CountingConnectionIdGenerator {
    fn decode_cid<'a>(&self, dec: &mut Decoder<'a>) -> Option<ConnectionIdRef<'a>> {
        let len = usize::from(dec.peek_byte().unwrap());
        dec.decode(len).map(ConnectionIdRef::from)
    }
}

impl ConnectionIdGenerator for CountingConnectionIdGenerator {
    fn generate_cid(&mut self) -> Option<ConnectionId> {
        let mut r = random(20);
        // Randomize length, but ensure that the connection ID is long
        // enough to pass for an original destination connection ID.
        r[0] = max(8, 5 + ((r[0] >> 4) & r[0]));
        r[1] = u8::try_from(self.counter >> 24).unwrap();
        r[2] = u8::try_from((self.counter >> 16) & 0xff).unwrap();
        r[3] = u8::try_from((self.counter >> 8) & 0xff).unwrap();
        r[4] = u8::try_from(self.counter & 0xff).unwrap();
        self.counter += 1;
        Some(ConnectionId::from(&r[..usize::from(r[0])]))
    }

    fn as_decoder(&self) -> &dyn ConnectionIdDecoder {
        self
    }
}

/// Create a transport client with default configuration.
#[must_use]
pub fn default_client() -> Connection {
    fixture_init();
    Connection::new_client(
        DEFAULT_SERVER_NAME,
        DEFAULT_ALPN,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        addr(),
        addr(),
        ConnectionParameters::default(),
        now(),
    )
    .expect("create a default client")
}

/// Create a transport server with default configuration.
#[must_use]
pub fn default_server() -> Connection {
    make_default_server(DEFAULT_ALPN)
}

/// Create a transport server with a configuration.
#[must_use]
pub fn configure_server(conn_param: ConnectionParameters) -> Connection {
    fixture_init();

    let mut c = Connection::new_server(
        DEFAULT_KEYS,
        DEFAULT_ALPN,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        conn_param,
    )
    .expect("create a default server");
    c.server_enable_0rtt(&anti_replay(), AllowZeroRtt {})
        .expect("enable 0-RTT");
    c
}

/// Create a transport server with default configuration.
#[must_use]
pub fn default_server_h3() -> Connection {
    make_default_server(DEFAULT_ALPN_H3)
}

fn make_default_server(alpn: &[impl AsRef<str>]) -> Connection {
    fixture_init();

    let mut c = Connection::new_server(
        DEFAULT_KEYS,
        alpn,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        ConnectionParameters::default(),
    )
    .expect("create a default server");
    c.server_enable_0rtt(&anti_replay(), AllowZeroRtt {})
        .expect("enable 0-RTT");
    c
}

/// If state is `AuthenticationNeeded` call `authenticated()`.
/// This funstion will consume all outstanding events on the connection.
#[must_use]
pub fn maybe_authenticate(conn: &mut Connection) -> bool {
    let authentication_needed = |e| matches!(e, ConnectionEvent::AuthenticationNeeded);
    if conn.events().any(authentication_needed) {
        conn.authenticated(AuthenticationStatus::Ok, now());
        return true;
    }
    false
}

pub fn handshake(client: &mut Connection, server: &mut Connection) {
    let mut a = client;
    let mut b = server;
    let mut datagram = None;
    let is_done = |c: &Connection| {
        matches!(
            c.state(),
            State::Confirmed | State::Closing { .. } | State::Closed(..)
        )
    };
    while !is_done(a) {
        let _ = maybe_authenticate(a);
        let d = a.process(datagram, now());
        datagram = d.dgram();
        mem::swap(&mut a, &mut b);
    }
}

/// # Panics
/// When the connection fails.
#[must_use]
pub fn connect() -> (Connection, Connection) {
    let mut client = default_client();
    let mut server = default_server();
    handshake(&mut client, &mut server);
    assert_eq!(*client.state(), State::Confirmed);
    assert_eq!(*server.state(), State::Confirmed);
    (client, server)
}

/// Create a http3 client with default configuration.
/// # Panics
/// When the client can't be created.
#[must_use]
pub fn default_http3_client() -> Http3Client {
    fixture_init();
    Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        addr(),
        addr(),
        ConnectionParameters::default(),
        &Http3Parameters {
            qpack_settings: QpackSettings {
                max_table_size_encoder: 100,
                max_table_size_decoder: 100,
                max_blocked_streams: 100,
            },
            max_concurrent_push_streams: 10,
        },
        now(),
    )
    .expect("create a default client")
}

/// Create a http3 server with default configuration.
/// # Panics
/// When the server can't be created.
#[must_use]
pub fn default_http3_server() -> Http3Server {
    fixture_init();
    Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN_H3,
        anti_replay(),
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        QpackSettings {
            max_table_size_encoder: 100,
            max_table_size_decoder: 100,
            max_blocked_streams: 100,
        },
        None,
    )
    .expect("create a default server")
}

/// Split the first packet off a coalesced packet.
fn split_packet(buf: &[u8]) -> (&[u8], Option<&[u8]>) {
    if buf[0] & 0x80 == 0 {
        // Short header: easy.
        return (buf, None);
    }
    let mut dec = Decoder::from(buf);
    let first = dec.decode_byte().unwrap();
    assert_ne!(first & 0b0011_0000, 0b0011_0000, "retry not supported");
    dec.skip(4); // Version.
    dec.skip_vec(1); // DCID
    dec.skip_vec(1); // SCID
    if first & 0b0011_0000 == 0 {
        dec.skip_vvec(); // Initial token
    }
    dec.skip_vvec(); // The rest of the packet.
    let p1 = &buf[..dec.offset()];
    let p2 = if dec.remaining() > 0 {
        Some(dec.decode_remainder())
    } else {
        None
    };
    (p1, p2)
}

/// Split the first datagram off a coalesced datagram.
#[must_use]
pub fn split_datagram(d: &Datagram) -> (Datagram, Option<Datagram>) {
    let (a, b) = split_packet(&d[..]);
    (
        Datagram::new(d.source(), d.destination(), a),
        b.map(|b| Datagram::new(d.source(), d.destination(), b)),
    )
}
