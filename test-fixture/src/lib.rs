// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)] // This lint doesn't work here.

use std::{
    cell::{OnceCell, RefCell},
    cmp::max,
    convert::TryFrom,
    fmt::Display,
    io::{Cursor, Result, Write},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use neqo_common::{
    event::Provider,
    hex,
    qlog::{new_trace, NeqoQlog},
    qtrace, Datagram, Decoder, IpTos, Role,
};
use neqo_crypto::{init_db, random, AllowZeroRtt, AntiReplay, AuthenticationStatus};
use neqo_http3::{Http3Client, Http3Parameters, Http3Server};
use neqo_transport::{
    version::WireVersion, Connection, ConnectionEvent, ConnectionId, ConnectionIdDecoder,
    ConnectionIdGenerator, ConnectionIdRef, ConnectionParameters, State, Version,
};
use qlog::{events::EventImportance, streamer::QlogStreamer};

pub mod assertions;
pub mod sim;

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

/// A baseline time for all tests.  This needs to be earlier than what `now()` produces
/// because of the need to have a span of time elapse for anti-replay purposes.
fn earlier() -> Instant {
    // Note: It is only OK to have a different base time for each thread because our tests are
    // single-threaded.
    thread_local!(static EARLIER: OnceCell<Instant> = const { OnceCell::new() });
    fixture_init();
    EARLIER.with(|b| *b.get_or_init(Instant::now))
}

/// The current time for the test.  Which is in the future,
/// because 0-RTT tests need to run at least `ANTI_REPLAY_WINDOW` in the past.
///
/// # Panics
///
/// When the setup fails.
#[must_use]
pub fn now() -> Instant {
    earlier().checked_add(ANTI_REPLAY_WINDOW).unwrap()
}

/// Create a default anti-replay context.
///
/// # Panics
///
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
pub const DEFAULT_ADDR: SocketAddr = addr();
pub const DEFAULT_ADDR_V4: SocketAddr = addr_v4();

// Create a default datagram with the given data.
#[must_use]
pub fn datagram(data: Vec<u8>) -> Datagram {
    Datagram::new(
        DEFAULT_ADDR,
        DEFAULT_ADDR,
        IpTos::default(),
        Some(128),
        data,
    )
}

/// Create a default socket address.
#[must_use]
const fn addr() -> SocketAddr {
    let v6ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    SocketAddr::new(v6ip, 443)
}

/// An IPv4 version of the default socket address.
#[must_use]
const fn addr_v4() -> SocketAddr {
    let v4ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    SocketAddr::new(v4ip, DEFAULT_ADDR.port())
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
        let mut r = random::<20>();
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

/// Create a new client.
///
/// # Panics
///
/// If this doesn't work.
#[must_use]
pub fn new_client(params: ConnectionParameters) -> Connection {
    fixture_init();
    let (log, _contents) = new_neqo_qlog();
    let mut client = Connection::new_client(
        DEFAULT_SERVER_NAME,
        DEFAULT_ALPN,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR,
        DEFAULT_ADDR,
        params.ack_ratio(255), // Tests work better with this set this way.
        now(),
    )
    .expect("create a client");
    client.set_qlog(log);
    client
}

/// Create a transport client with default configuration.
#[must_use]
pub fn default_client() -> Connection {
    new_client(ConnectionParameters::default())
}

/// Create a transport server with default configuration.
#[must_use]
pub fn default_server() -> Connection {
    new_server(DEFAULT_ALPN, ConnectionParameters::default())
}

/// Create a transport server with default configuration.
#[must_use]
pub fn default_server_h3() -> Connection {
    new_server(DEFAULT_ALPN_H3, ConnectionParameters::default())
}

/// Create a transport server with a configuration.
///
/// # Panics
///
/// If this doesn't work.
#[must_use]
pub fn new_server(alpn: &[impl AsRef<str>], params: ConnectionParameters) -> Connection {
    fixture_init();
    let (log, _contents) = new_neqo_qlog();
    let mut c = Connection::new_server(
        DEFAULT_KEYS,
        alpn,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        params.ack_ratio(255),
    )
    .expect("create a server");
    c.set_qlog(log);
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
        _ = maybe_authenticate(a);
        let d = a.process(datagram.as_ref(), now());
        datagram = d.dgram();
        mem::swap(&mut a, &mut b);
    }
}

/// # Panics
///
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
///
/// # Panics
///
/// When the client can't be created.
#[must_use]
pub fn default_http3_client() -> Http3Client {
    fixture_init();
    Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR,
        DEFAULT_ADDR,
        Http3Parameters::default()
            .max_table_size_encoder(100)
            .max_table_size_decoder(100)
            .max_blocked_streams(100)
            .max_concurrent_push_streams(10),
        now(),
    )
    .expect("create a default client")
}

/// Create a http3 client.
///
/// # Panics
///
/// When the client can't be created.
#[must_use]
pub fn http3_client_with_params(params: Http3Parameters) -> Http3Client {
    fixture_init();
    Http3Client::new(
        DEFAULT_SERVER_NAME,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        DEFAULT_ADDR,
        DEFAULT_ADDR,
        params,
        now(),
    )
    .expect("create a client")
}

/// Create a http3 server with default configuration.
///
/// # Panics
///
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
        Http3Parameters::default()
            .max_table_size_encoder(100)
            .max_table_size_decoder(100)
            .max_blocked_streams(100)
            .max_concurrent_push_streams(10),
        None,
    )
    .expect("create a default server")
}

/// Split the first packet off a coalesced packet.
fn split_packet(buf: &[u8]) -> (&[u8], Option<&[u8]>) {
    const TYPE_MASK: u8 = 0b1011_0000;

    if buf[0] & 0x80 == 0 {
        // Short header: easy.
        return (buf, None);
    }
    let mut dec = Decoder::from(buf);
    let first = dec.decode_byte().unwrap();
    let v = Version::try_from(WireVersion::try_from(dec.decode_uint(4).unwrap()).unwrap()).unwrap(); // Version.
    let (initial_type, retry_type) = if v == Version::Version2 {
        (0b1001_0000, 0b1000_0000)
    } else {
        (0b1000_0000, 0b1011_0000)
    };
    assert_ne!(first & TYPE_MASK, retry_type, "retry not supported");
    dec.skip_vec(1); // DCID
    dec.skip_vec(1); // SCID
    if first & TYPE_MASK == initial_type {
        dec.skip_vvec(); // Initial token
    }
    dec.skip_vvec(); // The rest of the packet.
    let p1 = &buf[..dec.offset()];
    let p2 = if dec.remaining() > 0 {
        Some(dec.decode_remainder())
    } else {
        None
    };
    qtrace!("split packet: {} {:?}", hex(p1), p2.map(hex));
    (p1, p2)
}

/// Split the first datagram off a coalesced datagram.
#[must_use]
pub fn split_datagram(d: &Datagram) -> (Datagram, Option<Datagram>) {
    let (a, b) = split_packet(&d[..]);
    (
        Datagram::new(d.source(), d.destination(), d.tos(), d.ttl(), a),
        b.map(|b| Datagram::new(d.source(), d.destination(), d.tos(), d.ttl(), b)),
    )
}

#[derive(Clone, Default)]
pub struct SharedVec {
    buf: Arc<Mutex<Cursor<Vec<u8>>>>,
}

impl Write for SharedVec {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.buf.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> Result<()> {
        self.buf.lock().unwrap().flush()
    }
}

impl Display for SharedVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8(self.buf.lock().unwrap().clone().into_inner()).unwrap())
    }
}

/// Returns a pair of new enabled `NeqoQlog` that is backed by a [`Vec<u8>`]
/// together with a [`Cursor<Vec<u8>>`] that can be used to read the contents of
/// the log.
///
/// # Panics
///
/// Panics if the log cannot be created.
#[must_use]
pub fn new_neqo_qlog() -> (NeqoQlog, SharedVec) {
    let buf = SharedVec::default();

    if cfg!(feature = "bench") {
        return (NeqoQlog::disabled(), buf);
    }

    let mut trace = new_trace(Role::Client);
    // Set reference time to 0.0 for testing.
    trace.common_fields.as_mut().unwrap().reference_time = Some(0.0);
    let contents = buf.clone();
    let streamer = QlogStreamer::new(
        qlog::QLOG_VERSION.to_string(),
        None,
        None,
        None,
        std::time::Instant::now(),
        trace,
        EventImportance::Base,
        Box::new(buf),
    );
    let log = NeqoQlog::enabled(streamer, "");
    (log.expect("to be able to write to new log"), contents)
}

pub const EXPECTED_LOG_HEADER: &str = concat!(
    "\u{1e}",
    r#"{"qlog_version":"0.3","qlog_format":"JSON-SEQ","trace":{"vantage_point":{"name":"neqo-Client","type":"client"},"title":"neqo-Client trace","description":"Example qlog trace description","configuration":{"time_offset":0.0},"common_fields":{"reference_time":0.0,"time_format":"relative"}}}"#,
    "\n"
);
