// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::pedantic)]

use neqo_common::matches;
use neqo_crypto::{init_db, AntiReplay, AuthenticationStatus};
use neqo_http3::{Http3Client, Http3Server};
use neqo_transport::{Connection, ConnectionEvent, FixedConnectionIdManager, State};

use std::cell::RefCell;
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
#[must_use]
pub fn now() -> Instant {
    earlier().checked_add(ANTI_REPLAY_WINDOW).unwrap()
}

// Create a default anti-replay context.
#[must_use]
pub fn anti_replay() -> AntiReplay {
    AntiReplay::new(earlier(), ANTI_REPLAY_WINDOW, 1, 3).expect("setup anti-replay")
}

pub const DEFAULT_SERVER_NAME: &str = "example.com";
pub const DEFAULT_KEYS: &[&str] = &["key"];
pub const LONG_CERT_KEYS: &[&str] = &["A long cert"];
pub const DEFAULT_ALPN: &[&str] = &["alpn"];

/// Create a default socket address.
#[must_use]
pub fn loopback() -> SocketAddr {
    // These could be const functions, but they aren't...
    let localhost_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    SocketAddr::new(localhost_v6, 443)
}

/// Create a transport client with default configuration.
#[must_use]
pub fn default_client() -> Connection {
    fixture_init();
    Connection::new_client(
        DEFAULT_SERVER_NAME,
        DEFAULT_ALPN,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(3))),
        loopback(),
        loopback(),
    )
    .expect("create a default client")
}

/// Create a transport server with default configuration.
#[must_use]
pub fn default_server() -> Connection {
    fixture_init();
    Connection::new_server(
        DEFAULT_KEYS,
        DEFAULT_ALPN,
        &anti_replay(),
        Rc::new(RefCell::new(FixedConnectionIdManager::new(5))),
    )
    .expect("create a default server")
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
    let is_done = |c: &Connection| matches!(c.state(), State::Confirmed | State::Closing { .. } | State::Closed(..));
    while !is_done(a) {
        let _ = maybe_authenticate(a);
        let d = a.process(datagram, now());
        datagram = d.dgram();
        mem::swap(&mut a, &mut b);
    }
}

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
#[must_use]
pub fn default_http3_client() -> Http3Client {
    fixture_init();
    Http3Client::new(
        DEFAULT_SERVER_NAME,
        DEFAULT_ALPN,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(3))),
        loopback(),
        loopback(),
        100,
        100,
    )
    .expect("create a default client")
}

/// Create a http3 server with default configuration.
#[must_use]
pub fn default_http3_server() -> Http3Server {
    fixture_init();
    Http3Server::new(
        now(),
        DEFAULT_KEYS,
        DEFAULT_ALPN,
        anti_replay(),
        Rc::new(RefCell::new(FixedConnectionIdManager::new(5))),
        100,
        100,
    )
    .expect("create a default server")
}
