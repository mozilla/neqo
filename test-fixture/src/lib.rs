// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::once::OnceResult;
use neqo_crypto::{AntiReplay, init_db};
use neqo_transport::Connection;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The path for the database used in tests.
pub const NSS_DB_PATH: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/db");

/// Initialize the test fixture.  Only call this if you aren't also calling a
/// fixture function that depends on setup.  Other functions in the fixture
/// that depend on this setup call the function for you.
pub fn fixture_init() {
    init_db(NSS_DB_PATH);
}

// This needs to be > 2ms to avoid it being rounded to zero.
// NSS operates in milliseconds and halves any value it is provided.
pub const ANTI_REPLAY_WINDOW: Duration = Duration::from_millis(10);

fn earlier() -> Instant {
    static mut BASE_TIME: OnceResult<Instant> = OnceResult::new();
    *unsafe { BASE_TIME.call_once(|| Instant::now()) }
}

/// The current time for the test.  Which is in the future,
/// because 0-RTT tests need to run at least ANTI_REPLAY_WINDOW in the past.
pub fn now() -> Instant {
    earlier().checked_add(ANTI_REPLAY_WINDOW).unwrap()
}

// Create a default anti-replay context.
pub fn anti_replay() -> AntiReplay {
    fixture_init();
    AntiReplay::new(earlier(), ANTI_REPLAY_WINDOW, 1, 3)
        .expect("setup anti-replay")
}

pub const DEFAULT_SERVER_NAME: &'static str = "example.com";
pub const DEFAULT_KEYS: &'static [&'static str] = &["key"];
pub const DEFAULT_ALPN: &'static [&'static str] = &["alpn"];

/// Create a default socket address.
pub fn loopback() -> SocketAddr {
    // These could be const functions, but they aren't...
    let localhost_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    SocketAddr::new(localhost_v6, 443)
}

/// Create a transport client with default configuration.
pub fn default_client() -> Connection {
    fixture_init();
    Connection::new_client(DEFAULT_SERVER_NAME, DEFAULT_ALPN, loopback(), loopback())
            .expect("create a default client")
}

/// Create a transport server with default configuration.
pub fn default_server() -> Connection {
    fixture_init();
    Connection::new_server(DEFAULT_KEYS, DEFAULT_ALPN, &anti_replay())
        .expect("create a default server")
}