// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::once::OnceResult;
use neqo_crypto::{AntiReplay, init_db};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};


pub fn init() {
    init_db(concat!(env!("CARGO_MANIFEST_DIR"), "/db"));
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
    AntiReplay::new(earlier(), ANTI_REPLAY_WINDOW, 1, 3).expect("setup anti-replay")
}

pub const DEFAULT_KEYS: &[&str] = &["key"];
pub const DEFAULT_ALPN: &[&str] = &["alpn"];

fn loopback() -> SocketAddr {
    let localhost_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    SocketAddr::new(localhost_v6, 443)
}

pub fn default_client() -> Connection {
    Connection::new_client()
}

