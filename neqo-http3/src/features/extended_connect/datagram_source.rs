// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

use neqo_transport::{DatagramTracking, OutgoingDatagramSource};

use super::session::Session;

/// The [`neqo_transport::Connection`]-facing source registered via
/// [`neqo_transport::Connection::set_outgoing_datagram_source`]: round-robins
/// outgoing-datagram pulls across every live extended-CONNECT session
/// sharing this connection, so one session with plenty queued cannot starve
/// another sharing the same connection's packets.
///
/// [`Self::next_datagram_len`] and [`Self::take_next_datagram`] must be
/// called as a strict pair (see [`OutgoingDatagramSource`]'s contract):
/// `next_datagram_len` remembers which session it peeked in [`Self::peeked`],
/// and `take_next_datagram` pulls from exactly that one, regardless of
/// where `next` has since rotated to.
#[derive(Debug, Default)]
pub struct SessionDatagramSources {
    /// Every registered session, in registration order. A session that has
    /// dropped its last strong reference is pruned lazily, the next time
    /// this is walked.
    sessions: Vec<Weak<RefCell<Session>>>,
    /// Index into `sessions` that the next [`Self::next_datagram_len`] call
    /// tries first. Advanced past whichever session last yielded a
    /// datagram, mirroring the send-group round-robin within a single
    /// session's own queue.
    next: usize,
    /// Index into `sessions` that the most recent [`Self::next_datagram_len`]
    /// call peeked, if it returned `Some`.
    peeked: Option<usize>,
}

impl SessionDatagramSources {
    /// Register a session so its outgoing datagrams participate in the
    /// round-robin. Idempotent: registering the same session twice (e.g. on
    /// every session-creation call site, for simplicity) is a no-op after
    /// the first time.
    pub fn register(&mut self, session: &Rc<RefCell<Session>>) {
        let weak = Rc::downgrade(session);
        if self.sessions.iter().any(|s| s.ptr_eq(&weak)) {
            return;
        }
        self.sessions.push(weak);
    }

    /// Every live registered session. Prunes dead entries as a side effect.
    pub fn iter_sessions(&mut self) -> impl Iterator<Item = Rc<RefCell<Session>>> + '_ {
        self.sessions.retain(|s| s.strong_count() > 0);
        self.sessions.iter().filter_map(Weak::upgrade)
    }

    /// Expire every session's stale datagrams and return the earliest
    /// instant any of them next needs this called again. `default_max_age`
    /// is computed once by the caller from `conn.stats().min_rtt`, since
    /// [`OutgoingDatagramSource`] itself gives pulls no connection access.
    pub fn expire_all(&mut self, now: Instant, default_max_age: Duration) -> Option<Instant> {
        self.iter_sessions()
            .filter_map(|session| {
                let mut session = session.borrow_mut();
                session.expire_datagrams(now, default_max_age);
                session.next_datagram_expiry(default_max_age)
            })
            .min()
    }
}

impl OutgoingDatagramSource for SessionDatagramSources {
    fn next_datagram_len(&mut self, now: Instant) -> Option<usize> {
        self.peeked = None;
        self.sessions.retain(|s| s.strong_count() > 0);
        if self.sessions.is_empty() {
            self.next = 0;
            return None;
        }
        self.next %= self.sessions.len();
        for offset in 0..self.sessions.len() {
            let i = (self.next + offset) % self.sessions.len();
            let Some(session) = self.sessions[i].upgrade() else {
                continue;
            };
            if let Some(len) = session.borrow().next_datagram_len(now) {
                self.peeked = Some(i);
                return Some(len);
            }
        }
        None
    }

    fn take_next_datagram(&mut self, now: Instant) -> Option<(Vec<u8>, DatagramTracking)> {
        let i = self.peeked.take()?;
        let session = self.sessions.get(i)?.upgrade()?;
        let result = session.borrow_mut().take_next_datagram(now);
        self.next = i + 1;
        result
    }
}
