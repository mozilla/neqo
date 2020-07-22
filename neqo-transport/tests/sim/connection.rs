// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::Node;
use crate::boxed; // Macro export rules are completely messed up.
use neqo_common::{qdebug, Datagram};
use neqo_crypto::AuthenticationStatus;
use neqo_transport::{Connection, ConnectionEvent, Output, State};
use std::fmt::{self, Debug};
use std::time::Instant;

pub trait ConnectionGoal {
    fn init(&mut self, _c: &mut Connection) {}
    /// Handle an event from the provided connection, returning `true` when the
    /// goal is achieved.
    fn handle_event(&mut self, c: &mut Connection, e: &ConnectionEvent, now: Instant) -> bool;
}

pub struct ConnectionNode {
    c: Connection,
    goals: Vec<Box<dyn ConnectionGoal>>,
}

impl ConnectionNode {
    pub fn new_client(goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>) -> Self {
        Self {
            c: test_fixture::default_client(),
            goals: goals.into_iter().collect(),
        }
    }

    pub fn new_server(goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>) -> Self {
        Self {
            c: test_fixture::default_server(),
            goals: goals.into_iter().collect(),
        }
    }

    #[allow(dead_code)]
    pub fn clear_goals(&mut self) {
        self.goals.clear();
    }

    #[allow(dead_code)]
    pub fn add_goal(&mut self, goal: Box<dyn ConnectionGoal>) {
        self.goals.push(goal);
    }
}

impl Node for ConnectionNode {
    fn process(&mut self, d: Option<Datagram>, now: Instant) -> Output {
        let res = self.c.process(d, now);
        for e in self.c.events() {
            qdebug!([self.c], "received event {:?}", e);

            // Perform authentication automatically.
            if matches!(e, ConnectionEvent::AuthenticationNeeded) {
                self.c.authenticated(AuthenticationStatus::Ok, now);
            }

            // Waiting on drain_filter...
            // let _ = self.goals.drain_filter(|g| g.handle_event(&mut self.c, &e)).count();
            let mut i = 0;
            while i < self.goals.len() {
                if self.goals[i].handle_event(&mut self.c, &e, now) {
                    self.goals.remove(i);
                } else {
                    i += 1;
                }
            }
        }
        res
    }

    fn done(&self) -> bool {
        self.goals.is_empty()
    }
}

impl Default for ConnectionNode {
    fn default() -> Self {
        Self::new_client(boxed![Confirmed::default()])
    }
}

impl Debug for ConnectionNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.c.fmt(f)
    }
}

#[derive(Debug, Default)]
pub struct Confirmed {}

impl ConnectionGoal for Confirmed {
    fn handle_event(&mut self, _c: &mut Connection, e: &ConnectionEvent, _now: Instant) -> bool {
        matches!(e, ConnectionEvent::StateChange(State::Confirmed))
    }
}
