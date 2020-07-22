// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(dead_code)]

use super::connection::ConnectionGoal;
use super::Node;

use neqo_common::Datagram;
use neqo_transport::{server::Server, Connection, Output};
use std::fmt::{self, Debug};
use std::time::Instant;

pub trait ServerGoal {
    fn init(&mut self, _s: &mut Server) {}
    fn handle_connection(
        &mut self,
        c: &mut Connection,
        now: Instant,
    ) -> Vec<Box<dyn ConnectionGoal>>;
}

pub struct ServerNode {
    s: Server,
    goals: Vec<Box<dyn ServerGoal>>,
}

impl Node for ServerNode {
    fn process(&mut self, _d: Option<Datagram>, _now: Instant) -> Output {
        // TODO
        Output::None
    }

    /// An node can report when it considers itself "done".
    fn done(&self) -> bool {
        true
    }
}

impl Debug for ServerNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Server")
    }
}
