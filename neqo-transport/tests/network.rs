// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::pedantic)]

#[macro_use]
mod sim;

use sim::{connection::Confirmed, connection::ConnectionNode, Simulator};

#[test]
fn simple() {
    let mut sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![Confirmed::default()]),
        ConnectionNode::new_server(boxed![Confirmed::default()]),
    ]);
    sim.run();
}
