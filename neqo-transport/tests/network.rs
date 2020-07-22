// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::pedantic)]

#[macro_use]
mod sim;

use neqo_transport::{ConnectionError, Error, State};
use sim::{
    connection::{ConnectionNode, ReachState, ReceiveData, SendData},
    Simulator,
};

#[test]
fn direct_connect() {
    let sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![ReachState::new(State::Confirmed)]),
        ConnectionNode::new_server(boxed![ReachState::new(State::Confirmed)]),
    ]);
    sim.run();
}

#[test]
fn direct_idle_timeout() {
    let sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![
            ReachState::new(State::Confirmed),
            ReachState::new(State::Closed(ConnectionError::Transport(
                Error::IdleTimeout
            )))
        ]),
        ConnectionNode::new_server(boxed![
            ReachState::new(State::Confirmed),
            ReachState::new(State::Closed(ConnectionError::Transport(
                Error::IdleTimeout
            )))
        ]),
    ]);
    sim.run();
}

#[test]
fn direct_transfer() {
    const AMOUNT: usize = 1 << 20;
    let sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![SendData::new(AMOUNT)]),
        ConnectionNode::new_server(boxed![ReceiveData::new(AMOUNT)]),
    ]);
    sim.run();
}
