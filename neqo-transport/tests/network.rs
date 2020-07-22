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
    network::{Delay, Drop},
    Simulator,
};
use std::time::Duration;

// Some constants that are useful common values.
const TRANSFER_AMOUNT: usize = 1 << 20;
const ZERO: Duration = Duration::from_millis(0);
const DELAY: Duration = Duration::from_millis(50);

#[test]
fn connect_direct() {
    let sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![ReachState::new(State::Confirmed)]),
        ConnectionNode::new_server(boxed![ReachState::new(State::Confirmed)]),
    ]);
    sim.run();
}

#[test]
fn idle_timeout() {
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
fn transfer() {
    let sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
        ConnectionNode::new_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
    ]);
    sim.run();
}

#[test]
fn connect_fixed_rtt() {
    let sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![ReachState::new(State::Confirmed)]),
        Delay::new(DELAY..DELAY),
        ConnectionNode::new_server(boxed![ReachState::new(State::Confirmed)]),
        Delay::new(DELAY..DELAY),
    ]);
    sim.run();
}

#[test]
fn transfer_fixed_seed() {
    let mut sim = Simulator::new(boxed![
        ConnectionNode::new_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
        Delay::new(ZERO..DELAY),
        Drop::percentage(1),
        ConnectionNode::new_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
        Delay::new(ZERO..DELAY),
        Drop::percentage(1),
    ]);
    sim.seed_str("117f65d90ee5c1a7fb685f3af502c7730ba5d31866b758d98f5e3c2117cf9b86");
    sim.run();
}
