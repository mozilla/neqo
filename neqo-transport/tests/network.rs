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
    network::{Delay, Drop, TailDrop},
    Simulator,
};
use std::ops::Range;
use std::time::Duration;

/// The amount of transfer.  Much more than this takes a surprising amount of time.
const TRANSFER_AMOUNT: usize = 1 << 20; // 1M
const TRANSFER_AMOUNT_10: usize = 10 * (1 << 20); // 10M
const ZERO: Duration = Duration::from_millis(0);
const DELAY: Duration = Duration::from_millis(50);
const DELAY_RANGE: Range<Duration> = DELAY..Duration::from_millis(55);
const JITTER: Duration = Duration::from_millis(10);

simulate!(
    connect_direct,
    [
        ConnectionNode::new_client(boxed![ReachState::new(State::Confirmed)]),
        ConnectionNode::new_server(boxed![ReachState::new(State::Confirmed)]),
    ]
);

simulate!(
    idle_timeout,
    [
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
    ]
);

simulate!(
    idle_timeout_crazy_rtt,
    [
        ConnectionNode::new_client(boxed![
            ReachState::new(State::Confirmed),
            ReachState::new(State::Closed(ConnectionError::Transport(
                Error::IdleTimeout
            )))
        ]),
        Delay::new(Duration::from_secs(15)..Duration::from_secs(15)),
        Drop::percentage(10),
        ConnectionNode::new_server(boxed![
            ReachState::new(State::Confirmed),
            ReachState::new(State::Closed(ConnectionError::Transport(
                Error::IdleTimeout
            )))
        ]),
        Delay::new(Duration::from_secs(10)..Duration::from_secs(10)),
        Drop::percentage(10),
    ],
);

simulate!(
    transfer,
    [
        ConnectionNode::new_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
        ConnectionNode::new_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
    ]
);

simulate!(
    connect_fixed_rtt,
    [
        ConnectionNode::new_client(boxed![ReachState::new(State::Confirmed)]),
        Delay::new(DELAY..DELAY),
        ConnectionNode::new_server(boxed![ReachState::new(State::Confirmed)]),
        Delay::new(DELAY..DELAY),
    ],
);

simulate!(
    connect_taildrop_jitter,
    [
        ConnectionNode::new_client(boxed![ReachState::new(State::Confirmed)]),
        TailDrop::dsl_uplink(),
        Delay::new(ZERO..JITTER),
        ConnectionNode::new_server(boxed![ReachState::new(State::Confirmed)]),
        TailDrop::dsl_downlink(),
        Delay::new(ZERO..JITTER),
    ],
);

simulate!(
    connect_taildrop,
    [
        ConnectionNode::new_client(boxed![ReachState::new(State::Confirmed)]),
        TailDrop::dsl_uplink(),
        ConnectionNode::new_server(boxed![ReachState::new(State::Confirmed)]),
        TailDrop::dsl_downlink(),
    ],
);

simulate!(
    transfer_delay_drop,
    [
        ConnectionNode::new_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
        Delay::new(DELAY_RANGE),
        Drop::percentage(1),
        ConnectionNode::new_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
        Delay::new(DELAY_RANGE),
        Drop::percentage(1),
    ],
);

simulate!(
    transfer_taildrop,
    [
        ConnectionNode::new_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
        TailDrop::dsl_uplink(),
        ConnectionNode::new_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
        TailDrop::dsl_downlink(),
    ],
);

simulate!(
    transfer_taildrop_jitter,
    [
        ConnectionNode::new_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
        TailDrop::dsl_uplink(),
        Delay::new(ZERO..JITTER),
        ConnectionNode::new_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
        TailDrop::dsl_downlink(),
        Delay::new(ZERO..JITTER),
    ],
);

/// This test is a nasty piece of work.  Delays are anything from 0 to 50ms and 1% of
/// packets get dropped.
#[test]
fn transfer_fixed_seed() {
    let mut sim = Simulator::new(
        "transfer_fixed_seed",
        boxed![
            ConnectionNode::new_client(boxed![SendData::new(TRANSFER_AMOUNT)]),
            Delay::new(ZERO..DELAY),
            Drop::percentage(1),
            ConnectionNode::new_server(boxed![ReceiveData::new(TRANSFER_AMOUNT)]),
            Delay::new(ZERO..DELAY),
            Drop::percentage(1),
        ],
    );
    sim.seed_str("117f65d90ee5c1a7fb685f3af502c7730ba5d31866b758d98f5e3c2117cf9b86");
    sim.run();
}

// bandwidth 50Mbps
// delay by 10ms, 25ms, 50ms, 100ms, 250ms
// loss 1%, 2%, 5%, 10% and 20%
// With tail-drop queue
#[test]
#[ignore]
fn diff_conditions_loss() {
    let b = 50;
    for delay in &[10, 25, 50, 100, 250] {
        for loss in &[1, 2, 5, 10, 20] {
            Simulator::new(
                format!("diff conditions download {} {} {}", b, *delay, *loss),
                boxed![
                    ConnectionNode::new_client(boxed![
                        ReachState::new(State::Confirmed),
                        ReceiveData::new(TRANSFER_AMOUNT_10),
                    ]),
                    // TailDrop requires bandwidth in bytes/s
                    TailDrop::new(b * (1 << 17), 32_768, Duration::from_millis(*delay)),
                    ConnectionNode::new_server(boxed![
                        ReachState::new(State::Confirmed),
                        SendData::new(TRANSFER_AMOUNT_10),
                    ]),
                    Drop::percentage(*loss),
                    // TailDrop requires bandwidth in bytes/s
                    TailDrop::new(b * (1 << 17), 32_768, Duration::from_millis(*delay)),
                ],
            )
            .run();
        }
    }
}

// bandwidth 10Mbps, 20Mbps, 50Mbps and 100Mbps
// delay by 10ms, 50ms, 100ms and 250ms
// loss 0%
// With tail-drop queue
#[test]
#[ignore]
fn diff_conditions_tail_drop() {
    for b in &[10, 20, 50, 100] {
        for delay in &[10, 25, 50, 100, 250] {
            Simulator::new(
                format!("diff conditions download taildrop only {} {}", b, *delay),
                boxed![
                    ConnectionNode::new_client(boxed![
                        ReachState::new(State::Confirmed),
                        ReceiveData::new(
                            TRANSFER_AMOUNT * if b * delay < 25 { 1 } else { b * delay / 25 }
                        ),
                    ]),
                    // TailDrop requires bandwidth in bytes/s
                    TailDrop::new(b * (1 << 17), 32_768, Duration::from_millis(*delay as u64)),
                    ConnectionNode::new_server(boxed![
                        ReachState::new(State::Confirmed),
                        SendData::new(
                            TRANSFER_AMOUNT * if b * delay < 25 { 1 } else { b * delay / 25 }
                        ),
                    ]),
                    // TailDrop requires bandwidth in bytes/s
                    TailDrop::new(b * (1 << 17), 32_768, Duration::from_millis(*delay as u64)),
                ],
            )
            .run();
        }
    }
}
