// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A simulated transfer benchmark, asserting a minimum bandwidth.
//!
//! This is using [`test_fixture::sim`], i.e. does no I/O beyond the process
//! boundary and runs in simulated time. Given that [`test_fixture::sim`] is
//! deterministic, there is no need for multiple benchmark iterations. Still it
//! is a Rust benchmark instead of a unit test due to its runtime (> 10s) even
//! in Rust release mode.

use std::time::Duration;

use neqo_common::{log::init as init_log, qinfo};
use neqo_transport::{ConnectionParameters, State};
use test_fixture::{
    boxed,
    sim::{
        connection::{Node, ReachState, ReceiveData, SendData},
        network::{Mtu, TailDrop},
        Simulator,
    },
};

#[expect(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "OK in a bench."
)]
pub fn main() {
    const MIB: usize = 1_024 * 1_024;
    const GIB: usize = 1_024 * MIB;

    const MBIT: usize = 1_000 * 1_000;
    const GBIT: usize = 1_000 * MBIT;

    const TRANSFER_AMOUNT: usize = GIB;
    const LINK_BANDWIDTH: usize = GBIT;
    const LINK_RTT_MS: usize = 40;
    /// The amount of delay that the link buffer will add, when full.
    const BUFFER_LATENCY_MS: usize = 4;
    /// The proportion of the link buffer at which marking starts.
    const ECN_THRESHOLD: f64 = 0.8;
    /// How much of the theoretical bandwidth we will expect to deliver.
    const MINIMUM_EXPECTED_UTILIZATION: f64 = 0.7;

    let gbit_link = || {
        let rate_byte = LINK_BANDWIDTH / 8;
        let capacity_byte = LINK_BANDWIDTH * BUFFER_LATENCY_MS / 1000;
        let mark_capacity = ((capacity_byte as f64) * ECN_THRESHOLD) as usize;
        let delay = Duration::from_millis(LINK_RTT_MS as u64) / 2;
        TailDrop::new(rate_byte, capacity_byte, mark_capacity, delay)
    };

    init_log(None);

    let simulated_time = Simulator::new(
        "gbit-bandwidth",
        boxed![
            Node::new_client(
                ConnectionParameters::default().ack_ratio(255),
                boxed![ReachState::new(State::Confirmed)],
                boxed![ReceiveData::new(TRANSFER_AMOUNT)]
            ),
            Mtu::new(1500),
            gbit_link(),
            Node::new_server(
                ConnectionParameters::default().ack_ratio(255),
                boxed![ReachState::new(State::Confirmed)],
                boxed![SendData::new(TRANSFER_AMOUNT)]
            ),
            Mtu::new(1500),
            gbit_link(),
        ],
    )
    .setup()
    .run();

    let achieved_bandwidth = TRANSFER_AMOUNT as f64 * 8.0 / simulated_time.as_secs_f64();
    qinfo!(
        "Achieved {} Mb/s bandwidth (link rate {})",
        achieved_bandwidth / MBIT as f64,
        LINK_BANDWIDTH / MBIT
    );

    assert!(
        LINK_BANDWIDTH as f64 * MINIMUM_EXPECTED_UTILIZATION < achieved_bandwidth,
        "expected to reach {MINIMUM_EXPECTED_UTILIZATION} of maximum bandwidth ({} Mbit/s) but got {} Mbit/s",
        LINK_BANDWIDTH  / MBIT,
        achieved_bandwidth / MBIT as f64,
    );
}
