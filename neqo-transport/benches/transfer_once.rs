use std::time::Duration;

use neqo_transport::{ConnectionParameters, State};
use test_fixture::{
    boxed,
    sim::{
        connection::{ConnectionNode, ReachState, ReceiveData, SendData},
        network::{NonRandomDelay, TailDrop},
        Simulator,
    },
};

#[allow(clippy::cast_precision_loss)]
pub fn main() {
    const MIB: usize = 1024 * 1024;
    const TRANSFER_AMOUNT: usize = 1000 * MIB;

    let sim = Simulator::new(
        "gbit-bandwidth",
        boxed![
            ConnectionNode::new_client(
                ConnectionParameters::default().pmtud(false).pacing(true),
                boxed![ReachState::new(State::Confirmed)],
                boxed![ReceiveData::new(TRANSFER_AMOUNT)]
            ),
            TailDrop::gbit_link(),
            NonRandomDelay::new(Duration::from_millis(20)),
            ConnectionNode::new_server(
                ConnectionParameters::default().pmtud(false).pacing(true),
                boxed![ReachState::new(State::Confirmed)],
                boxed![SendData::new(TRANSFER_AMOUNT)]
            ),
            TailDrop::gbit_link(),
            NonRandomDelay::new(Duration::from_millis(20)),
        ],
    );

    let simulated_time = sim.setup().run();
    let bandwidth = TRANSFER_AMOUNT as f64 * 8.0 / simulated_time.as_secs_f64();

    let maximum_bandwidth = 1_000_000_000.0;
    let expected_utilization = 0.5;

    assert!(
        maximum_bandwidth * expected_utilization < bandwidth,
        "expected to reach {expected_utilization} of maximum bandwidth ({} Mbit/s) but got {} Mbit/s",
        maximum_bandwidth / MIB as f64,
        bandwidth  / MIB as f64,
    );
}
