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

use std::{
    env,
    time::{Duration, Instant},
};

use neqo_common::log::init as init_log;
use neqo_transport::{Connection, ConnectionEvent, ConnectionParameters, State};
use test_fixture::{
    boxed,
    sim::{
        GoalStatus, Simulator,
        connection::{Goal, Node, ReachState, ReceiveData, SendData},
        network::{Aqm, Mtu, TailDrop},
    },
};

/// `SendData` that, once all data is sent, asserts that ECN signalled congestion.
#[derive(Debug)]
struct SendDataWithEcn(SendData);

impl SendDataWithEcn {
    fn check(c: &Connection, status: GoalStatus) -> GoalStatus {
        if status == GoalStatus::Done {
            let events = c.stats().cc.congestion_events;
            assert!(events.ecn > 0, "no ECN congestion events: {events:?}");
        }
        status
    }
}

impl Goal for SendDataWithEcn {
    fn process(&mut self, c: &mut Connection, now: Instant) -> GoalStatus {
        let status = self.0.process(c, now);
        Self::check(c, status)
    }

    fn handle_event(
        &mut self,
        c: &mut Connection,
        e: &ConnectionEvent,
        now: Instant,
    ) -> GoalStatus {
        let status = self.0.handle_event(c, e, now);
        Self::check(c, status)
    }
}

/// Run a transfer of a gigabyte over a gigabit link.
/// Check to see that the achieved transfer rate matches expectations.
#[expect(clippy::cast_precision_loss, reason = "OK in a bench.")]
fn gbit_bandwidth(ecn: bool) {
    const MIB: usize = 1_024 * 1_024;
    const GIB: usize = 1_024 * MIB;

    const MBIT: usize = 1_000 * 1_000;
    const GBIT: usize = 1_000 * MBIT;

    const TRANSFER_AMOUNT: usize = GIB;
    const LINK_BANDWIDTH: usize = GBIT;
    const LINK_RTT_MS: u64 = 40;
    /// The amount of delay that the link buffer will add when full.
    const BUFFER_LATENCY_MS: usize = 4;
    /// The same with ECN: `CoDel` marks only once queueing delay has stayed above its 5 ms target
    /// for 100 ms, so a shallower buffer overflows first and the transfer sees losses, not marks.
    const ECN_BUFFER_LATENCY_MS: usize = 64;
    /// How much of the theoretical bandwidth we will expect to deliver, without and with ECN.
    /// The simulation is deterministic, so these sit just below what it achieves and a
    /// throughput regression fails.
    const MINIMUM_EXPECTED_UTILIZATION: f64 = 0.6;
    const MINIMUM_EXPECTED_UTILIZATION_ECN: f64 = 0.7;

    let send = SendData::new(TRANSFER_AMOUNT);
    let (suffix, aqm, buffer_ms, minimum, send_goal): (_, _, _, _, Box<dyn Goal>) = if ecn {
        (
            "ecn",
            Aqm::codel(),
            ECN_BUFFER_LATENCY_MS,
            MINIMUM_EXPECTED_UTILIZATION_ECN,
            Box::new(SendDataWithEcn(send)),
        )
    } else {
        (
            "noecn",
            Aqm::None,
            BUFFER_LATENCY_MS,
            MINIMUM_EXPECTED_UTILIZATION,
            Box::new(send),
        )
    };

    let gbit_link = || {
        let rate_byte = LINK_BANDWIDTH / 8;
        let capacity_byte = (rate_byte / 1000) * buffer_ms;
        let delay = Duration::from_millis(LINK_RTT_MS) / 2;
        TailDrop::new(rate_byte, capacity_byte, aqm.clone(), delay)
    };

    init_log(None);

    let name = format!("gbit-bandwidth-{suffix}");
    let simulated_time = Simulator::new(
        &name,
        boxed![
            Node::new_client(
                ConnectionParameters::default().ack_ratio(200),
                boxed![ReachState::new(State::Confirmed)],
                boxed![ReceiveData::new(TRANSFER_AMOUNT)]
            ),
            Mtu::new(1500),
            gbit_link(),
            Node::new_server(
                ConnectionParameters::default().ack_ratio(200),
                boxed![ReachState::new(State::Confirmed)],
                [send_goal]
            ),
            Mtu::new(1500),
            gbit_link(),
        ],
    )
    .setup()
    .run();

    let achieved_bandwidth = TRANSFER_AMOUNT as f64 * 8.0 / simulated_time.as_secs_f64();
    eprintln!(
        // Not `info!`: `--features bench` drops that level. Stderr keeps it out of `results.txt`.
        "{name} achieved {a} Mb/s bandwidth (link rate {t})",
        a = achieved_bandwidth / MBIT as f64,
        t = LINK_BANDWIDTH / MBIT
    );

    assert!(
        LINK_BANDWIDTH as f64 * minimum < achieved_bandwidth,
        "{name} expected to reach {minimum} of maximum bandwidth ({t} Mbit/s) but got {a} Mbit/s",
        t = LINK_BANDWIDTH / MBIT,
        a = achieved_bandwidth / MBIT as f64,
    );
}

fn main() {
    // `harness = false`, so answer criterion's enumeration instead of running the simulations.
    if env::args().any(|a| a == "--list") {
        return;
    }
    gbit_bandwidth(false);
    gbit_bandwidth(true);
}
