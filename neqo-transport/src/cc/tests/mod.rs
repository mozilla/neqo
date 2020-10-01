// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

use crate::cc::cubic::{CUBIC_BETA_USIZE, CUBIC_DIV};
use crate::cc::new_reno_cubic::NewRenoCubic;
use crate::cc::{CongestionControl, CongestionControlAlgorithm, CWND_INITIAL, CWND_MIN};
use crate::packet::{PacketNumber, PacketType};
use crate::tracking::SentPacket;
use std::convert::TryFrom;
use std::rc::Rc;
use std::time::{Duration, Instant};
use test_fixture::now;

const PTO: Duration = Duration::from_millis(100);
const RTT: Duration = Duration::from_millis(98);
pub const CWND_INITIAL_DECREASE: usize = CWND_INITIAL * CUBIC_BETA_USIZE / CUBIC_DIV;

mod cubic;
mod new_reno;

fn lost(pn: PacketNumber, ack_eliciting: bool, t: Duration) -> SentPacket {
    SentPacket::new(
        PacketType::Short,
        pn,
        now() + t,
        ack_eliciting,
        Rc::default(),
        100,
    )
}

fn persistent_congestion(
    cc_version: &CongestionControlAlgorithm,
    lost_packets: &[SentPacket],
) -> bool {
    let mut cc = NewRenoCubic::new(cc_version);
    cc.start_pacer(now());
    for p in lost_packets {
        cc.on_packet_sent(p, RTT);
    }

    cc.on_packets_lost(now(), Some(now()), None, PTO, lost_packets);
    if cc.cwnd() == CWND_INITIAL / 2 {
        assert!(matches!(cc_version, CongestionControlAlgorithm::NewReno));
        false
    } else if cc.cwnd() == CWND_INITIAL_DECREASE {
        assert!(matches!(cc_version, CongestionControlAlgorithm::Cubic));
        false
    } else if cc.cwnd() == CWND_MIN {
        true
    } else {
        panic!("unexpected cwnd");
    }
}

/// Get a time, in multiples of `PTO`, relative to `now()`.
fn by_pto(t: u32) -> Instant {
    now() + (PTO * t)
}

/// Make packets that will be made lost.
/// `times` is the time of sending, in multiples of `PTO`, relative to `now()`.
fn make_lost(times: &[u32]) -> Vec<SentPacket> {
    times
        .iter()
        .enumerate()
        .map(|(i, &t)| {
            SentPacket::new(
                PacketType::Short,
                u64::try_from(i).unwrap(),
                by_pto(t),
                true,
                Rc::default(),
                1000,
            )
        })
        .collect::<Vec<_>>()
}

/// Call `detect_persistent_congestion_test` using times relative to now and the fixed PTO time.
/// `last_ack` and `rtt_time` are times in multiples of `PTO`, relative to `now()`,
/// for the time of the largest acknowledged and the first RTT sample, respectively.
fn persistent_congestion_by_pto(
    cc_version: &CongestionControlAlgorithm,
    last_ack: u32,
    rtt_time: u32,
    lost: &[SentPacket],
) -> bool {
    let mut cc = NewRenoCubic::new(cc_version);
    assert_eq!(cc.cwnd(), CWND_INITIAL);

    let last_ack = Some(by_pto(last_ack));
    let rtt_time = Some(by_pto(rtt_time));

    // Persistent congestion is never declared if the RTT time is `None`.
    cc.detect_persistent_congestion_test(None, None, PTO, lost);
    assert_eq!(cc.cwnd(), CWND_INITIAL);
    cc.detect_persistent_congestion_test(None, last_ack, PTO, lost);
    assert_eq!(cc.cwnd(), CWND_INITIAL);

    cc.detect_persistent_congestion_test(rtt_time, last_ack, PTO, lost);
    cc.cwnd() == CWND_MIN
}
