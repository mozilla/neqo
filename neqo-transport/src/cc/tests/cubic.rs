// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

use super::{
    by_pto, lost, make_lost, persistent_congestion, persistent_congestion_by_pto,
    CWND_INITIAL_DECREASE, PTO, RTT,
};
use crate::cc::new_reno_cubic::{NewRenoCubic, PERSISTENT_CONG_THRESH};
use crate::cc::{CongestionControl, CongestionControlAlgorithm, CWND_INITIAL, CWND_MIN};
use crate::packet::PacketType;
use crate::tracking::SentPacket;
use std::rc::Rc;
use std::time::Duration;
use test_fixture::now;

const CC_VERSION: &CongestionControlAlgorithm = &CongestionControlAlgorithm::Cubic;

const ZERO: Duration = Duration::from_secs(0);
const EPSILON: Duration = Duration::from_nanos(1);
const GAP: Duration = Duration::from_secs(1);
/// The largest time between packets without causing persistent congestion.
const SUB_PC: Duration = Duration::from_millis(100 * PERSISTENT_CONG_THRESH as u64);
/// The minimum time between packets to cause persistent congestion.
/// Uses an odd expression because `Duration` arithmetic isn't `const`.
const PC: Duration = Duration::from_nanos(100_000_000 * (PERSISTENT_CONG_THRESH as u64) + 1);

#[test]
fn issue_876() {
    let mut cc = NewRenoCubic::new(&CC_VERSION);
    let time_now = now();
    let time_before = time_now - Duration::from_millis(100);
    let time_after1 = time_now + Duration::from_millis(100);
    let time_after2 = time_now + Duration::from_millis(150);
    let time_after3 = time_now + Duration::from_millis(175);

    cc.start_pacer(time_now);

    let sent_packets = vec![
        SentPacket::new(
            PacketType::Short,
            1,             // pn
            time_before,   // time sent
            true,          // ack eliciting
            Rc::default(), // tokens
            103,           // size
        ),
        SentPacket::new(
            PacketType::Short,
            2,             // pn
            time_before,   // time sent
            true,          // ack eliciting
            Rc::default(), // tokens
            105,           // size
        ),
        SentPacket::new(
            PacketType::Short,
            3,             // pn
            time_after2,   // time sent
            true,          // ack eliciting
            Rc::default(), // tokens
            107,           // size
        ),
    ];

    cc.on_packet_sent(&sent_packets[0], RTT);
    assert_eq!(cc.acked_bytes(), 0);
    assert_eq!(cc.cwnd(), CWND_INITIAL);
    assert_eq!(cc.ssthresh(), usize::MAX);
    assert_eq!(cc.bif(), 103);

    cc.on_packet_sent(&sent_packets[1], RTT);
    assert_eq!(cc.acked_bytes(), 0);
    assert_eq!(cc.cwnd(), CWND_INITIAL);
    assert_eq!(cc.ssthresh(), usize::MAX);
    assert_eq!(cc.bif(), 208);

    cc.on_packets_lost(time_after1, Some(time_now), None, PTO, &sent_packets[0..1]);

    // We are now in recovery
    assert_eq!(cc.acked_bytes(), 0);
    assert_eq!(cc.cwnd(), CWND_INITIAL_DECREASE);
    assert_eq!(cc.ssthresh(), CWND_INITIAL_DECREASE);
    assert_eq!(cc.bif(), 105);

    // Send a packet after recovery starts
    cc.on_packet_sent(&sent_packets[2], RTT);
    assert_eq!(cc.acked_bytes(), 0);
    assert_eq!(cc.cwnd(), CWND_INITIAL_DECREASE);
    assert_eq!(cc.ssthresh(), CWND_INITIAL_DECREASE);
    assert_eq!(cc.bif(), 212);

    // and ack it. cwnd increases slightly
    cc.on_packets_acked(&sent_packets[2..3], time_now, RTT);
    assert_eq!(cc.acked_bytes(), 0);
    assert!(cc.cwnd() > CWND_INITIAL_DECREASE);
    assert_eq!(cc.ssthresh(), CWND_INITIAL_DECREASE);
    assert_eq!(cc.bif(), 105);

    // Packet from before is lost. Should not hurt cwnd.
    cc.on_packets_lost(time_after3, Some(time_now), None, PTO, &sent_packets[1..2]);
    assert_eq!(cc.acked_bytes(), 0);
    assert!(cc.cwnd() > CWND_INITIAL_DECREASE);
    assert_eq!(cc.ssthresh(), CWND_INITIAL_DECREASE);
    assert_eq!(cc.bif(), 0);
}

/// A span of exactly the PC threshold only reduces the window on loss.
#[test]
fn persistent_congestion_none() {
    assert!(!persistent_congestion(
        CC_VERSION,
        &[lost(1, true, ZERO), lost(2, true, SUB_PC),]
    ));
}

/// A span of just more than the PC threshold causes persistent congestion.
#[test]
fn persistent_congestion_simple() {
    assert!(persistent_congestion(
        CC_VERSION,
        &[lost(1, true, ZERO), lost(2, true, PC),]
    ));
}

/// Both packets need to be ack-eliciting.
#[test]
fn persistent_congestion_non_ack_eliciting() {
    assert!(!persistent_congestion(
        CC_VERSION,
        &[lost(1, false, ZERO), lost(2, true, PC),]
    ));
    assert!(!persistent_congestion(
        CC_VERSION,
        &[lost(1, true, ZERO), lost(2, false, PC),]
    ));
}

/// Packets in the middle, of any type, are OK.
#[test]
fn persistent_congestion_middle() {
    assert!(persistent_congestion(
        CC_VERSION,
        &[lost(1, true, ZERO), lost(2, false, RTT), lost(3, true, PC),]
    ));
    assert!(persistent_congestion(
        CC_VERSION,
        &[lost(1, true, ZERO), lost(2, true, RTT), lost(3, true, PC),]
    ));
}

/// Leading non-ack-eliciting packets are skipped.
#[test]
fn persistent_congestion_leading_non_ack_eliciting() {
    assert!(!persistent_congestion(
        CC_VERSION,
        &[lost(1, false, ZERO), lost(2, true, RTT), lost(3, true, PC),]
    ));
    assert!(persistent_congestion(
        CC_VERSION,
        &[
            lost(1, false, ZERO),
            lost(2, true, RTT),
            lost(3, true, RTT + PC),
        ]
    ));
}

/// Trailing non-ack-eliciting packets aren't relevant.
#[test]
fn persistent_congestion_trailing_non_ack_eliciting() {
    assert!(persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, PC),
            lost(3, false, PC + EPSILON),
        ]
    ));
    assert!(!persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, SUB_PC),
            lost(3, false, PC),
        ]
    ));
}

/// Gaps in the middle, of any type, restart the count.
#[test]
fn persistent_congestion_gap_reset() {
    assert!(!persistent_congestion(
        CC_VERSION,
        &[lost(1, true, ZERO), lost(3, true, PC),]
    ));
    assert!(!persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, RTT),
            lost(4, true, GAP),
            lost(5, true, GAP + PTO * PERSISTENT_CONG_THRESH),
        ]
    ));
}

/// A span either side of a gap will cause persistent congestion.
#[test]
fn persistent_congestion_gap_or() {
    assert!(persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, PC),
            lost(4, true, GAP),
            lost(5, true, GAP + PTO),
        ]
    ));
    assert!(persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, PTO),
            lost(4, true, GAP),
            lost(5, true, GAP + PC),
        ]
    ));
}

/// A gap only restarts after an ack-eliciting packet.
#[test]
fn persistent_congestion_gap_non_ack_eliciting() {
    assert!(!persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, PTO),
            lost(4, false, GAP),
            lost(5, true, GAP + PC),
        ]
    ));
    assert!(!persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, PTO),
            lost(4, false, GAP),
            lost(5, true, GAP + RTT),
            lost(6, true, GAP + RTT + SUB_PC),
        ]
    ));
    assert!(persistent_congestion(
        CC_VERSION,
        &[
            lost(1, true, ZERO),
            lost(2, true, PTO),
            lost(4, false, GAP),
            lost(5, true, GAP + RTT),
            lost(6, true, GAP + RTT + PC),
        ]
    ));
}

/// No persistent congestion can be had if there are no lost packets.
#[test]
fn persistent_congestion_no_lost() {
    let lost = make_lost(&[]);
    assert!(!persistent_congestion_by_pto(CC_VERSION, 0, 0, &lost));
}

/// No persistent congestion can be had if there is only one lost packet.
#[test]
fn persistent_congestion_one_lost() {
    let lost = make_lost(&[1]);
    assert!(!persistent_congestion_by_pto(CC_VERSION, 0, 0, &lost));
}

/// Persistent congestion can't happen based on old packets.
#[test]
fn persistent_congestion_past() {
    // Packets sent prior to either the last acknowledged or the first RTT
    // sample are not considered.  So 0 is ignored.
    let lost = make_lost(&[0, PERSISTENT_CONG_THRESH + 1, PERSISTENT_CONG_THRESH + 2]);
    assert!(!persistent_congestion_by_pto(CC_VERSION, 1, 1, &lost));
    assert!(!persistent_congestion_by_pto(CC_VERSION, 0, 1, &lost));
    assert!(!persistent_congestion_by_pto(CC_VERSION, 1, 0, &lost));
}

/// Persistent congestion doesn't start unless the packet is ack-eliciting.
#[test]
fn persistent_congestion_ack_eliciting() {
    let mut lost = make_lost(&[1, PERSISTENT_CONG_THRESH + 2]);
    lost[0] = SentPacket::new(
        lost[0].pt,
        lost[0].pn,
        lost[0].time_sent,
        false,
        Rc::default(),
        lost[0].size,
    );
    assert!(!persistent_congestion_by_pto(CC_VERSION, 0, 0, &lost));
}

/// Detect persistent congestion.  Note that the first lost packet needs to have a time
/// greater than the previously acknowledged packet AND the first RTT sample.  And the
/// difference in times needs to be greater than the persistent congestion threshold.
#[test]
fn persistent_congestion_min() {
    let lost = make_lost(&[1, PERSISTENT_CONG_THRESH + 2]);
    assert!(persistent_congestion_by_pto(CC_VERSION, 0, 0, &lost));
}

/// Make sure that not having a previous largest acknowledged also results
/// in detecting persistent congestion.  (This is not expected to happen, but
/// the code permits it).
#[test]
fn persistent_congestion_no_prev_ack() {
    let lost = make_lost(&[1, PERSISTENT_CONG_THRESH + 2]);
    let mut cc = NewRenoCubic::new(&CC_VERSION);
    cc.detect_persistent_congestion_test(Some(by_pto(0)), None, PTO, &lost);
    assert_eq!(cc.cwnd(), CWND_MIN);
}

/// The code asserts on ordering errors.
#[test]
#[should_panic]
fn persistent_congestion_unsorted() {
    let lost = make_lost(&[PERSISTENT_CONG_THRESH + 2, 1]);
    assert!(!persistent_congestion_by_pto(CC_VERSION, 0, 0, &lost));
}
