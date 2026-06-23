// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control

#![expect(
    clippy::too_many_lines,
    reason = "A lot of multiline function calls due to formatting"
)]

use std::time::Duration;

use neqo_common::to_u64;
use test_fixture::now;

use super::{RTT, make_cc_newreno};
use crate::{
    cc::{
        ClassicCongestionController, ClassicSlowStart, CongestionController as _, new_reno::NewReno,
    },
    packet,
    recovery::{self, sent},
    rtt::RttEstimate,
    stats::CongestionControlStats,
};

const PTO: Duration = RTT;

fn cwnd_is_default(cc: &ClassicCongestionController<ClassicSlowStart, NewReno>) {
    assert_eq!(cc.cwnd(), cc.cwnd_initial());
    assert_eq!(cc.ssthresh(), None);
}

fn cwnd_is_halved(cc: &ClassicCongestionController<ClassicSlowStart, NewReno>) {
    assert_eq!(cc.cwnd(), cc.cwnd_initial() / 2);
    assert_eq!(cc.ssthresh(), Some(cc.cwnd_initial() / 2));
}

#[test]
fn issue_876() {
    let mut cc = make_cc_newreno();
    let mut cc_stats = CongestionControlStats::default();
    let now = now();
    let before = now.checked_sub(Duration::from_millis(100)).unwrap();
    let after = now + Duration::from_millis(150);

    let sent_packets = &[
        sent::Packet::new(
            packet::Type::Short,
            1,
            before,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size() - 1,
        ),
        sent::Packet::new(
            packet::Type::Short,
            2,
            before,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size() - 2,
        ),
        sent::Packet::new(
            packet::Type::Short,
            3,
            before,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size(),
        ),
        sent::Packet::new(
            packet::Type::Short,
            4,
            before,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size(),
        ),
        sent::Packet::new(
            packet::Type::Short,
            5,
            before,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size(),
        ),
        sent::Packet::new(
            packet::Type::Short,
            6,
            before,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size(),
        ),
        sent::Packet::new(
            packet::Type::Short,
            7,
            after,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size() - 3,
        ),
    ];

    // Send some more packets so that the cc is not app-limited.
    for p in &sent_packets[..6] {
        cc.on_packet_sent(p, now, false);
    }
    assert_eq!(cc.acked_bytes(), 0);
    cwnd_is_default(&cc);
    assert_eq!(cc.bytes_in_flight(), 6 * cc.max_datagram_size() - 3);

    cc.on_packets_lost(
        Some(now),
        None,
        PTO,
        &sent_packets[0..1],
        now,
        &mut cc_stats,
    );

    // We are now in recovery
    assert!(cc.recovery_packet());
    assert_eq!(cc.acked_bytes(), 0);
    cwnd_is_halved(&cc);
    assert_eq!(cc.bytes_in_flight(), 5 * cc.max_datagram_size() - 2);

    // Send a packet after recovery starts
    cc.on_packet_sent(&sent_packets[6], now, false);
    assert!(!cc.recovery_packet());
    cwnd_is_halved(&cc);
    assert_eq!(cc.acked_bytes(), 0);
    assert_eq!(cc.bytes_in_flight(), 6 * cc.max_datagram_size() - 5);

    // and ack it. cwnd increases slightly
    cc.on_packets_acked(
        &sent_packets[6..],
        &RttEstimate::new(crate::DEFAULT_INITIAL_RTT),
        now,
        &mut cc_stats,
    );
    assert_eq!(cc.acked_bytes(), sent_packets[6].len());
    cwnd_is_halved(&cc);
    assert_eq!(cc.bytes_in_flight(), 5 * cc.max_datagram_size() - 2);

    // Packet from before is lost. Should not hurt cwnd.
    cc.on_packets_lost(
        Some(now),
        None,
        PTO,
        &sent_packets[1..2],
        now,
        &mut cc_stats,
    );
    assert!(!cc.recovery_packet());
    assert_eq!(cc.acked_bytes(), sent_packets[6].len());
    cwnd_is_halved(&cc);
    assert_eq!(cc.bytes_in_flight(), 4 * cc.max_datagram_size());
}

#[test]
// https://github.com/mozilla/neqo/pull/1465
fn issue_1465() {
    let mut cc = make_cc_newreno();
    let mut cc_stats = CongestionControlStats::default();
    let mut pn = 0;
    let mut now = now();
    let max_datagram_size = cc.max_datagram_size();
    let mut next_packet = |now| {
        let p = sent::Packet::new(
            packet::Type::Short,
            pn,
            now,
            true,
            recovery::Tokens::new(),
            max_datagram_size,
        );
        pn += 1;
        p
    };
    let mut send_next = |cc: &mut ClassicCongestionController<ClassicSlowStart, NewReno>, now| {
        let p = next_packet(now);
        cc.on_packet_sent(&p, now, false);
        p
    };

    let p1 = send_next(&mut cc, now);
    let p2 = send_next(&mut cc, now);
    let p3 = send_next(&mut cc, now);

    assert_eq!(cc.acked_bytes(), 0);
    cwnd_is_default(&cc);
    assert_eq!(cc.bytes_in_flight(), 3 * cc.max_datagram_size());

    // advance one rtt to detect lost packet there this simplifies the timers, because
    // on_packet_loss would only be called after RTO, but that is not relevant to the problem
    now += RTT;
    cc.on_packets_lost(Some(now), None, PTO, &[p1], now, &mut cc_stats);

    // We are now in recovery
    assert!(cc.recovery_packet());
    assert_eq!(cc.acked_bytes(), 0);
    cwnd_is_halved(&cc);
    assert_eq!(cc.bytes_in_flight(), 2 * cc.max_datagram_size());

    // Don't reduce the cwnd again on second packet loss
    cc.on_packets_lost(Some(now), None, PTO, &[p3], now, &mut cc_stats);
    assert_eq!(cc.acked_bytes(), 0);
    cwnd_is_halved(&cc); // still the same as after first packet loss
    assert_eq!(cc.bytes_in_flight(), cc.max_datagram_size());

    // the acked packets before on_packet_sent were the cause of
    // https://github.com/mozilla/neqo/pull/1465
    cc.on_packets_acked(
        &[p2],
        &RttEstimate::new(crate::DEFAULT_INITIAL_RTT),
        now,
        &mut cc_stats,
    );

    assert_eq!(cc.bytes_in_flight(), 0);

    // send out recovery packet and get it acked to get out of recovery state
    let p4 = send_next(&mut cc, now);
    now += RTT;
    cc.on_packets_acked(
        &[p4],
        &RttEstimate::new(crate::DEFAULT_INITIAL_RTT),
        now,
        &mut cc_stats,
    );

    // do the same as in the first rtt but now the bug appears
    let p5 = send_next(&mut cc, now);
    let p6 = send_next(&mut cc, now);
    now += RTT;

    let cur_cwnd = cc.cwnd();
    cc.on_packets_lost(Some(now), None, PTO, &[p5], now, &mut cc_stats);

    // go back into recovery
    assert!(cc.recovery_packet());
    assert_eq!(cc.cwnd(), cur_cwnd / 2);
    assert_eq!(cc.acked_bytes(), 0);
    assert_eq!(cc.bytes_in_flight(), cc.max_datagram_size());

    // this shouldn't introduce further cwnd reduction, but it did before https://github.com/mozilla/neqo/pull/1465
    cc.on_packets_lost(Some(now), None, PTO, &[p6], now, &mut cc_stats);
    assert_eq!(cc.cwnd(), cur_cwnd / 2);
}

#[test]
fn new_reno_display() {
    assert_eq!(NewReno::default().to_string(), "NewReno");
}

#[test]
fn congestion_avoidance_no_two_mss_cap() {
    // Acking 3 * cwnd bytes in one on_packets_acked call should earn 3 MSS.
    let mut cc = make_cc_newreno();
    let mut cc_stats = CongestionControlStats::default();
    let now = now();
    let mtu = cc.max_datagram_size();

    // Force congestion avoidance: set ssthresh == cwnd.
    // For NewReno, bytes_for_cwnd_increase returns cwnd, so one MSS of cwnd
    // growth requires acknowledging a full cwnd worth of bytes.
    let cwnd0 = cc.cwnd();
    cc.set_ssthresh(cwnd0);

    // Send 3 * cwnd / mtu + 1 packets. The +1 makes new_acked a non-multiple of
    // cwnd so we can verify the carry (remainder) is preserved correctly.
    // BIF stays well above the app-limited threshold so is_app_limited is false.
    let n = 3 * (cwnd0 / mtu) + 1;
    let mut pkts = Vec::with_capacity(n);
    for pn in 0..n {
        let p = sent::make_packet(to_u64(pn), now, mtu);
        cc.on_packet_sent(&p, now, false);
        pkts.push(p);
    }

    // ACK all packets in one call: new_acked = 3 * cwnd + mtu.
    cc.on_packets_acked(&pkts, &RttEstimate::new(RTT), now + RTT, &mut cc_stats);

    // new_acked / bytes_for_increase = (3*cwnd0 + mtu) / cwnd0 = 3 increments,
    // remainder = mtu (one MTU of carry preserved for the next ACK).
    assert_eq!(cc.cwnd(), cwnd0 + 3 * mtu);
    assert_eq!(cc.acked_bytes(), mtu);
}
