// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "OK in tests."
)]

use std::{
    ops::Sub,
    time::{Duration, Instant},
};

use test_fixture::now;

use super::{IP_ADDR, MTU, RTT};
use crate::{
    cc::{
        classic_cc::ClassicCongestionControl,
        cubic::{convert_to_f64, Cubic},
        CongestionControl as _, CongestionEvent,
    },
    pmtud::Pmtud,
    recovery::sent,
    rtt::RttEstimate,
    stats::CongestionControlStats,
};

const fn cwnd_after_loss(cwnd: usize) -> usize {
    cwnd * Cubic::BETA_USIZE_DIVIDEND / Cubic::BETA_USIZE_DIVISOR
}

const fn cwnd_after_loss_slow_start(cwnd: usize, mtu: usize) -> usize {
    (cwnd + mtu) * Cubic::BETA_USIZE_DIVIDEND / Cubic::BETA_USIZE_DIVISOR
}

/// Sets up a Cubic congestion controller in congestion avoidance phase.
///
/// If `fast_convergence` is true, sets `w_max` higher than cwnd to trigger fast convergence.
/// If false, sets `w_max` lower than cwnd to prevent fast convergence.
fn setup_congestion_avoidance(
    fast_convergence: bool,
) -> (ClassicCongestionControl<Cubic>, CongestionControlStats) {
    let mut cc = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));
    let mut cc_stats = CongestionControlStats::default();
    // Enter congestion avoidance phase.
    cc.set_ssthresh(1);
    // Configure fast convergence behavior.
    let cwnd_f64 = convert_to_f64(cc.cwnd_initial());
    let w_max = if fast_convergence {
        cwnd_f64 * 10.0
    } else {
        convert_to_f64(cc.max_datagram_size()) * 3.0
    };
    cc.cc_algorithm_mut().set_w_max(w_max);
    // Fill cwnd and ack one packet to establish baseline.
    _ = fill_cwnd(&mut cc, 0, now());
    ack_packet(&mut cc, 0, now(), &mut cc_stats);
    (cc, cc_stats)
}

fn fill_cwnd(cc: &mut ClassicCongestionControl<Cubic>, mut next_pn: u64, now: Instant) -> u64 {
    while cc.bytes_in_flight() < cc.cwnd() {
        let sent = sent::make_packet(next_pn, now, cc.max_datagram_size());
        cc.on_packet_sent(&sent, now);
        next_pn += 1;
    }
    next_pn
}

fn ack_packet(
    cc: &mut ClassicCongestionControl<Cubic>,
    pn: u64,
    now: Instant,
    cc_stats: &mut CongestionControlStats,
) {
    let acked = sent::make_packet(pn, now, cc.max_datagram_size());
    cc.on_packets_acked(&[acked], &RttEstimate::new(RTT), now, cc_stats);
}

fn packet_lost(
    cc: &mut ClassicCongestionControl<Cubic>,
    pn: u64,
    cc_stats: &mut CongestionControlStats,
) {
    const PTO: Duration = Duration::from_millis(120);
    let now = now();
    let p_lost = sent::make_packet(pn, now, cc.max_datagram_size());
    cc.on_packets_lost(None, None, PTO, &[p_lost], now, cc_stats);
}

fn ecn_ce(
    cc: &mut ClassicCongestionControl<Cubic>,
    pn: u64,
    now: Instant,
    cc_stats: &mut CongestionControlStats,
) {
    let pkt = sent::make_packet(pn, now, cc.max_datagram_size());
    cc.on_ecn_ce_received(&pkt, now, cc_stats);
}

fn expected_tcp_acks(cwnd_rtt_start: usize, mtu: usize) -> u64 {
    (f64::from(i32::try_from(cwnd_rtt_start).unwrap())
        / f64::from(i32::try_from(mtu).unwrap())
        / Cubic::ALPHA)
        .round() as u64
}

#[test]
fn tcp_phase() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));
    let mut cc_stats = CongestionControlStats::default();

    // change to congestion avoidance state.
    cubic.set_ssthresh(1);

    let mut now = now();
    let start_time = now;
    // helper variables to remember the next packet number to be sent/acked.
    let mut next_pn_send = 0;
    let mut next_pn_ack = 0;

    next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);

    // This will start with TCP phase.
    // in this phase cwnd is increase by CUBIC_ALPHA every RTT. We can look at it as
    // increase of MAX_DATAGRAM_SIZE every 1 / CUBIC_ALPHA RTTs.
    // The phase will end when cwnd calculated with cubic equation is equal to TCP estimate:
    // Cubic::C * (n * RTT / Cubic::ALPHA)^3 * MAX_DATAGRAM_SIZE = n * MAX_DATAGRAM_SIZE
    // from this n = sqrt(Cubic::ALPHA^3/ (Cubic::C * RTT^3)).
    let num_tcp_increases = (Cubic::ALPHA.powi(3) / (Cubic::C * RTT.as_secs_f64().powi(3)))
        .sqrt()
        .floor() as u64;

    for _ in 0..num_tcp_increases {
        let cwnd_rtt_start = cubic.cwnd();
        // Expected acks during a period of RTT / Cubic::ALPHA.
        let acks = expected_tcp_acks(cwnd_rtt_start, cubic.max_datagram_size());
        // The time between acks if they are ideally paced over a RTT.
        let time_increase =
            RTT / u32::try_from(cwnd_rtt_start / cubic.max_datagram_size()).unwrap();

        for _ in 0..acks {
            now += time_increase;
            ack_packet(&mut cubic, next_pn_ack, now, &mut cc_stats);
            next_pn_ack += 1;
            next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);
        }

        assert_eq!(cubic.cwnd() - cwnd_rtt_start, cubic.max_datagram_size());
    }

    // The next increase will be according to the cubic equation.

    let cwnd_rtt_start = cubic.cwnd();
    // cwnd_rtt_start has change, therefore calculate new time_increase (the time
    // between acks if they are ideally paced over a RTT).
    let time_increase = RTT / u32::try_from(cwnd_rtt_start / cubic.max_datagram_size()).unwrap();
    let mut num_acks = 0; // count the number of acks. until cwnd is increased by cubic.max_datagram_size().

    while cwnd_rtt_start == cubic.cwnd() {
        num_acks += 1;
        now += time_increase;
        ack_packet(&mut cubic, next_pn_ack, now, &mut cc_stats);
        next_pn_ack += 1;
        next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);
    }

    // Make sure that the increase is not according to TCP equation, i.e., that it took
    // less than RTT / Cubic::ALPHA.
    let expected_ack_tcp_increase = expected_tcp_acks(cwnd_rtt_start, cubic.max_datagram_size());
    assert!(num_acks < expected_ack_tcp_increase);

    // This first increase after a TCP phase may be shorter than what it would take by a regular
    // cubic phase, because of the proper byte counting and the credit it already had before
    // entering this phase. Therefore We will perform another round and compare it to expected
    // increase using the cubic equation.

    let cwnd_rtt_start_after_tcp = cubic.cwnd();
    let elapsed_time = now - start_time;

    // calculate new time_increase.
    let time_increase =
        RTT / u32::try_from(cwnd_rtt_start_after_tcp / cubic.max_datagram_size()).unwrap();
    let mut num_acks2 = 0; // count the number of acks. until cwnd is increased by MAX_DATAGRAM_SIZE.

    while cwnd_rtt_start_after_tcp == cubic.cwnd() {
        num_acks2 += 1;
        now += time_increase;
        ack_packet(&mut cubic, next_pn_ack, now, &mut cc_stats);
        next_pn_ack += 1;
        next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);
    }

    let expected_ack_tcp_increase2 =
        expected_tcp_acks(cwnd_rtt_start_after_tcp, cubic.max_datagram_size());
    assert!(num_acks2 < expected_ack_tcp_increase2);

    // The time needed to increase cwnd by MAX_DATAGRAM_SIZE using the cubic equation will be
    // calculated from: W_cubic(elapsed_time + t_to_increase) - W_cubic(elapsed_time) =
    // MAX_DATAGRAM_SIZE => Cubic::C * (elapsed_time + t_to_increase)^3 * MAX_DATAGRAM_SIZE +
    // CWND_INITIAL - Cubic::C * elapsed_time^3 * MAX_DATAGRAM_SIZE + CWND_INITIAL =
    // MAX_DATAGRAM_SIZE => t_to_increase = cbrt((1 + Cubic::C * elapsed_time^3) / Cubic::C) -
    // elapsed_time (t_to_increase is in seconds)
    // number of ack needed is t_to_increase / time_increase.
    let expected_ack_cubic_increase =
        (((Cubic::C.mul_add((elapsed_time).as_secs_f64().powi(3), 1.0) / Cubic::C).cbrt()
            - elapsed_time.as_secs_f64())
            / time_increase.as_secs_f64())
        .ceil() as u64;
    // num_acks is very close to the calculated value. The exact value is hard to calculate
    // because the proportional increase (i.e. curr_cwnd_f64 / (target - curr_cwnd_f64) *
    // MAX_DATAGRAM_SIZE_F64) and the byte counting.
    assert_eq!(num_acks2, expected_ack_cubic_increase + 2);
}

#[test]
fn cubic_phase() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));
    let mut cc_stats = CongestionControlStats::default();
    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    // Set w_max to a higher number make sure that cc is the cubic phase (cwnd is calculated
    // by the cubic equation).
    cubic.cc_algorithm_mut().set_w_max(cwnd_initial_f64 * 10.0);
    // Set ssthresh to something small to make sure that cc is in the congection avoidance phase.
    cubic.set_ssthresh(1);
    let mut now = now();
    let mut next_pn_send = 0;
    let mut next_pn_ack = 0;

    next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);

    let k = (cwnd_initial_f64.mul_add(10.0, -cwnd_initial_f64)
        / Cubic::C
        / convert_to_f64(cubic.max_datagram_size()))
    .cbrt();
    let epoch_start = now;

    // The number of RTT until W_max is reached.
    let num_rtts_w_max = (k / RTT.as_secs_f64()).round() as u64;
    for _ in 0..num_rtts_w_max {
        let cwnd_rtt_start = cubic.cwnd();
        // Expected acks
        let acks = cwnd_rtt_start / cubic.max_datagram_size();
        let time_increase = RTT / u32::try_from(acks).unwrap();
        for _ in 0..acks {
            now += time_increase;
            ack_packet(&mut cubic, next_pn_ack, now, &mut cc_stats);
            next_pn_ack += 1;
            next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);
        }

        let expected = (Cubic::C * ((now - epoch_start).as_secs_f64() - k).powi(3))
            .mul_add(
                convert_to_f64(cubic.max_datagram_size()),
                cwnd_initial_f64 * 10.0,
            )
            .round() as usize;

        assert_within(cubic.cwnd(), expected, cubic.max_datagram_size());
    }
    assert_eq!(cubic.cwnd(), cubic.cwnd_initial() * 10);
}

fn assert_within<T: Sub<Output = T> + PartialOrd + Copy>(value: T, expected: T, margin: T) {
    if value >= expected {
        assert!(value - expected < margin);
    } else {
        assert!(expected - value < margin);
    }
}

#[test]
fn congestion_event_slow_start() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));
    let mut cc_stats = CongestionControlStats::default();

    _ = fill_cwnd(&mut cubic, 0, now());
    ack_packet(&mut cubic, 0, now(), &mut cc_stats);

    assert_within(cubic.cc_algorithm().w_max(), 0.0, f64::EPSILON);

    // cwnd is increased by 1 in slow start phase, after an ack.
    assert_eq!(
        cubic.cwnd(),
        cubic.cwnd_initial() + cubic.max_datagram_size()
    );

    // Trigger a congestion_event in slow start phase
    packet_lost(&mut cubic, 1, &mut cc_stats);

    // w_max is equal to cwnd before decrease.
    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    assert_within(
        cubic.cc_algorithm().w_max(),
        cwnd_initial_f64 + convert_to_f64(cubic.max_datagram_size()),
        f64::EPSILON,
    );
    assert_eq!(
        cubic.cwnd(),
        cwnd_after_loss_slow_start(cubic.cwnd_initial(), cubic.max_datagram_size())
    );
    assert_eq!(cc_stats.congestion_events[CongestionEvent::Loss], 1);
}

#[test]
fn congestion_event_congestion_avoidance() {
    let (mut cubic, mut cc_stats) = setup_congestion_avoidance(false);

    assert_eq!(cubic.cwnd(), cubic.cwnd_initial());

    // Trigger a congestion_event in congestion avoidance phase.
    packet_lost(&mut cubic, 1, &mut cc_stats);

    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    assert_within(cubic.cc_algorithm().w_max(), cwnd_initial_f64, f64::EPSILON);
    assert_eq!(cubic.cwnd(), cwnd_after_loss(cubic.cwnd_initial()));
    assert_eq!(cc_stats.congestion_events[CongestionEvent::Loss], 1);
}

/// Verify that `acked_bytes` is correctly reduced on a congestion event.
fn acked_bytes_reduced_on_congestion_event(
    trigger: impl FnOnce(&mut ClassicCongestionControl<Cubic>, Instant, &mut CongestionControlStats),
    beta: usize,
) {
    let (mut cubic, mut cc_stats) = setup_congestion_avoidance(false);

    // The helper acked packet 0. Ack one more to accumulate acked_bytes.
    let now = now() + RTT / 10;
    _ = fill_cwnd(&mut cubic, 10, now);
    ack_packet(&mut cubic, 1, now, &mut cc_stats);

    // Verify cwnd hasn't increased (so acked_bytes wasn't reset).
    assert_eq!(cubic.cwnd(), cubic.cwnd_initial());

    let acked_bytes_before = cubic.acked_bytes();
    assert!(acked_bytes_before > 0);

    // Trigger the congestion event.
    trigger(&mut cubic, now, &mut cc_stats);

    // Verify acked_bytes was reduced by the correct factor.
    let expected = acked_bytes_before * beta / Cubic::BETA_USIZE_DIVISOR;
    assert_eq!(cubic.acked_bytes(), expected);
}

#[test]
fn acked_bytes_reduced_on_loss() {
    acked_bytes_reduced_on_congestion_event(
        |cc, _, stats| packet_lost(cc, 2, stats),
        Cubic::BETA_USIZE_DIVIDEND,
    );
}

#[test]
fn acked_bytes_reduced_on_ecn_ce() {
    acked_bytes_reduced_on_congestion_event(
        |cc, now, stats| ecn_ce(cc, 2, now, stats),
        Cubic::BETA_USIZE_DIVIDEND_ECN,
    );
}

#[test]
fn congestion_event_congestion_avoidance_fast_convergence() {
    let (mut cubic, mut cc_stats) = setup_congestion_avoidance(true);

    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    assert_within(
        cubic.cc_algorithm().w_max(),
        cwnd_initial_f64 * 10.0,
        f64::EPSILON,
    );
    assert_eq!(cubic.cwnd(), cubic.cwnd_initial());

    // Trigger a congestion_event.
    packet_lost(&mut cubic, 1, &mut cc_stats);

    assert_within(
        cubic.cc_algorithm().w_max(),
        cwnd_initial_f64 * Cubic::FAST_CONVERGENCE_FACTOR,
        f64::EPSILON,
    );
    assert_eq!(cubic.cwnd(), cwnd_after_loss(cubic.cwnd_initial()));
    assert_eq!(cc_stats.congestion_events[CongestionEvent::Loss], 1);
}

#[test]
fn congestion_event_congestion_avoidance_no_overflow() {
    const PTO: Duration = Duration::from_millis(120);
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));
    let mut cc_stats = CongestionControlStats::default();

    // Set ssthresh to something small to make sure that cc is in the congection avoidance phase.
    cubic.set_ssthresh(1);

    // Set w_max to something higher than cwnd so that the fast convergence is triggered.
    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    cubic.cc_algorithm_mut().set_w_max(cwnd_initial_f64 * 10.0);

    _ = fill_cwnd(&mut cubic, 0, now());
    ack_packet(&mut cubic, 1, now(), &mut cc_stats);

    assert_within(
        cubic.cc_algorithm().w_max(),
        cwnd_initial_f64 * 10.0,
        f64::EPSILON,
    );
    assert_eq!(cubic.cwnd(), cubic.cwnd_initial());

    // Now ack packet that was send earlier.
    ack_packet(
        &mut cubic,
        0,
        now().checked_sub(PTO).unwrap(),
        &mut cc_stats,
    );
}
