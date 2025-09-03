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
    f64,
    fmt::Display,
    ops::Sub,
    time::{Duration, Instant},
};

use neqo_common::qdebug;
use test_fixture::now;

use super::{IP_ADDR, MTU, RTT};
use crate::{
    cc::{
        classic_cc::ClassicCongestionControl,
        cubic::{
            convert_to_f64, Cubic, CUBIC_BETA_USIZE_DIVIDEND, CUBIC_BETA_USIZE_DIVISOR, CUBIC_C,
            CUBIC_FAST_CONVERGENCE_FACTOR,
        },
        CongestionControl as _,
    },
    packet,
    pmtud::Pmtud,
    recovery::{self, sent},
    rtt::RttEstimate,
};

const fn cwnd_after_loss(cwnd: usize) -> usize {
    cwnd * CUBIC_BETA_USIZE_DIVIDEND / CUBIC_BETA_USIZE_DIVISOR
}

const fn cwnd_after_loss_slow_start(cwnd: usize, mtu: usize) -> usize {
    (cwnd + mtu) * CUBIC_BETA_USIZE_DIVIDEND / CUBIC_BETA_USIZE_DIVISOR
}

fn fill_cwnd(cc: &mut ClassicCongestionControl<Cubic>, mut next_pn: u64, now: Instant) -> u64 {
    while cc.bytes_in_flight() < cc.cwnd() {
        let sent = sent::Packet::new(
            packet::Type::Short,
            next_pn,
            now,
            true,
            recovery::Tokens::new(),
            cc.max_datagram_size(),
        );
        cc.on_packet_sent(&sent, now);
        next_pn += 1;
    }
    next_pn
}

fn ack_packet(cc: &mut ClassicCongestionControl<Cubic>, pn: u64, now: Instant) {
    let acked = sent::Packet::new(
        packet::Type::Short,
        pn,
        now,
        true,
        recovery::Tokens::new(),
        cc.max_datagram_size(),
    );
    cc.on_packets_acked(&[acked], &RttEstimate::new(RTT), now);
}

fn packet_lost(cc: &mut ClassicCongestionControl<Cubic>, pn: u64) {
    const PTO: Duration = Duration::from_millis(120);
    let p_lost = sent::Packet::new(
        packet::Type::Short,
        pn,
        now(),
        true,
        recovery::Tokens::new(),
        cc.max_datagram_size(),
    );
    cc.on_packets_lost(None, None, PTO, &[p_lost], now());
}

fn expected_tcp_acks(cwnd_rtt_start: usize, mtu: usize, alpha: f64) -> u64 {
    (f64::from(i32::try_from(cwnd_rtt_start).unwrap())
        / f64::from(i32::try_from(mtu).unwrap())
        / alpha)
        .round() as u64
}

#[test]
fn tcp_phase() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));

    // change to congestion avoidance state.
    cubic.set_ssthresh(1);

    let mut now = now();
    // helper variables to remember the next packet number to be sent/acked.
    let mut next_pn_send = 0;
    let mut next_pn_ack = 0;

    next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);

    // This will start with TCP phase.
    // in this phase cwnd is increase by CUBIC_ALPHA every RTT. We can look at it as
    // increase of MAX_DATAGRAM_SIZE every 1 / CUBIC_ALPHA RTTs.
    // The phase will end when cwnd calculated with cubic equation is equal to TCP estimate:
    // CUBIC_C * (n * RTT / CUBIC_ALPHA)^3 * MAX_DATAGRAM_SIZE = n * MAX_DATAGRAM_SIZE
    // from this n = sqrt(CUBIC_ALPHA^3/ (CUBIC_C * RTT^3)).
    let num_tcp_increases = (cubic.cc_algorithm().alpha().powi(3)
        / (CUBIC_C * RTT.as_secs_f64().powi(3)))
    .sqrt()
    .floor() as u64;
    for _ in 0..num_tcp_increases {
        let cwnd_rtt_start = cubic.cwnd();
        // Expected acks during a period of RTT / CUBIC_ALPHA.
        let acks = expected_tcp_acks(
            cwnd_rtt_start,
            cubic.max_datagram_size(),
            cubic.cc_algorithm().alpha(),
        );
        // The time between acks if they are ideally paced over a RTT.
        let time_increase =
            RTT / u32::try_from(cwnd_rtt_start / cubic.max_datagram_size()).unwrap();

        for _ in 0..acks {
            now += time_increase;
            ack_packet(&mut cubic, next_pn_ack, now);
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
        ack_packet(&mut cubic, next_pn_ack, now);
        next_pn_ack += 1;
        next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);
    }

    // Make sure that the increase is not according to TCP equation, i.e., that it took
    // less than RTT / CUBIC_ALPHA.
    let expected_ack_tcp_increase = expected_tcp_acks(
        cwnd_rtt_start,
        cubic.max_datagram_size(),
        cubic.cc_algorithm().alpha(),
    );

    assert!(
        num_acks < expected_ack_tcp_increase,
        "num_acks: {num_acks}, expected_ack_tcp_increase: {expected_ack_tcp_increase}",
    );
}

#[test]
fn cubic_phase() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));
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
        / CUBIC_C
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
            ack_packet(&mut cubic, next_pn_ack, now);
            next_pn_ack += 1;
            next_pn_send = fill_cwnd(&mut cubic, next_pn_send, now);
        }

        let expected = (CUBIC_C * ((now - epoch_start).as_secs_f64() - k).powi(3))
            .mul_add(
                convert_to_f64(cubic.max_datagram_size()),
                cwnd_initial_f64 * 10.0,
            )
            .round() as usize;

        assert_within(cubic.cwnd(), expected, cubic.max_datagram_size());
    }
    assert_eq!(cubic.cwnd(), cubic.cwnd_initial() * 10);
}

fn assert_within<T: Sub<Output = T> + PartialOrd + Copy + Display>(
    value: T,
    expected: T,
    margin: T,
) {
    if value >= expected {
        assert!(
            value - expected < margin,
            "Expected: {expected}, Actual: {value}"
        );
    } else {
        assert!(
            expected - value < margin,
            "Expected: {expected}, Actual: {value}"
        );
    }
}

#[test]
fn congestion_event_slow_start() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));

    _ = fill_cwnd(&mut cubic, 0, now());
    ack_packet(&mut cubic, 0, now());

    assert_within(cubic.cc_algorithm().w_max(), 0.0, f64::EPSILON);

    // cwnd is increased by 1 in slow start phase, after an ack.
    assert_eq!(
        cubic.cwnd(),
        cubic.cwnd_initial() + cubic.max_datagram_size()
    );

    // Trigger a congestion_event in slow start phase
    packet_lost(&mut cubic, 1);

    // After congestion_event w_max is equal to the cwnd before the decrease.
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
}

#[test]
fn congestion_event_congestion_avoidance() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));

    // Set ssthresh to something small to make sure that cc is in the congection avoidance phase.
    cubic.set_ssthresh(1);

    // Set w_max to something smaller than cwnd so that the fast convergence is not
    // triggered.
    let max_datagram_size = cubic.max_datagram_size();
    cubic
        .cc_algorithm_mut()
        .set_w_max(3.0 * convert_to_f64(max_datagram_size));

    _ = fill_cwnd(&mut cubic, 0, now());
    ack_packet(&mut cubic, 0, now());

    assert_eq!(cubic.cwnd(), cubic.cwnd_initial());

    // Trigger a congestion_event in congestion avoidance
    packet_lost(&mut cubic, 1);

    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    assert_within(cubic.cc_algorithm().w_max(), cwnd_initial_f64, f64::EPSILON);
    assert_eq!(cubic.cwnd(), cwnd_after_loss(cubic.cwnd_initial()));
}

#[test]
fn congestion_event_congestion_avoidance_fast_convergence() {
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));

    // Set ssthresh to something small to make sure that cc is in the congection avoidance phase.
    cubic.set_ssthresh(1);

    // Set w_max to something higher than cwnd so that the fast convergence is triggered.
    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    cubic.cc_algorithm_mut().set_w_max(cwnd_initial_f64 * 10.0);

    _ = fill_cwnd(&mut cubic, 0, now());
    ack_packet(&mut cubic, 0, now());

    assert_within(
        cubic.cc_algorithm().w_max(),
        cwnd_initial_f64 * 10.0,
        f64::EPSILON,
    );
    assert_eq!(cubic.cwnd(), cubic.cwnd_initial());

    // Trigger a congestion_event.
    packet_lost(&mut cubic, 1);

    assert_within(
        cubic.cc_algorithm().w_max(),
        cwnd_initial_f64 * CUBIC_FAST_CONVERGENCE_FACTOR,
        f64::EPSILON,
    );
    assert_eq!(cubic.cwnd(), cwnd_after_loss(cubic.cwnd_initial()));
}

#[test]
fn congestion_event_congestion_avoidance_no_overflow() {
    const PTO: Duration = Duration::from_millis(120);
    let mut cubic = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));

    // Set ssthresh to something small to make sure that cc is in the congection avoidance phase.
    cubic.set_ssthresh(1);

    // Set w_max to something higher than cwnd so that the fast convergence is triggered.
    let cwnd_initial_f64 = convert_to_f64(cubic.cwnd_initial());
    cubic.cc_algorithm_mut().set_w_max(cwnd_initial_f64 * 10.0);

    _ = fill_cwnd(&mut cubic, 0, now());
    ack_packet(&mut cubic, 1, now());

    assert_within(
        cubic.cc_algorithm().w_max(),
        cwnd_initial_f64 * 10.0,
        f64::EPSILON,
    );
    assert_eq!(cubic.cwnd(), cubic.cwnd_initial());

    // Now ack packet that was send earlier.
    ack_packet(&mut cubic, 0, now().checked_sub(PTO).unwrap());
}

/// This tests the dynamic changing of the `alpha` value outlined in RFC 9438 section 4.3.
///
/// <https://datatracker.ietf.org/doc/html/rfc9438#section-4.3-11>
#[test]
fn alpha_changes_for_high_w_est_values() {
    const NORMAL_ALPHA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7);
    const INCREASED_ALPHA: f64 = 1.0;
    let mut cc = ClassicCongestionControl::new(Cubic::default(), Pmtud::new(IP_ADDR, MTU));
    let mut next_pn_to_send = 0;
    let mut last_sent_pn;
    let mut first_sent_pn;

    // Set ssthresh to something small to make sure that cc is in the congection avoidance phase.
    cc.set_ssthresh(1);

    // Send 1*cwnd worth of packets and ack all but the last one
    next_pn_to_send = fill_cwnd(&mut cc, next_pn_to_send, now());
    last_sent_pn = next_pn_to_send - 1;
    for pn in 0..last_sent_pn {
        ack_packet(&mut cc, pn, now());
    }

    // Since we never had a congestion event we started with the initial values for `w_est =
    // cwnd_prior = current_cwnd`, thus `w_est >= cwnd_prior` should be `true` and `alpha` should be
    // set to it's increased value.
    assert!(cc.cc_algorithm().w_est() >= cc.cc_algorithm().cwnd_prior());
    assert_within(cc.cc_algorithm().alpha(), INCREASED_ALPHA, f64::EPSILON);

    // Trigger a congestion event, which eventually calls `reduce_cwnd`
    packet_lost(&mut cc, last_sent_pn);

    // Ack the lost packet to trigger another `on_packets_acked` and update `w_est` and `alpha`
    // in `start_epoch`
    ack_packet(&mut cc, last_sent_pn, now());

    // Now `w_est` should be smaller than `cwnd_prior`, thus `alpha` should have it's normal value.
    assert!(cc.cc_algorithm().w_est() < cc.cc_algorithm().cwnd_prior());
    assert_within(cc.cc_algorithm().alpha(), NORMAL_ALPHA, f64::EPSILON);

    // Send and ack packets until the congestion window grew so much that `w_est` is as big as
    // `cwnd_prior`.
    loop {
        qdebug!(
            "w_est: {} | cwnd_prior: {} | bytes_in_flight: {}",
            cc.cc_algorithm().w_est(),
            cc.cc_algorithm().cwnd_prior(),
            cc.bytes_in_flight()
        );
        first_sent_pn = next_pn_to_send;
        next_pn_to_send = fill_cwnd(&mut cc, next_pn_to_send, now());
        last_sent_pn = next_pn_to_send - 1;
        qdebug!("first: {first_sent_pn} | last: {last_sent_pn}");
        for pn in first_sent_pn..=last_sent_pn {
            ack_packet(&mut cc, pn, now());
            qdebug!("packet acked: {pn}");
        }
        if cc.cc_algorithm().w_est() >= cc.cc_algorithm().cwnd_prior() {
            break;
        }
    }

    // Now `w_est` should be as big as `cwnd_prior`, thus `alpha` should have it's increased value.
    assert!(cc.cc_algorithm().w_est() >= cc.cc_algorithm().cwnd_prior());
    assert_within(cc.cc_algorithm().alpha(), INCREASED_ALPHA, f64::EPSILON);
}
