// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! HyStart++ (RFC 9406) test suite

use std::time::Duration;

use neqo_common::qdebug;
use test_fixture::now;

use super::make_cc_hystart;
use crate::{
    cc::{CongestionControl as _, classic_cc::SlowStart as _, hystart::HyStart},
    recovery::sent,
    rtt::RttEstimate,
    stats::CongestionControlStats,
};

const SMSS: usize = 1200;

/// Helper to create a HyStart instance with pacing enabled (L=infinity).
fn make_hystart_paced() -> HyStart {
    HyStart::new(true)
}

/// Helper to create a HyStart instance with pacing disabled (L=8).
fn make_hystart_unpaced() -> HyStart {
    HyStart::new(false)
}

/// Helper to set up HyStart state through two rounds with the given RTT values.
/// Can be used to test CSS entry (when `new_rtt` triggers it) or non-entry (when it doesn't).
fn maybe_enter_css(hystart: &mut HyStart, base_rtt: Duration, new_rtt: Duration) {
    // First round with base RTT
    let window_end = HyStart::N_RTT_SAMPLE as u64;
    hystart.on_packet_sent(window_end);

    assert!(hystart.window_end().is_some_and(|pn| pn == window_end));

    // Collect N_RTT_SAMPLE samples with base RTT and end first round
    for i in 0..=window_end {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(base_rtt),
            SMSS,
            i,
        );
    }

    assert!(hystart.window_end().is_none());

    // Second round with new RTT value
    let window_end2 = 2 * HyStart::N_RTT_SAMPLE as u64;
    hystart.on_packet_sent(window_end2);

    assert!(hystart.window_end().is_some_and(|pn| pn == window_end2));

    // Collect N_RTT_SAMPLE samples with new RTT and end second round
    for i in window_end + 1..=window_end2 {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(new_rtt),
            SMSS,
            i,
        );
    }

    assert!(hystart.window_end().is_none());
}

/// Tests that rounds are started and finished correctly and that `window_end` is set accordingly.
#[test]
fn round_tracking_lifecycle() {
    let mut hystart = make_hystart_paced();

    // Before any packet is sent, window_end should be None
    assert!(hystart.window_end().is_none());

    // Start a round with window_end = 10
    let window_end = 10;
    hystart.on_packet_sent(window_end);
    assert_eq!(
        hystart.window_end(),
        Some(window_end),
        "First send should start round with window_end"
    );

    // Send more packets - window_end should not change during the round
    hystart.on_packet_sent(11);
    hystart.on_packet_sent(12);
    assert_eq!(
        hystart.window_end(),
        Some(window_end),
        "window_end should not change during round"
    );

    // Ack packets less than window_end - round should continue
    for pn in 0..(window_end - 1) {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(Duration::from_millis(100)),
            SMSS,
            pn, // All < window_end
        );
        assert_eq!(
            hystart.window_end(),
            Some(window_end),
            "Round should continue while largest_acked < window_end"
        );
    }

    // Now ack window_end - this should end the round
    hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        SMSS,
        &RttEstimate::new(Duration::from_millis(100)),
        SMSS,
        window_end, // largest_acked=window_end, round ends
    );
    assert!(
        hystart.window_end().is_none(),
        "Round should end when largest_acked >= window_end"
    );

    // Start new round
    let window_end2 = 100;
    hystart.on_packet_sent(window_end2);
    assert_eq!(
        hystart.window_end(),
        Some(window_end2),
        "New round should start with new window_end"
    );
}

/// Tests that `current_round_min_rtt` is tracked correctly when packets are acked.
#[test]
fn rtt_sample_collection_tracks_minimum() {
    const BASE_RTT: Duration = Duration::from_millis(100);
    const HIGH_RTT: Duration = Duration::from_millis(120);
    const LOW_RTT: Duration = Duration::from_millis(80);
    let mut hystart = make_hystart_paced();

    hystart.on_packet_sent(0);

    // First ACK with RTT of 100ms
    hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        SMSS,
        &RttEstimate::new(BASE_RTT),
        SMSS,
        0,
    );
    assert_eq!(hystart.rtt_sample_count(), 1);
    assert_eq!(
        hystart.current_round_min_rtt(),
        BASE_RTT,
        "First sample should set the minimum"
    );

    // Second ACK with RTT of 80ms (lower) - should update minimum
    hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        SMSS,
        &RttEstimate::new(LOW_RTT),
        SMSS,
        1,
    );
    assert_eq!(hystart.rtt_sample_count(), 2);
    assert_eq!(
        hystart.current_round_min_rtt(),
        LOW_RTT,
        "Lower RTT should update the minimum"
    );

    // Third ACK with RTT of 120ms (higher) - should NOT update minimum
    hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        SMSS,
        &RttEstimate::new(HIGH_RTT),
        SMSS,
        2,
    );
    assert_eq!(hystart.rtt_sample_count(), 3);
    assert_eq!(
        hystart.current_round_min_rtt(),
        LOW_RTT,
        "Higher RTT should not update the minimum"
    );
}

#[test]
#[expect(
    clippy::cast_possible_truncation,
    reason = "No truncation will happen for values from 1 to 10."
)]
fn rtt_sample_count_increments_per_ack() {
    let mut hystart = make_hystart_paced();
    hystart.on_packet_sent(0);

    assert_eq!(hystart.rtt_sample_count(), 0);

    for i in 0..10 {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(Duration::from_millis(100)),
            SMSS,
            i,
        );
        assert_eq!(hystart.rtt_sample_count(), (i + 1) as usize);
    }
}

#[test]
fn css_entry_not_triggered_with_insufficient_samples() {
    let mut hystart = make_hystart_paced();

    // First round to set baseline RTT
    let window_end1 = (HyStart::N_RTT_SAMPLE) as u64;
    hystart.on_packet_sent(window_end1);

    for i in 0..=window_end1 {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(Duration::from_millis(100)),
            SMSS,
            i,
        );
    }

    // Second round with increased RTT but insufficient samples
    let window_end2 = window_end1 + HyStart::N_RTT_SAMPLE as u64;
    hystart.on_packet_sent(window_end2);

    // Collect only N_RTT_SAMPLE - 1 samples, not enough to enter CSS with
    for i in (window_end1 + 1)..window_end2 {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(Duration::from_millis(120)),
            SMSS,
            i,
        );
    }

    assert!(
        !hystart.in_css(),
        "CSS should not be entered with insufficient samples"
    );
}

#[test]
fn css_entry_triggered_on_rtt_increase() {
    let mut hystart = make_hystart_paced();

    // Use helper to set up two rounds with RTT increase
    // rtt_thresh = max(4ms, min(100ms / 8, 16ms)) = max(4ms, min(12.5ms, 16ms)) = 12.5ms
    // Since 120ms >= 100ms + 12.5ms, CSS should be entered
    maybe_enter_css(
        &mut hystart,
        Duration::from_millis(100),
        Duration::from_millis(120),
    );

    assert!(hystart.in_css(), "CSS should be entered on RTT increase");
}

#[test]
fn css_entry_not_triggered_on_small_rtt_increase() {
    let mut hystart = make_hystart_paced();

    // Use helper with small RTT increase that's below threshold
    // rtt_thresh = 12.5ms, but increase is only 5ms
    maybe_enter_css(
        &mut hystart,
        Duration::from_millis(100),
        Duration::from_millis(105),
    );

    assert!(
        !hystart.in_css(),
        "CSS should not be entered on small RTT increase"
    );
}

#[test]
fn css_entry_triggered_on_min_rtt_thresh() {
    let mut hystart = make_hystart_paced();

    // Test MIN_RTT_THRESH bound: very small base RTT
    // rtt_thresh = max(MIN_RTT_THRESH, min(10ms / 8, MAX_RTT_THRESH))
    //            = max(4ms, 1.25ms) = 4ms
    // 15ms >= 10ms + 4ms, so CSS should be entered
    maybe_enter_css(
        &mut hystart,
        Duration::from_millis(10),
        Duration::from_millis(15),
    );

    assert!(
        hystart.in_css(),
        "CSS should be entered with MIN_RTT_THRESH"
    );
}

#[test]
fn css_entry_triggered_on_max_rtt_thresh() {
    let mut hystart = make_hystart_paced();

    // Test MAX_RTT_THRESH bound: large base RTT
    // rtt_thresh = max(MIN_RTT_THRESH, min(200ms / 8, MAX_RTT_THRESH))
    //            = max(4ms, min(25ms, 16ms)) = 16ms
    // 218ms >= 200ms + 16ms, so CSS should be entered
    maybe_enter_css(
        &mut hystart,
        Duration::from_millis(200),
        Duration::from_millis(218),
    );

    assert!(
        hystart.in_css(),
        "CSS should be entered with MAX_RTT_THRESH"
    );
}

#[test]
fn css_growth_rate_is_one_quarter() {
    const NEW_ACKED: usize = 4 * SMSS;
    let mut hystart = make_hystart_paced();

    maybe_enter_css(
        &mut hystart,
        Duration::from_millis(100),
        Duration::from_millis(120),
    );
    assert!(hystart.in_css(), "Should have entered CSS");

    let result = hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        NEW_ACKED,
        &RttEstimate::new(Duration::from_millis(120)),
        SMSS,
        10,
    );

    // In CSS, growth is divided by CSS_GROWTH_DIVISOR
    assert_eq!(
        result.cwnd_increase,
        NEW_ACKED / HyStart::CSS_GROWTH_DIVISOR,
        "CSS growth should be 1/{} of new_acked",
        HyStart::CSS_GROWTH_DIVISOR
    );
}

#[test]
fn css_exit_after_n_rounds() {
    let mut hystart = make_hystart_paced();
    maybe_enter_css(
        &mut hystart,
        Duration::from_millis(100),
        Duration::from_millis(120),
    );
    assert!(hystart.in_css(), "Should have entered CSS");
    assert_eq!(hystart.css_round_count(), 1);

    // Note: maybe_enter_css already completed a partial round in CSS (count = 1) so we start with
    // round 2.
    for round in 2..=HyStart::CSS_ROUNDS {
        // Start a new round
        let new_window_end = round as u64 * 100;
        hystart.on_packet_sent(new_window_end);

        // Collect samples
        for i in 0..HyStart::N_RTT_SAMPLE {
            hystart.on_packets_acked(
                10 * SMSS,
                usize::MAX,
                SMSS,
                &RttEstimate::new(Duration::from_millis(120)),
                SMSS,
                i as u64,
            );
        }

        // End round by acking window_end
        let result = hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(Duration::from_millis(120)),
            SMSS,
            new_window_end,
        );

        if round < HyStart::CSS_ROUNDS {
            assert!(
                !result.exit_slow_start,
                "Should not exit before {} rounds completed but exited after round {round}",
                HyStart::CSS_ROUNDS,
            );
            assert!(hystart.in_css(), "Should still be in CSS");
        } else {
            assert!(
                result.exit_slow_start,
                "Should exit after {} rounds have completed",
                HyStart::CSS_ROUNDS
            );
        }
    }
}

#[test]
fn css_back_to_slow_start_on_rtt_decrease() {
    const CSS_BASELINE_RTT: Duration = Duration::from_millis(120);
    const LOWER_RTT: Duration = Duration::from_millis(110);
    let mut hystart = make_hystart_paced();
    maybe_enter_css(&mut hystart, Duration::from_millis(100), CSS_BASELINE_RTT);
    assert!(hystart.in_css(), "Should have entered CSS");

    // Start a new round in CSS
    let new_window_end = 300;
    hystart.on_packet_sent(new_window_end);

    // RTT decreases below baseline - should exit CSS
    for i in 0..HyStart::N_RTT_SAMPLE {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(LOWER_RTT),
            SMSS,
            i as u64, // Less than window_end
        );
    }

    assert!(
        !hystart.in_css(),
        "Should exit CSS when RTT decreases below baseline"
    );
    assert_eq!(
        hystart.css_round_count(),
        0,
        "CSS round count should be reset"
    );
}

#[test]
fn css_exit_to_slow_start_restores_normal_growth() {
    const CSS_BASELINE_RTT: Duration = Duration::from_millis(120);
    const LOWER_RTT: Duration = Duration::from_millis(110);
    const NEW_ACKED: usize = 4 * SMSS;
    let mut hystart = make_hystart_paced();
    maybe_enter_css(&mut hystart, Duration::from_millis(100), CSS_BASELINE_RTT);
    assert!(hystart.in_css(), "Should have entered CSS");

    // Test CSS growth (1/CSS_GROWTH_DIVISOR rate)
    let css_result = hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        NEW_ACKED,
        &RttEstimate::new(CSS_BASELINE_RTT),
        SMSS,
        10,
    );
    assert_eq!(
        css_result.cwnd_increase,
        NEW_ACKED / HyStart::CSS_GROWTH_DIVISOR,
        "CSS growth should be 1/{}",
        HyStart::CSS_GROWTH_DIVISOR
    );

    // Start new round with lower RTT
    let new_window_end = 400;
    hystart.on_packet_sent(new_window_end);
    for i in 0..HyStart::N_RTT_SAMPLE {
        hystart.on_packets_acked(
            10 * SMSS,
            usize::MAX,
            SMSS,
            &RttEstimate::new(LOWER_RTT),
            SMSS,
            i as u64, // Less than window_end
        );
    }

    assert!(!hystart.in_css(), "Should have exited CSS");

    // Test normal slow start growth (1:1 rate)
    let ss_result = hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        NEW_ACKED,
        &RttEstimate::new(LOWER_RTT),
        SMSS,
        30,
    );
    assert_eq!(
        ss_result.cwnd_increase, NEW_ACKED,
        "Normal SS growth should be 1:1"
    );
}

#[test]
fn l_limit_paced_no_cap() {
    let mut hystart = make_hystart_paced(); // L = infinity
    hystart.on_packet_sent(0);

    // Try to increase by more than NON_PACED_L * SMSS
    let result = hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        100 * SMSS,
        &RttEstimate::new(Duration::from_millis(100)),
        SMSS,
        0,
    );

    assert_eq!(result.cwnd_increase, 100 * SMSS, "Paced should have no cap");
}

#[test]
fn l_limit_unpaced_is_capped() {
    let mut hystart = make_hystart_unpaced(); // L = NON_PACED_L
    hystart.on_packet_sent(0);

    // Try to increase by more than NON_PACED_L * SMSS
    let result = hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX,
        100 * SMSS,
        &RttEstimate::new(Duration::from_millis(100)),
        SMSS,
        0,
    );

    assert_eq!(
        result.cwnd_increase,
        HyStart::NON_PACED_L * SMSS,
        "Unpaced should cap at L * SMSS"
    );
}

#[test]
fn hystart_only_used_in_initial_slow_start() {
    let mut hystart = make_hystart_paced();

    // In initial slow start (ssthresh = usize::MAX), HyStart++ is active
    hystart.on_packet_sent(0);

    let _result1 = hystart.on_packets_acked(
        10 * SMSS,
        usize::MAX, // ssthresh is default
        SMSS,
        &RttEstimate::new(Duration::from_millis(100)),
        SMSS,
        0,
    );

    // HyStart++ should be collecting samples
    assert_eq!(hystart.rtt_sample_count(), 1);

    // Now with ssthresh != usize::MAX, should fall back to classic
    let _result2 = hystart.on_packets_acked(
        10 * SMSS,
        20 * SMSS, // ssthresh set
        SMSS,
        &RttEstimate::new(Duration::from_millis(100)),
        SMSS,
        1,
    );

    // Should be using classic slow start, so HyStart++ should not be collecting new samples
    assert_eq!(hystart.rtt_sample_count(), 1);

    // Classic slow start with ssthresh set: exit when reaching ssthresh
    let result3 = hystart.on_packets_acked(
        19 * SMSS,
        20 * SMSS,
        2 * SMSS,
        &RttEstimate::new(Duration::from_millis(100)),
        SMSS,
        2,
    );

    // Should cap at ssthresh
    assert_eq!(result3.cwnd_increase, SMSS, "Should cap at ssthresh");
    assert!(
        result3.exit_slow_start,
        "Should exit when reaching ssthresh"
    );
}

/// Integration test that is run through a `ClassicCongestionControl` instance and moves through the
/// full slowstart -> CSS -> congestion avoidance lifetime while continuously ACK'ing and sending
/// packets.
#[test]
fn integration_full_slow_start_to_css_to_ca() {
    let mut cc = make_cc_hystart(true);
    let mut stats = CongestionControlStats::default();
    let mut now = now();

    let base_rtt = Duration::from_millis(100);
    let increased_rtt = Duration::from_millis(120);
    let base_rtt_est = RttEstimate::new(base_rtt);
    let increased_rtt_est = RttEstimate::new(increased_rtt);

    assert_eq!(cc.ssthresh(), usize::MAX, "Should start in slow start");

    let mut next_send: u64 = 0;
    let mut next_ack: u64 = 0;
    let mut css_detected = false;
    let mut ca_detected = false;

    // Send initial cwnd worth of packets.
    let initial_cwnd_packets = cc.cwnd() / SMSS;
    for _ in 0..initial_cwnd_packets {
        let pkt = sent::make_packet(next_send, now, SMSS);
        cc.on_packet_sent(&pkt, now);
        next_send += 1;
    }

    // Wait 1 `base_rtt` for first ACK to arrive.
    now += base_rtt;

    // Continuous send/ACK alternation:
    // ACK'ing packet 0 ends round 1, next send starts round 2 and so on.
    let max_iterations = 1000; // Enough for multiple CSS rounds and CA entry
    for iteration in 0..max_iterations {
        // ACK the next packet
        let ack_pn = next_ack;

        // Have `base_rtt` for the first cwnd that was sent before the loop. Have `increased_rtt`
        // for all subsequent packets to trigger and go through CSS.
        let rtt_to_use = if ack_pn < initial_cwnd_packets as u64 {
            base_rtt
        } else {
            increased_rtt
        };
        let rtt_est = if ack_pn < initial_cwnd_packets as u64 {
            &base_rtt_est
        } else {
            &increased_rtt_est
        };

        let pkt = sent::make_packet(ack_pn, now.checked_sub(rtt_to_use).unwrap(), SMSS);
        let cwnd_before = cc.cwnd();
        let ssthresh_before = cc.ssthresh();
        cc.on_packets_acked(&[pkt], rtt_est, now, &mut stats);
        let cwnd_after = cc.cwnd();
        let ssthresh_after = cc.ssthresh();
        let growth = cwnd_after - cwnd_before;
        next_ack += 1;

        // Detect CSS: growth becomes 1/4
        if growth > 0 && growth == SMSS / HyStart::CSS_GROWTH_DIVISOR && !css_detected {
            css_detected = true;
            qdebug!("CSS entered at ack_pn={ack_pn}, iteration={iteration}");
        }

        // Detect CA: ssthresh has been set
        if ssthresh_before == usize::MAX && ssthresh_after != usize::MAX {
            ca_detected = true;
            qdebug!("CA entered at ack_pn={ack_pn}, iteration={iteration}");
            // This assert makes sure that the ACK that we decided to move to CA on does not apply
            // exponential growth from slow start/CSS anymore.
            assert!(
                growth < SMSS / HyStart::CSS_GROWTH_DIVISOR,
                "We should be using CA growth once we detected exit to CA."
            );
            break;
        }

        // As the cwnd grows during the loop above we cannot keep alternating ACK'ing and sending
        // just one packet. This sends more packets until the cwnd is full so we don't become
        // app-limited.
        while cc.bytes_in_flight() < cc.cwnd() {
            let send_pn = next_send;
            let pkt = sent::make_packet(send_pn, now, SMSS);
            cc.on_packet_sent(&pkt, now);
            next_send += 1;
        }

        // Advance time by a small increment to simulate continuous operation.
        now += increased_rtt / 10;
    }

    assert!(css_detected, "Should have entered CSS");
    assert!(ca_detected, "Should have entered CA after CSS rounds");
    assert_eq!(cc.ssthresh(), cc.cwnd(), "ssthresh should be set in CA");
}
