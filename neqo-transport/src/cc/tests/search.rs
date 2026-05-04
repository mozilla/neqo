// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Slow start Exit At Right CHokepoint (SEARCH) test suite

use std::time::{Duration, Instant};

use test_fixture::now;

use crate::{
    MIN_INITIAL_PACKET_SIZE,
    cc::{CongestionControlStats, Search, classic_cc::SlowStart as _, tests::INITIAL_CWND},
    rtt::RttEstimate,
};

const INITIAL_RTT: Duration = Duration::from_millis(100);
const HIGH_RTT: Duration = Duration::from_millis(200);

/// Helper to create and initialize a SEARCH instance. Internally asserts that all fields are
/// correctly initialized.
///
/// Returns the initialized SEARCH instance, the value that `bin_duration` was initialized to and
/// the current simulated time.
fn init_search(initial_rtt: Duration) -> (Search, Duration, Instant) {
    let mut search = Search::new();
    let mut now = now();
    let rtt_est = RttEstimate::new(initial_rtt);

    search.on_packet_sent(0, MIN_INITIAL_PACKET_SIZE);
    now += initial_rtt;
    search.on_packets_acked(
        &rtt_est,
        0,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    // `bin_duration = initial_rtt * WINDOW_SIZE_FACTOR / W` with a scale factor of 100.
    let bin_duration = initial_rtt * 350 / 100 / 10;

    assert_eq!(search.bin_duration(), bin_duration);
    assert_eq!(search.bin_end(), Some(now + bin_duration));
    assert_eq!(search.acked_bin(0), MIN_INITIAL_PACKET_SIZE);
    assert_eq!(search.sent_bin(0), MIN_INITIAL_PACKET_SIZE);
    assert_eq!(search.curr_idx(), Some(0));

    (search, bin_duration, now)
}

#[test]
fn initialize_on_first_ack_only() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);

    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);
    now += HIGH_RTT;
    search.on_packets_acked(
        &RttEstimate::new(HIGH_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    assert_eq!(
        search.bin_duration(),
        bin_duration,
        "bin_duration is initialized during first ACK and should not be reset by the new RTT"
    );
    assert_ne!(
        search.curr_idx(),
        Some(0),
        "curr_idx has progressed and wasn't reset to 0 by the second ACK"
    );
}

#[test]
#[should_panic(
    expected = "bin_duration must be non-zero for correctness and to guard against div by zero -- initial_rtt was zero or too small"
)]
fn initialization_with_zero_rtt() {
    init_search(Duration::ZERO);
}

#[test]
fn update_bins_after_bin_end_passed() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);

    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);
    now += bin_duration;
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    assert_eq!(
        search.curr_idx(),
        Some(0),
        "now == bin_end, shouldn't update bins"
    );

    search.on_packet_sent(2, MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        2,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now + Duration::from_nanos(1),
    );

    assert_eq!(
        search.curr_idx(),
        Some(1),
        "now == bin_end + 1ns, bins should be updated"
    );
    assert_eq!(
        search.bin_end(),
        Some(now + bin_duration),
        "Should've advanced bin_end to the next bin"
    );
    assert_eq!(search.acked_bin(1), 3 * MIN_INITIAL_PACKET_SIZE);
    assert_eq!(search.sent_bin(1), 3 * MIN_INITIAL_PACKET_SIZE);
}

#[test]
fn update_bins_skipped_bins_propagate_prev_value() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);

    let prev_acked = search.acked_bin(0);
    let prev_sent = search.sent_bin(0);

    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);

    // move time by more than 2 bins, i.e. skip one
    now += 2 * bin_duration + Duration::from_nanos(1);

    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    assert_eq!(search.curr_idx(), Some(2), "Should've skipped index 1");
    assert_eq!(
        search.acked_bin(1),
        prev_acked,
        "bin 1 should be propagated from the previous value"
    );
    assert_eq!(
        search.sent_bin(1),
        prev_sent,
        "bin 1 should be propagated from the previous value"
    );
    assert_eq!(search.acked_bin(2), 2 * MIN_INITIAL_PACKET_SIZE);
    assert_eq!(search.sent_bin(2), 2 * MIN_INITIAL_PACKET_SIZE);
}

#[test]
fn reset_and_reinitialize_on_too_many_skipped_bins() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);

    // Pass 10 bins, which is the W SEARCH parameter for how many bins are in a window,
    // which is used as the guard for resetting if passing more than that.
    now += 10 * bin_duration;
    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    assert!(
        search.curr_idx().is_some(),
        "passing one window of bins should not reset"
    );

    // Pass 11 bins, which is one bin more than the W SEARCH parameter for how many bins are in
    // a window.
    now += 11 * bin_duration;
    search.on_packet_sent(2, MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        2,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    assert!(
        search.curr_idx().is_none(),
        "passing more than one window of bins should reset"
    );

    search.on_packet_sent(3, MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(HIGH_RTT),
        3,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    let new_bin_duration = HIGH_RTT * 350 / 100 / 10;
    assert_eq!(
        search.curr_idx(),
        Some(0),
        "curr_idx should be re-initialized after next ACK"
    );
    assert_eq!(
        search.bin_duration(),
        new_bin_duration,
        "bin_duration should be re-initialized with the new RTT"
    );
}

#[test]
fn sent_and_acked_bytes_accumulate() {
    let (mut search, _, mut now) = init_search(INITIAL_RTT);

    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);
    search.on_packet_sent(2, MIN_INITIAL_PACKET_SIZE);
    search.on_packet_sent(3, MIN_INITIAL_PACKET_SIZE);

    // 10ms pass, not enough to reach bin_end
    now += Duration::from_millis(10);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );
    assert_eq!(search.curr_idx(), Some(0));

    // 10ms more pass, still not enough
    now += Duration::from_millis(10);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        2,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );
    assert_eq!(search.curr_idx(), Some(0));

    // another 20ms pass, now bins get updated
    now += Duration::from_millis(20);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        3,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        &mut CongestionControlStats::default(),
        now,
    );

    // Assert that the bins got updated and that the bytes from all sent and acked packets are
    // accounted for (1 each from init_search and 3 each from the code above)
    assert_eq!(search.curr_idx(), Some(1));
    assert_eq!(search.acked_bin(1), 4 * MIN_INITIAL_PACKET_SIZE);
    assert_eq!(search.sent_bin(1), 4 * MIN_INITIAL_PACKET_SIZE);
}

#[test]
fn search_exits_when_delivery_rate_slows_down() {
    let (mut search, _, mut now) = init_search(INITIAL_RTT);

    let mut bytes_this_round = INITIAL_CWND;
    let mut pn = 1;

    // With `rtt = 100ms` and `bin_duration = 35ms` we pass 2 bins per rtt. SEARCH checks start once
    // `curr_idx - passed_bins > W`. So with `W = 10` we need until `curr_idx = 12` for SEARCH
    // checks to run.
    while search.curr_idx() < Some(12) {
        search.on_packet_sent(pn, bytes_this_round);
        now += INITIAL_RTT;
        search.on_packets_acked(
            &RttEstimate::new(INITIAL_RTT),
            pn,
            bytes_this_round,
            bytes_this_round,
            &mut CongestionControlStats::default(),
            now,
        );
        pn += 1;
        // bytes double every round in slow start
        bytes_this_round *= 2;
    }

    // Now keep sending and ack-ing for a bit with warm-up done to confirm that SEARCH doesn't exit
    // if the delivery rate is steady.
    for _ in 1..=10 {
        search.on_packet_sent(pn, bytes_this_round);
        now += INITIAL_RTT;
        let result = search.on_packets_acked(
            &RttEstimate::new(INITIAL_RTT),
            pn,
            bytes_this_round,
            bytes_this_round,
            &mut CongestionControlStats::default(),
            now,
        );
        pn += 1;
        bytes_this_round *= 2;
        assert!(
            result.is_none(),
            "SEARCH should not exit if delivery rate is steady"
        );
    }

    // Finally keep sending but only ack a quarter of the bytes sent. Eventually SEARCH should
    // detect an exit based on the flattening delivery rate.
    for i in 1..=4 {
        search.on_packet_sent(pn, bytes_this_round);
        now += INITIAL_RTT;
        let result = search.on_packets_acked(
            &RttEstimate::new(INITIAL_RTT),
            pn,
            bytes_this_round / 4,
            bytes_this_round,
            &mut CongestionControlStats::default(),
            now,
        );
        if i == 4 {
            assert_eq!(
                result,
                Some(bytes_this_round),
                "Because of slowing delivery rate should have eventually exited Slow Start with current cwnd"
            );
            break;
        }
        pn += 1;
        bytes_this_round += bytes_this_round / 4;
    }
}
