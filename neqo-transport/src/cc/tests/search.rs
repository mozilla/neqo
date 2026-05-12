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
    cc::{
        CongestionControlStats, Outcome, Search, classic_cc::SlowStart as _, tests::INITIAL_CWND,
    },
    rtt::RttEstimate,
};

const INITIAL_RTT: Duration = Duration::from_millis(100);
const LOW_RTT: Duration = Duration::from_millis(80);
const HIGH_RTT: Duration = Duration::from_millis(200);
const POST_RESET_RTT: Duration = Duration::from_millis(150);

/// Helper to call both [`Search::record_acked_bytes`] and [`Search::on_packets_acked`].
fn ack(
    search: &mut Search,
    rtt_est: &RttEstimate,
    largest_acked: u64,
    new_acked_bytes: usize,
    curr_cwnd: usize,
    now: Instant,
) -> Option<usize> {
    search.record_acked_bytes(new_acked_bytes);
    search.on_packets_acked(
        rtt_est,
        largest_acked,
        curr_cwnd,
        &mut CongestionControlStats::default(),
        now,
    )
}

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
    ack(
        &mut search,
        &rtt_est,
        0,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
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
    ack(
        &mut search,
        &RttEstimate::new(HIGH_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
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
#[cfg(debug_assertions)]
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
    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        now,
    );

    assert_eq!(
        search.curr_idx(),
        Some(0),
        "now == bin_end, shouldn't update bins"
    );

    search.on_packet_sent(2, MIN_INITIAL_PACKET_SIZE);
    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        2,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
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

    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
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
    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
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
    let mut cc_stats = CongestionControlStats::default();
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        2,
        INITIAL_CWND,
        &mut cc_stats,
        now,
    );

    assert!(
        search.curr_idx().is_none(),
        "passing more than one window of bins should reset"
    );
    assert_eq!(cc_stats.search_reset.count, 1);
    assert_eq!(cc_stats.search_reset.max_passed_bins, Some(11));

    search.on_packet_sent(3, MIN_INITIAL_PACKET_SIZE);
    ack(
        &mut search,
        &RttEstimate::new(HIGH_RTT),
        3,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
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
    assert_eq!(
        search.bin_end(),
        Some(now + new_bin_duration),
        "bin_end should be re-initialized with the new RTT"
    );

    // Trigger a second reset with more skipped bins to verify max_passed_bins tracks the max.
    now += 15 * new_bin_duration;
    search.on_packet_sent(4, MIN_INITIAL_PACKET_SIZE);
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(HIGH_RTT),
        4,
        INITIAL_CWND,
        &mut cc_stats,
        now,
    );
    assert!(search.curr_idx().is_none());
    assert_eq!(cc_stats.search_reset.count, 2);
    assert_eq!(cc_stats.search_reset.max_passed_bins, Some(15));
}

#[test]
fn sent_and_acked_bytes_accumulate() {
    let (mut search, _, mut now) = init_search(INITIAL_RTT);

    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);
    search.on_packet_sent(2, MIN_INITIAL_PACKET_SIZE);
    search.on_packet_sent(3, MIN_INITIAL_PACKET_SIZE);

    // 10ms pass, not enough to reach bin_end
    now += Duration::from_millis(10);
    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        now,
    );
    assert_eq!(search.curr_idx(), Some(0));

    // 10ms more pass, still not enough
    now += Duration::from_millis(10);
    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        2,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        now,
    );
    assert_eq!(search.curr_idx(), Some(0));

    // another 20ms pass, now bins get updated
    now += Duration::from_millis(20);
    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        3,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        now,
    );

    // Assert that the bins got updated and that the bytes from all sent and acked packets are
    // accounted for (1 each from init_search and 3 each from the code above)
    assert_eq!(search.curr_idx(), Some(1));
    assert_eq!(search.acked_bin(1), 4 * MIN_INITIAL_PACKET_SIZE);
    assert_eq!(search.sent_bin(1), 4 * MIN_INITIAL_PACKET_SIZE);
}

#[test]
fn prev_idx_and_fraction_calculation() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);

    // Progress time so we have some space to look back for the test's sake.
    now += bin_duration * 5;
    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);
    ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        1,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        now,
    );
    let curr_idx = search.curr_idx().unwrap();
    let (prev_idx, fraction) = search.calc_prev_idx_test(INITIAL_RTT, curr_idx);

    // With `rtt = 100ms` and `bin_duration = 35ms` we have passed `100 / 35 = 2.857` bins. Since
    // the value is floored we should get `prev_idx = curr_idx - 2` and `fraction = 85`.
    assert_eq!(
        prev_idx,
        curr_idx - 2,
        "prev_idx should be `curr_idx - 2` and curr_idx is {curr_idx}"
    );
    assert_eq!(fraction, 85);
}

#[test]
fn sent_and_acked_byte_computation() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);

    // Send and ack some packets to fill the bins. We advance one bin boundary per loop, so this
    // will give us exactly `previous_bin + 1000` bytes in each new bin for both sent and acked
    // bins.
    for pn in 0..20 {
        search.on_packet_sent(pn, 1000);
        now += bin_duration + Duration::from_nanos(1);
        ack(
            &mut search,
            &RttEstimate::new(INITIAL_RTT),
            pn,
            1000,
            INITIAL_CWND,
            now,
        );
    }

    let curr_idx = search.curr_idx().unwrap();
    let (prev_idx, fraction) = search.calc_prev_idx_test(INITIAL_RTT, curr_idx);

    let sent_bytes = search.compute_sent_test(prev_idx - 10, prev_idx, fraction);
    let delv_bytes = search.compute_delv_test(curr_idx - 10, curr_idx);

    // We looked back exactly 10 bins and each bin grew by 1000 bytes, so the results for both
    // `sent_bytes` and `delv_bytes` should be `10 * 1000 = 10_000`.
    assert!(
        sent_bytes == delv_bytes && delv_bytes == 10_000,
        "Should have `sent_bytes == delv_bytes == 10_000` and got `sent_bytes = {sent_bytes}` and `delv_bytes = {delv_bytes}`"
    );
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
        ack(
            &mut search,
            &RttEstimate::new(INITIAL_RTT),
            pn,
            bytes_this_round,
            bytes_this_round,
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
        let result = ack(
            &mut search,
            &RttEstimate::new(INITIAL_RTT),
            pn,
            bytes_this_round,
            bytes_this_round,
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
    search.on_packet_sent(pn, bytes_this_round);
    now += INITIAL_RTT;
    let result = ack(
        &mut search,
        &RttEstimate::new(INITIAL_RTT),
        pn,
        bytes_this_round / 4,
        bytes_this_round,
        now,
    );
    assert_eq!(
        result, None,
        "SEARCH doesn't immediately exit when delivery slows down"
    );
    pn += 1;
    bytes_this_round += bytes_this_round / 4;

    // Pass a persistent `cc_stats` to `on_packets_acked` to verify stats are recorded on exit.
    let mut cc_stats = CongestionControlStats::default();
    search.on_packet_sent(pn, bytes_this_round);
    now += INITIAL_RTT;
    search.record_acked_bytes(bytes_this_round / 4);
    let result = search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        pn,
        bytes_this_round,
        &mut cc_stats,
        now,
    );
    assert_eq!(
        result,
        Some(bytes_this_round),
        "Once slow down is not just intermittent SEARCH exits"
    );
    assert!(cc_stats.search_empty_buffer_target.is_some());
    assert!(cc_stats.search_full_buffer_target.is_some());
}

#[test]
fn inflated_rtt_is_guarded() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);
    let rtt_est = RttEstimate::new(INITIAL_RTT);
    let mut pn = 1;

    // Advance to curr_idx >= 28 so that with 600ms RTT:
    //   bins_last_rtt = 600ms / 35ms = 17, so prev_idx = curr_idx - 17
    //   prev_idx = 28 - 17 = 11 > W(10) --> first guard passes
    //   curr_idx - prev_idx = 17 >= EXTRA_BINS(15) --> second guard fires
    while search.curr_idx() < Some(28) {
        search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
        now += bin_duration + Duration::from_nanos(1);
        ack(
            &mut search,
            &rtt_est,
            pn,
            MIN_INITIAL_PACKET_SIZE,
            INITIAL_CWND,
            now,
        );
        pn += 1;
    }

    let curr_idx = search.curr_idx().unwrap();
    let high_rtt = Duration::from_millis(600);
    assert_eq!(
        search.evaluate_test(high_rtt, curr_idx, INITIAL_CWND),
        Outcome::RttInflated(17),
    );

    // Verify the stat is recorded through the full on_packets_acked path.
    let mut cc_stats = CongestionControlStats::default();
    search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
    now += bin_duration + Duration::from_nanos(1);
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(high_rtt),
        pn,
        INITIAL_CWND,
        &mut cc_stats,
        now,
    );
    assert_eq!(cc_stats.search_lookback_bins_needed, Some(17));

    // A lower RTT that still triggers RttInflated should not overwrite the max.
    // curr_idx is now 29. With 525ms RTT: bins_last_rtt = floor(525/35) = 15,
    // prev_idx = 29 - 15 = 14 > W(10), curr_idx - prev_idx = 15 >= EXTRA_BINS(15) → RttInflated.
    pn += 1;
    let lower_rtt = Duration::from_millis(525);
    search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
    now += bin_duration + Duration::from_nanos(1);
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(lower_rtt),
        pn,
        INITIAL_CWND,
        &mut cc_stats,
        now,
    );
    assert_eq!(cc_stats.search_lookback_bins_needed, Some(17));
}

#[test]
fn no_sent_bytes() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);
    let rtt_est = RttEstimate::new(INITIAL_RTT);
    let mut pn = 1;

    // After init_search, never call on_packet_sent again. All subsequent bins are
    // stamped with the same cumulative sent_bytes value, making compute_sent return 0.
    // Advance to curr_idx >= 13 so prev_idx = curr_idx - 2 > W(10).
    while search.curr_idx() < Some(13) {
        now += bin_duration + Duration::from_nanos(1);
        ack(&mut search, &rtt_est, pn, 0, INITIAL_CWND, now);
        pn += 1;
    }

    let curr_idx = search.curr_idx().unwrap();
    assert_eq!(
        search.evaluate_test(INITIAL_RTT, curr_idx, INITIAL_CWND),
        Outcome::ZeroSent,
    );

    // Verify the stat is recorded through the full on_packets_acked path.
    let mut cc_stats = CongestionControlStats::default();
    now += bin_duration + Duration::from_nanos(1);
    search.record_acked_bytes(0);
    search.on_packets_acked(&rtt_est, pn, INITIAL_CWND, &mut cc_stats, now);
    assert_eq!(cc_stats.search_zero_sent_bytes, 1);
}

#[test]
fn warming_up() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);
    let rtt_est = RttEstimate::new(INITIAL_RTT);
    let mut pn = 1;

    // Advance to curr_idx = 12, the exact WarmingUp boundary.
    // bins_last_rtt = 100ms / 35ms = 2, so prev_idx = 12 - 2 = 10 = W(10).
    // Guard is prev_idx <= W, so this is the last index that returns WarmingUp.
    while search.curr_idx() < Some(12) {
        search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
        now += bin_duration + Duration::from_nanos(1);
        ack(
            &mut search,
            &rtt_est,
            pn,
            MIN_INITIAL_PACKET_SIZE,
            INITIAL_CWND,
            now,
        );
        pn += 1;
    }

    let curr_idx = search.curr_idx().unwrap();
    assert_eq!(
        search.evaluate_test(INITIAL_RTT, curr_idx, INITIAL_CWND),
        Outcome::WarmingUp,
    );

    // One more bin crosses the boundary: prev_idx = 13 - 2 = 11 > W(10).
    search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
    now += bin_duration + Duration::from_nanos(1);
    ack(
        &mut search,
        &rtt_est,
        pn,
        MIN_INITIAL_PACKET_SIZE,
        INITIAL_CWND,
        now,
    );

    let curr_idx = search.curr_idx().unwrap();
    // Now the SEARCH checks should run.
    assert_eq!(
        search.evaluate_test(INITIAL_RTT, curr_idx, INITIAL_CWND),
        Outcome::Continue(0),
    );
}

#[test]
fn continue_when_delivery_rate_steady() {
    let (mut search, bin_duration, mut now) = init_search(INITIAL_RTT);
    let rtt_est = RttEstimate::new(INITIAL_RTT);
    let mut pn = 1;

    // Advance past warm-up boundary with equal send/ack each bin.
    // With W = 10 and bin_duration = 100ms / 35ms = 2 we need to advance to curr_idx = 12.
    while search.curr_idx() < Some(13) {
        search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
        now += bin_duration + Duration::from_nanos(1);
        ack(
            &mut search,
            &rtt_est,
            pn,
            MIN_INITIAL_PACKET_SIZE,
            INITIAL_CWND,
            now,
        );
        pn += 1;
    }

    // Keep going for 10 more bins with steady delivery rate, asserting
    // Continue each time.
    for _ in 0..10 {
        search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
        now += bin_duration + Duration::from_nanos(1);
        ack(
            &mut search,
            &rtt_est,
            pn,
            MIN_INITIAL_PACKET_SIZE,
            INITIAL_CWND,
            now,
        );
        pn += 1;

        let curr_idx = search.curr_idx().unwrap();
        assert_eq!(
            search.evaluate_test(INITIAL_RTT, curr_idx, INITIAL_CWND),
            Outcome::Continue(0),
        );
    }

    // Verify the stat is recorded and tracks the running max.
    // Ack less than sent to create a non-zero norm_diff.
    let mut cc_stats = CongestionControlStats::default();
    search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
    now += bin_duration + Duration::from_nanos(1);
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE / 4);
    search.on_packets_acked(&rtt_est, pn, INITIAL_CWND, &mut cc_stats, now);
    let max = cc_stats.search_max_norm_diff;
    assert!(max > Some(0));

    // A subsequent steady round should not overwrite the max.
    pn += 1;
    search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
    now += bin_duration + Duration::from_nanos(1);
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(&rtt_est, pn, INITIAL_CWND, &mut cc_stats, now);
    assert_eq!(cc_stats.search_max_norm_diff, max);
}

#[test]
fn first_and_second_rtt_stats() {
    use crate::cc::classic_cc::SlowStart as _;

    let mut search = Search::new();
    let mut now = now();
    let mut cc_stats = CongestionControlStats::default();

    assert!(cc_stats.search_first_rtt.is_none());
    assert!(cc_stats.search_second_rtt.is_none());

    search.on_packet_sent(0, MIN_INITIAL_PACKET_SIZE);
    now += INITIAL_RTT;
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(INITIAL_RTT),
        0,
        INITIAL_CWND,
        &mut cc_stats,
        now,
    );

    assert_eq!(cc_stats.search_first_rtt, Some(INITIAL_RTT));
    assert!(cc_stats.search_second_rtt.is_none());

    search.on_packet_sent(1, MIN_INITIAL_PACKET_SIZE);
    now += LOW_RTT;
    search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
    search.on_packets_acked(
        &RttEstimate::new(LOW_RTT),
        1,
        INITIAL_CWND,
        &mut cc_stats,
        now,
    );

    assert_eq!(cc_stats.search_first_rtt, Some(INITIAL_RTT));
    assert_eq!(cc_stats.search_second_rtt, Some(LOW_RTT));

    // After a reset, two subsequent ACKs with a distinct RTT must not overwrite either recorded
    // value.
    search.reset();

    for pn in 2..=3 {
        search.on_packet_sent(pn, MIN_INITIAL_PACKET_SIZE);
        now += POST_RESET_RTT;
        search.record_acked_bytes(MIN_INITIAL_PACKET_SIZE);
        search.on_packets_acked(
            &RttEstimate::new(POST_RESET_RTT),
            pn,
            INITIAL_CWND,
            &mut cc_stats,
            now,
        );
    }

    // Assert that the recorded RTTs remain unchanged after the reset.
    assert_eq!(cc_stats.search_first_rtt, Some(INITIAL_RTT));
    assert_eq!(cc_stats.search_second_rtt, Some(LOW_RTT));
}
