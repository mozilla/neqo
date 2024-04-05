// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use enum_map::{enum_map, Enum};
use neqo_common::{qdebug, qinfo, qwarn, Datagram, IpTos, IpTosEcn};
use test_fixture::{
    assertions::{assert_v4_path, assert_v6_path},
    fixture_init, now, DEFAULT_ADDR_V4,
};

use super::{connect_rtt_idle_with_modifier, send_something_with_modifier, DatagramModifier};
use crate::{
    connection::tests::{
        connect_force_idle, connect_force_idle_with_modifier, default_client, default_server,
        migration::get_cid, new_client, new_server, send_something,
    },
    ecn::ECN_TEST_COUNT,
    ConnectionId, ConnectionParameters, StreamType,
};

const RTT: Duration = Duration::from_millis(20);

fn assert_ecn_enabled(tos: IpTos) {
    assert_eq!(IpTosEcn::from(tos), IpTosEcn::Ect0);
}

fn assert_ecn_disabled(tos: IpTos) {
    assert_eq!(IpTosEcn::from(tos), IpTosEcn::default());
}

fn connect_and_send_something_with_modifier(mut modifier: impl DatagramModifier) -> Datagram {
    let now = now();
    let mut client = default_client();
    let mut server = default_server();
    connect_rtt_idle_with_modifier(&mut client, &mut server, RTT, &mut modifier);

    // Right after the handshake, the ECN validation should still be in progress.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_enabled(client_pkt.tos());

    for _ in 0..ECN_TEST_COUNT {
        let client_pkt = send_something_with_modifier(&mut client, now, &mut modifier);
        server.process_input(&client_pkt, now);
    }

    // Client should now process ACKs with incorrect ECN counts and disable ECN.
    while let Some(server_pkt) = server.process_output(now).dgram() {
        client.process_input(&server_pkt, now);
    }

    // Return another client packet for the caller to check.
    send_something(&mut client, now)
}

fn set_tos(mut d: Datagram, ecn: IpTosEcn) -> Datagram {
    qwarn!("Setting ECN to {:?}", ecn);
    d.set_tos(ecn.into());
    d
}

// fn noop() -> impl DatagramModifier {
//     Some
// }

fn bleach() -> impl DatagramModifier {
    |d| Some(set_tos(d, IpTosEcn::default()))
}

fn remark() -> impl DatagramModifier {
    |d| Some(set_tos(d, IpTosEcn::Ect1))
}

fn ce() -> impl DatagramModifier {
    |d| Some(set_tos(d, IpTosEcn::Ce))
}

#[test]
fn disables_when_bleached() {
    let pkt = connect_and_send_something_with_modifier(bleach());
    assert_ecn_disabled(pkt.tos());
}

#[test]
fn disables_when_remarked() {
    let pkt = connect_and_send_something_with_modifier(remark());
    assert_ecn_disabled(pkt.tos());
}

#[test]
fn stay_enabled_under_ce_data() {
    let pkt = connect_and_send_something_with_modifier(ce());
    assert_ecn_enabled(pkt.tos());
}

#[test]
fn disables_on_loss() {
    let now = now();
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    // Right after the handshake, the ECN validation should still be in progress.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_enabled(client_pkt.tos());

    for _ in 0..ECN_TEST_COUNT {
        send_something(&mut client, now);
    }

    // ECN should now be disabled.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_disabled(client_pkt.tos());
}

/// This function performs a handshake over a path that modifies packets via `old_path_modifier`.
/// It then sends `path_packets` packets on that path, and then migrates to a new path that
/// modifies packets via `new_path_modifier`.  It sends `path_packets` packets on the new path.
/// The function returns the TOS value of the last packet sent on the old path and the TOS value
/// of the last packet sent on the new path to allow for verification of correct behavior.
pub fn migration_with_modifiers(
    mut orig_path_modifier: impl DatagramModifier,
    mut new_path_modifier: impl DatagramModifier,
    burst: usize,
) -> (IpTos, IpTos) {
    fixture_init();
    let mut client = new_client(
        ConnectionParameters::default()
            .max_streams(StreamType::UniDi, 64)
            .idle_timeout(Duration::from_secs(6000)),
    );
    let mut server = new_server(
        ConnectionParameters::default()
            .max_streams(StreamType::UniDi, 64)
            .idle_timeout(Duration::from_secs(6000)),
    );

    connect_force_idle_with_modifier(&mut client, &mut server, &mut orig_path_modifier);
    let mut now = now();

    // Send some data on the current path.
    for _ in 0..burst {
        let client_pkt = send_something_with_modifier(&mut client, now, &mut orig_path_modifier);
        server.process_input(&client_pkt, now);
    }

    if let Some(ack) = server.process_output(now).dgram() {
        client.process_input(&ack, now);
    }

    let client_pkt = send_something(&mut client, now);
    let tos_before_migration = client_pkt.tos();
    server.process_input(&orig_path_modifier(client_pkt).unwrap(), now);

    client
        .migrate(Some(DEFAULT_ADDR_V4), Some(DEFAULT_ADDR_V4), false, now)
        .unwrap();


    let probe = new_path_modifier(client.process_output(now).dgram().unwrap()).unwrap();
    assert_v4_path(&probe, true); // Contains PATH_CHALLENGE.
    assert_eq!(client.stats().frame_tx.path_challenge, 1);
    let probe_cid = ConnectionId::from(get_cid(&probe));

    let resp = new_path_modifier(server.process(Some(&probe), now).dgram().unwrap()).unwrap();
    assert_v4_path(&resp, true);
    assert_eq!(server.stats().frame_tx.path_response, 1);
    assert_eq!(server.stats().frame_tx.path_challenge, 1);

    // Data continues to be exchanged on the old path.
    let client_data = send_something_with_modifier(&mut client, now, &mut orig_path_modifier);
    assert_ne!(get_cid(&client_data), probe_cid);
    assert_v6_path(&client_data, false);
    server.process_input(&client_data, now);
    let server_data = send_something_with_modifier(&mut server, now, &mut orig_path_modifier);
    assert_v6_path(&server_data, false);
    client.process_input(&server_data, now);

    // Once the client receives the probe response, it migrates to the new path.
    client.process_input(&resp, now);
    assert_eq!(client.stats().frame_rx.path_challenge, 1);
    let migrate_client = send_something_with_modifier(&mut client, now, &mut new_path_modifier);
    assert_v4_path(&migrate_client, true); // Responds to server probe.

    // The server now sees the migration and will switch over.
    // However, it will probe the old path again, even though it has just
    // received a response to its last probe, because it needs to verify
    // that the migration is genuine.
    server.process_input(&migrate_client, now);
    let stream_before = server.stats().frame_tx.stream;
    let probe_old_server = send_something_with_modifier(&mut server, now, &mut orig_path_modifier);
    // This is just the double-check probe; no STREAM frames.
    assert_v6_path(&probe_old_server, true);
    assert_eq!(server.stats().frame_tx.path_challenge, 2);
    assert_eq!(server.stats().frame_tx.stream, stream_before);

    // The server then sends data on the new path.
    let migrate_server = new_path_modifier(server.process_output(now).dgram().unwrap()).unwrap();
    assert_v4_path(&migrate_server, false);
    assert_eq!(server.stats().frame_tx.path_challenge, 2);
    assert_eq!(server.stats().frame_tx.stream, stream_before + 1);

    // The client receives these checks and responds to the probe, but uses the new path.
    client.process_input(&migrate_server, now);
    client.process_input(&probe_old_server, now);
    let old_probe_resp = send_something_with_modifier(&mut client, now, &mut new_path_modifier);
    assert_v6_path(&old_probe_resp, true);
    let client_confirmation = client.process_output(now).dgram().unwrap();
    assert_v4_path(&client_confirmation, false);

    // The server has now sent 2 packets, so it is blocked on the pacer.  Wait.
    let server_pacing = server.process_output(now).callback();
    assert_ne!(server_pacing, Duration::new(0, 0));
    // ... then confirm that the server sends on the new path still.
    let server_confirmation =
        send_something_with_modifier(&mut server, now + server_pacing, &mut new_path_modifier);
    assert_v4_path(&server_confirmation, false);
    client.process_input(&server_confirmation, now);

    // Send some data on the new path.
    for _ in 0..burst {
        now += client.process_output(now).callback();
        let client_pkt = send_something_with_modifier(&mut client, now, &mut new_path_modifier);
        server.process_input(&client_pkt, now);
    }

    if let Some(ack) = server.process_output(now).dgram() {
        client.process_input(&ack, now);
    }

    now += client.process_output(now).callback();
    let client_pkt = send_something(&mut client, now);
    let tos_after_migration = client_pkt.tos();
    (tos_before_migration, tos_after_migration)
}

#[test]
fn ecn_migration_matrix() {
    #[derive(Debug, Enum)]
    enum Modifier {
        DropEcn,
        NoOp,
        Bleach,
        Remark,
        Ce,
    }

    let modifiers = enum_map! {
        // All packets passed unmodified.
        Modifier::NoOp => Some,

        // All packets with any set ECN bits are dropped.
        Modifier::DropEcn => |d : Datagram| if d.tos() == IpTos::default() { Some(d) } else { None },

        // All packets with any set ECN bits have their ECN bits bleached to NotEct.
        Modifier::Bleach => |d : Datagram| if d.tos() == IpTos::default() { Some(d) } else { Some(set_tos(d, IpTosEcn::default()))},

        // All packets with any set ECN bits have their ECN bits remarked to ECT(1).
        Modifier::Remark => |d: Datagram| if d.tos() == IpTos::default() { Some(d) } else { Some(set_tos(d, IpTosEcn::Ect1))},

        // All packets with any set ECN bits have their ECN bits set to CE.
        Modifier::Ce => |d: Datagram| if d.tos() == IpTos::default() { Some(d) } else { Some(set_tos(d, IpTosEcn::Ce))} ,
    };

    for (op_orig, mod_orig) in &modifiers {
        for (op_new, mod_new) in &modifiers {
            for burst in [0, ECN_TEST_COUNT] {
                qinfo!(
                    "ECN migration test from orig path w/{:?} to new path w/{:?} with {} packets",
                    op_orig,
                    op_new,
                    burst
                );
                let (before, after) = migration_with_modifiers(mod_orig, mod_new, burst);
                if burst == 0 {
                    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
                    assert_ecn_enabled(after); // Too few packets sent after migration to conclude
                                               // ECN validation.
                }
            }
        }
    }
}

// How to parse the test names:
//
// ecn_migration_<old_path_modifier>_<new_path_modifier>_<data/nodata>
//
// The first part of the test name (`old_path_modifier`) indicates the modifier used on the old
// path. The second part of the test name (`new_path_modifier`) indicates the modifier used on the
// new path. The third part of the test name (`data` or `nodata`) indicates whether data is sent on
// the paths or not.
//
// The modifiers are:
// - `noop`: No modification is made to the ECN bits.
// - `bleach`: The ECN bits are set to `NotEct`.
// - `remark`: The ECN bits are set to `Ect1`.
// - `ce`: The ECN bits are set to `Ce`.
//
// The test checks that ECN is correctly enabled or disabled on the old and new paths, depending on
// the modifiers used and whether data is sent on the paths.

// #[test]
// fn ecn_migration_noop_noop_nodata() {
//     let (before, after) = migration_with_modifiers(noop(), noop(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_noop_bleach_nodata() {
//     let (before, after) = migration_with_modifiers(noop(), bleach(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_noop_remark_nodata() {
//     let (before, after) = migration_with_modifiers(noop(), remark(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_noop_ce_nodata() {
//     let (before, after) = migration_with_modifiers(noop(), ce(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_noop_noop_data() {
//     let (before, after) = migration_with_modifiers(noop(), noop(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration.
//     assert_ecn_enabled(after); // ECN validation concludes after migration.
// }

// #[test]
// fn ecn_migration_noop_bleach_data() {
//     let (before, after) = migration_with_modifiers(noop(), bleach(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching.
// }

// #[test]
// fn ecn_migration_noop_remark_data() {
//     let (before, after) = migration_with_modifiers(noop(), remark(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
// }

// #[test]
// fn ecn_migration_noop_ce_data() {
//     let (before, after) = migration_with_modifiers(noop(), ce(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration.
//     assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
// }

// // A set of tests where the first path leaves bleaches ECN and the second path modifies them.

// #[test]
// fn ecn_migration_bleach_noop_nodata() {
//     let (before, after) = migration_with_modifiers(bleach(), noop(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_bleach_bleach_nodata() {
//     let (before, after) = migration_with_modifiers(bleach(), bleach(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_bleach_remark_nodata() {
//     let (before, after) = migration_with_modifiers(bleach(), remark(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_bleach_ce_nodata() {
//     let (before, after) = migration_with_modifiers(bleach(), ce(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_bleach_noop_data() {
//     let (before, after) = migration_with_modifiers(bleach(), noop(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
//     assert_ecn_enabled(after); // ECN validation concludes after migration.
// }

// #[test]
// fn ecn_migration_bleach_bleach_data() {
//     let (before, after) = migration_with_modifiers(bleach(), bleach(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching
// }

// #[test]
// fn ecn_migration_bleach_remark_data() {
//     let (before, after) = migration_with_modifiers(bleach(), remark(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
// }

// #[test]
// fn ecn_migration_bleach_ce_data() {
//     let (before, after) = migration_with_modifiers(bleach(), ce(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
//     assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
// }

// #[test]
// fn ecn_migration_remark_noop_nodata() {
//     let (before, after) = migration_with_modifiers(remark(), noop(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_remark_bleach_nodata() {
//     let (before, after) = migration_with_modifiers(remark(), bleach(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_remark_remark_nodata() {
//     let (before, after) = migration_with_modifiers(remark(), remark(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_remark_ce_nodata() {
//     let (before, after) = migration_with_modifiers(remark(), ce(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_remark_noop_data() {
//     let (before, after) = migration_with_modifiers(remark(), noop(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
//     assert_ecn_enabled(after); // ECN validation concludes after migration.
// }

// #[test]
// fn ecn_migration_remark_bleach_data() {
//     let (before, after) = migration_with_modifiers(remark(), bleach(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching
// }

// #[test]
// fn ecn_migration_remark_remark_data() {
//     let (before, after) = migration_with_modifiers(remark(), remark(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
// }

// #[test]
// fn ecn_migration_remark_ce_data() {
//     let (before, after) = migration_with_modifiers(remark(), ce(), ECN_TEST_COUNT);
//     assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
//     assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
// }

// #[test]
// fn ecn_migration_ce_noop_nodata() {
//     let (before, after) = migration_with_modifiers(ce(), noop(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_ce_bleach_nodata() {
//     let (before, after) = migration_with_modifiers(ce(), bleach(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_ce_remark_nodata() {
//     let (before, after) = migration_with_modifiers(ce(), remark(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_ce_ce_nodata() {
//     let (before, after) = migration_with_modifiers(ce(), ce(), 0);
//     assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
//     assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
// }

// #[test]
// fn ecn_migration_ce_noop_data() {
//     let (before, after) = migration_with_modifiers(ce(), noop(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
//     assert_ecn_enabled(after); // ECN validation concludes after migration.
// }

// #[test]
// fn ecn_migration_ce_bleach_data() {
//     let (before, after) = migration_with_modifiers(ce(), bleach(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching
// }

// #[test]
// fn ecn_migration_ce_remark_data() {
//     let (before, after) = migration_with_modifiers(ce(), remark(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
//     assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
// }

// #[test]
// fn ecn_migration_ce_ce_data() {
//     let (before, after) = migration_with_modifiers(ce(), ce(), ECN_TEST_COUNT);
//     assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
//     assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
// }
