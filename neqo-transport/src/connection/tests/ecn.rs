// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Duration;

use neqo_common::{Datagram, IpTos, IpTosEcn};
use test_fixture::{
    assertions::{assert_v4_path, assert_v6_path},
    fixture_init, now, DEFAULT_ADDR_V4,
};

use super::{send_something_with_modifier, DatagramModifier};
use crate::{
    connection::tests::{
        connect_force_idle, connect_force_idle_with_modifier, default_client, default_server,
        migration::get_cid, new_client, new_server, send_something,
    },
    ecn::ECN_TEST_COUNT,
    ConnectionId, ConnectionParameters, StreamType,
};

fn assert_ecn_enabled(tos: IpTos) {
    assert_eq!(IpTosEcn::from(tos), IpTosEcn::Ect0);
}

fn assert_ecn_disabled(tos: IpTos) {
    assert_eq!(IpTosEcn::from(tos), IpTosEcn::NotEct);
}

fn set_tos(mut d: Datagram, ecn: IpTosEcn) -> Datagram {
    d.set_tos(ecn.into());
    d
}

fn noop() -> impl DatagramModifier {
    Some
}

fn bleach() -> impl DatagramModifier {
    |d| Some(set_tos(d, IpTosEcn::NotEct))
}

fn remark() -> impl DatagramModifier {
    |d| {
        if IpTosEcn::from(d.tos()) == IpTosEcn::NotEct {
            Some(d)
        } else {
            Some(set_tos(d, IpTosEcn::Ect1))
        }
    }
}

fn ce() -> impl DatagramModifier {
    |d| {
        if IpTosEcn::from(d.tos()) == IpTosEcn::NotEct {
            Some(d)
        } else {
            Some(set_tos(d, IpTosEcn::Ce))
        }
    }
}

fn drop() -> impl DatagramModifier {
    |_| None
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

/// This function performs a handshake over a path that modifies packets via `orig_path_modifier`.
/// It then sends `burst` packets on that path, and then migrates to a new path that
/// modifies packets via `new_path_modifier`.  It sends `burst` packets on the new path.
/// The function returns the TOS value of the last packet sent on the old path and the TOS value
/// of the last packet sent on the new path to allow for verification of correct behavior.
pub fn migration_with_modifiers(
    mut orig_path_modifier: impl DatagramModifier,
    mut new_path_modifier: impl DatagramModifier,
    burst: usize,
) -> (IpTos, IpTos) {
    fixture_init();
    let mut client = new_client(ConnectionParameters::default().max_streams(StreamType::UniDi, 64));
    let mut server = new_server(ConnectionParameters::default().max_streams(StreamType::UniDi, 64));

    connect_force_idle_with_modifier(&mut client, &mut server, &mut orig_path_modifier);
    let mut now = now();

    // Right after the handshake, the ECN validation should still be in progress.
    let client_pkt = send_something(&mut client, now);
    assert_ecn_enabled(client_pkt.tos());
    server.process_input(&orig_path_modifier(client_pkt).unwrap(), now);

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

    let mut migrated = false;
    let probe = new_path_modifier(client.process_output(now).dgram().unwrap());
    if let Some(probe) = probe {
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
        migrated = true;

        let migrate_client = send_something_with_modifier(&mut client, now, &mut new_path_modifier);
        assert_v4_path(&migrate_client, true); // Responds to server probe.

        // The server now sees the migration and will switch over.
        // However, it will probe the old path again, even though it has just
        // received a response to its last probe, because it needs to verify
        // that the migration is genuine.
        server.process_input(&migrate_client, now);
    }

    let stream_before = server.stats().frame_tx.stream;
    let probe_old_server = send_something_with_modifier(&mut server, now, &mut orig_path_modifier);
    // This is just the double-check probe; no STREAM frames.
    assert_v6_path(&probe_old_server, migrated);
    assert_eq!(
        server.stats().frame_tx.path_challenge,
        if migrated { 2 } else { 0 }
    );
    assert_eq!(
        server.stats().frame_tx.stream,
        if migrated { stream_before } else { 1 }
    );

    if migrated {
        // The server then sends data on the new path.
        let migrate_server =
            new_path_modifier(server.process_output(now).dgram().unwrap()).unwrap();
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
    }

    now += client.process_output(now).callback();
    let mut client_pkt = send_something(&mut client, now);
    while !migrated && client_pkt.source() == DEFAULT_ADDR_V4 {
        client_pkt = send_something(&mut client, now);
    }
    let tos_after_migration = client_pkt.tos();
    (tos_before_migration, tos_after_migration)
}

#[test]
fn ecn_migration_noop_noop_nodata() {
    let (before, after) = migration_with_modifiers(noop(), noop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_noop_bleach_nodata() {
    let (before, after) = migration_with_modifiers(noop(), bleach(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_noop_remark_nodata() {
    let (before, after) = migration_with_modifiers(noop(), remark(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_noop_ce_nodata() {
    let (before, after) = migration_with_modifiers(noop(), ce(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_noop_drop_nodata() {
    let (before, after) = migration_with_modifiers(noop(), drop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration attempt to conclude ECN validation.
    assert_ecn_enabled(after); // Migration failed, still too few packets to conclude ECN
                               // validation.
}

#[test]
fn ecn_migration_noop_noop_data() {
    let (before, after) = migration_with_modifiers(noop(), noop(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration.
    assert_ecn_enabled(after); // ECN validation concludes after migration.
}

#[test]
fn ecn_migration_noop_bleach_data() {
    let (before, after) = migration_with_modifiers(noop(), bleach(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration.
    assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching.
}

#[test]
fn ecn_migration_noop_remark_data() {
    let (before, after) = migration_with_modifiers(noop(), remark(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration.
    assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
}

#[test]
fn ecn_migration_noop_ce_data() {
    let (before, after) = migration_with_modifiers(noop(), ce(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration.
    assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
}

#[test]
fn ecn_migration_noop_drop_data() {
    let (before, after) = migration_with_modifiers(noop(), drop(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration.
    assert_ecn_enabled(after); // Migration failed, ECN on original path is still validated.
}

#[test]
fn ecn_migration_bleach_noop_nodata() {
    let (before, after) = migration_with_modifiers(bleach(), noop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_bleach_bleach_nodata() {
    let (before, after) = migration_with_modifiers(bleach(), bleach(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_bleach_remark_nodata() {
    let (before, after) = migration_with_modifiers(bleach(), remark(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_bleach_ce_nodata() {
    let (before, after) = migration_with_modifiers(bleach(), ce(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_bleach_drop_nodata() {
    let (before, after) = migration_with_modifiers(bleach(), drop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Migration failed, still too few packets to conclude ECN
                               // validation.
}

#[test]
fn ecn_migration_bleach_noop_data() {
    let (before, after) = migration_with_modifiers(bleach(), noop(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
    assert_ecn_enabled(after); // ECN validation concludes after migration.
}

#[test]
fn ecn_migration_bleach_bleach_data() {
    let (before, after) = migration_with_modifiers(bleach(), bleach(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
    assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching.
}

#[test]
fn ecn_migration_bleach_remark_data() {
    let (before, after) = migration_with_modifiers(bleach(), remark(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
    assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
}

#[test]
fn ecn_migration_bleach_ce_data() {
    let (before, after) = migration_with_modifiers(bleach(), ce(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
    assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
}

#[test]
fn ecn_migration_bleach_drop_data() {
    let (before, after) = migration_with_modifiers(bleach(), drop(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to bleaching.
    assert_ecn_disabled(after); // Migration failed, ECN on original path is still disabled.
}

#[test]
fn ecn_migration_remark_noop_nodata() {
    let (before, after) = migration_with_modifiers(remark(), noop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_remark_bleach_nodata() {
    let (before, after) = migration_with_modifiers(remark(), bleach(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_remark_remark_nodata() {
    let (before, after) = migration_with_modifiers(remark(), remark(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_remark_ce_nodata() {
    let (before, after) = migration_with_modifiers(remark(), ce(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_remark_drop_nodata() {
    let (before, after) = migration_with_modifiers(remark(), drop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Migration failed, still too few packets to conclude ECN
                               // validation.
}

#[test]
fn ecn_migration_remark_noop_data() {
    let (before, after) = migration_with_modifiers(remark(), noop(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
    assert_ecn_enabled(after); // ECN validation succeeds after migration.
}

#[test]
fn ecn_migration_remark_bleach_data() {
    let (before, after) = migration_with_modifiers(remark(), bleach(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
    assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching.
}

#[test]
fn ecn_migration_remark_remark_data() {
    let (before, after) = migration_with_modifiers(remark(), remark(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
    assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
}

#[test]
fn ecn_migration_remark_ce_data() {
    let (before, after) = migration_with_modifiers(remark(), ce(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
    assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
}

#[test]
fn ecn_migration_remark_drop_data() {
    let (before, after) = migration_with_modifiers(remark(), drop(), ECN_TEST_COUNT);
    assert_ecn_disabled(before); // ECN validation fails before migration due to remarking.
    assert_ecn_disabled(after); // Migration failed, ECN on original path is still disabled.
}

#[test]
fn ecn_migration_ce_noop_nodata() {
    let (before, after) = migration_with_modifiers(ce(), noop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_ce_bleach_nodata() {
    let (before, after) = migration_with_modifiers(ce(), bleach(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_ce_remark_nodata() {
    let (before, after) = migration_with_modifiers(ce(), remark(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_ce_ce_nodata() {
    let (before, after) = migration_with_modifiers(ce(), ce(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration to conclude ECN validation.
    assert_ecn_enabled(after); // Too few packets sent after migration to conclude ECN validation.
}

#[test]
fn ecn_migration_ce_drop_nodata() {
    let (before, after) = migration_with_modifiers(ce(), drop(), 0);
    assert_ecn_enabled(before); // Too few packets sent before migration attempt to conclude ECN validation.
    assert_ecn_enabled(after); // Migration failed, still too few packets to conclude ECN
                               // validation.
}

#[test]
fn ecn_migration_ce_noop_data() {
    let (before, after) = migration_with_modifiers(ce(), noop(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
    assert_ecn_enabled(after); // ECN validation concludes after migration.
}

#[test]
fn ecn_migration_ce_bleach_data() {
    let (before, after) = migration_with_modifiers(ce(), bleach(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
    assert_ecn_disabled(after); // ECN validation fails after migration due to bleaching
}

#[test]
fn ecn_migration_ce_remark_data() {
    let (before, after) = migration_with_modifiers(ce(), remark(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
    assert_ecn_disabled(after); // ECN validation fails after migration due to remarking.
}

#[test]
fn ecn_migration_ce_ce_data() {
    let (before, after) = migration_with_modifiers(ce(), ce(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
    assert_ecn_enabled(after); // ECN validation concludes after migration, despite all CE marks.
}

#[test]
fn ecn_migration_ce_drop_data() {
    let (before, after) = migration_with_modifiers(ce(), drop(), ECN_TEST_COUNT);
    assert_ecn_enabled(before); // ECN validation concludes before migration, despite all CE marks.
    assert_ecn_enabled(after); // Migration failed, ECN on original path is still enabled.
}
