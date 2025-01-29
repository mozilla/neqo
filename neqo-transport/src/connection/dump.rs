// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Enable just this file for logging to just see packets.
// e.g. "RUST_LOG=neqo_transport::dump neqo-client ..."

use std::{fmt::Write as _, time::Instant};

use neqo_common::{qdebug, Decoder, IpTos};

use crate::{
    connection::Connection,
    frame::Frame,
    packet::{PacketNumber, PacketType},
    path::PathRef,
    qlog,
};

pub enum Direction {
    Tx,
    Rx,
}
#[allow(clippy::too_many_arguments)]
fn dump_packet(
    conn: &Connection,
    path: &PathRef,
    dir: &str,
    pt: PacketType,
    pn: PacketNumber,
    payload: &[u8],
    tos: IpTos,
    len: usize,
) {
    if log::STATIC_MAX_LEVEL == log::LevelFilter::Off || !log::log_enabled!(log::Level::Debug) {
        return;
    }

    let mut s = String::new();
    let mut d = Decoder::from(payload);
    while d.remaining() > 0 {
        let Ok(f) = Frame::decode(&mut d) else {
            s.push_str(" [broken]...");
            break;
        };
        let x = f.dump();
        if !x.is_empty() {
            _ = write!(&mut s, "\n  {dir} {}", &x);
        }
    }
    qdebug!(
        "[{conn}] pn={pn} type={pt:?} {} {tos:?} len {len}{s}",
        path.borrow()
    );
}

#[allow(clippy::too_many_arguments)]
pub fn log_packet(
    conn: &Connection,
    path: &PathRef,
    dir: &Direction,
    pt: PacketType,
    pn: PacketNumber,
    tos: IpTos,
    payload: &[u8],
    plen: usize,
    now: Instant,
) {
    let dir_str = match dir {
        Direction::Tx => "TX ->",
        Direction::Rx => "-> RX",
    };
    dump_packet(conn, path, dir_str, pt, pn, payload, tos, plen);
    match dir {
        Direction::Tx => qlog::packet_sent(&conn.qlog, pt, pn, plen, payload, now),
        Direction::Rx => qlog::packet_received(&conn.qlog, pt, pn, plen, payload, now),
    }
}
