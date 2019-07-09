// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This file implements a server that can handle multiple connections.

<<<<<<< HEAD
use neqo_common::{hex, qtrace, Datagram};
=======
use neqo_common::timer::Timer;
use neqo_common::{qtrace, Datagram};
>>>>>>> Stub server, basic timer wheel

<<<<<<< HEAD
use crate::QUIC_VERSION;
=======
use crate::connection::{Connection, QUIC_VERSION};
>>>>>>> Basic timer wheel
use crate::packet::{
<<<<<<< HEAD
    encode_retry, ConnectionId, PacketDecoder, PacketHdr, PacketType, Version,
};
use crate::{Error, Res};

<<<<<<< HEAD
#[derive(Debug, Default)]
pub struct Server {
    version: Version,
    cidlen: usize,
}
=======
=======
    decode_packet_hdr, encode_retry, ConnectionId, PacketDecoder, PacketHdr, PacketType, Version,
};
use crate::{Error, Res};

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
>>>>>>> Stub server, basic timer wheel
use std::rc::Rc;
use std::time::{Duration, Instant};
>>>>>>> Basic timer wheel

pub enum RetryResult {
    Ok,
    SendRetry(Datagram),
}

/// MIN_INITIAL_PACKET_SIZE is the smallest packet that can be used to establish
/// a new connection across all QUIC versions this server supports.
const MIN_INITIAL_PACKET_SIZE: usize = 1200;
const TIMER_GRANULARITY: Duration = Duration::from_millis(10);
const TIMER_CAPACITY: usize = 1024;
const FIXED_TOKEN: &[u8] = &[1, 2, 3];

type ConnectionRef = Rc<RefCell<Connection>>;

#[derive(Debug)]
struct ServerConnectionState {
    c: ConnectionRef,
    next_timeout: Option<Instant>,
}

impl ServerConnectionState {
    fn update_timer(&mut self, timer: &mut Timer<ConnectionRef>, time: Option<Instant>) {
        if time == self.next_timeout {
            return;
        }
        if let Some(to) = self.next_timeout {
            let removed = timer.remove(to, |x| Rc::ptr_eq(x, &self.c));
            debug_assert!(removed.is_some());
        }
        self.next_timeout = time;
        if let Some(to) = self.next_timeout {
            timer.add(to, self.c.clone());
        }
    }
}

pub struct Server {
    version: Version,
    connections: HashMap<ConnectionId, ServerConnectionState>,
    waiting: VecDeque<ConnectionRef>,
    timers: Timer<ConnectionRef>,
    cidlen: usize,
}

impl Server {
    pub fn new(now: Instant) -> Server {
        Server {
            version: QUIC_VERSION,
            connections: Default::default(),
            waiting: Default::default(),
            timers: Timer::new(now, TIMER_GRANULARITY, TIMER_CAPACITY),
            cidlen: 8,
        }
    }

    fn token_is_ok(&self, token: &[u8]) -> bool {
        token == &FIXED_TOKEN[..]
    }

    fn generate_token(&self) -> Vec<u8> {
        Vec::from(FIXED_TOKEN)
    }

    fn generate_cid(&self) -> ConnectionId {
        ConnectionId::generate(self.cidlen)
    }

    pub fn check_retry(&self, hdr: &PacketHdr, received: Datagram) -> Res<RetryResult> {
        qtrace!("Received packet: {}", hex(&received[..]));

        if let PacketType::Initial(token) = &hdr.tipe {
            if self.token_is_ok(token) {
                return Ok(RetryResult::Ok);
            }
            if !token.is_empty() {
                return Err(Error::ProtocolViolation);
            }
        } else {
            return Ok(RetryResult::Ok);
        }

        let hdr = PacketHdr::new(
            0, // tbyte (unused on encode)
            PacketType::Retry {
                odcid: hdr.dcid.clone(),
                token: self.generate_token(),
            },
            Some(self.version),
            hdr.scid.as_ref().unwrap().clone(),
            Some(self.generate_cid()),
            0, // Packet number
            0, // Epoch
        );
        let retry = encode_retry(&hdr);
        let dgram = Datagram::new(received.destination(), received.source(), retry);
        Ok(RetryResult::SendRetry(dgram))
    }

    /// Iterate through the pending timers and any that fire prior to
    fn process_next_output(&mut self, _now: Instant) -> Option<Datagram> {
        // TODO
        None
    }

    fn next_time(&mut self, now: Instant) -> Option<Duration> {
        if self.waiting.is_empty() {
            self.timers.next_time().map(|x| x - now)
        } else {
            Some(Duration::new(0, 0))
        }
    }

    fn process_inner(&mut self, dgram: Datagram, now: Instant) -> Option<Datagram> {
        let hdr = match decode_packet_hdr(self, &dgram[..]) {
            Ok(h) => h,
            _ => {
                qtrace!([self] "Discarding {:?}", dgram);
                return None;
            }
        };

        // Finding an existing connection should be the hot path.
        if let Some(c) = self.connections.get_mut(&hdr.dcid) {
            let (out, time) = c.c.borrow_mut().process(Some(dgram), now);
            c.update_timer(&mut self.timers, time.map(|t| now + t));
            return out;
        }

        if dgram.len() < MIN_INITIAL_PACKET_SIZE {
            // TODO maybe send a stateless reset
            return None;
        }

        // TODO maybe send VN
        // TODO maybe send Retry
        // TODO maybe create a new connection
        None
    }

    pub fn process(
        &mut self,
        dgram: Option<Datagram>,
        now: Instant,
    ) -> (Option<Datagram>, Option<Duration>) {
        let out = match dgram {
            Some(d) => self.process_inner(d, now),
            None => None,
        };

        (
            out.or_else(|| self.process_next_output(now)),
            self.next_time(now),
        )
    }
}

impl PacketDecoder for Server {
    fn get_cid_len(&self) -> usize {
        self.cidlen
    }
}

impl ::std::fmt::Display for Server {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Server")
    }
}
