// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This file implements a server that can handle multiple connections.

use neqo_common::{hex, qtrace, Datagram};

<<<<<<< HEAD
use crate::QUIC_VERSION;
=======
use crate::connection::{Connection, QUIC_VERSION};
>>>>>>> Basic timer wheel
use crate::packet::{
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
use std::rc::Rc;
use std::time::{Duration, Instant};
>>>>>>> Basic timer wheel

pub enum RetryResult {
    Ok,
    SendRetry(Datagram),
}

const FIXED_TOKEN: &[u8] = &[1, 2, 3];

#[derive(Debug, Default)]
pub struct Server {
    version: crate::packet::Version,
    connections: HashMap<ConnectionId, Rc<Connection>>,
    cidlen: usize,
}

impl Server {
    pub fn new() -> Server {
        Server {
            version: QUIC_VERSION,
            connections: Default::Default(),
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
            if self.token_is_ok(&token) {
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
        let dgram = Datagram::new(*received.destination(), *received.source(), retry);
        Ok(RetryResult::SendRetry(dgram))
    }

    /// Iterate through the pending timers and any that fire prior to
    fn process_next_output(now: Instant) -> Option<Datagram> {}

    fn next_timer(now: Instant) -> Option<Duration> {}

    pub fn process(
        &mut self,
        dgram: Option<Datagram>,
        now: Instant,
    ) -> (Option<Datagram>, Option<Duration>) {
        if dgram.is_none() {
            return (self.process_next_output(now), self.next_timer(now));
        }

        let hdr = match decode_packet_hdr(self, &received[..]) {
            Ok(h) => h,
            Err(e) => {
                qtrace!([self] "Discarding {:?}", received);
                return (self.process_next_output(now), self.next_timer(now));
            }
        };
        if let Some(c) = self.connections.get_mut(hdr.dcid) {
            let (out, time) = c.process(dgram, now);
        }
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
