// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Implementing features specific to the server role.

use neqo_common::{hex, qtrace, Datagram};

use crate::QUIC_VERSION;
use crate::packet::{
    encode_retry, ConnectionId, PacketDecoder, PacketHdr, PacketType, Version,
};
use crate::{Error, Res};

#[derive(Debug, Default)]
pub struct Server {
    version: Version,
    cidlen: usize,
}

pub enum RetryResult {
    Ok,
    SendRetry(Datagram),
}

const FIXED_TOKEN: &[u8] = &[1, 2, 3];

impl Server {
    pub fn new(cidlen: usize) -> Server {
        Server { version: QUIC_VERSION,  cidlen }
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

    // pub fn process_input(&mut self, dgram: Datagram, now: Instant) -> (Option<Datagram>, Option<Duration>) {
    //     let hdr = match decode_packet_hdr(self, &received[..]) {
    //         Ok(h) => h,
    //         Err(e) => {
    //             qtrace!([self] "Discarding {:?}", received);
    //             return (None, self.next_timer())
    //         }
    //     };
    //     let retry = self.check_retry(&hdr, dgram)
    //     if let RetryResult::SendRetry(dgram) = retry {
    //         return (Some(dgram), self.next_timer());
    //     }
    //     (None, None) // TODO(mt)
    // }
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
