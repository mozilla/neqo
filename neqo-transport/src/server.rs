// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Implementing features specific to the server role.

use neqo_common::{hex, qinfo, qtrace, Datagram};

use crate::packet::{
    decode_packet_hdr, encode_retry, ConnectionId, PacketDecoder, PacketHdr, PacketType,
};
use crate::{Error, Res};

#[derive(Debug, Default)]
pub struct Server {
    version: crate::packet::Version,
    cidlen: usize,
}

pub enum RetryResult {
    Ok,
    SendRetry(Datagram),
}

const FIXED_TOKEN: &[u8] = &[1, 2, 3];

impl Server {
    fn token_is_ok(&self, token: &[u8]) -> bool {
        token == &FIXED_TOKEN[..]
    }

    fn generate_token(&self) -> Vec<u8> {
        Vec::from(FIXED_TOKEN)
    }

    fn generate_cid(&self) -> ConnectionId {
        ConnectionId::generate(self.cidlen)
    }

    pub fn check_retry(&self, received: &Datagram) -> Res<RetryResult> {
        qinfo!("Generating a Retry packet");
        qtrace!("Received packet: {}", hex(&received[..]));

        let hdr = decode_packet_hdr(self, &received[..])?;
        if let PacketType::Initial(token) = hdr.tipe {
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
                odcid: hdr.dcid,
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

    // pub fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> (Option<Datagram>, Option<Duration>) {
    //     let hdr = match decode_packet_hdr(self, &received[..]) {
    //         Ok(h) => h,
    //         Err(e) => {
    //             qtrace!([self] "Discarding {:?}", received);
    //             return (None, self.next_timer())
    //         }
    //     };
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
