// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Encoding and decoding packets off the wire.

use neqo_common::{hex, matches, Decoder};
use neqo_crypto::random;

use std::cmp::max;

#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct ConnectionId(pub Vec<u8>);

impl std::ops::Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConnectionId {
    pub fn generate(len: usize) -> Self {
        assert!(matches!(len, 0..=20));
        Self(random(len))
    }

    // Apply a wee bit of greasing here in picking a length between 8 and 20 bytes long.
    pub fn generate_initial() -> Self {
        let v = random(1);
        // Bias selection toward picking 8 (>50% of the time).
        let len: usize = max(8, 5 + (v[0] & (v[0] >> 4))).into();
        Self::generate(len)
    }
}

impl ::std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "CID {}", hex(&self.0))
    }
}

impl ::std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

impl From<&[u8]> for ConnectionId {
    fn from(buf: &[u8]) -> Self {
        Self(Vec::from(buf))
    }
}

pub trait ConnectionIdDecoder {
    fn decode_cid(&self, dec: &mut Decoder) -> Option<ConnectionId>;
}

pub trait ConnectionIdManager: ConnectionIdDecoder {
    fn generate_cid(&mut self) -> ConnectionId;
    fn as_decoder(&self) -> &dyn ConnectionIdDecoder;
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_common::matches;
    use test_fixture::fixture_init;

    #[test]
    fn generate_initial_cid() {
        fixture_init();
        for _ in 0..100 {
            let cid = ConnectionId::generate_initial();
            if !matches!(cid.len(), 8..=20) {
                panic!("connection ID {:?}", cid);
            }
        }
    }
}
