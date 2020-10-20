// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Representation and management of connection IDs.

use crate::{Error, Res};

use neqo_common::{hex, hex_with_len, Decoder};
use neqo_crypto::random;

use smallvec::SmallVec;
use std::borrow::Borrow;
use std::cmp::max;
use std::convert::AsRef;

pub const MAX_CONNECTION_ID_LEN: usize = 20;
pub const LOCAL_ACTIVE_CID_LIMIT: usize = 8;

#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct ConnectionId {
    pub(crate) cid: SmallVec<[u8; MAX_CONNECTION_ID_LEN]>,
}

impl ConnectionId {
    pub fn generate(len: usize) -> Self {
        assert!(matches!(len, 0..=MAX_CONNECTION_ID_LEN));
        Self::from(random(len))
    }

    // Apply a wee bit of greasing here in picking a length between 8 and 20 bytes long.
    pub fn generate_initial() -> Self {
        let v = random(1);
        // Bias selection toward picking 8 (>50% of the time).
        let len: usize = max(8, 5 + (v[0] & (v[0] >> 4))).into();
        Self::generate(len)
    }

    pub fn as_cid_ref(&self) -> ConnectionIdRef {
        ConnectionIdRef::from(&self.cid[..])
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        self.borrow()
    }
}

impl Borrow<[u8]> for ConnectionId {
    fn borrow(&self) -> &[u8] {
        &self.cid
    }
}

impl From<SmallVec<[u8; MAX_CONNECTION_ID_LEN]>> for ConnectionId {
    fn from(cid: SmallVec<[u8; MAX_CONNECTION_ID_LEN]>) -> Self {
        Self { cid }
    }
}

impl From<Vec<u8>> for ConnectionId {
    fn from(cid: Vec<u8>) -> Self {
        Self::from(SmallVec::from(cid))
    }
}

impl From<&[u8]> for ConnectionId {
    fn from(buf: &[u8]) -> Self {
        Self::from(SmallVec::from(buf))
    }
}

impl<'a> From<&ConnectionIdRef<'a>> for ConnectionId {
    fn from(cidref: &ConnectionIdRef<'a>) -> Self {
        Self::from(SmallVec::from(cidref.cid))
    }
}

impl std::ops::Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.cid
    }
}

impl ::std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "CID {}", hex_with_len(&self.cid))
    }
}

impl ::std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", hex(&self.cid))
    }
}

impl<'a> PartialEq<ConnectionIdRef<'a>> for ConnectionId {
    fn eq(&self, other: &ConnectionIdRef<'a>) -> bool {
        &self.cid[..] == other.cid
    }
}

#[derive(Hash, Eq, PartialEq)]
pub struct ConnectionIdRef<'a> {
    cid: &'a [u8],
}

impl<'a> ::std::fmt::Debug for ConnectionIdRef<'a> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "CID {}", hex_with_len(&self.cid))
    }
}

impl<'a> ::std::fmt::Display for ConnectionIdRef<'a> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", hex(&self.cid))
    }
}

impl<'a> From<&'a [u8]> for ConnectionIdRef<'a> {
    fn from(cid: &'a [u8]) -> Self {
        Self { cid }
    }
}

impl<'a> std::ops::Deref for ConnectionIdRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.cid
    }
}

impl<'a> PartialEq<ConnectionId> for ConnectionIdRef<'a> {
    fn eq(&self, other: &ConnectionId) -> bool {
        self.cid == &other.cid[..]
    }
}

pub trait ConnectionIdDecoder {
    fn decode_cid<'a>(&self, dec: &mut Decoder<'a>) -> Option<ConnectionIdRef<'a>>;
}

pub trait ConnectionIdManager: ConnectionIdDecoder {
    fn generate_cid(&mut self) -> ConnectionId;
    fn as_decoder(&self) -> &dyn ConnectionIdDecoder;
}

/// A single connection ID, as saved from NEW_CONNECTION_ID.
/// This is templated so that the connection ID entries from a peer can be
/// saved with a stateless reset token.  Local entries don't need that.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConnectionIdEntry<SRT: Clone + PartialEq> {
    /// The sequence number.
    seqno: u64,
    /// The connection ID.
    cid: ConnectionId,
    /// The corresponding stateless reset token.
    srt: SRT,
}

impl ConnectionIdEntry<[u8; 16]> {
    /// Create the first entry, which won't have a stateless reset token.
    pub fn initial_remote(cid: ConnectionId) -> Self {
        Self::new(0, cid, [0; 16])
    }

    fn token_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
        // rustc might decide to optimize this and make this non-constant-time
        // with respect to `t`, but it doesn't appear to currently.
        let mut c = 0;
        for (&a, &b) in a.iter().zip(b) {
            c |= a ^ b;
        }
        c == 0
    }

    /// Determine whether this is a valid stateless reset.
    pub fn is_stateless_reset(&self, token: &[u8; 16]) -> bool {
        // A sequence number of 0 has no corresponding stateless reset token.
        Self::token_equal(&self.srt, token)
    }

    /// Return true if the two contain any equal parts.
    fn any_part_equal(&self, other: &Self) -> bool {
        self.seqno == other.seqno || self.cid == other.cid || self.srt == other.srt
    }
}

impl ConnectionIdEntry<()> {
    /// Create an initial entry.
    pub fn initial_local(cid: ConnectionId) -> Self {
        Self::new(0, cid, ())
    }
}

impl<SRT: Clone + PartialEq> ConnectionIdEntry<SRT> {
    pub fn new(seqno: u64, cid: ConnectionId, srt: SRT) -> Self {
        Self { seqno, cid, srt }
    }

    /// Update the stateless reset token.  This panics if the sequence number is non-zero.
    pub fn set_stateless_reset_token(&mut self, srt: SRT) {
        assert_eq!(self.seqno, 0);
        self.srt = srt;
    }

    /// Replace the connection ID.  This panics if the sequence number is non-zero.
    pub fn update_cid(&mut self, cid: ConnectionId) {
        assert_eq!(self.seqno, 0);
        self.cid = cid;
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.cid
    }
}

pub type RemoteConnectionIdEntry = ConnectionIdEntry<[u8; 16]>;

/// A collection of connection IDs that are indexed by a sequence number.
/// Used to store connection IDs that are provided by a peer.
#[derive(Debug, Default)]
pub struct ConnectionIdStore<SRT: Clone + PartialEq> {
    cids: SmallVec<[ConnectionIdEntry<SRT>; 8]>,
}

impl<SRT: Clone + PartialEq> ConnectionIdStore<SRT> {
    pub fn retire(&mut self, seqno: u64) {
        self.cids.retain(|c| c.seqno != seqno);
    }

    pub fn contains(&self, cid: &ConnectionIdRef) -> bool {
        self.cids.iter().any(|c| &c.cid == cid)
    }

    pub fn next(&mut self) -> Option<ConnectionIdEntry<SRT>> {
        if self.cids.is_empty() {
            None
        } else {
            Some(self.cids.remove(0))
        }
    }
}

impl ConnectionIdStore<[u8; 16]> {
    pub fn add_remote(&mut self, entry: ConnectionIdEntry<[u8; 16]>) -> Res<()> {
        // It's OK if this perfectly matches an existing entry.
        if self.cids.iter().any(|c| c == &entry) {
            return Ok(());
        }
        // It's not OK if any individual piece matches though.
        if self.cids.iter().any(|c| c.any_part_equal(&entry)) {
            return Err(Error::ProtocolViolation);
        }
        if self.cids.len() >= LOCAL_ACTIVE_CID_LIMIT {
            return Err(Error::ConnectionIdLimitExceeded);
        }

        self.cids.push(entry);
        Ok(())
    }
}

impl ConnectionIdStore<()> {
    pub fn add_local(&mut self, entry: ConnectionIdEntry<()>) {
        self.cids.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_fixture::fixture_init;

    #[test]
    fn generate_initial_cid() {
        fixture_init();
        for _ in 0..100 {
            let cid = ConnectionId::generate_initial();
            if !matches!(cid.len(), 8..=MAX_CONNECTION_ID_LEN) {
                panic!("connection ID {:?}", cid);
            }
        }
    }
}
