// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This file implements functions necessary for address validation.

use neqo_common::{qinfo, qtrace, Decoder, Encoder, Role};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3},
    selfencrypt::SelfEncrypt,
};

use crate::cid::ConnectionId;
use crate::frame::Frame;
use crate::recovery::RecoveryToken;
use crate::Res;

use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// A prefix we add to Retry tokens to distinguish them from NEW_TOKEN tokens.
const TOKEN_IDENTIFIER_RETRY: &[u8] = &[0x52, 0x65, 0x74, 0x72, 0x79];
/// A prefix on NEW_TOKEN tokens, that is maximally Hamming distant from NEW_TOKEN.
const TOKEN_IDENTIFIER_NEW_TOKEN: &[u8] = &[0xad, 0x9a, 0x8b, 0x8d, 0x86];

/// The maximum number of tokens we'll save from NEW_TOKEN.
/// This should be the same as the value of MAX_TICKETS in neqo-crypto.
const MAX_NEW_TOKEN: usize = 4;

/// `ValidateAddress` determines what sort of address validation is performed.
/// In short, this determines when a Retry packet is sent.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidateAddress {
    /// Require address validation never.
    Never,
    /// Require address validation unless a NEW_TOKEN token is provided.
    NoToken,
    /// Require address validation even if a NEW_TOKEN token is provided.
    Always,
}

pub enum AddressValidationResult {
    Pass,
    ValidRetry(ConnectionId),
    Validate,
    Invalid,
}

pub struct AddressValidation {
    /// What sort of validation is performed.
    validation: ValidateAddress,
    /// A self-encryption object used for protecting Retry tokens.
    self_encrypt: SelfEncrypt,
    /// When this object was created.
    start_time: Instant,
}

impl AddressValidation {
    pub fn new(now: Instant, validation: ValidateAddress) -> Res<Self> {
        Ok(Self {
            validation,
            self_encrypt: SelfEncrypt::new(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256)?,
            start_time: now,
        })
    }

    fn encode_aad(peer_address: SocketAddr, retry: bool) -> Encoder {
        // Let's be "clever" by putting the peer's address in the AAD.
        // We don't need to encode these into the token as they should be
        // available when we need to check the token.
        let mut aad = Encoder::default();
        if retry {
            aad.encode(TOKEN_IDENTIFIER_RETRY);
        } else {
            aad.encode(TOKEN_IDENTIFIER_NEW_TOKEN);
        }
        match peer_address.ip() {
            IpAddr::V4(a) => {
                aad.encode_byte(4);
                aad.encode(&a.octets());
            }
            IpAddr::V6(a) => {
                aad.encode_byte(6);
                aad.encode(&a.octets());
            }
        }
        if retry {
            aad.encode_uint(2, peer_address.port());
        }
        aad
    }

    pub fn generate_token(
        &self,
        dcid: Option<&ConnectionId>,
        peer_address: SocketAddr,
        now: Instant,
    ) -> Res<Vec<u8>> {
        const EXPIRATION_RETRY: Duration = Duration::from_secs(5);
        const EXPIRATION_NEW_TOKEN: Duration = Duration::from_secs(60 * 60 * 24);

        // TODO(mt) rotate keys on a fixed schedule.
        let retry = dcid.is_some();
        let mut data = Encoder::default();
        let end = now
            + if retry {
                EXPIRATION_RETRY
            } else {
                EXPIRATION_NEW_TOKEN
            };
        let end_millis = u32::try_from(end.duration_since(self.start_time).as_millis())?;
        data.encode_uint(4, end_millis);
        if let Some(dcid) = dcid {
            data.encode(dcid);
        }

        // Include the token identifier ("Retry"/~) in the AAD, then keep it for plaintext.
        let mut buf = Self::encode_aad(peer_address, retry);
        let encrypted = self.self_encrypt.seal(&buf, &data)?;
        buf.truncate(TOKEN_IDENTIFIER_RETRY.len());
        buf.encode(&encrypted);
        Ok(buf.into())
    }

    /// This generates a token for use with Retry.
    pub fn generate_retry_token(
        &self,
        dcid: &ConnectionId,
        peer_address: SocketAddr,
        now: Instant,
    ) -> Res<Vec<u8>> {
        self.generate_token(Some(dcid), peer_address, now)
    }

    /// This generates a token for use with NEW_TOKEN.
    pub fn generate_new_token(&self, peer_address: SocketAddr, now: Instant) -> Res<Vec<u8>> {
        self.generate_token(None, peer_address, now)
    }

    pub fn set_validation(&mut self, validation: ValidateAddress) {
        qtrace!("AddressValidation {:p}: set to {:?}", self, validation);
        self.validation = validation;
    }

    /// Decrypts `token` and returns the connection ID it contains.
    /// Returns a tuple with a boolean indicating whether this thinks
    /// that the token was a Retry token, and a connection ID, that is
    /// None if the token wasn't successfully decrypted.
    fn decrypt_token(
        &self,
        token: &[u8],
        peer_address: SocketAddr,
        retry: bool,
        now: Instant,
    ) -> Option<ConnectionId> {
        let peer_addr = Self::encode_aad(peer_address, retry);
        let data = if let Ok(d) = self.self_encrypt.open(&peer_addr, token) {
            d
        } else {
            return None;
        };
        let mut dec = Decoder::new(&data);
        match dec.decode_uint(4) {
            Some(d) => {
                let end = self.start_time + Duration::from_millis(d);
                if end < now {
                    qtrace!("Expired token: {:?} vs. {:?}", end, now);
                    return None;
                }
            }
            _ => return None,
        }
        Some(ConnectionId::from(dec.decode_remainder()))
    }

    /// Calculate the Hamming difference between our identifier and the target.
    /// Less than one difference per byte indicates that it is likely not a Retry.
    /// This generous interpretation allows for a lot of damage in transit.
    /// Note that if this check fails, then the token will be treated like it came
    /// from NEW_TOKEN instead.  If there truly is corruption of packets that causes
    /// validation failure, it will be a failure that we try to recover from.
    fn is_likely_retry(token: &[u8]) -> bool {
        let mut difference = 0;
        for i in 0..TOKEN_IDENTIFIER_RETRY.len() {
            difference += (token[i] ^ TOKEN_IDENTIFIER_RETRY[i]).count_ones();
        }
        usize::try_from(difference).unwrap() < TOKEN_IDENTIFIER_RETRY.len()
    }

    pub fn validate(
        &self,
        token: &[u8],
        peer_address: SocketAddr,
        now: Instant,
    ) -> AddressValidationResult {
        qtrace!(
            "AddressValidation {:p}: validate {:?}",
            self,
            self.validation
        );

        if token.is_empty() {
            if self.validation == ValidateAddress::Never {
                qinfo!("AddressValidation: no token; accepting");
                return AddressValidationResult::Pass;
            } else {
                qinfo!("AddressValidation: no token; validating");
                return AddressValidationResult::Validate;
            }
        }
        if token.len() <= TOKEN_IDENTIFIER_RETRY.len() {
            // Treat bad tokens strictly.
            qinfo!("AddressValidation: too short token");
            return AddressValidationResult::Invalid;
        }
        let retry = Self::is_likely_retry(token);
        let enc = &token[TOKEN_IDENTIFIER_RETRY.len()..];
        // Note that this allows the token identifier part to be corrupted.
        // That's OK here as we don't depend on that being authenticated.
        if let Some(cid) = self.decrypt_token(enc, peer_address, retry, now) {
            if retry {
                // This is from Retry, so we should have an ODCID >= 8.
                if cid.len() >= 8 {
                    qinfo!("AddressValidation: valid Retry token for {}", cid);
                    AddressValidationResult::ValidRetry(cid)
                } else {
                    panic!("AddressValidation: Retry token with small CID {}", cid);
                }
            } else if cid.is_empty() {
                // An empty connection ID means NEW_TOKEN.
                if self.validation == ValidateAddress::Always {
                    qinfo!("AddressValidation: valid NEW_TOKEN token; validating again");
                    AddressValidationResult::Validate
                } else {
                    qinfo!("AddressValidation: valid NEW_TOKEN token; accepting");
                    AddressValidationResult::Pass
                }
            } else {
                panic!("AddressValidation: NEW_TOKEN token with CID {}", cid);
            }
        } else {
            // From here on, we have a token that we couldn't decrypt.
            // We've either lost the keys or we've received junk.
            if retry {
                // If this looked like a Retry, treat it as being bad.
                qinfo!("AddressValidation: invalid Retry token; rejecting");
                AddressValidationResult::Invalid
            } else if self.validation == ValidateAddress::Never {
                // We don't require validation, so OK.
                qinfo!("AddressValidation: invalid NEW_TOKEN token; accepting");
                AddressValidationResult::Pass
            } else {
                // This might be an invalid NEW_TOKEN token, or a valid one
                // for which we have since lost the keys.  Check again.
                qinfo!("AddressValidation: invalid NEW_TOKEN token; validating again");
                AddressValidationResult::Validate
            }
        }
    }
}

pub enum NewTokenState {
    Client(Vec<Vec<u8>>),
    Server(NewTokenSender),
}

impl NewTokenState {
    pub fn new(role: Role) -> Self {
        match role {
            Role::Client => Self::Client(Vec::new()),
            Role::Server => Self::Server(NewTokenSender::default()),
        }
    }

    /// If this is a client, take a token if there is one.
    /// If this is a server, panic.
    pub fn take_token(&mut self) -> Option<Vec<u8>> {
        if let Self::Client(ref mut tokens) = self {
            tokens.pop()
        } else {
            unreachable!();
        }
    }

    /// If this is a client, save a token.
    /// If this is a server, panic.
    pub fn save_token(&mut self, token: Vec<u8>) {
        if let Self::Client(ref mut tokens) = self {
            for t in tokens.iter().rev() {
                if t == &token {
                    qinfo!("NewTokenState discarding duplicate NEW_TOKEN");
                    return;
                }
            }

            if tokens.len() >= MAX_NEW_TOKEN {
                tokens.remove(0);
            }
            tokens.push(token);
        } else {
            unreachable!();
        }
    }

    /// If this is a server, maybe send a frame.
    /// If this is a client, do nothing.
    pub fn get_frame(&mut self, space: usize) -> Option<(Frame, Option<RecoveryToken>)> {
        if let Self::Server(ref mut sender) = self {
            sender.get_frame(space)
        } else {
            None
        }
    }

    /// If this a server, buffer a NEW_TOKEN for sending.
    /// If this is a client, panic.
    pub fn send_new_token(&mut self, token: Vec<u8>) {
        if let Self::Server(ref mut sender) = self {
            sender.send_new_token(token);
        } else {
            unreachable!();
        }
    }

    /// If this a server, process a lost signal for a NEW_TOKEN frame.
    /// If this is a client, panic.
    pub fn lost(&mut self, seqno: usize) {
        if let Self::Server(ref mut sender) = self {
            sender.lost(seqno);
        } else {
            unreachable!();
        }
    }

    /// If this a server, process remove the acknowledged NEW_TOKEN frame.
    /// If this is a client, panic.
    pub fn acked(&mut self, seqno: usize) {
        if let Self::Server(ref mut sender) = self {
            sender.acked(seqno);
        } else {
            unreachable!();
        }
    }
}

struct NewTokenFrameStatus {
    seqno: usize,
    token: Vec<u8>,
    needs_sending: bool,
}

impl NewTokenFrameStatus {
    fn fits(&self, space: usize) -> bool {
        1 + Encoder::varint_len(u64::try_from(self.token.len()).unwrap()) + self.token.len()
            <= space
    }
}

#[derive(Default)]
pub struct NewTokenSender {
    /// The unacknowledged NEW_TOKEN frames we are yet to send.
    tokens: Vec<NewTokenFrameStatus>,
    /// A sequence number that is used to track individual tokens
    /// by reference (so that recovery tokens can be simple).
    next_seqno: usize,
}

impl NewTokenSender {
    /// Add a token to be sent.
    pub fn send_new_token(&mut self, token: Vec<u8>) {
        self.tokens.push(NewTokenFrameStatus {
            seqno: self.next_seqno,
            token,
            needs_sending: true,
        });
        self.next_seqno += 1;
    }

    pub fn get_frame(&mut self, space: usize) -> Option<(Frame, Option<RecoveryToken>)> {
        for t in self.tokens.iter_mut() {
            if t.needs_sending && t.fits(space) {
                t.needs_sending = false;
                return Some((
                    Frame::NewToken {
                        token: t.token.clone(),
                    },
                    Some(RecoveryToken::NewToken(t.seqno)),
                ));
            }
        }
        None
    }

    pub fn lost(&mut self, seqno: usize) {
        for t in self.tokens.iter_mut() {
            if t.seqno == seqno {
                t.needs_sending = true;
                break;
            }
        }
    }

    pub fn acked(&mut self, seqno: usize) {
        self.tokens.retain(|i| i.seqno != seqno);
    }
}
