// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Stateless Reset Token implementation.

use neqo_crypto::random;

use crate::Error;

pub const SRT_LEN: usize = 16;

/// A stateless reset token is a 16-byte value that is used to identify
/// a stateless reset packet.
#[derive(Clone, Debug, Default)]
pub struct StatelessResetToken([u8; SRT_LEN]);

impl StatelessResetToken {
    /// Create a new stateless reset token from a byte array.
    #[must_use]
    pub const fn new(token: [u8; SRT_LEN]) -> Self {
        Self(token)
    }

    /// Generate a random stateless reset token.
    #[must_use]
    pub fn random() -> Self {
        Self(random::<SRT_LEN>())
    }

    /// Get the token as a byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SRT_LEN] {
        &self.0
    }
}

/// Compare two tokens in constant time to prevent timing attacks.
impl PartialEq for StatelessResetToken {
    fn eq(&self, other: &Self) -> bool {
        let mut c = 0;
        for (&a, &b) in self.0.iter().zip(&other.0) {
            c |= a ^ b;
        }
        c == 0
    }
}

impl TryFrom<&[u8]> for StatelessResetToken {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != SRT_LEN {
            return Err(Error::TransportParameter);
        }
        let mut token = [0u8; SRT_LEN];
        token.copy_from_slice(value);
        Ok(Self(token))
    }
}

impl AsRef<[u8]> for StatelessResetToken {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_token() {
        let bytes = [1u8; SRT_LEN];
        let token = StatelessResetToken::new(bytes);
        assert_eq!(token.as_bytes(), &bytes);
    }

    #[test]
    fn random_token() {
        neqo_crypto::init().unwrap();
        let token1 = StatelessResetToken::random();
        let token2 = StatelessResetToken::random();
        // With very high probability, two random tokens should be different
        assert_ne!(token1, token2);
    }

    #[test]
    fn eq_same() {
        let bytes = [42u8; SRT_LEN];
        let token1 = StatelessResetToken::new(bytes);
        let token2 = StatelessResetToken::new(bytes);
        assert_eq!(token1, token2);
    }

    #[test]
    fn eq_different() {
        let token1 = StatelessResetToken::new([1u8; SRT_LEN]);
        let token2 = StatelessResetToken::new([2u8; SRT_LEN]);
        assert_ne!(token1, token2);
    }

    #[test]
    fn from_slice_valid() {
        let bytes = [3u8; SRT_LEN];
        let token = StatelessResetToken::try_from(&bytes[..]).unwrap();
        assert_eq!(token.as_bytes(), &bytes);
    }

    #[test]
    fn from_slice_invalid_length() {
        let bytes = [3u8; 15];
        let result = StatelessResetToken::try_from(&bytes[..]);
        assert!(result.is_err());
    }
}
