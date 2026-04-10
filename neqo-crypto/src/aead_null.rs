// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt;

use crate::{
    aead::Aead,
    constants::{Cipher, Version},
    err::{Error, Res, sec::SEC_ERROR_BAD_DATA},
    p11::SymKey,
};

pub const AEAD_NULL_TAG: &[u8] = &[0x0a; 16];

pub struct AeadNull {}

impl AeadNull {
    fn decrypt_check(&self, _count: u64, _aad: &[u8], input: &[u8]) -> Res<usize> {
        if input.len() < self.expansion() {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        let len_encrypted = input
            .len()
            .checked_sub(self.expansion())
            .ok_or_else(|| Error::from(SEC_ERROR_BAD_DATA))?;
        // Check that:
        // 1) expansion is all zeros and
        // 2) if the encrypted data is also supplied that at least some values are no zero
        //    (otherwise padding will be interpreted as a valid packet)
        if &input[len_encrypted..] == AEAD_NULL_TAG
            && (len_encrypted == 0 || input[..len_encrypted].iter().any(|x| *x != 0x0))
        {
            Ok(len_encrypted)
        } else {
            Err(Error::from(SEC_ERROR_BAD_DATA))
        }
    }
}

impl Aead for AeadNull {
    fn new(_version: Version, _cipher: Cipher, _secret: &SymKey, _prefix: &str) -> Res<Self> {
        Ok(Self {})
    }

    fn expansion(&self) -> usize {
        AEAD_NULL_TAG.len()
    }

    fn encrypt<'a>(
        &self,
        _count: u64,
        _aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let l = input.len();
        output[..l].copy_from_slice(input);
        output[l..l + self.expansion()].copy_from_slice(AEAD_NULL_TAG);
        Ok(&output[..l + self.expansion()])
    }

    fn encrypt_in_place(&self, _count: u64, _aad: &[u8], data: &mut [u8]) -> Res<usize> {
        let pos = data.len() - self.expansion();
        data[pos..].copy_from_slice(AEAD_NULL_TAG);
        Ok(data.len())
    }

    fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        self.decrypt_check(count, aad, input).map(|len| {
            output[..len].copy_from_slice(&input[..len]);
            &output[..len]
        })
    }

    fn decrypt_in_place(&self, count: u64, aad: &[u8], data: &mut [u8]) -> Res<usize> {
        self.decrypt_check(count, aad, data)
    }
}

impl fmt::Debug for AeadNull {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[NULL AEAD]")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{AEAD_NULL_TAG, AeadNull};
    use crate::aead::Aead as _;

    fn aead() -> AeadNull {
        AeadNull {}
    }

    #[test]
    fn expansion() {
        assert_eq!(aead().expansion(), AEAD_NULL_TAG.len());
    }

    #[test]
    fn debug() {
        assert_eq!(format!("{:?}", aead()), "[NULL AEAD]");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let a = aead();
        let plaintext = b"hello world";
        let mut out = vec![0u8; plaintext.len() + a.expansion()];
        let encrypted = a.encrypt(0, b"aad", plaintext, &mut out).unwrap();
        assert_eq!(encrypted.len(), plaintext.len() + a.expansion());
        assert_eq!(&encrypted[..plaintext.len()], plaintext);
        assert_eq!(&encrypted[plaintext.len()..], AEAD_NULL_TAG);

        let mut dec_out = vec![0u8; plaintext.len()];
        let decrypted = a.decrypt(0, b"aad", encrypted, &mut dec_out).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_in_place_roundtrip() {
        let a = aead();
        let plaintext = b"hello";
        let mut buf = plaintext.to_vec();
        buf.resize(plaintext.len() + a.expansion(), 0);
        let len = a.encrypt_in_place(0, b"", &mut buf).unwrap();
        assert_eq!(len, buf.len());
        assert_eq!(&buf[plaintext.len()..], AEAD_NULL_TAG);

        let dec_len = a.decrypt_in_place(0, b"", &mut buf).unwrap();
        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&buf[..dec_len], plaintext);
    }

    #[test]
    fn decrypt_empty_plaintext() {
        // Zero-length plaintext (just the tag) is valid.
        let a = aead();
        let mut out = vec![0u8; a.expansion()];
        a.encrypt(0, b"", b"", &mut out).unwrap();
        let mut dec = vec![];
        let res = a.decrypt(0, b"", &out, &mut dec).unwrap();
        assert_eq!(res, b"");
    }

    #[test]
    fn decrypt_fails_too_short() {
        let a = aead();
        let short = &AEAD_NULL_TAG[..a.expansion() - 1];
        assert!(a.decrypt(0, b"", short, &mut []).is_err());
    }

    #[test]
    fn decrypt_fails_bad_tag() {
        let a = aead();
        let plaintext = b"test";
        let mut buf = vec![0u8; plaintext.len() + a.expansion()];
        a.encrypt(0, b"", plaintext, &mut buf).unwrap();
        // Corrupt the tag.
        let tag_start = plaintext.len();
        buf[tag_start] ^= 0xff;
        assert!(a.decrypt(0, b"", &buf, &mut []).is_err());
    }

    #[test]
    fn decrypt_rejects_all_zero_data_bytes() {
        // All-zero plaintext with correct tag should fail (looks like padding).
        let a = aead();
        let mut buf = vec![0u8; 4 + a.expansion()];
        buf[4..].copy_from_slice(AEAD_NULL_TAG);
        assert!(a.decrypt(0, b"", &buf, &mut []).is_err());
    }
}
