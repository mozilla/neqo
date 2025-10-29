// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! High-performance AEAD implementations using AWS-LC-RS.
//!
//! This module provides AEAD implementations for QUIC using the `aws-lc-rs` crate,
//! which offers superior performance compared to both NSS FFI calls and pure Rust
//! implementations. AWS-LC-RS provides FIPS-validated cryptography and is the
//! recommended crypto provider for rustls.

use std::{
    fmt,
    os::raw::c_uint,
    ptr::{null, null_mut},
};

use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN,
};

use crate::{
    constants::{
        Cipher, Version, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    },
    err::{sec::SEC_ERROR_BAD_DATA, Error, Res},
    hp::SSL_HkdfExpandLabelWithMech,
    p11::{PK11SymKey, SymKey, CKM_HKDF_DERIVE, CK_MECHANISM_TYPE},
};

/// Size of the AEAD authentication tag.
const TAG_SIZE: usize = 16;

/// Size of the AEAD nonce.
const NONCE_SIZE: usize = NONCE_LEN;

/// AWS-LC-RS-based AEAD implementation.
pub struct AwsLcAead {
    key: LessSafeKey,
    iv: [u8; NONCE_SIZE],
}

impl AwsLcAead {
    /// Construct a nonce by `XORing` the IV with the packet number.
    /// This follows the QUIC specification (RFC 9001 Section 5.3).
    fn make_nonce(&self, count: u64) -> Nonce {
        let mut nonce = self.iv;
        // XOR the packet number (in big-endian) into the last 8 bytes of the nonce.
        let count_bytes = count.to_be_bytes();
        for (i, byte) in count_bytes.iter().enumerate() {
            nonce[NONCE_SIZE - 8 + i] ^= byte;
        }
        Nonce::assume_unique_for_key(nonce)
    }
}

impl crate::aead::Aead for AwsLcAead {
    fn new(version: Version, cipher: Cipher, secret: &SymKey, prefix: &str) -> Res<Self> {
        // Determine the algorithm and key size based on cipher.
        let (algorithm, key_size) = match cipher {
            TLS_AES_128_GCM_SHA256 => (&AES_128_GCM, 16),
            TLS_AES_256_GCM_SHA384 => (&AES_256_GCM, 32),
            TLS_CHACHA20_POLY1305_SHA256 => (&CHACHA20_POLY1305, 32),
            _ => return Err(Error::UnsupportedCipher),
        };
        let mech = CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE);

        // Derive the key and IV from the secret using HKDF-Expand-Label.
        let key_label = format!("{prefix}key");
        let iv_label = format!("{prefix}iv");

        // Derive the AEAD key with the correct size.
        let key_secret = {
            let mut secret_ptr: *mut PK11SymKey = null_mut();
            let label_bytes = key_label.as_bytes();
            unsafe {
                SSL_HkdfExpandLabelWithMech(
                    version,
                    cipher,
                    **secret,
                    null(),
                    0,
                    label_bytes.as_ptr().cast(),
                    c_uint::try_from(label_bytes.len())?,
                    mech,
                    key_size,
                    &mut secret_ptr,
                )
            }?;
            SymKey::from_ptr(secret_ptr)?
        };

        // Derive the IV (always 12 bytes for QUIC).
        let iv_secret = {
            let mut secret_ptr: *mut PK11SymKey = null_mut();
            let label_bytes = iv_label.as_bytes();
            unsafe {
                SSL_HkdfExpandLabelWithMech(
                    version,
                    cipher,
                    **secret,
                    null(),
                    0,
                    label_bytes.as_ptr().cast(),
                    c_uint::try_from(label_bytes.len())?,
                    mech,
                    c_uint::try_from(NONCE_SIZE)?,
                    &mut secret_ptr,
                )
            }?;
            SymKey::from_ptr(secret_ptr)?
        };

        // Extract the raw bytes from the NSS SymKey.
        let key_bytes = key_secret.as_bytes()?;
        let iv_bytes = iv_secret.as_bytes()?;

        // Validate sizes.
        if key_bytes.len() != usize::try_from(key_size)? || iv_bytes.len() != NONCE_SIZE {
            return Err(Error::CipherInit);
        }

        let mut iv = [0u8; NONCE_SIZE];
        iv.copy_from_slice(iv_bytes);

        // Create the UnboundKey and then the LessSafeKey.
        let unbound_key = UnboundKey::new(algorithm, key_bytes).map_err(|_| Error::CipherInit)?;
        let key = LessSafeKey::new(unbound_key);

        Ok(Self { key, iv })
    }

    fn expansion(&self) -> usize {
        TAG_SIZE
    }

    fn encrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        if output.len() < input.len() + TAG_SIZE {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        // Copy input to output.
        output[..input.len()].copy_from_slice(input);

        let nonce = self.make_nonce(count);
        let aad = Aad::from(aad);

        // Encrypt in place.
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, &mut output[..input.len()])
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))?;

        // Append the tag.
        output[input.len()..input.len() + TAG_SIZE].copy_from_slice(tag.as_ref());

        Ok(&output[..input.len() + TAG_SIZE])
    }

    fn encrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        if data.len() < TAG_SIZE {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        let nonce = self.make_nonce(count);
        let aad = Aad::from(aad);
        let plaintext_len = data.len() - TAG_SIZE;

        // Encrypt in place and get the tag.
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, &mut data[..plaintext_len])
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))?;

        // Append the tag.
        data[plaintext_len..].copy_from_slice(tag.as_ref());

        Ok(data)
    }

    fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        if input.len() < TAG_SIZE || output.len() < input.len() {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        // Copy input to output.
        output[..input.len()].copy_from_slice(input);

        let nonce = self.make_nonce(count);
        let aad = Aad::from(aad);

        // Decrypt in place.
        let plaintext = self
            .key
            .open_in_place(nonce, aad, &mut output[..input.len()])
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))?;

        Ok(plaintext)
    }

    fn decrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        if data.len() < TAG_SIZE {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        let nonce = self.make_nonce(count);
        let aad = Aad::from(aad);

        // Decrypt in place.
        let plaintext = self
            .key
            .open_in_place(nonce, aad, data)
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))?;

        Ok(plaintext)
    }
}

impl fmt::Debug for AwsLcAead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[AWS-LC AEAD]")
    }
}
