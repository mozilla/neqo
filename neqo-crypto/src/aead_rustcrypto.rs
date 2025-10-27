// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Pure Rust AEAD implementations using `RustCrypto` crates.
//!
//! This module provides AEAD implementations for QUIC using the `RustCrypto` project's
//! crates, which offer better performance on many platforms compared to NSS FFI calls.

use std::{
    fmt,
    os::raw::c_uint,
    ptr::{null, null_mut},
};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit as _},
    Aes128Gcm, Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;

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
const NONCE_SIZE: usize = 12;

/// Trait for AEAD implementations that work with packet numbers.
trait AeadOps: Sized {
    /// Create a new AEAD instance from raw key bytes.
    fn new_from_key(key: &[u8]) -> Res<Self>;

    /// Encrypt in place with the given nonce, AAD, and plaintext/ciphertext buffer.
    fn encrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()>;

    /// Decrypt in place with the given nonce, AAD, and ciphertext/plaintext buffer.
    fn decrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()>;
}

impl AeadOps for Aes128Gcm {
    fn new_from_key(key: &[u8]) -> Res<Self> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| Error::CipherInit)?;
        Ok(Self::new(&key_array.into()))
    }

    fn encrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        AeadInPlace::encrypt_in_place(self, nonce.into(), aad, buffer)
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))
    }

    fn decrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        AeadInPlace::decrypt_in_place(self, nonce.into(), aad, buffer)
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))
    }
}

impl AeadOps for Aes256Gcm {
    fn new_from_key(key: &[u8]) -> Res<Self> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| Error::CipherInit)?;
        Ok(Self::new(&key_array.into()))
    }

    fn encrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        AeadInPlace::encrypt_in_place(self, nonce.into(), aad, buffer)
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))
    }

    fn decrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        AeadInPlace::decrypt_in_place(self, nonce.into(), aad, buffer)
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))
    }
}

impl AeadOps for ChaCha20Poly1305 {
    fn new_from_key(key: &[u8]) -> Res<Self> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| Error::CipherInit)?;
        Ok(Self::new(&key_array.into()))
    }

    fn encrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        AeadInPlace::encrypt_in_place(self, nonce.into(), aad, buffer)
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))
    }

    fn decrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        AeadInPlace::decrypt_in_place(self, nonce.into(), aad, buffer)
            .map_err(|_| Error::from(SEC_ERROR_BAD_DATA))
    }
}

/// Enum containing one of the three AEAD implementations.
/// All variants are boxed to avoid large size differences.
enum AeadVariant {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl AeadVariant {
    fn encrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.encrypt_buffer(nonce, aad, buffer),
            Self::Aes256Gcm(cipher) => cipher.encrypt_buffer(nonce, aad, buffer),
            Self::ChaCha20Poly1305(cipher) => cipher.encrypt_buffer(nonce, aad, buffer),
        }
    }

    fn decrypt_buffer(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut dyn aes_gcm::aead::Buffer,
    ) -> Res<()> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt_buffer(nonce, aad, buffer),
            Self::Aes256Gcm(cipher) => cipher.decrypt_buffer(nonce, aad, buffer),
            Self::ChaCha20Poly1305(cipher) => cipher.decrypt_buffer(nonce, aad, buffer),
        }
    }
}

/// RustCrypto-based AEAD implementation.
pub struct RustCryptoAead {
    aead: AeadVariant,
    iv: [u8; NONCE_SIZE],
}

impl RustCryptoAead {
    /// Construct a nonce by `XORing` the IV with the packet number.
    /// This follows the QUIC specification (RFC 9001 Section 5.3).
    fn make_nonce(&self, count: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = self.iv;
        // XOR the packet number (in big-endian) into the last 8 bytes of the nonce.
        let count_bytes = count.to_be_bytes();
        for (i, byte) in count_bytes.iter().enumerate() {
            nonce[NONCE_SIZE - 8 + i] ^= byte;
        }
        nonce
    }
}

impl crate::aead::Aead for RustCryptoAead {
    fn new(version: Version, cipher: Cipher, secret: &SymKey, prefix: &str) -> Res<Self> {
        // Determine the key size based on cipher.
        // Use CKM_HKDF_DERIVE as the mechanism for deriving generic secrets.
        let key_size = match cipher {
            TLS_AES_128_GCM_SHA256 => 16,
            TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => 32,
            _ => return Err(Error::UnsupportedCipher),
        };
        let mech = CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE);

        // Derive the key and IV from the secret using HKDF-Expand-Label.
        // The prefix is typically "quic " for QUIC packet protection.
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

        // Create the appropriate AEAD implementation based on the cipher.
        let aead = match cipher {
            TLS_AES_128_GCM_SHA256 => {
                AeadVariant::Aes128Gcm(Box::new(Aes128Gcm::new_from_key(key_bytes)?))
            }
            TLS_AES_256_GCM_SHA384 => {
                AeadVariant::Aes256Gcm(Box::new(Aes256Gcm::new_from_key(key_bytes)?))
            }
            TLS_CHACHA20_POLY1305_SHA256 => {
                AeadVariant::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new_from_key(key_bytes)?))
            }
            _ => return Err(Error::UnsupportedCipher),
        };

        Ok(Self { aead, iv })
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

        // Create a buffer wrapper for in-place encryption.
        let result_len = {
            let mut buffer = InPlaceBuffer {
                data: output,
                len: input.len(),
            };

            self.aead.encrypt_buffer(&nonce, aad, &mut buffer)?;
            buffer.len
        };

        Ok(&output[..result_len])
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
        let plaintext_len = data.len() - TAG_SIZE;

        {
            let mut buffer = InPlaceBuffer {
                data,
                len: plaintext_len,
            };

            self.aead.encrypt_buffer(&nonce, aad, &mut buffer)?;
            debug_assert_eq!(buffer.len, buffer.data.len());
        }

        Ok(data)
    }

    fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        if output.len() < input.len() {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        // Copy input to output.
        output[..input.len()].copy_from_slice(input);

        let nonce = self.make_nonce(count);

        let result_len = {
            let mut buffer = InPlaceBuffer {
                data: output,
                len: input.len(),
            };

            self.aead.decrypt_buffer(&nonce, aad, &mut buffer)?;
            buffer.len
        };

        Ok(&output[..result_len])
    }

    fn decrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        let nonce = self.make_nonce(count);
        let input_len = data.len();

        let result_len = {
            let mut buffer = InPlaceBuffer {
                data,
                len: input_len,
            };

            self.aead.decrypt_buffer(&nonce, aad, &mut buffer)?;
            buffer.len
        };

        Ok(&mut data[..result_len])
    }
}

impl fmt::Debug for RustCryptoAead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[RustCrypto AEAD]")
    }
}

/// Helper struct to adapt a mutable slice to the `Buffer` trait required by `RustCrypto`.
struct InPlaceBuffer<'a> {
    data: &'a mut [u8],
    len: usize,
}

impl aes_gcm::aead::Buffer for InPlaceBuffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        let new_len = self.len + other.len();
        if new_len > self.data.len() {
            return Err(aes_gcm::aead::Error);
        }
        self.data[self.len..new_len].copy_from_slice(other);
        self.len = new_len;
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for InPlaceBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl AsMut<[u8]> for InPlaceBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}
