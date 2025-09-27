// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt,
    ops::Deref,
    os::raw::{c_char, c_uint},
    ptr::null_mut,
};

use crate::{
    constants::{Cipher, Version},
    err::{sec::SEC_ERROR_BAD_DATA, Error, Res},
    experimental_api,
    p11::{PK11SymKey, SymKey},
    scoped_ptr,
    ssl::{PRUint16, PRUint64, PRUint8, SSLAeadContext},
};

/// Trait for AEAD (Authenticated Encryption with Associated Data) operations.
///
/// This trait provides a common interface for both real and null AEAD implementations,
/// eliminating code duplication and allowing for consistent usage patterns.
pub trait Aead {
    /// Create a new AEAD instance.
    ///
    /// # Errors
    ///
    /// Returns `Error` when the underlying crypto operations fail.
    fn new(version: Version, cipher: Cipher, secret: &SymKey, prefix: &str) -> Res<Self>
    where
        Self: Sized;

    /// Get the expansion size (authentication tag length) for this AEAD.
    fn expansion(&self) -> usize;

    /// Encrypt plaintext with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when encryption fails.
    fn encrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]>;

    /// Encrypt plaintext in place with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when encryption fails.
    fn encrypt_in_place<'a>(&self, count: u64, aad: &[u8], data: &'a mut [u8])
        -> Res<&'a mut [u8]>;

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when decryption or authentication fails.
    fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]>;

    /// Decrypt ciphertext in place with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when decryption or authentication fails.
    fn decrypt_in_place<'a>(&self, count: u64, aad: &[u8], data: &'a mut [u8])
        -> Res<&'a mut [u8]>;
}

experimental_api!(SSL_MakeAead(
    version: PRUint16,
    cipher: PRUint16,
    secret: *mut PK11SymKey,
    label_prefix: *const c_char,
    label_prefix_len: c_uint,
    ctx: *mut *mut SSLAeadContext,
));
experimental_api!(SSL_AeadEncrypt(
    ctx: *const SSLAeadContext,
    counter: PRUint64,
    aad: *const PRUint8,
    aad_len: c_uint,
    input: *const PRUint8,
    input_len: c_uint,
    output: *const PRUint8,
    output_len: *mut c_uint,
    max_output: c_uint
));
experimental_api!(SSL_AeadDecrypt(
    ctx: *const SSLAeadContext,
    counter: PRUint64,
    aad: *const PRUint8,
    aad_len: c_uint,
    input: *const PRUint8,
    input_len: c_uint,
    output: *const PRUint8,
    output_len: *mut c_uint,
    max_output: c_uint
));
experimental_api!(SSL_DestroyAead(ctx: *mut SSLAeadContext));
scoped_ptr!(AeadContext, SSLAeadContext, SSL_DestroyAead);

pub struct RealAead {
    ctx: AeadContext,
}

impl RealAead {
    unsafe fn from_raw(
        version: Version,
        cipher: Cipher,
        secret: *mut PK11SymKey,
        prefix: &str,
    ) -> Res<Self> {
        let p = prefix.as_bytes();
        let mut ctx: *mut SSLAeadContext = null_mut();
        SSL_MakeAead(
            version,
            cipher,
            secret,
            p.as_ptr().cast(),
            c_uint::try_from(p.len())?,
            &mut ctx,
        )?;
        Ok(Self {
            ctx: AeadContext::from_ptr(ctx)?,
        })
    }
}

impl Aead for RealAead {
    fn new(version: Version, cipher: Cipher, secret: &SymKey, prefix: &str) -> Res<Self> {
        let s: *mut PK11SymKey = **secret;
        unsafe { Self::from_raw(version, cipher, s, prefix) }
    }

    fn expansion(&self) -> usize {
        16
    }

    fn encrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let mut l: c_uint = 0;
        unsafe {
            SSL_AeadEncrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                input.as_ptr(),
                c_uint::try_from(input.len())?,
                output.as_mut_ptr(),
                &mut l,
                c_uint::try_from(output.len())?,
            )
        }?;
        Ok(&output[..l.try_into()?])
    }

    fn encrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        if data.len() < self.expansion() {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        let mut l: c_uint = 0;
        unsafe {
            SSL_AeadEncrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                data.as_ptr(),
                c_uint::try_from(data.len() - self.expansion())?,
                data.as_mut_ptr(),
                &mut l,
                c_uint::try_from(data.len())?,
            )
        }?;
        debug_assert_eq!(usize::try_from(l)?, data.len());
        Ok(data)
    }

    fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let mut l: c_uint = 0;
        unsafe {
            // Note that NSS insists upon having extra space available for decryption, so
            // the buffer for `output` should be the same length as `input`, even though
            // the final result will be shorter.
            SSL_AeadDecrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                input.as_ptr(),
                c_uint::try_from(input.len())?,
                output.as_mut_ptr(),
                &mut l,
                c_uint::try_from(output.len())?,
            )
        }?;
        Ok(&output[..l.try_into()?])
    }

    fn decrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        let mut l: c_uint = 0;
        unsafe {
            // Note that NSS insists upon having extra space available for decryption, so
            // the buffer for `output` should be the same length as `input`, even though
            // the final result will be shorter.
            SSL_AeadDecrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                data.as_ptr(),
                c_uint::try_from(data.len())?,
                data.as_mut_ptr(),
                &mut l,
                c_uint::try_from(data.len())?,
            )
        }?;
        debug_assert_eq!(usize::try_from(l)?, data.len() - self.expansion());
        Ok(&mut data[..l.try_into()?])
    }
}

impl fmt::Debug for RealAead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[AEAD Context]")
    }
}
