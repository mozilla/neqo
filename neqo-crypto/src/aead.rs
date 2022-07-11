// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::constants::{Cipher, Version};
use crate::err::Res;
#[cfg(feature = "fuzzing")]
use crate::err::{sec::SEC_ERROR_BAD_DATA, Error};
use crate::p11::{PK11SymKey, SymKey};
use crate::ssl;
use crate::ssl::{PRUint16, PRUint64, PRUint8, SSLAeadContext};

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_char, c_uint};
use std::ptr::null_mut;

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

#[cfg(feature = "fuzzing")]
pub const FIXED_TAG_FUZZING: &[u8] = &[0x0a; 16];

pub struct Aead {
    ctx: AeadContext,
    #[cfg(feature = "fuzzing")]
    fuzzing_mode: bool,
}

impl Aead {
    /// Create a new AEAD based on the indicated TLS version and cipher suite.
    ///
    /// # Errors
    /// Returns `Error` when the supporting NSS functions fail.
    pub fn new(
        version: Version,
        cipher: Cipher,
        secret: &SymKey,
        prefix: &str,
        #[cfg(feature = "fuzzing")]
        fuzzing_mode: bool,
    ) -> Res<Self> {
        let s: *mut PK11SymKey = **secret;
        unsafe {
            Self::from_raw(
                version,
                cipher,
                s,
                prefix,
                #[cfg(feature = "fuzzing")]
                fuzzing_mode,
            )
        }
    }

    #[must_use]
    pub fn expansion(&self) -> usize {
        #[cfg(feature = "fuzzing")]
        if self.fuzzing_mode {
            return FIXED_TAG_FUZZING.len();
        }
        16
    }

    unsafe fn from_raw(
        version: Version,
        cipher: Cipher,
        secret: *mut PK11SymKey,
        prefix: &str,
        #[cfg(feature = "fuzzing")]
        fuzzing_mode: bool,
    ) -> Res<Self> {
        let p = prefix.as_bytes();
        let mut ctx: *mut ssl::SSLAeadContext = null_mut();
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
            #[cfg(feature = "fuzzing")]
            fuzzing_mode: fuzzing_mode,
        })
    }

    /// Decrypt a plaintext.
    ///
    /// The space provided in `output` needs to be larger than `input` by
    /// the value provided in `Aead::expansion`.
    ///
    /// # Errors
    /// If the input can't be protected or any input is too large for NSS.
    pub fn encrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        #[cfg(feature = "fuzzing")]
        if self.fuzzing_mode {
            let l = input.len();
            output[..l].copy_from_slice(input);
            output[l..l + 16].copy_from_slice(FIXED_TAG_FUZZING);
            return Ok(&output[..l + 16]);
        }

        let mut l: c_uint = 0;
        unsafe {
            SSL_AeadEncrypt(
                *self.ctx.deref(),
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
        Ok(&output[0..(l.try_into()?)])
    }

    /// Decrypt a ciphertext.
    ///
    /// Note that NSS insists upon having extra space available for decryption, so
    /// the buffer for `output` should be the same length as `input`, even though
    /// the final result will be shorter.
    ///
    /// # Errors
    /// If the input isn't authenticated or any input is too large for NSS.
    pub fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        #[cfg(feature = "fuzzing")]
        if self.fuzzing_mode {
            if input.len() < FIXED_TAG_FUZZING.len() {
                return Err(Error::from(SEC_ERROR_BAD_DATA));
            }

            let len_encrypted = input.len() - FIXED_TAG_FUZZING.len();
            // Check that:
            // 1) expansion is all zeros and
            // 2) if the encrypted data is also supplied that at least some values
            //    are no zero (otherwise padding will be interpreted as a valid packet)
            if &input[len_encrypted..] == FIXED_TAG_FUZZING
                && (len_encrypted == 0 || input[..len_encrypted].iter().any(|x| *x != 0x0))
            {
                output[..len_encrypted].copy_from_slice(&input[..len_encrypted]);
                return Ok(&output[..len_encrypted]);
            } else {
                return Err(Error::from(SEC_ERROR_BAD_DATA));
            }
        }

        let mut l: c_uint = 0;
        unsafe {
            SSL_AeadDecrypt(
                *self.ctx.deref(),
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
        Ok(&output[0..(l.try_into()?)])
    }
}

impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "fuzzing")]
        if self.fuzzing_mode {
            return write!(f, "[FUZZING AEAD]");
        }

        write!(f, "[AEAD Context]")
    }
}
