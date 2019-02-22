use crate::constants::*;
use crate::err::{Error, Res};
use crate::p11::{PK11SymKey, SymKey};
use crate::result;
use crate::ssl;
use crate::ssl::{PRUint16, PRUint64, PRUint8, SSLAeadContext};

use std::ops::{Deref, DerefMut};
use std::os::raw::{c_char, c_uint};
use std::ptr::{null_mut, NonNull};

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

pub struct Aead {
    ctx: AeadContext,
}

impl Aead {
    pub fn new<S: Into<String>>(
        version: Version,
        cipher: Cipher,
        secret: &SymKey,
        prefix: S,
    ) -> Res<Aead> {
        let s: *mut PK11SymKey = **secret;
        Aead::from_raw(version, cipher, s, prefix)
    }

    pub fn from_raw<S: Into<String>>(
        version: Version,
        cipher: Cipher,
        secret: *mut PK11SymKey,
        prefix: S,
    ) -> Res<Aead> {
        let prefix_str = prefix.into();
        let p = prefix_str.as_bytes();
        let mut ctx: *mut ssl::SSLAeadContext = null_mut();
        let rv = unsafe {
            SSL_MakeAead(
                version,
                cipher,
                secret,
                p.as_ptr() as *const i8,
                p.len() as u32,
                &mut ctx,
            )
        };
        result::result(rv)?;
        match NonNull::new(ctx) {
            None => Err(Error::InternalError),
            Some(ctx_ptr) => Ok(Aead {
                ctx: AeadContext::new(ctx_ptr),
            }),
        }
    }

    pub fn encrypt(&self, count: u64, aad: &[u8], input: &[u8], output: &mut [u8]) -> Res<usize> {
        let mut l: c_uint = 0;
        let rv = unsafe {
            SSL_AeadEncrypt(
                *self.ctx.deref(),
                count,
                aad.as_ptr(),
                aad.len() as c_uint,
                input.as_ptr(),
                input.len() as c_uint,
                output.as_mut_ptr(),
                &mut l,
                output.len() as c_uint,
            )
        };
        result::result(rv)?;
        return Ok(l as usize);
    }

    pub fn decrypt(&self, count: u64, aad: &[u8], input: &[u8], output: &mut [u8]) -> Res<usize> {
        let mut l: c_uint = 0;
        let rv = unsafe {
            SSL_AeadDecrypt(
                *self.ctx.deref(),
                count,
                aad.as_ptr(),
                aad.len() as c_uint,
                input.as_ptr(),
                input.len() as c_uint,
                output.as_mut_ptr(),
                &mut l,
                output.len() as c_uint,
            )
        };
        result::result(rv)?;
        return Ok(l as usize);
    }
}
