use crate::err::{Error, Res};
use crate::p11;
use crate::result;
use crate::ssl;

use std::ops::{Deref, DerefMut};
use std::os::raw::c_uint;
use std::ptr::{null_mut, NonNull};

type SymKey = p11::SymKey;

scoped_ptr!(AeadContext, ssl::SSLAeadContext, ssl::SSL_DestroyAead);

pub struct Aead {
    ctx: AeadContext,
}

impl Aead {
    pub fn new<S: Into<String>>(secret: &SymKey, cipher: u16, prefix: S) -> Res<Aead> {
        let s: *mut ssl::PK11SymKey = **secret;
        let prefix_str = prefix.into();
        let p = prefix_str.as_bytes();
        let mut ctx: *mut ssl::SSLAeadContext = null_mut();
        let rv = unsafe {
            ssl::SSL_MakeAead(
                s as *mut ssl::PK11SymKey,
                cipher,
                p.as_ptr() as *const i8,
                p.len() as u32,
                &mut ctx,
            )
        };
        result::result(rv)?;
        match NonNull::new(ctx) {
            None => Err(Error::AeadInitFailure),
            Some(ctx_ptr) => Ok(Aead {
                ctx: AeadContext::new(ctx_ptr),
            }),
        }
    }

    pub fn encrypt(&self, count: u64, aad: &[u8], input: &[u8], output: &mut [u8]) -> Res<usize> {
        let mut l: c_uint = 0;
        let rv = unsafe {
            ssl::SSL_AeadEncrypt(
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
            ssl::SSL_AeadDecrypt(
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

#[derive(Default)]
pub struct Secrets {
    r: DirectionalSecrets,
    w: DirectionalSecrets,
}

impl Secrets {
    pub fn put(&mut self, epoch: u16, dir: ssl::SSLSecretDirection::Type, key: SymKey) {
        let keys = match dir {
            ssl::SSLSecretDirection::ssl_secret_read => &mut self.r,
            ssl::SSLSecretDirection::ssl_secret_write => &mut self.w,
            _ => unreachable!(),
        };
        keys.put(epoch, key);
    }

    pub fn read(&self) -> &DirectionalSecrets {
        &self.r
    }

    pub fn write(&self) -> &DirectionalSecrets {
        &self.w
    }
}

#[derive(Default)]
pub struct DirectionalSecrets {
    // We only need to maintain 4 secrets for the epochs used during the handshake.
    secrets: [Option<SymKey>; 4],
}

impl DirectionalSecrets {
    pub fn put(&mut self, epoch: u16, key: SymKey) {
        let i = epoch as usize;
        assert!(i < self.secrets.len());
        assert!(self.secrets[i].is_none());
        self.secrets[i] = Some(key);
    }

    pub fn make_aead<S: Into<String>>(&self, epoch: u16, cipher: u16, prefix: S) -> Res<Aead> {
        let i = epoch as usize;
        if i >= self.secrets.len() {
            return Err(Error::InvalidEpoch);
        }
        match &self.secrets[i] {
            None => Err(Error::InvalidEpoch),
            Some(secret) => Aead::new(&secret, cipher, prefix),
        }
    }
}
