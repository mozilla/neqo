// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::constants::*;
use crate::err::Res;
use crate::p11::{PK11SymKey, PK11_ReferenceSymKey, SymKey};
use crate::result;
use crate::ssl::{PRFileDesc, SSLSecretCallback, SSLSecretDirection};

use neqo_common::qdebug;
use std::os::raw::c_void;
use std::ptr::NonNull;

experimental_api!(SSL_SecretCallback(
    fd: *mut PRFileDesc,
    cb: SSLSecretCallback,
    arg: *mut c_void,
));

#[derive(Clone, Copy, Debug)]
pub enum SecretDirection {
    Read,
    Write,
}

impl From<SSLSecretDirection::Type> for SecretDirection {
    fn from(dir: SSLSecretDirection::Type) -> Self {
        match dir {
            SSLSecretDirection::ssl_secret_read => SecretDirection::Read,
            SSLSecretDirection::ssl_secret_write => SecretDirection::Write,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Secrets {
    r: DirectionalSecrets,
    w: DirectionalSecrets,
}

impl Secrets {
    unsafe extern "C" fn secret_available(
        _fd: *mut PRFileDesc,
        epoch: u16,
        dir: SSLSecretDirection::Type,
        secret: *mut PK11SymKey,
        arg: *mut c_void,
    ) {
        let secrets_ptr = arg as *mut Secrets;
        let secrets = secrets_ptr.as_mut().unwrap();
        secrets.put_raw(epoch, dir, secret);
    }

    pub fn register(&mut self, fd: *mut PRFileDesc) -> Res<()> {
        let p = self as *const Secrets as *const c_void;
        let rv =
            unsafe { SSL_SecretCallback(fd, Some(Secrets::secret_available), p as *mut c_void) };
        result::result(rv)
    }

    fn put_raw(&mut self, epoch: Epoch, dir: SSLSecretDirection::Type, key_ptr: *mut PK11SymKey) {
        let key_ptr = unsafe { PK11_ReferenceSymKey(key_ptr) };
        let key = match NonNull::new(key_ptr) {
            None => panic!("NSS shouldn't be passing out NULL secrets"),
            Some(p) => SymKey::new(p),
        };
        self.put(dir.into(), epoch, key);
    }

    pub fn put(&mut self, dir: SecretDirection, epoch: Epoch, key: SymKey) {
        qdebug!("{:?} secret available for {:?}", dir, epoch);
        let keys = match dir {
            SecretDirection::Read => &mut self.r,
            SecretDirection::Write => &mut self.w,
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

#[derive(Debug, Default)]
pub struct DirectionalSecrets {
    // We only need to maintain 4 secrets for the epochs used during the handshake.
    secrets: [Option<SymKey>; 4],
}

impl DirectionalSecrets {
    pub fn put(&mut self, epoch: Epoch, key: SymKey) {
        let i = epoch as usize;
        assert!(i < self.secrets.len());
        assert!(self.secrets[i].is_none());
        self.secrets[i] = Some(key);
    }

    pub fn get(&self, epoch: Epoch) -> Option<&SymKey> {
        let i = epoch as usize;
        assert!(i < self.secrets.len());
        self.secrets[i].as_ref()
    }
}
