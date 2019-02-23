use crate::aead::Aead;
use crate::constants::*;
use crate::err::{Error, Res};
use crate::p11::{PK11SymKey, PK11_ReferenceSymKey, SymKey};
use crate::result;
use crate::ssl::{PRFileDesc, SSLSecretCallback, SSLSecretDirection};

use std::os::raw::c_void;
use std::ptr::NonNull;

experimental_api!(SSL_SecretCallback(
    fd: *mut PRFileDesc,
    cb: SSLSecretCallback,
    arg: *mut c_void,
));

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
        let p: *const c_void = self as *const Secrets as *const _;
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
        self.put(epoch, dir, key);
    }

    pub fn put(&mut self, epoch: Epoch, dir: SSLSecretDirection::Type, key: SymKey) {
        let keys = match dir {
            SSLSecretDirection::ssl_secret_read => &mut self.r,
            SSLSecretDirection::ssl_secret_write => &mut self.w,
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

    pub fn make_aead<S: Into<String>>(
        &self,
        epoch: Epoch,
        version: Version,
        cipher: Cipher,
        prefix: S,
    ) -> Res<Aead> {
        let i = epoch as usize;
        if i >= self.secrets.len() {
            return Err(Error::InvalidEpoch);
        }
        match &self.secrets[i] {
            None => Err(Error::InvalidEpoch),
            Some(secret) => Aead::new(version, cipher, &secret, prefix),
        }
    }
}
