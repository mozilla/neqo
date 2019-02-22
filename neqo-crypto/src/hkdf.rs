// TODO(mt) consider naming this just KDF.
use crate::constants::*;
use crate::err::{Error, Res};
use crate::p11::{PK11SymKey, SymKey};
use crate::result;

use std::os::raw::{c_char, c_uint};
use std::ptr::{null_mut, NonNull};

experimental_api!(SSL_HkdfExtract(
    version: Version,
    cipher: Cipher,
    salt: *mut PK11SymKey,
    ikm: *mut PK11SymKey,
    prk: *mut *mut PK11SymKey,
));
experimental_api!(SSL_HkdfDeriveSecret(
    version: Version,
    cipher: Cipher,
    prk: *mut PK11SymKey,
    label: *const c_char,
    label_len: c_uint,
    secret: *mut *mut PK11SymKey,
));

pub fn extract(version: Version, cipher: Cipher, salt: &SymKey, ikm: &SymKey) -> Res<SymKey> {
    let mut prk: *mut PK11SymKey = null_mut();
    let rv = unsafe { SSL_HkdfExtract(version, cipher, **salt, **ikm, &mut prk) };
    result::result(rv)?;
    match NonNull::new(prk) {
        None => Err(Error::InternalError),
        Some(p) => Ok(SymKey::new(p)),
    }
}

pub fn derive_secret<S: Into<String>>(
    version: Version,
    cipher: Cipher,
    prk: &SymKey,
    label: S,
) -> Res<SymKey> {
    let label_str = label.into();
    let l = label_str.as_bytes();
    let mut secret: *mut PK11SymKey = null_mut();
    let rv = unsafe {
        SSL_HkdfDeriveSecret(
            version,
            cipher,
            **prk,
            l.as_ptr() as *const c_char,
            l.len() as c_uint,
            &mut secret,
        )
    };
    result::result(rv)?;
    match NonNull::new(secret) {
        None => Err(Error::HkdfError),
        Some(p) => Ok(SymKey::new(p)),
    }
}
