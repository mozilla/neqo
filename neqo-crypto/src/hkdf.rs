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
experimental_api!(SSL_HkdfExpandLabel(
    version: Version,
    cipher: Cipher,
    prk: *mut PK11SymKey,
    handshake_hash: *const u8,
    handshake_hash_len: c_uint,
    label: *const c_char,
    label_len: c_uint,
    secret: *mut *mut PK11SymKey,
));

pub fn extract(
    version: Version,
    cipher: Cipher,
    salt: Option<&SymKey>,
    ikm: &SymKey,
) -> Res<SymKey> {
    let mut prk: *mut PK11SymKey = null_mut();
    let salt_ptr: *mut PK11SymKey = match salt {
        Some(s) => **s,
        None => null_mut(),
    };
    let rv = unsafe { SSL_HkdfExtract(version, cipher, salt_ptr, **ikm, &mut prk) };
    result::result(rv)?;
    match NonNull::new(prk) {
        None => Err(Error::InternalError),
        Some(p) => Ok(SymKey::new(p)),
    }
}

pub fn expand_label<S: Into<String>>(
    version: Version,
    cipher: Cipher,
    prk: &SymKey,
    handshake_hash: &[u8],
    label: S,
) -> Res<SymKey> {
    let label_str = label.into();
    let l = label_str.as_bytes();
    let mut secret: *mut PK11SymKey = null_mut();

    // Note that this doesn't allow for passing null() for the handshake hash.
    // A zero-length slice produces an identical result.
    let rv = unsafe {
        SSL_HkdfExpandLabel(
            version,
            cipher,
            **prk,
            handshake_hash.as_ptr(),
            handshake_hash.len() as c_uint,
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
