// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::constants::*;
use crate::convert::to_c_uint;
use crate::err::{Error, Res};
use crate::p11::{
    PK11Origin, PK11SymKey, PK11_GetInternalSlot, PK11_ImportSymKey, SECItem, SECItemType, Slot,
    SymKey, CKA_DERIVE, CKM_INVALID_MECHANISM, CKM_NSS_HKDF_SHA256, CKM_NSS_HKDF_SHA384,
    CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE,
};
use crate::result;

use std::os::raw::{c_char, c_uchar, c_uint};
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

/// Import a symmetric key for use with HKDF.
pub fn import_key(version: Version, cipher: Cipher, buf: &[u8]) -> Res<SymKey> {
    if version != TLS_VERSION_1_3 {
        return Err(Error::UnsupportedVersion);
    }
    let mech = match cipher {
        TLS_AES_128_GCM_SHA256 | TLS_CHACHA20_POLY1305_SHA256 => CKM_NSS_HKDF_SHA256,
        TLS_AES_256_GCM_SHA384 => CKM_NSS_HKDF_SHA384,
        _ => CKM_INVALID_MECHANISM,
    };
    if mech == CKM_INVALID_MECHANISM {
        return Err(Error::UnsupportedCipher);
    }
    let mut item = SECItem {
        type_: SECItemType::siBuffer,
        data: buf.as_ptr() as *mut c_uchar,
        len: to_c_uint(buf.len())?,
    };
    let slot_ptr = unsafe { PK11_GetInternalSlot() };
    let slot = match NonNull::new(slot_ptr) {
        Some(p) => Slot::new(p),
        None => return Err(Error::InternalError),
    };
    let key_ptr = unsafe {
        PK11_ImportSymKey(
            *slot,
            CK_MECHANISM_TYPE::from(mech),
            PK11Origin::PK11_OriginUnwrap,
            CK_ATTRIBUTE_TYPE::from(CKA_DERIVE),
            &mut item,
            null_mut(),
        )
    };
    match NonNull::new(key_ptr) {
        Some(p) => Ok(SymKey::new(p)),
        None => Err(Error::InternalError),
    }
}

/// Extract a PRK from the given salt and IKM using the algorithm defined in RFC 5869.
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
        Some(p) => Ok(SymKey::new(p)),
        None => Err(Error::InternalError),
    }
}

/// Expand a PRK using the HKDF-Expand-Label function defined in RFC 8446.
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
            to_c_uint(handshake_hash.len())?,
            l.as_ptr() as *const c_char,
            to_c_uint(l.len())?,
            &mut secret,
        )
    };
    result::result(rv)?;
    match NonNull::new(secret) {
        Some(p) => Ok(SymKey::new(p)),
        None => Err(Error::HkdfError),
    }
}
