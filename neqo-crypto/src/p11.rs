#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ops::Deref;

include!(concat!(env!("OUT_DIR"), "/nss_p11.rs"));

macro_rules! scoped_ptr {
    ($scoped:ident, $target:ident, $dtor:ident) => {
        // TODO(mt) build the macro
    };
}

pub struct ScopedCertificate(pub *mut CERTCertificate);

impl Drop for ScopedCertificate {
    fn drop(&mut self) {
        unsafe {
            CERT_DestroyCertificate(self.0);
        }
    }
}

impl Deref for ScopedCertificate {
    type Target = *mut CERTCertificate;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ScopedPrivateKey(pub *mut SECKEYPrivateKey);

impl Drop for ScopedPrivateKey {
    fn drop(&mut self) {
        unsafe {
            SECKEY_DestroyPrivateKey(self.0);
        }
    }
}

impl Deref for ScopedPrivateKey {
    type Target = *mut SECKEYPrivateKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
