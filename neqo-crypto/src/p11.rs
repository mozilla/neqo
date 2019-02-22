#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::err::{Error, Res};

use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

include!(concat!(env!("OUT_DIR"), "/nss_p11.rs"));

macro_rules! scoped_ptr {
    ($scoped:ident, $target:path, $dtor:path) => {
        pub struct $scoped {
            ptr: *mut $target,
        }

        impl $scoped {
            pub fn new(ptr: NonNull<$target>) -> $scoped {
                $scoped { ptr: ptr.as_ptr() }
            }
        }

        impl Deref for $scoped {
            type Target = *mut $target;
            fn deref(&self) -> &*mut $target {
                &self.ptr
            }
        }

        impl DerefMut for $scoped {
            fn deref_mut(&mut self) -> &mut *mut $target {
                &mut self.ptr
            }
        }

        impl Drop for $scoped {
            fn drop(&mut self) {
                unsafe { $dtor(self.ptr) };
            }
        }
    };
}

scoped_ptr!(Certificate, CERTCertificate, CERT_DestroyCertificate);
scoped_ptr!(PrivateKey, SECKEYPrivateKey, SECKEY_DestroyPrivateKey);
scoped_ptr!(SymKey, PK11SymKey, PK11_FreeSymKey);

impl SymKey {
    pub fn import(buf: &[u8]) -> Res<SymKey> {
        // SECItem zeroItem = {
        //     siBuffer,
        //     (unsigned char *)zeroKeyBuf,
        //     kTlsHkdfInfo[baseHash].hashSize
        // };
        // slot = PK11_GetInternalSlot();
        // if (!slot) {
        //     return SECFailure;
        // }
        // zeroKey = PK11_ImportSymKey(slot,
        //                             kTlsHkdfInfo[baseHash].pkcs11Mech,
        //                             PK11_OriginUnwrap,
        //                             CKA_DERIVE, &zeroItem, NULL);
        // if (!zeroKey)
        //     return SECFailure;
        Err(Error::InternalError)
    }
}
