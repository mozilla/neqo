#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::constants::*;
use crate::err::{Error, Res};

use std::ops::{Deref, DerefMut};
use std::os::raw::{c_uchar, c_uint};
use std::ptr::{null_mut, NonNull};

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
scoped_ptr!(Slot, PK11SlotInfo, PK11_FreeSlot);

impl SymKey {
    pub fn import(cipher: Cipher, buf: &[u8]) -> Res<SymKey> {
        let mut item = SECItem {
            type_: SECItemType::siBuffer,
            data: buf.as_ptr() as *mut c_uchar,
            len: buf.len() as c_uint,
        };
        let slot_ptr = unsafe { PK11_GetInternalSlot() };
        let slot = match NonNull::new(slot_ptr) {
            None => return Err(Error::InternalError),
            Some(p) => Slot::new(p),
        };
        let mech = match cipher {
            TLS_AES_128_GCM_SHA256 | TLS_CHACHA20_POLY1305_SHA256 => CKM_NSS_HKDF_SHA256,
            TLS_AES_256_GCM_SHA384 => CKM_NSS_HKDF_SHA384,
            _ => return Err(Error::InternalError),
        };
        let key_ptr = unsafe {
            PK11_ImportSymKey(
                *slot,
                mech as u64,
                PK11Origin::PK11_OriginUnwrap,
                CKA_DERIVE as u64,
                &mut item,
                null_mut(),
            )
        };
        Err(Error::InternalError)
    }
}
