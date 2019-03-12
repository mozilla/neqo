#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::constants::*;
use crate::err::{Error, Res};
use crate::result;

use std::ops::{Deref, DerefMut};
use std::os::raw::{c_uchar, c_uint};
use std::ptr::{null_mut, NonNull};

include!(concat!(env!("OUT_DIR"), "/nss_p11.rs"));

macro_rules! scoped_ptr {
    ($scoped:ident, $target:ty, $dtor:path) => {
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

#[derive(Clone, Copy, Debug)]
pub enum SymKeyTarget {
    Hkdf(Cipher),
    HpMask(Cipher),
}

impl SymKey {
    pub fn import(target: SymKeyTarget, buf: &[u8]) -> Res<SymKey> {
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
        let mech = match target {
            SymKeyTarget::Hkdf(cipher) => match cipher {
                TLS_AES_128_GCM_SHA256 | TLS_CHACHA20_POLY1305_SHA256 => CKM_NSS_HKDF_SHA256,
                TLS_AES_256_GCM_SHA384 => CKM_NSS_HKDF_SHA384,
                _ => CKM_INVALID_MECHANISM,
            },
            SymKeyTarget::HpMask(cipher) => match cipher {
                TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 => CKM_AES_ECB,
                #[cfg(feature = "chacha")] TLS_CHACHA20_POLY1305_SHA256 => CKM_NSS_CHACHA20_CTR,
                _ => CKM_INVALID_MECHANISM,
            },
        };
        if mech == CKM_INVALID_MECHANISM {
            return Err(Error::InternalError);
        }
        let key_ptr = unsafe {
            PK11_ImportSymKey(
                *slot,
                mech as CK_MECHANISM_TYPE,
                PK11Origin::PK11_OriginUnwrap,
                CKA_DERIVE as CK_ATTRIBUTE_TYPE,
                &mut item,
                null_mut(),
            )
        };
        match NonNull::new(key_ptr) {
            None => Err(Error::InternalError),
            Some(p) => Ok(SymKey::new(p)),
        }
    }

    /// You really don't want to use this.
    pub fn as_bytes<'a>(&'a self) -> Res<&'a [u8]> {
        let rv = unsafe { PK11_ExtractKeyValue(self.ptr) };
        result::result(rv)?;

        let key_item = unsafe { PK11_GetKeyData(self.ptr) };
        // This is accessing a value attached to the key, so we can treat this as a borrow.
        match unsafe { key_item.as_mut() } {
            None => Err(Error::InternalError),
            Some(key) => Ok(unsafe { std::slice::from_raw_parts(key.data, key.len as usize) }),
        }
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SymKey")
    }
}
