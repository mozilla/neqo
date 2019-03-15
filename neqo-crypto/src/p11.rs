#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::err::{Error, Res};
use crate::result;

use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

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

impl SymKey {
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
