#[macro_use]
mod p11;

mod aead;
mod agent;
mod agentio;
mod constants;
mod err;
mod prio;
mod result;
mod ssl;

pub use crate::aead::Aead;
pub use crate::agent::{Agent, Client, HandshakeState, Server};
pub use crate::constants::*;
use crate::err::Res;
pub use crate::p11::SymKey;

use std::ffi::CString;
use std::path::Path;
use std::ptr::null;
use std::sync::Once;

mod nss {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]

    include!(concat!(env!("OUT_DIR"), "/nss_init.rs"));
}

// Need to map the types through.
fn result(code: nss::SECStatus) -> Res<()> {
    crate::result::result(code as crate::ssl::SECStatus)
}

enum NssLoaded {
    NotLoaded,
    LoadedNoDb,
    LoadedDb(Box<Path>),
}

impl Drop for NssLoaded {
    fn drop(&mut self) {
        match self {
            NssLoaded::LoadedNoDb | NssLoaded::LoadedDb(_) => unsafe {
                result(nss::NSS_Shutdown()).expect("NSS Shutdown failed")
            },
            _ => {}
        }
    }
}

static mut INITIALIZED: NssLoaded = NssLoaded::NotLoaded;
static INIT_ONCE: Once = Once::new();

// Grab one of these to make sure that NSS is initialized.
pub fn init() {
    unsafe {
        INIT_ONCE.call_once(|| {
            let initialized = nss::NSS_IsInitialized() != 0;
            if initialized {
                panic!("Already initialized")
            }

            let st = nss::NSS_NoDB_Init(null());
            result(st).expect("NSS_NoDB_Init failed");
            let st = nss::NSS_SetDomesticPolicy();
            result(st).expect("NSS_SetDomesticPolicy failed");

            INITIALIZED = NssLoaded::LoadedNoDb;
        });
    }
}

pub fn init_db(dir: &str) {
    unsafe {
        INIT_ONCE.call_once(|| {
            let initialized = nss::NSS_IsInitialized() != 0;
            if initialized {
                panic!("NSS is already initialized")
            }

            let path = Path::new(dir);
            assert!(path.is_dir());
            let pathstr = path.to_str().expect("path converts to string").to_string();
            let dircstr = CString::new(pathstr).expect("new CString");
            let empty = CString::new("").expect("new empty CString");
            let st = nss::NSS_Initialize(
                dircstr.as_ptr(),
                empty.as_ptr(),
                empty.as_ptr(),
                nss::SECMOD_DB.as_ptr() as *const i8,
                nss::NSS_INIT_READONLY,
            );
            result(st).expect("NSS_Initialize failed");

            let st = nss::NSS_SetDomesticPolicy();
            result(st).expect("NSS_SetDomesticPolicy failed");

            let st = ssl::SSL_ConfigServerSessionIDCache(1024, 0, 0, dircstr.as_ptr());
            result(st).expect("SSL_ConfigServerSessionIDCache failed");

            INITIALIZED = NssLoaded::LoadedDb(path.to_path_buf().into_boxed_path());
        });
    }
}

pub fn initialized() -> bool {
    unsafe {
        match INITIALIZED {
            NssLoaded::NotLoaded => false,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_nodb() {
        init();
        unsafe {
            if let NssLoaded::NotLoaded = INITIALIZED {
                panic!("not initialized");
            }
            assert!(nss::NSS_IsInitialized() != 0);
        }
    }

    #[test]
    fn init_withdb() {
        init_db("./db");
        unsafe {
            if let NssLoaded::NotLoaded = INITIALIZED {
                panic!("not initialized");
            }
            assert!(nss::NSS_IsInitialized() != 0);
        }
    }
}
