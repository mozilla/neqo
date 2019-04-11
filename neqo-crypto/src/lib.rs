// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

#[macro_use]
mod exp;
#[macro_use]
pub mod p11;

pub mod aead;
pub mod agent;
mod agentio;
mod cert;
pub mod constants;
mod err;
pub mod ext;
pub mod hkdf;
pub mod hp;
mod prio;
mod result;
mod secrets;
mod ssl;

pub use self::agent::{
    Agent, Client, HandshakeState, Record, RecordList, SecretAgent, SecretAgentInfo,
    SecretAgentPreInfo, Server,
};
pub use self::constants::*;
pub use self::err::{Error, Res};
pub use self::ext::{ExtensionHandler, ExtensionHandlerResult, ExtensionWriterResult};
pub use self::p11::SymKey;
pub use self::secrets::SecretDirection;

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::ptr::null;
use std::sync::Once;

mod nss {
    #![allow(non_upper_case_globals)]

    include!(concat!(env!("OUT_DIR"), "/nss_init.rs"));
}

// Need to map the types through.
fn result(code: nss::SECStatus) -> Res<()> {
    crate::result::result(code as crate::ssl::SECStatus)
}

enum NssLoaded {
    NotLoaded,
    LoadedExternally,
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

unsafe fn already_initialized() -> bool {
    match nss::NSS_IsInitialized() {
        0 => false,
        _ => {
            INITIALIZED = NssLoaded::LoadedExternally;
            true
        }
    }
}

/// Initialize NSS.  This only executes the initialization routines once, so if there is any chance that
pub fn init() {
    unsafe {
        INIT_ONCE.call_once(|| {
            if already_initialized() {
                return;
            }

            let st = nss::NSS_NoDB_Init(null());
            result(st).expect("NSS_NoDB_Init failed");
            let st = nss::NSS_SetDomesticPolicy();
            result(st).expect("NSS_SetDomesticPolicy failed");

            INITIALIZED = NssLoaded::LoadedNoDb;
        });
    }
}

pub fn init_db<P: Into<PathBuf>>(dir: P) {
    unsafe {
        INIT_ONCE.call_once(|| {
            if already_initialized() {
                return;
            }

            let path = dir.into();
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
