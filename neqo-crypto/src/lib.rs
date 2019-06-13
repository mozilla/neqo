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
mod convert;
mod err;
pub mod ext;
pub mod hkdf;
pub mod hp;
mod prio;
mod replay;
mod result;
mod secrets;
mod ssl;
pub mod time;

pub use self::agent::{
    Agent, Client, HandshakeState, Record, RecordList, SecretAgent, SecretAgentInfo,
    SecretAgentPreInfo, Server, ZeroRttCheckResult, ZeroRttChecker,
};
pub use self::constants::*;
pub use self::err::{Error, Res, SSLErrorCodes};
pub use self::ext::{ExtensionHandler, ExtensionHandlerResult, ExtensionWriterResult};
pub use self::p11::SymKey;
pub use self::replay::AntiReplay;
pub use self::secrets::SecretDirection;

use neqo_common::once::OnceResult;

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::ptr::null;

mod nss {
    #![allow(non_upper_case_globals)]
    #![allow(clippy::const_static_lifetime)]
    include!(concat!(env!("OUT_DIR"), "/nss_init.rs"));
}

// Need to map the types through.
fn result(code: nss::SECStatus) -> Res<()> {
    crate::result::result(code as crate::ssl::SECStatus)
}

enum NssLoaded {
    External,
    NoDb,
    Db(Box<Path>),
}

impl Drop for NssLoaded {
    fn drop(&mut self) {
        match self {
            NssLoaded::NoDb | NssLoaded::Db(_) => unsafe {
                result(nss::NSS_Shutdown()).expect("NSS Shutdown failed")
            },
            _ => {}
        }
    }
}

static mut INITIALIZED: OnceResult<NssLoaded> = OnceResult::new();

unsafe fn already_initialized() -> bool {
    nss::NSS_IsInitialized() != 0
}

/// Initialize NSS.  This only executes the initialization routines once, so if there is any chance that
pub fn init() {
    // Set time zero.
    time::init();
    unsafe {
        INITIALIZED.call_once(|| {
            if already_initialized() {
                return NssLoaded::External;
            }

            let st = nss::NSS_NoDB_Init(null());
            result(st).expect("NSS_NoDB_Init failed");
            let st = nss::NSS_SetDomesticPolicy();
            result(st).expect("NSS_SetDomesticPolicy failed");

            NssLoaded::NoDb
        });
    }
}

pub fn init_db<P: Into<PathBuf>>(dir: P) {
    time::init();
    unsafe {
        INITIALIZED.call_once(|| {
            if already_initialized() {
                return NssLoaded::External;
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

            NssLoaded::Db(path.to_path_buf().into_boxed_path())
        });
    }
}

/// Panic if NSS isn't initialized.
pub fn assert_initialized() {
    unsafe {
        INITIALIZED.call_once(|| {
            panic!("NSS not initialized with init or init_db");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(nss_nodb)]
    #[test]
    fn init_nodb() {
        init();
        unsafe {
            assert_initialized();
            assert!(nss::NSS_IsInitialized() != 0);
        }
    }

    #[cfg(not(nss_nodb))]
    #[test]
    fn init_withdb() {
        init_db("./db");
        assert_initialized();
        unsafe {
            assert!(nss::NSS_IsInitialized() != 0);
        }
    }
}
