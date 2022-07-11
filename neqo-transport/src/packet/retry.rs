// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

use crate::version::Version;
use crate::{Error, Res};

use neqo_common::qerror;
use neqo_crypto::{hkdf, Aead, TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3};

use std::cell::RefCell;

/// The AEAD used for Retry is fixed, so use thread local storage.
fn make_aead(
    version: Version,
    #[cfg(feature = "fuzzing")]
    fuzzing_mode: bool,
) -> Aead {
    #[cfg(debug_assertions)]
    ::neqo_crypto::assert_initialized();

    let secret = hkdf::import_key(TLS_VERSION_1_3, version.retry_secret()).unwrap();
    Aead::new(
        TLS_VERSION_1_3,
        TLS_AES_128_GCM_SHA256,
        &secret,
        version.label_prefix(),
        #[cfg(feature = "fuzzing")]
        fuzzing_mode,
    )
    .unwrap()
}
thread_local!(static RETRY_AEAD_29: RefCell<Aead> = RefCell::new(make_aead(
    Version::Draft29,
    #[cfg(feature = "fuzzing")]
    false,
)));
thread_local!(static RETRY_AEAD_V1: RefCell<Aead> = RefCell::new(make_aead(
    Version::Version1,
    #[cfg(feature = "fuzzing")]
    false,
)));
thread_local!(static RETRY_AEAD_V2: RefCell<Aead> = RefCell::new(make_aead(
    Version::Version2,
    #[cfg(feature = "fuzzing")]
    false,
)));
#[cfg(feature = "fuzzing")]
thread_local!(static RETRY_AEAD_29_FUZZ: RefCell<Aead> = RefCell::new(make_aead(Version::Draft29, true)));
#[cfg(feature = "fuzzing")]
thread_local!(static RETRY_AEAD_V1_FUZZ: RefCell<Aead> = RefCell::new(make_aead(Version::Version1, true)));
#[cfg(feature = "fuzzing")]
thread_local!(static RETRY_AEAD_V2_FUZZ: RefCell<Aead> = RefCell::new(make_aead(Version::Version2, true)));


/// Run a function with the appropriate Retry AEAD.
pub fn use_aead<F, T>(
    version: Version,
    #[cfg(feature = "fuzzing")]
    fuzzing_mode: bool,
    f: F,
) -> Res<T>
where
    F: FnOnce(&Aead) -> Res<T>,
{
    match version {
        Version::Version2 => {
            #[cfg(feature = "fuzzing")]
            if fuzzing_mode {
                &RETRY_AEAD_V2_FUZZ
            } else {
                &RETRY_AEAD_V2
            }
            #[cfg(not(feature = "fuzzing"))]
            &RETRY_AEAD_V2
        },
        Version::Version1 => {
            #[cfg(feature = "fuzzing")]
            if fuzzing_mode {
                &RETRY_AEAD_V1_FUZZ
            } else {
                &RETRY_AEAD_V1
            }
            #[cfg(not(feature = "fuzzing"))]
            &RETRY_AEAD_V1
        },
        Version::Draft29 | Version::Draft30 | Version::Draft31 | Version::Draft32 => {
            #[cfg(feature = "fuzzing")]
            if fuzzing_mode {
                &RETRY_AEAD_29_FUZZ
            } else {
                &RETRY_AEAD_29
            }
            #[cfg(not(feature = "fuzzing"))]
            &RETRY_AEAD_29
        },
    }
    .try_with(|aead| f(&aead.borrow()))
    .map_err(|e| {
        qerror!("Unable to access Retry AEAD: {:?}", e);
        Error::InternalError(6)
    })?
}

/// Determine how large the expansion is for a given key.
pub fn expansion(
    version: Version,
    #[cfg(feature = "fuzzing")]
    fuzzing_mode: bool,
) -> usize {
    if let Ok(ex) = use_aead(
        version,
        #[cfg(feature = "fuzzing")]
        fuzzing_mode,
        |aead| Ok(aead.expansion())
    ) {
        ex
    } else {
        panic!("Unable to access Retry AEAD")
    }
}
