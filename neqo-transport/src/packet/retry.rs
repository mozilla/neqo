// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

use crate::packet::QuicVersion;
use crate::{Error, Res};

use neqo_common::qerror;
use neqo_crypto::{aead::Aead, hkdf, TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3};

use std::cell::RefCell;

const RETRY_SECRET_27: &[u8] = &[
    0x65, 0x6e, 0x61, 0xe3, 0x36, 0xae, 0x94, 0x17, 0xf7, 0xf0, 0xed, 0xd8, 0xd7, 0x8d, 0x46, 0x1e,
    0x2a, 0xa7, 0x08, 0x4a, 0xba, 0x7a, 0x14, 0xc1, 0xe9, 0xf7, 0x26, 0xd5, 0x57, 0x09, 0x16, 0x9a,
];
const RETRY_SECRET_29: &[u8] = &[
    0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2, 0x07, 0xd8, 0x0d, 0xf2,
    0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42, 0xc3, 0x0a, 0x8b, 0xaa, 0x2b, 0xaa, 0xff, 0x4c,
];

/// The AEAD used for Retry is fixed, so use thread local storage.
fn make_aead(secret: &[u8]) -> Aead {
    #[cfg(debug_assertions)]
    ::neqo_crypto::assert_initialized();

    let secret = hkdf::import_key(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256, secret).unwrap();
    Aead::new(TLS_VERSION_1_3, TLS_AES_128_GCM_SHA256, &secret, "quic ").unwrap()
}
thread_local!(static RETRY_AEAD_27: RefCell<Aead> = RefCell::new(make_aead(RETRY_SECRET_27)));
thread_local!(static RETRY_AEAD_29: RefCell<Aead> = RefCell::new(make_aead(RETRY_SECRET_29)));

/// Run a function with the appropriate Retry AEAD.
pub fn use_aead<F, T>(quic_version: QuicVersion, f: F) -> Res<T>
where
    F: FnOnce(&Aead) -> Res<T>,
{
    match quic_version {
        QuicVersion::Draft27 | QuicVersion::Draft28 => &RETRY_AEAD_27,
        QuicVersion::Draft29
        | QuicVersion::Draft30
        | QuicVersion::Draft31
        | QuicVersion::Draft32 => &RETRY_AEAD_29,
    }
    .try_with(|aead| f(&aead.borrow()))
    .map_err(|e| {
        qerror!("Unable to access Retry AEAD: {:?}", e);
        Error::InternalError(6)
    })?
}

/// Determine how large the expansion is for a given key.
pub fn expansion(quic_version: QuicVersion) -> usize {
    if let Ok(ex) = use_aead(quic_version, |aead| Ok(aead.expansion())) {
        ex
    } else {
        panic!("Unable to access Retry AEAD")
    }
}
