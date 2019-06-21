// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::qinfo;
use neqo_crypto::aead::Aead;
use neqo_crypto::hkdf;
use neqo_crypto::hp::{extract_hp, HpKey};

use crate::nss::{Cipher, Epoch, SymKey, TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3};
use crate::recv_stream::RxStreamOrderer;
use crate::send_stream::TxBuffer;

#[derive(Clone, Copy, Debug)]
pub(crate) enum CryptoDxDirection {
    Read,
    Write,
}

#[derive(Debug)]
pub(crate) struct CryptoDxState {
    pub(crate) direction: CryptoDxDirection,
    pub(crate) epoch: Epoch,
    pub(crate) aead: Aead,
    pub(crate) hpkey: HpKey,
}

impl CryptoDxState {
    pub(crate) fn new(
        direction: CryptoDxDirection,
        epoch: Epoch,
        secret: &SymKey,
        cipher: Cipher,
    ) -> CryptoDxState {
        qinfo!(
            "Making {:?} {} CryptoDxState, cipher={}",
            direction,
            epoch,
            cipher
        );
        CryptoDxState {
            direction,
            epoch,
            aead: Aead::new(TLS_VERSION_1_3, cipher, secret, "quic ").unwrap(),
            hpkey: extract_hp(TLS_VERSION_1_3, cipher, secret, "quic hp").unwrap(),
        }
    }

    pub(crate) fn new_initial<S: Into<String>>(
        direction: CryptoDxDirection,
        label: S,
        dcid: &[u8],
    ) -> Option<CryptoDxState> {
        let cipher = TLS_AES_128_GCM_SHA256;
        const INITIAL_SALT: &[u8] = &[
            0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef, 0xcf, 0x80, 0x31, 0x33,
            0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0,
        ];
        let initial_secret = hkdf::extract(
            TLS_VERSION_1_3,
            cipher,
            Some(
                hkdf::import_key(TLS_VERSION_1_3, cipher, INITIAL_SALT)
                    .as_ref()
                    .unwrap(),
            ),
            hkdf::import_key(TLS_VERSION_1_3, cipher, dcid)
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        let secret =
            hkdf::expand_label(TLS_VERSION_1_3, cipher, &initial_secret, &[], label).unwrap();

        Some(CryptoDxState::new(direction, 0, &secret, cipher))
    }
}

#[derive(Debug)]
pub(crate) struct CryptoState {
    pub(crate) epoch: Epoch,
    pub(crate) tx: Option<CryptoDxState>,
    pub(crate) rx: Option<CryptoDxState>,
}

#[derive(Debug, Default)]
pub(crate) struct CryptoStream {
    pub(crate) tx: TxBuffer,
    pub(crate) rx: RxStreamOrderer,
}
