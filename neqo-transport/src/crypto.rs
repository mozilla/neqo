// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Instant;

use neqo_common::{qdebug, qinfo};
use neqo_crypto::aead::Aead;
use neqo_crypto::hp::{extract_hp, HpKey};
use neqo_crypto::{hkdf, Cipher, Epoch, SymKey, TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3};

use crate::frame::{Frame, FrameGenerator, FrameGeneratorToken, TxMode};
use crate::recv_stream::RxStreamOrderer;
use crate::send_stream::TxBuffer;
use crate::Connection;

#[derive(Debug, Default)]
pub(crate) struct Crypto {
    pub(crate) streams: [CryptoStream; 4],
    pub(crate) states: [Option<CryptoState>; 4],
}

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

#[derive(Debug, Default)]
pub(crate) struct CryptoGenerator {}

impl FrameGenerator for CryptoGenerator {
    fn generate(
        &mut self,
        conn: &mut Connection,
        _now: Instant,
        epoch: u16,
        mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        let tx_stream = &mut conn.crypto.streams[epoch as usize].tx;
        if let Some((offset, data)) = tx_stream.next_bytes(mode) {
            let data_len = data.len();
            assert!(data_len <= remaining);
            let frame = Frame::Crypto {
                offset,
                data: data.to_vec(),
            };
            tx_stream.mark_as_sent(offset, data_len);

            qdebug!(
                [conn]
                "Emitting crypto frame epoch={}, offset={}, len={}",
                epoch,
                offset,
                data_len
            );
            Some((
                frame,
                Some(Box::new(CryptoGeneratorToken {
                    epoch,
                    offset,
                    length: data_len as u64,
                })),
            ))
        } else {
            None
        }
    }
}

struct CryptoGeneratorToken {
    epoch: u16,
    offset: u64,
    length: u64,
}

impl FrameGeneratorToken for CryptoGeneratorToken {
    fn acked(&mut self, conn: &mut Connection) {
        qinfo!(
            [conn]
            "Acked crypto frame epoch={} offset={} length={}",
            self.epoch,
            self.offset,
            self.length
        );
        conn.crypto.streams[self.epoch as usize]
            .tx
            .mark_as_acked(self.offset, self.length as usize);
    }
    fn lost(&mut self, _conn: &mut Connection) {
        // TODO(agrover@mozilla.com): @ekr: resend?
    }
}
