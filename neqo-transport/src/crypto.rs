// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cell::RefCell;
use std::cmp::min;
use std::convert::TryInto;
use std::rc::Rc;

use neqo_common::{hex, qdebug, qinfo, qtrace};
use neqo_crypto::aead::Aead;
use neqo_crypto::hp::HpKey;
use neqo_crypto::{
    hkdf, Agent, AntiReplay, Cipher, Epoch, SymKey, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    TLS_VERSION_1_3,
};

use crate::connection::Role;
use crate::frame::{crypto_frame_hdr_len, Frame, TxMode};
use crate::packet::{CryptoCtx, PacketNumber};
use crate::recovery::RecoveryToken;
use crate::recv_stream::RxStreamOrderer;
use crate::send_stream::TxBuffer;
use crate::tparams::{TpZeroRttChecker, TransportParametersHandler};
use crate::{Error, Res};

const MAX_AUTH_TAG: usize = 32;

#[derive(Debug)]
pub(crate) struct Crypto {
    pub(crate) tls: Agent,
    pub(crate) streams: [CryptoStream; 4],
    pub(crate) states: [Option<CryptoState>; 4],
}

impl Crypto {
    pub fn new(
        mut agent: Agent,
        protocols: &[impl AsRef<str>],
        tphandler: Rc<RefCell<TransportParametersHandler>>,
        anti_replay: Option<&AntiReplay>,
    ) -> Res<Crypto> {
        agent.set_version_range(TLS_VERSION_1_3, TLS_VERSION_1_3)?;
        agent.enable_ciphers(&[TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384])?;
        agent.set_alpn(protocols)?;
        agent.disable_end_of_early_data();
        match &mut agent {
            Agent::Client(c) => c.enable_0rtt()?,
            Agent::Server(s) => s.enable_0rtt(
                anti_replay.unwrap(),
                0xffff_ffff,
                TpZeroRttChecker::wrap(tphandler.clone()),
            )?,
        }
        agent.extension_handler(0xffa5, tphandler)?;
        Ok(Crypto {
            tls: agent,
            streams: Default::default(),
            states: Default::default(),
        })
    }

    // Create the initial crypto state.
    pub fn create_initial_state(&mut self, role: Role, dcid: &[u8]) -> CryptoState {
        const CLIENT_INITIAL_LABEL: &str = "client in";
        const SERVER_INITIAL_LABEL: &str = "server in";

        qinfo!(
            [self]
            "Creating initial cipher state role={:?} dcid={}",
            role,
            hex(dcid)
        );

        let (write_label, read_label) = match role {
            Role::Client => (CLIENT_INITIAL_LABEL, SERVER_INITIAL_LABEL),
            Role::Server => (SERVER_INITIAL_LABEL, CLIENT_INITIAL_LABEL),
        };

        CryptoState {
            epoch: 0,
            tx: CryptoDxState::new_initial(CryptoDxDirection::Write, write_label, dcid),
            rx: CryptoDxState::new_initial(CryptoDxDirection::Read, read_label, dcid),
        }
    }

    // Get a crypto state, making it if necessary, otherwise return an error.
    pub fn obtain_crypto_state(&mut self, role: Role, epoch: Epoch) -> Res<&mut CryptoState> {
        #[cfg(debug_assertions)]
        let label = format!("{}", self);
        #[cfg(not(debug_assertions))]
        let label = "";

        let cs = &mut self.states[epoch as usize];
        if cs.is_none() {
            qtrace!([label] "Build crypto state for epoch {}", epoch);
            assert!(epoch != 0); // This state is made directly.

            let cipher = match (epoch, self.tls.info()) {
                (1, _) => self.tls.preinfo()?.early_data_cipher(),
                (_, None) => self.tls.preinfo()?.cipher_suite(),
                (_, Some(info)) => Some(info.cipher_suite()),
            };
            if cipher.is_none() {
                qdebug!([label] "cipher info not available yet");
                return Err(Error::KeysNotFound);
            }
            let cipher = cipher.unwrap();

            let rx = self
                .tls
                .read_secret(epoch)
                .map(|rs| CryptoDxState::new(CryptoDxDirection::Read, epoch, rs, cipher));
            let tx = self
                .tls
                .write_secret(epoch)
                .map(|ws| CryptoDxState::new(CryptoDxDirection::Write, epoch, ws, cipher));

            // Validate the key setup.
            match (&rx, &tx, role, epoch) {
                (None, Some(_), Role::Client, 1)
                | (Some(_), None, Role::Server, 1)
                | (Some(_), Some(_), _, _) => {}
                (None, None, _, _) => {
                    qdebug!([label] "Keying material not available for epoch {}", epoch);
                    return Err(Error::KeysNotFound);
                }
                _ => panic!("bad configuration of keys"),
            }

            *cs = Some(CryptoState { epoch, rx, tx });
        }

        Ok(cs.as_mut().unwrap())
    }

    pub fn acked(&mut self, token: CryptoRecoveryToken) {
        qinfo!(
            "Acked crypto frame epoch={} offset={} length={}",
            token.epoch,
            token.offset,
            token.length
        );
        self.streams[token.epoch as usize]
            .tx
            .mark_as_acked(token.offset, token.length);
    }

    pub fn lost(&mut self, token: CryptoRecoveryToken) {
        qinfo!(
            "Lost crypto frame epoch={} offset={} length={}",
            token.epoch,
            token.offset,
            token.length
        );
        self.streams[token.epoch as usize]
            .tx
            .mark_as_lost(token.offset, token.length);
    }

    pub fn retry(&mut self) {
        let sent = self.streams[0].tx.highest_sent();
        self.streams[0].tx.mark_as_lost(0, sent.try_into().unwrap());

        for s in &self.streams[1..] {
            debug_assert_eq!(s.tx.highest_sent(), 0);
        }
    }

    pub fn get_frame(
        &mut self,
        epoch: u16,
        mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<RecoveryToken>)> {
        let tx_stream = &mut self.streams[epoch as usize].tx;
        if let Some((offset, data)) = tx_stream.next_bytes(mode) {
            let frame_hdr_len = crypto_frame_hdr_len(offset, remaining);
            let length = min(data.len(), remaining - frame_hdr_len);
            let frame = Frame::Crypto {
                offset,
                data: data[..length].to_vec(),
            };
            tx_stream.mark_as_sent(offset, length);

            qdebug!(
                "Emitting crypto frame epoch={}, offset={}, len={}",
                epoch,
                offset,
                length
            );
            Some((
                frame,
                Some(RecoveryToken::Crypto(CryptoRecoveryToken {
                    epoch,
                    offset,
                    length,
                })),
            ))
        } else {
            None
        }
    }
}

impl ::std::fmt::Display for Crypto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Crypto")
    }
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
    pub fn new(
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
            hpkey: HpKey::extract(TLS_VERSION_1_3, cipher, secret, "quic hp").unwrap(),
        }
    }

    pub fn new_initial<S: Into<String>>(
        direction: CryptoDxDirection,
        label: S,
        dcid: &[u8],
    ) -> Option<CryptoDxState> {
        const INITIAL_SALT: &[u8] = &[
            0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51,
            0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a,
        ];
        let cipher = TLS_AES_128_GCM_SHA256;
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

impl CryptoCtx for CryptoDxState {
    fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>> {
        let mask = self.hpkey.mask(sample)?;
        qdebug!("HP sample={} mask={}", hex(sample), hex(&mask));
        Ok(mask)
    }

    fn aead_decrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
        qinfo!(
            [self]
            "aead_decrypt pn={} hdr={} body={}",
            pn,
            hex(hdr),
            hex(body)
        );
        let mut out = vec![0; body.len()];
        let res = self.aead.decrypt(pn, hdr, body, &mut out)?;
        Ok(res.to_vec())
    }

    fn aead_encrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
        qdebug!(
            [self]
            "aead_encrypt pn={} hdr={} body={}",
            pn,
            hex(hdr),
            hex(body)
        );

        let size = body.len() + MAX_AUTH_TAG;
        let mut out = vec![0; size];
        let res = self.aead.encrypt(pn, hdr, body, &mut out)?;

        qdebug!([self] "aead_encrypt ct={}", hex(res),);

        Ok(res.to_vec())
    }
}

impl std::fmt::Display for CryptoDxState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "epoch {} {:?}", self.epoch, self.direction)
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

#[derive(Debug)]
pub(crate) struct CryptoRecoveryToken {
    epoch: u16,
    offset: u64,
    length: usize,
}
