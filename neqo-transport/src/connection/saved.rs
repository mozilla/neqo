// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::mem;
use std::time::Instant;

use crate::crypto::CryptoSpace;
use neqo_common::{qdebug, qinfo, Datagram};

/// The number of datagrams that are saved during the handshake when
/// keys to decrypt them are not yet available.
///
/// This value exceeds what should be possible to send during the handshake.
/// Neither endpoint should have enough congestion window to send this
/// much before the handshake completes.
const MAX_SAVED_DATAGRAMS: usize = 32;

pub struct SavedDatagram {
    /// The datagram.
    pub d: Datagram,
    /// The time that the datagram was received.
    pub t: Instant,
}

#[derive(Default)]
pub struct SavedDatagrams {
    handshake: Vec<SavedDatagram>,
    application_data: Vec<SavedDatagram>,
}

impl SavedDatagrams {
    fn store(&mut self, cspace: CryptoSpace) -> &mut Vec<SavedDatagram> {
        match cspace {
            CryptoSpace::Handshake => &mut self.handshake,
            CryptoSpace::ApplicationData => &mut self.application_data,
            _ => panic!("unexpected space"),
        }
    }

    pub fn save(&mut self, cspace: CryptoSpace, d: Datagram, t: Instant) {
        let store = self.store(cspace);

        if store.len() < MAX_SAVED_DATAGRAMS {
            qdebug!("saving datagram of {} bytes", d.len());
            store.push(SavedDatagram { d, t });
        } else {
            qinfo!("not saving datagram of {} bytes", d.len());
        }
    }

    pub fn take_saved(&mut self, cspace: CryptoSpace) -> Vec<SavedDatagram> {
        mem::take(self.store(cspace))
    }
}
