// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::constants::{Cipher, Version};
use crate::err::{Error, Res};
use crate::p11::SymKey;
use std::fmt;

pub struct Aead {}

impl Aead {
    pub fn new(_version: Version, _cipher: Cipher, _secret: &SymKey, _prefix: &str) -> Res<Self> {
        Ok(Self {})
    }

    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn expansion(&self) -> usize {
        16
    }

    #[allow(clippy::unused_self)]
    pub fn encrypt<'a>(
        &self,
        _count: u64,
        _aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let l = input.len();
        output[..l].copy_from_slice(input);
        output[l..l + 16].copy_from_slice(&[0; 16]);
        Ok(&output[..l + 16])
    }

    pub fn decrypt<'a>(
        &self,
        _count: u64,
        _aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let l = input.len();
        // Check that:
        // 1) expansion is all zeros and
        // 2) if the encrypted data is also supplied that at least some values
        //    are no zero (otherwise padding will be interpreted as a valid packet)
        if input[l - 16..l].iter().all(|x| *x == 0x0) && (l == 16  || input[..l - 16].iter().any(|x| *x != 0x0)) {
            output[..l].copy_from_slice(input);
            Ok(&output[..l - 16])
        } else {
            Err(Error::NssError {
                name: "SEC_ERROR_BAD_DATA".to_string(),
                code: -8190,
                desc: "security library: received bad data.".to_string(),
            })
        }
    }
}

impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[AEAD Context]")
    }
}
