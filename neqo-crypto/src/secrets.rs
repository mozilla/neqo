use crate::aead::Aead;
use crate::constants::*;
use crate::err::{Error, Res};
use crate::p11:: SymKey;
use crate::ssl::SSLSecretDirection;

#[derive(Default)]
pub struct Secrets {
    r: DirectionalSecrets,
    w: DirectionalSecrets,
}

impl Secrets {
    pub fn put(&mut self, epoch: Epoch, dir: SSLSecretDirection::Type, key: SymKey) {
        let keys = match dir {
            SSLSecretDirection::ssl_secret_read => &mut self.r,
            SSLSecretDirection::ssl_secret_write => &mut self.w,
            _ => unreachable!(),
        };
        keys.put(epoch, key);
    }

    pub fn read(&self) -> &DirectionalSecrets {
        &self.r
    }

    pub fn write(&self) -> &DirectionalSecrets {
        &self.w
    }
}

#[derive(Default)]
pub struct DirectionalSecrets {
    // We only need to maintain 4 secrets for the epochs used during the handshake.
    secrets: [Option<SymKey>; 4],
}

impl DirectionalSecrets {
    pub fn put(&mut self, epoch: Epoch, key: SymKey) {
        let i = epoch as usize;
        assert!(i < self.secrets.len());
        assert!(self.secrets[i].is_none());
        self.secrets[i] = Some(key);
    }

    pub fn make_aead<S: Into<String>>(
        &self,
        epoch: Epoch,
        version: Version,
        cipher: Cipher,
        prefix: S,
    ) -> Res<Aead> {
        let i = epoch as usize;
        if i >= self.secrets.len() {
            return Err(Error::InvalidEpoch);
        }
        match &self.secrets[i] {
            None => Err(Error::InvalidEpoch),
            Some(secret) => Aead::new(version, cipher, &secret, prefix),
        }
    }
}
