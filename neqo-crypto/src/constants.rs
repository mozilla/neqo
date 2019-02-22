use crate::ssl;

pub type Version = u16;
pub const TLS_VERSION_1_2: Version = ssl::SSL_LIBRARY_VERSION_TLS_1_2 as Version;
pub const TLS_VERSION_1_3: Version = ssl::SSL_LIBRARY_VERSION_TLS_1_3 as Version;

mod ciphers {
    include!(concat!(env!("OUT_DIR"), "/nss_ciphers.rs"));
}

pub type Cipher = u16;
pub const TLS_AES_128_GCM_SHA256: Cipher = ciphers::TLS_AES_128_GCM_SHA256 as Cipher;
pub const TLS_AES_256_GCM_SHA384: Cipher = ciphers::TLS_AES_256_GCM_SHA384 as Cipher;
pub const TLS_CHACHA20_POLY1305_SHA256: Cipher = ciphers::TLS_CHACHA20_POLY1305_SHA256 as Cipher;

pub type Epoch = u16;
