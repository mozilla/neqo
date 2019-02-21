use crate::ssl;

pub const TLS_VERSION_1_2: u16 = ssl::SSL_LIBRARY_VERSION_TLS_1_2 as u16;
pub const TLS_VERSION_1_3: u16 = ssl::SSL_LIBRARY_VERSION_TLS_1_3 as u16;

mod ciphers {
    include!(concat!(env!("OUT_DIR"), "/nss_ciphers.rs"));
}

pub const TLS_AES_128_GCM_SHA256: u16 = ciphers::TLS_AES_128_GCM_SHA256 as u16;
pub const TLS_AES_256_GCM_SHA384: u16 = ciphers::TLS_AES_256_GCM_SHA384 as u16;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = ciphers::TLS_CHACHA20_POLY1305_SHA256 as u16;
