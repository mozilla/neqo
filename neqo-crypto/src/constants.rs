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

pub type Group = u16;
pub const TLS_GRP_EC_SECP256R1: Group = ssl::SSLNamedGroup::ssl_grp_ec_secp256r1 as Group;
pub const TLS_GRP_EC_SECP384R1: Group = ssl::SSLNamedGroup::ssl_grp_ec_secp384r1 as Group;
pub const TLS_GRP_EC_SECP521R1: Group = ssl::SSLNamedGroup::ssl_grp_ec_secp521r1 as Group;
pub const TLS_GRP_EC_X25519: Group = ssl::SSLNamedGroup::ssl_grp_ec_curve25519 as Group;
