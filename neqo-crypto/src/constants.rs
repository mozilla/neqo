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

pub type Extension = u16;
// TODO(mt) - work out why SSLExtensionType isn't being mapped by bindgen.
// macro_rules! ssl_ext {
//     ($n:ident, $v:ident) => {
//         pub const $n: Extension = ssl::SSLExtensionType::$v as Extension;
//     };
// }
// ssl_ext!(TLS_EXT_SERVER_NAME, ssl_server_name_xtn);
// ssl_ext!(TLS_EXT_CERT_STATUS, ssl_cert_status_xtn);
// ssl_ext!(TLS_EXT_GROUPS, ssl_supported_groups_xtn);
// ssl_ext!(TLS_EXT_EC_POINT_FORMATS, ssl_ec_point_formats_xtn);
// ssl_ext!(TLS_EXT_SIG_SCHEMES, ssl_signature_algorithms_xtn);
// ssl_ext!(TLS_EXT_USE_SRTP, ssl_use_srtp_xtn);
// ssl_ext!(TLS_EXT_ALPN, ssl_app_layer_protocol_xtn);
// ssl_ext!(TLS_EXT_SCT, ssl_signed_cert_timestamp_xtn);
// ssl_ext!(TLS_EXT_PADDING, ssl_padding_xtn);
// ssl_ext!(TLS_EXT_EMS, ssl_extended_master_secret_xtn);
// ssl_ext!(TLS_EXT_RECORD_SIZE, ssl_record_size_limit_xtn);
// ssl_ext!(TLS_EXT_SESSION_TICKET, ssl_session_ticket_xtn);
// ssl_ext!(TLS_EXT_PSK, ssl_tls13_pre_shared_key_xtn);
// ssl_ext!(TLS_EXT_EARLY_DATA, ssl_tls13_early_data_xtn);
// ssl_ext!(TLS_EXT_VERSIONS, ssl_tls13_supported_versions_xtn);
// ssl_ext!(TLS_EXT_COOKIE, ssl_tls13_cookie_xtn);
// ssl_ext!(TLS_EXT_PSK_MODES, ssl_tls13_psk_key_exchange_modes_xtn);
// ssl_ext!(TLS_EXT_CA, ssl_tls13_certificate_authorities_xtn);
// ssl_ext!(TLS_EXT_POST_HS_AUTH, ssl_tls13_post_handshake_auth_xtn);
// ssl_ext!(TLS_EXT_CERT_SIG_SCHEMES, ssl_signature_algorithms_cert_xtn);
// ssl_ext!(TLS_EXT_KEY_SHARE, ssl_tls13_key_share_xtn);
// ssl_ext!(TLS_EXT_RENEGOTIATION_INFO, ssl_renegotiation_info_xtn);

pub type Alert = u8;
