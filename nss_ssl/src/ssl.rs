#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{c_void, CString};
use std::mem::transmute;

include!(concat!(env!("OUT_DIR"), "/nss_ssl.rs"));
mod SSLOption {
    include!(concat!(env!("OUT_DIR"), "/nss_sslopt.rs"));
}

// I clearly don't understand how bindgen operates.
pub enum PRFileDesc {}

// Remap some constants.
pub const TLS_VERSION_1_2: u16 = SSL_LIBRARY_VERSION_TLS_1_2 as u16;
pub const TLS_VERSION_1_3: u16 = SSL_LIBRARY_VERSION_TLS_1_3 as u16;
pub const SECSuccess: SECStatus = _SECStatus_SECSuccess;
pub const SECFailure: SECStatus = _SECStatus_SECFailure;

#[derive(Debug)]
pub enum Opt {
    Locking,
    Tickets,
    OcspStapling,
    Alpn,
    ExtendedMasterSecret,
    SignedCertificateTimestamps,
    EarlyData,
    RecordSizeLimit,
    Tls13CompatMode,
    HelloDowngradeCheck,
}

impl Opt {
    pub fn as_int(&self) -> PRInt32 {
        let i = match self {
            Opt::Locking => SSLOption::SSL_NO_LOCKS,
            Opt::Tickets => SSLOption::SSL_ENABLE_SESSION_TICKETS,
            Opt::OcspStapling => SSLOption::SSL_ENABLE_OCSP_STAPLING,
            Opt::Alpn => SSLOption::SSL_ENABLE_ALPN,
            Opt::ExtendedMasterSecret => SSLOption::SSL_ENABLE_EXTENDED_MASTER_SECRET,
            Opt::SignedCertificateTimestamps => SSLOption::SSL_ENABLE_SIGNED_CERT_TIMESTAMPS,
            Opt::EarlyData => SSLOption::SSL_ENABLE_0RTT_DATA,
            Opt::RecordSizeLimit => SSLOption::SSL_RECORD_SIZE_LIMIT,
            Opt::Tls13CompatMode => SSLOption::SSL_ENABLE_TLS13_COMPAT_MODE,
            Opt::HelloDowngradeCheck => SSLOption::SSL_ENABLE_HELLO_DOWNGRADE_CHECK,
        };
        i as PRInt32
    }

    // Some options are backwards, like SSL_NO_LOCKS, so use this to manage that.
    pub fn map_enabled(&self, enabled: bool) -> PRIntn {
        let v = match self {
            Opt::Locking => !enabled,
            _ => enabled,
        };
        v as PRIntn
    }
}

macro_rules! experimental_api {
    ( $n:ident ( $( $a:ident : $t:ty ),* ) ) => {
        pub unsafe fn $n ( $( $a : $t ),* ) -> SECStatus {
            const EXP_FUNCTION: &str = "$n";
            let n = CString::new(EXP_FUNCTION).unwrap();
            let f = SSL_GetExperimentalAPI(n.as_ptr());
            if f.is_null() {
                return SECFailure;
            }
            let f: unsafe extern "C" fn( $( $t ),* ) -> SECStatus = transmute(f);
            f( $( $a ),* )
        }
    };
    ( $n:ident ( $( $a:ident : $t:ty , )* ) ) => {
        experimental_api!($n( $( $a : $t ),* ));
    };
}

experimental_api!(SSL_SetResumptionTokenCallback(
    fd: *mut PRFileDesc,
    cb: SSLResumptionTokenCallback,
    ctx: *mut c_void
));

#[cfg(test)]
mod tests {
    use super::{SSL_GetNumImplementedCiphers, SSL_NumImplementedCiphers};

    #[test]
    fn num_ciphers() {
        assert!(unsafe { SSL_NumImplementedCiphers } > 0);
        assert!(unsafe { SSL_GetNumImplementedCiphers() } > 0);
        assert_eq!(unsafe { SSL_NumImplementedCiphers }, unsafe {
            SSL_GetNumImplementedCiphers()
        });
    }
}
