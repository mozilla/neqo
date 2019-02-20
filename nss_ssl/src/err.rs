#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/nspr_error.rs"));
include!(concat!(env!("OUT_DIR"), "/nss_secerr.rs"));
include!(concat!(env!("OUT_DIR"), "/nss_sslerr.rs"));
pub mod NSPRErrorCodes {
    include!(concat!(env!("OUT_DIR"), "/nspr_err.rs"));
}

pub type Res<T> = Result<T, Error>;

// TODO this Error class is awful.  It could probably be a lot better.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    CertificateLoading,
    CreateSslSocket,
    MixedHandshakeMethod,
    NoDataAvailable,
    NssError {
        name: String,
        code: PRErrorCode,
        desc: String,
    },
    OverrunError,
    UnexpectedError,
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error: {:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use crate::err::{NSPRErrorCodes, SECErrorCodes, SSLErrorCodes};
    use crate::init_db;

    #[test]
    fn error_code() {
        init_db("./db");
        assert_eq!(15 - 0x3000, SSLErrorCodes::SSL_ERROR_BAD_MAC_READ);
        assert_eq!(166 - 0x2000, SECErrorCodes::SEC_ERROR_LIBPKIX_INTERNAL);
        assert_eq!(-5998, NSPRErrorCodes::PR_WOULD_BLOCK_ERROR);
    }
}
