// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(dead_code)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/nspr_error.rs"));
include!(concat!(env!("OUT_DIR"), "/nss_secerr.rs"));
include!(concat!(env!("OUT_DIR"), "/nss_sslerr.rs"));
pub mod NSPRErrorCodes {
    include!(concat!(env!("OUT_DIR"), "/nspr_err.rs"));
}

pub type Res<T> = Result<T, Error>;

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
#[allow(clippy::pub_enum_variant_names)]
pub enum Error {
    AeadInitFailure,
    AeadError,
    CertificateLoading,
    CreateSslSocket,
    HkdfError,
    InternalError,
    IntegerOverflow,
    InvalidEpoch,
    MixedHandshakeMethod,
    NoDataAvailable,
    NssError {
        name: String,
        code: PRErrorCode,
        desc: String,
    },
    OverrunError,
    TimeTravelError,
    UnsupportedCipher,
    UnsupportedVersion,
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

// TryFromIntError is only ever used in time.rs for time conversion.
impl From<std::num::TryFromIntError> for Error {
    fn from(_: std::num::TryFromIntError) -> Self {
        Error::TimeTravelError
    }
}

#[cfg(test)]
mod tests {
    use crate::err::{NSPRErrorCodes, SECErrorCodes, SSLErrorCodes};
    use test_fixture::fixture_init;

    #[test]
    fn error_code() {
        fixture_init();
        assert_eq!(15 - 0x3000, SSLErrorCodes::SSL_ERROR_BAD_MAC_READ);
        assert_eq!(166 - 0x2000, SECErrorCodes::SEC_ERROR_LIBPKIX_INTERNAL);
        assert_eq!(-5998, NSPRErrorCodes::PR_WOULD_BLOCK_ERROR);
    }
}
