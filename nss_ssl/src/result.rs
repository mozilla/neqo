use crate::err::{
    Error, NSPRErrorCodes, PR_ErrorToName, PR_ErrorToString, PR_GetError, Res,
    PR_LANGUAGE_I_DEFAULT,
};
use crate::ssl;

use std::ffi::CStr;

pub fn result(rv: ssl::SECStatus) -> Res<()> {
    let _ = result_helper(rv, false)?;
    Ok(())
}

pub fn result_or_blocked(rv: ssl::SECStatus) -> Res<bool> {
    result_helper(rv, true)
}

fn wrap_str_fn<F>(f: F, dflt: &str) -> String
where
    F: FnOnce() -> *const i8,
{
    unsafe {
        let p = f();
        if p.is_null() {
            return dflt.to_string();
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

fn result_helper(rv: ssl::SECStatus, allow_blocked: bool) -> Res<bool> {
    if rv == ssl::_SECStatus_SECSuccess {
        println!("success");
        return Ok(false);
    }

    let code = unsafe { PR_GetError() };
    if allow_blocked && code == NSPRErrorCodes::PR_WOULD_BLOCK_ERROR {
        println!("blocked");
        return Ok(true);
    }

    let name = wrap_str_fn(|| unsafe { PR_ErrorToName(code) }, "UNKNOWN_ERROR");
    let desc = wrap_str_fn(
        || unsafe { PR_ErrorToString(code, PR_LANGUAGE_I_DEFAULT) },
        "...",
    );
    println!("error");
    Err(Error::NssError { name, code, desc })
}

#[cfg(test)]
mod tests {
    use super::{result, result_or_blocked};
    use crate::err::{Error, NSPRErrorCodes, PRErrorCode, PR_SetError, SSLErrorCodes};
    use crate::init_db;
    use crate::ssl;

    fn set_error_code(code: PRErrorCode) {
        unsafe { PR_SetError(code, 0) };
    }

    #[test]
    fn is_ok() {
        assert!(result(ssl::SECSuccess).is_ok());
    }

    #[test]
    fn is_err() {
        // This code doesn't work without initializing NSS first.
        init_db("./db");

        set_error_code(SSLErrorCodes::SSL_ERROR_BAD_MAC_READ);
        let r = result(ssl::SECFailure);
        assert!(r.is_err());
        match r.unwrap_err() {
            Error::NssError { name, code, desc } => {
                assert_eq!(name, "SSL_ERROR_BAD_MAC_READ");
                assert_eq!(code, -12273);
                assert_eq!(
                    desc,
                    "SSL received a record with an incorrect Message Authentication Code."
                );
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn is_err_zero_code() {
        // This code doesn't work without initializing NSS first.
        init_db("./db");

        set_error_code(0);
        let r = result(ssl::SECFailure);
        assert!(r.is_err());
        match r.unwrap_err() {
            Error::NssError { name, code, desc } => {
                assert_eq!(name, "UNKNOWN_ERROR");
                assert_eq!(code, 0);
                assert_eq!(desc, "Success");
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn blocked_as_error() {
        // This code doesn't work without initializing NSS first.
        init_db("./db");

        set_error_code(NSPRErrorCodes::PR_WOULD_BLOCK_ERROR);
        let r = result(ssl::SECFailure);
        assert!(r.is_err());
        match r.unwrap_err() {
            Error::NssError { name, code, desc } => {
                assert_eq!(name, "PR_WOULD_BLOCK_ERROR");
                assert_eq!(code, -5998);
                assert_eq!(desc, "The operation would have blocked");
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn is_blocked() {
        set_error_code(NSPRErrorCodes::PR_WOULD_BLOCK_ERROR);
        assert!(result_or_blocked(ssl::SECFailure).unwrap());
    }
}
