// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

macro_rules! experimental_api {
    ( $n:ident ( $( $a:ident : $t:ty ),* $(,)? ) ) => {
        #[allow(non_snake_case)]
        #[allow(clippy::too_many_arguments)]
        pub unsafe fn $n ( $( $a : $t ),* ) -> crate::ssl::SECStatus {
            const EXP_FUNCTION: &str = stringify!($n);
            let n = ::std::ffi::CString::new(EXP_FUNCTION).unwrap();
            let f = crate::ssl::SSL_GetExperimentalAPI(n.as_ptr());
            if f.is_null() {
                return crate::ssl::SECFailure;
            }
            let f: unsafe extern "C" fn( $( $t ),* ) -> crate::ssl::SECStatus = ::std::mem::transmute(f);
            f( $( $a ),* )
        }
    };
}
