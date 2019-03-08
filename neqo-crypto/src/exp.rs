macro_rules! experimental_api {
    ( $n:ident ( $( $a:ident : $t:ty ),* $(,)? ) ) => {
        #[allow(non_snake_case)]
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
