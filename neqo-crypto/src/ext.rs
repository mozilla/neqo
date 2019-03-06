use crate::constants::*;
use crate::err::Res;
use crate::result;
use crate::ssl;
use crate::ssl::{
    PRBool, PRFileDesc, SECFailure, SECStatus, SECSuccess, SSLAlertDescription,
    SSLExtensionHandler, SSLExtensionWriter, SSLHandshakeType,
};

use std::os::raw::{c_uint, c_void};

experimental_api!(SSL_InstallExtensionHooks(
    fd: *mut ssl::PRFileDesc,
    extension: u16,
    writer: SSLExtensionWriter,
    writer_arg: *mut c_void,
    handler: SSLExtensionHandler,
    handler_arg: *mut c_void,
));

pub enum ExtensionWriterResult {
    Write(usize),
    Skip,
}

pub enum ExtensionHandlerResult {
    Ok,
    Alert(crate::constants::Alert),
}

pub trait ExtensionHandler {
    fn write(&mut self, msg: SSLHandshakeType::Type, _d: &mut [u8]) -> ExtensionWriterResult {
        match msg {
            SSLHandshakeType::ssl_hs_client_hello
            | SSLHandshakeType::ssl_hs_encrypted_extensions => ExtensionWriterResult::Write(0),
            _ => ExtensionWriterResult::Skip,
        }
    }

    fn handle(&mut self, msg: SSLHandshakeType::Type, _d: &[u8]) -> ExtensionHandlerResult {
        match msg {
            SSLHandshakeType::ssl_hs_client_hello
            | SSLHandshakeType::ssl_hs_encrypted_extensions => ExtensionHandlerResult::Ok,
            _ => ExtensionHandlerResult::Alert(110), // unsupported_extension
        }
    }
}

pub struct ExtensionTracker {
    extension: Extension,
    handler: Box<Box<dyn ExtensionHandler>>,
}

impl ExtensionTracker {
    unsafe fn unpack_arg<'a>(arg: *mut c_void) -> &'a mut Box<dyn ExtensionHandler> {
        let handler_ptr = arg as *mut Box<dyn ExtensionHandler>;
        handler_ptr.as_mut().unwrap()
    }

    unsafe extern "C" fn extension_writer(
        _fd: *mut PRFileDesc,
        message: SSLHandshakeType::Type,
        data: *mut u8,
        len: *mut c_uint,
        max_len: c_uint,
        arg: *mut c_void,
    ) -> PRBool {
        let handler = ExtensionTracker::unpack_arg(arg);
        let d = std::slice::from_raw_parts_mut(data, max_len as usize);
        match handler.write(message, d) {
            ExtensionWriterResult::Write(sz) => {
                *len = sz as c_uint;
                1
            }
            ExtensionWriterResult::Skip => 0,
        }
    }

    unsafe extern "C" fn extension_handler(
        _fd: *mut PRFileDesc,
        message: SSLHandshakeType::Type,
        data: *const u8,
        len: c_uint,
        alert: *mut SSLAlertDescription,
        arg: *mut c_void,
    ) -> SECStatus {
        let handler = ExtensionTracker::unpack_arg(arg);
        let d = std::slice::from_raw_parts(data, len as usize);
        match handler.handle(message, d) {
            ExtensionHandlerResult::Ok => SECSuccess,
            ExtensionHandlerResult::Alert(a) => {
                *alert = a;
                SECFailure
            }
        }
    }

    pub fn new(
        fd: *mut ssl::PRFileDesc,
        extension: Extension,
        handler: Box<dyn ExtensionHandler>,
    ) -> Res<ExtensionTracker> {
        // This is rust magic.  handler is passed as a boxed trait object.
        let mut tracker = ExtensionTracker {
            extension,
            handler: Box::new(handler),
        };
        let p = &mut *tracker.handler as *mut Box<dyn ExtensionHandler> as *mut c_void;
        let rv = unsafe {
            SSL_InstallExtensionHooks(
                fd,
                extension,
                Some(ExtensionTracker::extension_writer),
                p,
                Some(ExtensionTracker::extension_handler),
                p,
            )
        };
        result::result(rv)?;
        Ok(tracker)
    }
}

impl std::fmt::Debug for ExtensionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ExtensionTracker: {:?}", self.extension)
    }
}
