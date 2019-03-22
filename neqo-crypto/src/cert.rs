use std::ptr::{null_mut, NonNull};

use crate::p11::{
    CERTCertList, CERTCertListNode, CERT_GetCertificateDer, CertList, PRCList, SECItem, SECItemType,
};
use crate::result;
use crate::ssl::{PRFileDesc, SSL_PeerCertificateChain};

pub struct CertificateChain {
    certs: CertList,
    cursor: *const CERTCertListNode,
}

impl CertificateChain {
    pub(crate) fn new(fd: *mut PRFileDesc) -> Option<Self> {
        let chain = unsafe { SSL_PeerCertificateChain(fd) };
        let certs = match NonNull::new(chain as *mut CERTCertList) {
            Some(certs_ptr) => CertList::new(certs_ptr),
            None => return None,
        };
        let cursor = CertificateChain::head(&certs);
        Some(CertificateChain { certs, cursor })
    }

    fn head(certs: &CertList) -> *const CERTCertListNode {
        // Three stars: one for the reference, one for the wrapper, one to deference the pointer.
        unsafe { &(***certs).list as *const PRCList as *const CERTCertListNode }
    }
}

impl<'a> Iterator for &'a mut CertificateChain {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        self.cursor = unsafe { *self.cursor }.links.next as *const CERTCertListNode;
        if self.cursor == CertificateChain::head(&self.certs) {
            return None;
        }
        let mut item = SECItem {
            type_: SECItemType::siBuffer,
            data: null_mut(),
            len: 0,
        };
        let cert = unsafe { *self.cursor }.cert;
        let rv = unsafe { CERT_GetCertificateDer(cert, &mut item) };
        match result::result(rv) {
            Err(_) => panic!("Error getting DER from certificate"),
            _ => {}
        };
        Some(unsafe { std::slice::from_raw_parts(item.data, item.len as usize) })
    }
}
