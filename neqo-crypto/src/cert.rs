// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ptr::{null_mut, NonNull};

use crate::p11::{
    CERTCertList, CERTCertListNode, CERT_GetCertificateDer, CertList, PRCList, SECItem,
    SECItemArray, SECItemType,
};
use crate::result;
use crate::ssl::{
    PRFileDesc, SSL_PeerCertificateChain, SSL_PeerSignedCertTimestamps,
    SSL_PeerStapledOCSPResponses,
};

use std::slice;

pub struct CertificateInfo {
    certs: CertList,
    cursor: *const CERTCertListNode,
    stapled_ocsp_responses: Option<Vec<Vec<u8>>>,
    signed_cert_timestamp: Option<Vec<u8>>,
}

impl CertificateInfo {
    pub(crate) fn new(fd: *mut PRFileDesc) -> Option<Self> {
        let chain = unsafe { SSL_PeerCertificateChain(fd) };
        let certs = match NonNull::new(chain as *mut CERTCertList) {
            Some(certs_ptr) => CertList::new(certs_ptr),
            None => return None,
        };
        let cursor = CertificateInfo::head(&certs);
        let mut stapled_ocsp_responses: Option<Vec<Vec<u8>>> = None;
        let ocsp_nss = unsafe { SSL_PeerStapledOCSPResponses(fd) };
        if let Some(ocsp_ptr) = NonNull::new(ocsp_nss as *mut SECItemArray) {
            let mut ocsp_helper: Vec<Vec<u8>> = Vec::new();
            let len = unsafe { ocsp_ptr.as_ref().len };
            for inx in 0..len {
                let item_nss =
                    unsafe { ocsp_ptr.as_ref().items.offset(inx as isize) as *const SECItem };
                let item =
                    unsafe { slice::from_raw_parts((*item_nss).data, (*item_nss).len as usize) };
                ocsp_helper.push(item.to_owned());
            }
            stapled_ocsp_responses = Some(ocsp_helper);
        }
        let mut signed_cert_timestamp: Option<Vec<u8>> = None;
        let sct_nss = unsafe { SSL_PeerSignedCertTimestamps(fd) };
        if let Some(sct_ptr) = NonNull::new(sct_nss as *mut SECItem) {
            let sct_slice = unsafe {
                slice::from_raw_parts(sct_ptr.as_ref().data, sct_ptr.as_ref().len as usize)
            };
            signed_cert_timestamp = Some(sct_slice.to_owned());
        };

        Some(CertificateInfo {
            certs,
            cursor,
            stapled_ocsp_responses,
            signed_cert_timestamp,
        })
    }

    fn head(certs: &CertList) -> *const CERTCertListNode {
        // Three stars: one for the reference, one for the wrapper, one to deference the pointer.
        unsafe { &(***certs).list as *const PRCList as *const CERTCertListNode }
    }
}

impl<'a> Iterator for &'a mut CertificateInfo {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        self.cursor = unsafe { *self.cursor }.links.next as *const CERTCertListNode;
        if self.cursor == CertificateInfo::head(&self.certs) {
            return None;
        }
        let mut item = SECItem {
            type_: SECItemType::siBuffer,
            data: null_mut(),
            len: 0,
        };
        let cert = unsafe { *self.cursor }.cert;
        let rv = unsafe { CERT_GetCertificateDer(cert, &mut item) };
        if result::result(rv).is_err() {
            panic!("Error getting DER from certificate");
        }
        Some(unsafe { std::slice::from_raw_parts(item.data, item.len as usize) })
    }
}

impl CertificateInfo {
    pub fn get_stapled_ocsp_responses(&mut self) -> &Option<Vec<Vec<u8>>> {
        &self.stapled_ocsp_responses
    }

    pub fn get_signed_cert_timestamp(&mut self) -> &Option<Vec<u8>> {
        &self.signed_cert_timestamp
    }
}
