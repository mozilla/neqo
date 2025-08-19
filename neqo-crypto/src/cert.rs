// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    experimental_api,
    p11::{ItemArray, ItemArrayIterator, SECItemArray},
    ssl::PRFileDesc,
};

experimental_api!(SSL_PeerCertificateChainDER(
    fd: *mut PRFileDesc,
    out: *mut *mut SECItemArray,
));

pub struct CertificateInfo {
    certs: ItemArray,
}

fn peer_certificate_chain(fd: *mut PRFileDesc) -> Option<ItemArray> {
    let mut chain_ptr: *mut SECItemArray = std::ptr::null_mut();
    let rv = unsafe { SSL_PeerCertificateChainDER(fd, &mut chain_ptr) };
    if rv.is_ok() {
        ItemArray::from_ptr(chain_ptr).ok()
    } else {
        None
    }
}

impl<'a> IntoIterator for &'a CertificateInfo {
    type IntoIter = ItemArrayIterator<'a>;
    type Item = &'a [u8];
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl CertificateInfo {
    pub(crate) fn new(fd: *mut PRFileDesc) -> Option<Self> {
        peer_certificate_chain(fd).map(|certs| Self { certs })
    }

    #[must_use]
    pub fn iter(&self) -> ItemArrayIterator<'_> {
        self.certs.into_iter()
    }
}
