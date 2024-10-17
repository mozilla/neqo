// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{net::SocketAddr, ops::Deref};

use crate::{hex_with_len, IpTos};

#[derive(Clone, PartialEq, Eq)]
pub struct Datagram<D = Vec<u8>> {
    src: SocketAddr,
    dst: SocketAddr,
    tos: IpTos,
    d: D,
}

impl<D> Datagram<D> {
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.src
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.dst
    }

    #[must_use]
    pub const fn tos(&self) -> IpTos {
        self.tos
    }

    pub fn set_tos(&mut self, tos: IpTos) {
        self.tos = tos;
    }
}

impl Datagram<Vec<u8>> {
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, tos: IpTos, d: V) -> Self {
        Self {
            src,
            dst,
            tos,
            d: d.into(),
        }
    }

    #[must_use]
    pub fn borrow(&self) -> Datagram<&[u8]> {
        Datagram {
            src: self.src,
            dst: self.dst,
            tos: self.tos,
            d: self.d.as_ref(),
        }
    }
}

impl Deref for Datagram {
    type Target = Vec<u8>;
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

impl<D: AsRef<[u8]>> std::fmt::Debug for Datagram<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Datagram {:?} {:?}->{:?}: {}",
            self.tos,
            self.src,
            self.dst,
            hex_with_len(&self.d)
        )
    }
}

impl Deref for Datagram<&[u8]> {
    type Target = [u8];
    #[must_use]
    fn deref(&self) -> &Self::Target {
        self.d
    }
}

impl<'a> Datagram<&'a [u8]> {
    #[must_use]
    pub const fn from_slice(src: SocketAddr, dst: SocketAddr, tos: IpTos, d: &'a [u8]) -> Self {
        Self { src, dst, tos, d }
    }

    #[must_use]
    pub fn to_owned(&self) -> Datagram {
        Datagram {
            src: self.src,
            dst: self.dst,
            tos: self.tos,
            d: self.d.to_vec(),
        }
    }
}

impl<'a> From<&'a Datagram> for Datagram<&'a [u8]> {
    fn from(value: &'a Datagram) -> Self {
        value.borrow()
    }
}

impl<D: AsRef<[u8]>> AsRef<[u8]> for Datagram<D> {
    fn as_ref(&self) -> &[u8] {
        self.d.as_ref()
    }
}

#[cfg(test)]
use test_fixture::datagram;

#[test]
fn fmt_datagram() {
    let d = datagram([0; 1].to_vec());
    assert_eq!(
        &format!("{d:?}"),
        "Datagram IpTos(Cs0, Ect0) [fe80::1]:443->[fe80::1]:443: [1]: 00"
    );
}
