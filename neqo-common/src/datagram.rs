// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{net::SocketAddr, ops::Deref};

use crate::{hex_with_len, IpTos};

#[derive(Clone, PartialEq, Eq)]
pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    tos: IpTos,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the [`Datagram`] only contains a single datagram
    segment_size: Option<usize>,
    d: Vec<u8>,
}

impl Datagram {
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, tos: IpTos, d: V) -> Self {
        Self {
            src,
            dst,
            tos,
            segment_size: None,
            d: d.into(),
        }
    }

    pub fn new_with_segment_size<V: Into<Vec<u8>>>(
        src: SocketAddr,
        dst: SocketAddr,
        tos: IpTos,
        segment_size: usize,
        d: V,
    ) -> Self {
        Self {
            src,
            dst,
            tos,
            segment_size: Some(segment_size),
            d: d.into(),
        }
    }

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

    pub fn into_recv_buf(self) -> Vec<u8> {
        self.d
    }

    pub fn segment_size(&self) -> Option<usize> {
        self.segment_size
    }
}

impl Deref for Datagram {
    type Target = Vec<u8>;
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

impl std::fmt::Debug for Datagram {
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
