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
    /// The size of each segment within the [`Datagram`]. All segments, but the
    /// last, have the same size. The last segment can be shorter than
    /// [`Datagram::segment_size`].
    segment_size: usize,
    tos: IpTos,
    d: D,
}

impl Copy for Datagram<&[u8]> {}

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

    #[must_use]
    pub const fn segment_size(&self) -> usize {
        self.segment_size
    }
}

impl<D: AsRef<[u8]>> Datagram<D> {
    pub fn new(
        src: SocketAddr,
        dst: SocketAddr,
        tos: IpTos,
        d: D,
        segment_size: Option<usize>,
    ) -> Self {
        Self {
            src,
            dst,
            tos,
            segment_size: segment_size.unwrap_or_else(|| d.as_ref().len()),
            d,
        }
    }
    pub fn iter_segments(&self) -> impl Iterator<Item = &[u8]> {
        self.d.as_ref().chunks(self.segment_size)
    }

    pub fn num_segments(&self) -> usize {
        self.d.as_ref().len().div_ceil(self.segment_size)
    }
}

// TODO: Should we really implement Deref here?
// https://doc.rust-lang.org/std/ops/trait.Deref.html#when-to-implement-deref-or-derefmut
impl<D: Deref<Target = [u8]>> Deref for Datagram<D> {
    // TODO: Target still correct?
    type Target = [u8];
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

// TODO: Remove
impl<'a> From<&'a Datagram> for Datagram<&'a [u8]> {
    fn from(value: &'a Datagram) -> Self {
        let Datagram {
            src,
            dst,
            tos,
            segment_size,
            d,
        } = value;
        Datagram {
            src: *src,
            dst: *dst,
            tos: *tos,
            segment_size: *segment_size,
            d,
        }
    }
}

// TODO: Remove
impl From<Datagram<&[u8]>> for Datagram {
    fn from(value: Datagram<&[u8]>) -> Self {
        let Datagram {
            src,
            dst,
            tos,
            segment_size,
            d,
        } = value;
        Self {
            src,
            dst,
            tos,
            segment_size,
            d: d.to_owned(),
        }
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

impl From<Datagram> for Vec<u8> {
    fn from(value: Datagram) -> Self {
        value.d
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
