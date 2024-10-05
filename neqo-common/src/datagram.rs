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
    /// The size of each segment within the [`Datagram`]. All segments, but the
    /// last, have the same size. The last segment can be shorter than
    /// [`Datagram::segment_size`].
    segment_size: usize,
    tos: IpTos,
    // TODO: Rename to `data`?
    d: Vec<u8>,
}

impl Datagram {
    #[must_use]
    pub fn new(
        src: SocketAddr,
        dst: SocketAddr,
        tos: IpTos,
        d: Vec<u8>,
        segment_size: Option<usize>,
    ) -> Self {
        Self {
            src,
            dst,
            tos,
            segment_size: segment_size.unwrap_or_else(|| d.len()),
            d,
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

    #[must_use]
    pub const fn segment_size(&self) -> usize {
        self.segment_size
    }

    // TODO: Needed?
    pub fn iter_segments(&self) -> impl Iterator<Item = &[u8]> {
        self.d.chunks(self.segment_size)
    }

    // TODO: Needed?
    pub fn num_segments(&self) -> usize {
        self.d.len().div_ceil(self.segment_size)
    }

    pub fn borrow<'a>(&'a self) -> BorrowedDatagram<'a> {
        BorrowedDatagram {
            src: self.src,
            dst: self.dst,
            segment_size: self.segment_size,
            tos: self.tos,
            d: self.d.as_ref(),
        }
    }

    pub fn len(&self) -> usize {
        self.d.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Datagram> for Vec<u8> {
    fn from(d: Datagram) -> Self {
        d.d
    }
}

impl<'a> From<BorrowedDatagram<'a>> for Datagram {
    fn from(value: BorrowedDatagram) -> Self {
        value.to_owned()
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

impl AsRef<[u8]> for Datagram {
    fn as_ref(&self) -> &[u8] {
        self.d.as_ref()
    }
}

// TODO: Really needed? Not idiomatic.
impl Deref for Datagram {
    type Target = [u8];
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BorrowedDatagram<'a> {
    src: SocketAddr,
    dst: SocketAddr,
    /// The size of each segment within the [`BorrowedDatagram`]. All segments, but the
    /// last, have the same size. The last segment can be shorter than
    /// [`BorrowedDatagram::segment_size`].
    segment_size: usize,
    tos: IpTos,
    d: &'a [u8],
}

impl<'a> BorrowedDatagram<'a> {
    pub fn new(
        src: SocketAddr,
        dst: SocketAddr,
        tos: IpTos,
        d: &'a [u8],
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

    pub fn iter_segments(&self) -> impl Iterator<Item = &[u8]> {
        self.d.as_ref().chunks(self.segment_size)
    }

    pub fn num_segments(&self) -> usize {
        self.d.as_ref().len().div_ceil(self.segment_size)
    }

    pub fn to_owned(&self) -> Datagram {
        Datagram {
            src: self.src,
            dst: self.dst,
            segment_size: self.segment_size,
            tos: self.tos,
            d: self.d.to_vec(),
        }
    }

    pub fn len(&self) -> usize {
        self.d.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> std::fmt::Debug for BorrowedDatagram<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "BorrowedDatagram {:?} {:?}->{:?}: {}",
            self.tos,
            self.src,
            self.dst,
            hex_with_len(&self.d)
        )
    }
}

impl<'a> From<&'a Datagram> for BorrowedDatagram<'a> {
    fn from(value: &'a Datagram) -> Self {
        BorrowedDatagram {
            src: value.src,
            dst: value.dst,
            segment_size: value.segment_size,
            tos: value.tos,
            d: value.d.as_ref(),
        }
    }
}

impl<'a> AsRef<[u8]> for BorrowedDatagram<'a> {
    fn as_ref(&self) -> &[u8] {
        self.d.as_ref()
    }
}

// TODO: Really needed? Not idiomatic.
impl<'a> Deref for BorrowedDatagram<'a> {
    type Target = [u8];
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

#[cfg(test)]
mod tests {
    use test_fixture::{datagram, DEFAULT_ADDR};

    use super::Datagram;
    use crate::IpTos;

    #[test]
    fn fmt_datagram() {
        let d = datagram([0; 1].to_vec());
        assert_eq!(
            &format!("{d:?}"),
            "Datagram IpTos(Cs0, Ect0) [fe80::1]:443->[fe80::1]:443: [1]: 00"
        );
    }

    /// Expect segment to span whole datagram when no segment size specified.
    #[test]
    fn no_segment_size() {
        let len = 42;
        let d = datagram(vec![0; len].to_vec());
        assert_eq!(d.segment_size(), len, "");
        assert_eq!(d.num_segments(), 1);
        assert_eq!(d.iter_segments().next(), Some(vec![0; len].as_slice()));
    }

    #[test]
    fn equal_size_segments() {
        let segment_size = 1_500;
        let d = Datagram::new(
            DEFAULT_ADDR,
            DEFAULT_ADDR,
            IpTos::default(),
            vec![0; segment_size * 2],
            Some(segment_size),
        );
        assert_eq!(d.segment_size(), segment_size);
        assert_eq!(d.num_segments(), 2);
        let mut iter = d.iter_segments();
        assert_eq!(iter.next(), Some(vec![0; segment_size].as_slice()));
        assert_eq!(iter.next(), Some(vec![0; segment_size].as_slice()));
    }

    #[test]
    fn unequal_size_segments() {
        let segment_size = 1_500;
        let d = Datagram::new(
            DEFAULT_ADDR,
            DEFAULT_ADDR,
            IpTos::default(),
            vec![0; 2_000],
            Some(segment_size),
        );
        assert_eq!(d.segment_size(), segment_size);
        assert_eq!(d.num_segments(), 2);
        let mut iter = d.iter_segments();
        assert_eq!(iter.next(), Some(vec![0; segment_size].as_slice()));
        assert_eq!(iter.next(), Some(vec![0; 500].as_slice()));
    }
}
