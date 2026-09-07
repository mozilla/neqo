// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Debug, Formatter},
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
};

use crate::{Buffer, Bytes, Tos, hex::HexWithLen};

/// A UDP datagram.
///
/// Guaranteed to not be empty.
#[derive(Clone, PartialEq, Eq)]
pub struct Datagram<D = Vec<u8>> {
    src: SocketAddr,
    dst: SocketAddr,
    tos: Tos,
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
    pub const fn tos(&self) -> Tos {
        self.tos
    }

    pub const fn set_tos(&mut self, tos: Tos) {
        self.tos = tos;
    }
}

impl<D: AsRef<[u8]>> Datagram<D> {
    #[expect(clippy::len_without_is_empty, reason = "is_empty() is always false")]
    #[must_use]
    pub fn len(&self) -> usize {
        self.d.as_ref().len()
    }

    #[must_use]
    pub fn to_owned(&self) -> Datagram {
        Datagram {
            src: self.src,
            dst: self.dst,
            tos: self.tos,
            d: self.d.as_ref().to_vec(),
        }
    }
}

impl<D: AsMut<[u8]> + AsRef<[u8]>> AsMut<[u8]> for Datagram<D> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.d.as_mut()
    }
}

impl Datagram<Vec<u8>> {
    /// # Panics
    ///
    /// Panics if `d` converts to an empty vector.
    #[must_use]
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, tos: Tos, d: V) -> Self {
        let d = d.into();
        assert!(!d.is_empty(), "Datagram data cannot be empty");
        Self { src, dst, tos, d }
    }
}

impl<D: AsRef<[u8]> + AsMut<[u8]>> DerefMut for Datagram<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        AsMut::<[u8]>::as_mut(self)
    }
}

impl<D: AsRef<[u8]>> Deref for Datagram<D> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        AsRef::<[u8]>::as_ref(self)
    }
}

impl<D: AsRef<[u8]>> Debug for Datagram<D> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Datagram {:?} {:?}->{:?}: {}",
            self.tos,
            self.src,
            self.dst,
            HexWithLen::new(&self.d)
        )
    }
}

impl<'a> Datagram<&'a mut [u8]> {
    /// # Panics
    ///
    /// Panics if the data is empty.
    #[must_use]
    pub fn from_slice(src: SocketAddr, dst: SocketAddr, tos: Tos, d: &'a mut [u8]) -> Self {
        assert!(!d.is_empty(), "Datagram data cannot be empty");
        Self { src, dst, tos, d }
    }
}

impl Datagram<Bytes> {
    /// # Panics
    ///
    /// Panics if the data is empty.
    #[must_use]
    pub fn from_bytes(src: SocketAddr, dst: SocketAddr, tos: Tos, d: Bytes) -> Self {
        assert!(!d.is_empty(), "Datagram data cannot be empty");
        Self { src, dst, tos, d }
    }
}

impl<D: AsRef<[u8]>> AsRef<[u8]> for Datagram<D> {
    fn as_ref(&self) -> &[u8] {
        self.d.as_ref()
    }
}

/// A batch of [`Datagram`]s with the same metadata, e.g., destination.
///
/// Upholds Linux GSO requirement. That is, all but the last datagram in the
/// batch have the same size. The last datagram may be equal or smaller.
///
/// Borrows the caller's buffer, so the send path is not generic over it.
#[derive(PartialEq, Eq)]
pub struct Batch<'a> {
    src: SocketAddr,
    dst: SocketAddr,
    tos: Tos,
    datagram_size: NonZeroUsize,
    d: &'a mut [u8],
}

impl Debug for Batch<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "datagram::Batch {:?} {:?}->{:?} {:?}: {}",
            self.tos,
            self.src,
            self.dst,
            self.datagram_size,
            HexWithLen::new(&*self.d)
        )
    }
}

impl<'a> Batch<'a> {
    #[must_use]
    pub const fn new(
        src: SocketAddr,
        dst: SocketAddr,
        tos: Tos,
        datagram_size: NonZeroUsize,
        d: &'a mut [u8],
    ) -> Self {
        Self {
            src,
            dst,
            tos,
            datagram_size,
            d,
        }
    }

    /// Copy `d` onto the end of `buffer`, returning a batch over just those bytes.
    ///
    /// For cold paths with an owned datagram, such as Retry.
    ///
    /// # Errors
    /// When `buffer` cannot hold `d`.
    ///
    /// # Panics
    /// Never, as a [`Datagram`] is not empty.
    pub fn copy_from<B: Buffer>(d: &Datagram, buffer: &'a mut B) -> Result<Self, io::Error> {
        let start = buffer.position();
        // `write_all` writes what fits before failing, so undo a partial write.
        if let Err(e) = buffer.write_all(d) {
            buffer.truncate(start);
            return Err(e);
        }
        let datagram_size = NonZeroUsize::new(d.len()).expect("Datagram is not empty");
        Ok(Self::new(
            d.source(),
            d.destination(),
            d.tos(),
            datagram_size,
            &mut buffer.as_mut()[start..],
        ))
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
    pub const fn tos(&self) -> Tos {
        self.tos
    }

    pub const fn set_tos(&mut self, tos: Tos) {
        self.tos = tos;
    }

    #[must_use]
    pub const fn datagram_size(&self) -> NonZeroUsize {
        self.datagram_size
    }

    /// Metadata, copied out so the buffer's borrow can end.
    #[must_use]
    pub const fn meta(&self) -> (SocketAddr, SocketAddr, Tos, NonZeroUsize) {
        (self.src, self.dst, self.tos, self.datagram_size)
    }

    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.d
    }

    #[must_use]
    pub const fn num_datagrams(&self) -> usize {
        self.d.len().div_ceil(self.datagram_size.get())
    }

    pub fn iter(&self) -> impl Iterator<Item = Datagram<&[u8]>> {
        self.d.chunks(self.datagram_size.get()).map(|d| Datagram {
            src: self.src,
            dst: self.dst,
            tos: self.tos,
            d,
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = Datagram<&mut [u8]>> {
        let datagram_size = self.datagram_size.get();
        let src = self.src;
        let dst = self.dst;
        let tos = self.tos;
        self.d
            .chunks_mut(datagram_size)
            .map(move |d| Datagram { src, dst, tos, d })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        io::Cursor,
        net::{IpAddr, Ipv6Addr, SocketAddr},
        num::NonZeroUsize,
    };

    use test_fixture::{DEFAULT_ADDR, datagram};

    use crate::{Buffer, Datagram, Ecn, Tos, datagram};

    #[test]
    fn fmt_datagram() {
        let d = datagram([0; 1].to_vec());
        assert_eq!(
            &format!("{d:?}"),
            "Datagram Tos(Cs0, Ect0) [fe80::1]:443->[fe80::1]:443: [1]: 00"
        );
    }

    #[test]
    #[should_panic(expected = "Datagram data cannot be empty")]
    fn new_empty() {
        let _d = Datagram::new(DEFAULT_ADDR, DEFAULT_ADDR, Ecn::Ect0.into(), vec![]);
    }

    #[test]
    #[should_panic(expected = "Datagram data cannot be empty")]
    fn from_slice_empty() {
        let _d = Datagram::from_slice(DEFAULT_ADDR, DEFAULT_ADDR, Ecn::Ect0.into(), &mut []);
    }

    #[test]
    #[should_panic(expected = "Datagram data cannot be empty")]
    fn from_bytes_empty() {
        let _d = Datagram::from_bytes(DEFAULT_ADDR, DEFAULT_ADDR, Ecn::Ect0.into(), vec![].into());
    }

    #[test]
    fn batch_num_datagrams() {
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234);
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678);
        let tos = Tos::default();

        for (len, segment_size, datagrams) in [
            (10, 4, 3), // 4+4+2
            (8, 4, 2),  // 4+4
            (5, 5, 1),
            (6, 5, 2), // 5+1
        ] {
            let mut buf = vec![0u8; len];
            let batch = datagram::Batch::new(
                src,
                dst,
                tos,
                NonZeroUsize::new(segment_size).unwrap(),
                &mut buf,
            );
            assert_eq!(
                batch.num_datagrams(),
                datagrams,
                "{len} bytes / {segment_size}"
            );
        }
    }

    #[test]
    fn batch_tos() {
        let mut buf = vec![0u8; 10];
        let mut batch = datagram::Batch::new(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678),
            Tos::default(),
            NonZeroUsize::new(4).unwrap(),
            &mut buf,
        );
        batch.set_tos(Ecn::Ce.into());
        assert_eq!(batch.tos(), Ecn::Ce.into());
    }

    #[test]
    fn batch_copy_from() {
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234);
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678);
        let d = Datagram::new(src, dst, Ecn::Ce.into(), vec![1, 2, 3, 4, 5]);

        let mut buf = Vec::new();
        let batch = datagram::Batch::copy_from(&d, &mut buf).unwrap();
        assert_eq!(batch.source(), src);
        assert_eq!(batch.destination(), dst);
        assert_eq!(batch.tos(), Ecn::Ce.into());
        assert_eq!(batch.datagram_size().get(), d.len());
        assert_eq!(batch.data(), &d[..]);
        assert_eq!(batch.num_datagrams(), 1);
    }

    #[test]
    fn batch_copy_from_too_small() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234);
        // Non-zero, so an undone write is visible.
        let d = Datagram::new(addr, addr, Tos::default(), vec![0xAB; 10]);

        let mut buf = [0; 4];
        let mut cursor = Cursor::new(&mut buf[..]);
        assert!(datagram::Batch::copy_from(&d, &mut cursor).is_err());
        // A partial write is undone.
        assert_eq!(Buffer::position(&cursor), 0);
        assert_eq!(buf, [0; 4]);
    }

    #[test]
    fn batch_iter() {
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234);
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678);
        let tos = Tos::default();
        let mut buf = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let batch = datagram::Batch::new(src, dst, tos, NonZeroUsize::new(4).unwrap(), &mut buf);
        let datagrams: Vec<_> = batch.iter().collect();
        assert_eq!(datagrams.len(), 3);
        assert_eq!(datagrams[0].d, &[1, 2, 3, 4]);
        assert_eq!(datagrams[1].d, &[5, 6, 7, 8]);
        assert_eq!(datagrams[2].d, &[9]);

        for d in datagrams {
            assert_eq!(d.source(), src);
            assert_eq!(d.destination(), dst);
            assert_eq!(d.tos(), tos);
        }
    }

    #[test]
    fn batch_iter_mut() {
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234);
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678);
        let tos = Tos::default();
        let mut buf = vec![10, 20, 30, 40, 50, 60, 70];
        let mut batch =
            datagram::Batch::new(src, dst, tos, NonZeroUsize::new(3).unwrap(), &mut buf);
        for datagram in batch.iter_mut() {
            assert_eq!(datagram.source(), src);
            assert_eq!(datagram.destination(), dst);
            assert_eq!(datagram.tos(), tos);
            for b in datagram.d {
                *b += 1;
            }
        }
        let datagrams: Vec<_> = batch.iter().collect();
        assert_eq!(datagrams.len(), 3);
        assert_eq!(datagrams[0].d, &[11, 21, 31]);
        assert_eq!(datagrams[1].d, &[41, 51, 61]);
        assert_eq!(datagrams[2].d, &[71]);
    }

    #[test]
    fn datagram_len_and_accessors() {
        let mut d = Datagram::new(DEFAULT_ADDR, DEFAULT_ADDR, Tos::default(), vec![1, 2, 3]);
        assert_eq!(d.len(), 3);
        assert!(!d.is_empty());
        assert_eq!(d.as_ref(), &[1, 2, 3]);
        d.as_mut()[0] = 9;
        assert_eq!(d.as_ref(), &[9, 2, 3]);
        d.set_tos(Ecn::Ce.into());
        assert_eq!(d.tos(), Ecn::Ce.into());
    }

    #[test]
    fn batch_debug() {
        let mut buf = vec![1, 2, 3, 4];
        let batch = datagram::Batch::new(
            DEFAULT_ADDR,
            DEFAULT_ADDR,
            Tos::default(),
            NonZeroUsize::new(2).unwrap(),
            &mut buf,
        );
        assert_eq!(batch.data(), &[1, 2, 3, 4]);
        assert!(format!("{batch:?}").starts_with("datagram::Batch"));
    }
}
