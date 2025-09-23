// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    ops::{Deref, DerefMut},
};

use crate::{hex_with_len, Tos};

#[derive(Clone, PartialEq, Eq)]
pub struct Datagram<D = Vec<u8>> {
    src: SocketAddr,
    dst: SocketAddr,
    tos: Tos,
    d: D,
}

impl TryFrom<DatagramBatch> for Datagram {
    type Error = ();

    fn try_from(d: DatagramBatch) -> Result<Self, Self::Error> {
        if d.num_datagrams() != 1 {
            return Err(());
        }
        Ok(Self {
            src: d.src,
            dst: d.dst,
            tos: d.tos,
            d: d.d,
        })
    }
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

    pub fn set_tos(&mut self, tos: Tos) {
        self.tos = tos;
    }
}

impl<D: AsRef<[u8]>> Datagram<D> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.d.as_ref().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    #[must_use]
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, tos: Tos, d: V) -> Self {
        Self {
            src,
            dst,
            tos,
            d: d.into(),
        }
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
            hex_with_len(&self.d)
        )
    }
}

impl<'a> Datagram<&'a mut [u8]> {
    #[must_use]
    pub fn from_slice(src: SocketAddr, dst: SocketAddr, tos: Tos, d: &'a mut [u8]) -> Self {
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
#[derive(Clone, PartialEq, Eq)]
pub struct DatagramBatch {
    src: SocketAddr,
    dst: SocketAddr,
    tos: Tos,
    datagram_size: usize,
    d: Vec<u8>,
}

impl Debug for DatagramBatch {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "DatagramBatch {:?} {:?}->{:?} {:?}: {}",
            self.tos,
            self.src,
            self.dst,
            self.datagram_size,
            hex_with_len(&self.d)
        )
    }
}

impl From<Datagram<Vec<u8>>> for DatagramBatch {
    fn from(d: Datagram<Vec<u8>>) -> Self {
        Self {
            src: d.src,
            dst: d.dst,
            tos: d.tos,
            datagram_size: d.d.len(),
            d: d.d,
        }
    }
}

impl DatagramBatch {
    #[must_use]
    pub const fn new(
        src: SocketAddr,
        dst: SocketAddr,
        tos: Tos,
        datagram_size: usize,
        d: Vec<u8>,
    ) -> Self {
        Self {
            src,
            dst,
            tos,
            datagram_size,
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
    pub const fn tos(&self) -> Tos {
        self.tos
    }

    pub fn set_tos(&mut self, tos: Tos) {
        self.tos = tos;
    }

    #[must_use]
    pub const fn datagram_size(&self) -> usize {
        self.datagram_size
    }

    #[allow(
        clippy::allow_attributes,
        clippy::missing_const_for_fn,
        reason = "False positive on 1.86, remove when MSRV is higher."
    )]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.d
    }

    #[must_use]
    pub fn num_datagrams(&self) -> usize {
        self.d.len().div_ceil(self.datagram_size)
    }

    pub fn iter(&self) -> impl Iterator<Item = Datagram<&[u8]>> {
        self.d.chunks(self.datagram_size).map(|d| Datagram {
            src: self.src,
            dst: self.dst,
            tos: self.tos,
            d,
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = Datagram<&mut [u8]>> {
        self.d.chunks_mut(self.datagram_size).map(|d| Datagram {
            src: self.src,
            dst: self.dst,
            tos: self.tos,
            d,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    use test_fixture::datagram;

    use crate::{DatagramBatch, Ecn, Tos};

    #[test]
    fn fmt_datagram() {
        let d = datagram([0; 1].to_vec());
        assert_eq!(
            &format!("{d:?}"),
            "Datagram Tos(Cs0, Ect0) [fe80::1]:443->[fe80::1]:443: [1]: 00"
        );
    }

    #[test]
    fn is_empty() {
        let d = datagram(vec![]);
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());
    }

    #[test]
    fn batch_num_datagrams() {
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234);
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678);
        let tos = Tos::default();

        // 10 bytes, segment size 4 -> 3 datagrams (4+4+2)
        let batch = DatagramBatch::new(src, dst, tos, 4, vec![0u8; 10]);
        assert_eq!(batch.num_datagrams(), 3);

        // 8 bytes, segment size 4 -> 2 datagrams (4+4)
        let batch = DatagramBatch::new(src, dst, tos, 4, vec![0u8; 8]);
        assert_eq!(batch.num_datagrams(), 2);

        // 5 bytes, segment size 5 -> 1 datagram
        let batch = DatagramBatch::new(src, dst, tos, 5, vec![0u8; 5]);
        assert_eq!(batch.num_datagrams(), 1);

        // 6 bytes, segment size 5 -> 2 datagrams (5+1)
        let batch = DatagramBatch::new(src, dst, tos, 5, vec![0u8; 6]);
        assert_eq!(batch.num_datagrams(), 2);
    }

    #[test]
    fn batch_tos() {
        let mut batch = DatagramBatch::new(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678),
            Tos::default(),
            4,
            vec![0u8; 10],
        );
        batch.set_tos(Ecn::Ce.into());
        assert_eq!(batch.tos(), Ecn::Ce.into());
    }

    #[test]
    fn batch_iter() {
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234);
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678);
        let tos = Tos::default();
        let batch = DatagramBatch::new(src, dst, tos, 4, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
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
        let mut batch = DatagramBatch::new(src, dst, tos, 3, vec![10, 20, 30, 40, 50, 60, 70]);
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
}
