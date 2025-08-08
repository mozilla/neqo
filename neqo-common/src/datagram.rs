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
    pub fn len(&self) -> usize {
        self.d.as_ref().len()
    }

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
    /// Maximum [`DatagramBatch`] size in bytes.
    ///
    /// This value is set conservatively to ensure compatibility with batch IO
    /// system calls across all supported platforms.
    ///
    /// See for example Linux limit in
    /// <https://github.com/torvalds/linux/blob/fb4d33ab452ea254e2c319bac5703d1b56d895bf/include/linux/netdevice.h#L2402>.
    pub const MAX: usize = 65535 // maximum UDP datagram size
        - 40 // IPv6 header
        - 8; // UDP header

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

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.d
    }

    #[must_use]
    pub fn num_datagrams(&self) -> usize {
        self.d.len().div_ceil(self.datagram_size)
    }

    #[cfg(feature = "build-fuzzing-corpus")]
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.d.chunks(self.datagram_size)
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
}
