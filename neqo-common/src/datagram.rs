// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};

use crate::{hex_with_len, IpTos};

/// The meta data associated with a UDP datagram.
#[derive(Clone, PartialEq, Eq)]
pub struct DatagramMetaData {
    src: SocketAddr,
    dst: SocketAddr,
    tos: IpTos,
    len: usize,
}

impl DatagramMetaData {
    #[must_use]
    pub const fn new(src: SocketAddr, dst: SocketAddr, tos: IpTos, len: usize) -> Self {
        Self { src, dst, tos, len }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub const fn tos(&self) -> IpTos {
        self.tos
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.dst
    }

    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.src
    }
}

/// Whether the given datagram matches this meta data.
impl PartialEq<Datagram> for DatagramMetaData {
    fn eq(&self, other: &Datagram) -> bool {
        self.dst == other.destination() && self.len == other.len() && self.tos == other.tos()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Datagram<D = Vec<u8>> {
    meta: DatagramMetaData,
    d: D,
}

impl<D> Datagram<D> {
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.meta.source()
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.meta.destination()
    }

    #[must_use]
    pub const fn tos(&self) -> IpTos {
        self.meta.tos()
    }

    pub fn set_tos(&mut self, tos: IpTos) {
        self.meta.tos = tos;
    }

    pub const fn meta(&self) -> &DatagramMetaData {
        &self.meta
    }
}

impl<D: AsRef<[u8]>> Datagram<D> {
    pub fn len(&self) -> usize {
        self.d.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<D: AsMut<[u8]> + AsRef<[u8]>> AsMut<[u8]> for Datagram<D> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.d.as_mut()
    }
}

impl Datagram<Vec<u8>> {
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, tos: IpTos, d: V) -> Self {
        let d = d.into();
        Self {
            meta: DatagramMetaData {
                src,
                dst,
                len: d.len(),
                tos,
            },
            d,
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

impl<D: AsRef<[u8]>> std::fmt::Debug for Datagram<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Datagram {:?} {:?}->{:?}: {}",
            self.meta.tos(),
            self.meta.source(),
            self.meta.destination(),
            hex_with_len(&self.d)
        )
    }
}

impl<'a> Datagram<&'a mut [u8]> {
    #[must_use]
    pub fn from_slice(src: SocketAddr, dst: SocketAddr, tos: IpTos, d: &'a mut [u8]) -> Self {
        Self {
            meta: DatagramMetaData {
                src,
                dst,
                len: d.len(),
                tos,
            },
            d,
        }
    }

    #[must_use]
    pub fn to_owned(&self) -> Datagram {
        Datagram {
            meta: self.meta.clone(),
            d: self.d.to_vec(),
        }
    }
}

impl<D: AsRef<[u8]>> AsRef<[u8]> for Datagram<D> {
    fn as_ref(&self) -> &[u8] {
        self.d.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use test_fixture::datagram;

    #[test]
    fn fmt_datagram() {
        let d = datagram([0; 1].to_vec());
        assert_eq!(
            &format!("{d:?}"),
            "Datagram IpTos(Cs0, Ect0) [fe80::1]:443->[fe80::1]:443: [1]: 00"
        );
    }

    #[test]
    fn is_empty() {
        let d = datagram(vec![]);
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());
    }
}
