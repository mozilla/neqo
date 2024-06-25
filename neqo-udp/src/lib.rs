// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::missing_errors_doc)] // Functions simply delegate to tokio and quinn-udp.
#![allow(clippy::missing_panics_doc)] // Functions simply delegate to tokio and quinn-udp.

use std::{
    cell::RefCell,
    io::{self, IoSliceMut},
    net::SocketAddr,
    slice,
};

use neqo_common::{qtrace, Datagram, IpTos};
use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};

/// Socket receive buffer size.
///
/// Allows reading multiple datagrams in a single [`Socket::recv`] call.
const RECV_BUF_SIZE: usize = u16::MAX as usize;

std::thread_local! {
    static RECEIVE_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; RECV_BUF_SIZE]);
}

pub struct Socket<S> {
    state: UdpSocketState,
    inner: S,
}

impl<S> Socket<S> {
    fn send_inner(
        state: &UdpSocketState,
        socket: quinn_udp::UdpSockRef<'_>,
        d: &Datagram,
    ) -> io::Result<()> {
        let transmit = Transmit {
            destination: d.destination(),
            ecn: EcnCodepoint::from_bits(Into::<u8>::into(d.tos())),
            contents: d,
            segment_size: None,
            src_ip: None,
        };

        state.send(socket, &transmit)?;

        qtrace!(
            "sent {} bytes from {} to {}",
            d.len(),
            d.source(),
            d.destination()
        );

        Ok(())
    }

    fn recv_inner(
        local_address: &SocketAddr,
        state: &UdpSocketState,
        socket: quinn_udp::UdpSockRef<'_>,
    ) -> Result<Vec<Datagram>, io::Error> {
        let mut meta = RecvMeta::default();

        let dgrams =
            RECEIVE_BUFFER.with_borrow_mut(|recv_buf| -> Result<Vec<Datagram>, io::Error> {
                state.recv(
                    socket,
                    &mut [IoSliceMut::new(recv_buf)],
                    slice::from_mut(&mut meta),
                )?;

                Ok(recv_buf[0..meta.len]
                    .chunks(meta.stride.min(recv_buf.len()))
                    .map(|d| {
                        qtrace!(
                            "received {} bytes from {} to {}",
                            d.len(),
                            meta.addr,
                            local_address,
                        );
                        Datagram::new(
                            meta.addr,
                            *local_address,
                            meta.ecn.map(|n| IpTos::from(n as u8)).unwrap_or_default(),
                            None, // TODO: get the real TTL https://github.com/quinn-rs/quinn/issues/1749
                            d,
                        )
                    })
                    .collect())
            })?;

        qtrace!(
            "received {} datagrams ({:?})",
            dgrams.len(),
            dgrams.iter().map(|d| d.len()).collect::<Vec<_>>(),
        );

        Ok(dgrams)
    }
}

#[cfg(unix)]
type BorrowedSocket = std::os::fd::BorrowedFd<'static>;
#[cfg(windows)]
type BorrowedSocket = std::os::windows::io::BorrowedSocket<'static>;

impl Socket<BorrowedSocket> {
    pub fn new(socket: BorrowedSocket) -> Result<Self, io::Error> {
        Ok(Self {
            state: quinn_udp::UdpSocketState::new((&socket).into())?,
            inner: socket,
        })
    }

    pub fn send(&self, d: &Datagram) -> io::Result<()> {
        Self::send_inner(&self.state, (&self.inner).into(), d)
    }

    pub fn recv(&mut self, local_address: &SocketAddr) -> Result<Vec<Datagram>, io::Error> {
        Self::recv_inner(local_address, &self.state, (&self.inner).into())
    }
}

#[cfg(feature = "tokio")]
impl Socket<tokio::net::UdpSocket> {
    /// Calls [`std::net::UdpSocket::bind`] and instantiates [`quinn_udp::UdpSocketState`].
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        let socket = std::net::UdpSocket::bind(addr)?;

        Ok(Self {
            state: quinn_udp::UdpSocketState::new((&socket).into())?,
            inner: tokio::net::UdpSocket::from_std(socket)?,
        })
    }

    /// See [`tokio::net::UdpSocket::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// See [`tokio::net::UdpSocket::writable`].
    pub async fn writable(&self) -> Result<(), io::Error> {
        self.inner.writable().await
    }

    /// See [`tokio::net::UdpSocket::readable`].
    pub async fn readable(&self) -> Result<(), io::Error> {
        self.inner.readable().await
    }

    /// Send the UDP datagram.
    pub fn send(&self, d: &Datagram) -> io::Result<()> {
        self.inner.try_io(tokio::io::Interest::WRITABLE, || {
            Self::send_inner(&self.state, (&self.inner).into(), d)
        })
    }

    /// Receive a UDP datagram.
    pub fn recv(&mut self, local_address: &SocketAddr) -> Result<Vec<Datagram>, io::Error> {
        self.inner
            .try_io(tokio::io::Interest::READABLE, || {
                Self::recv_inner(local_address, &self.state, (&self.inner).into())
            })
            .or_else(|e| {
                if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(vec![])
                } else {
                    Err(e)
                }
            })
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use neqo_common::{IpTosDscp, IpTosEcn};

    use super::*;

    #[tokio::test]
    async fn datagram_tos() -> Result<(), io::Error> {
        let sender = Socket::bind("127.0.0.1:0")?;
        let receiver_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut receiver = Socket::bind(receiver_addr)?;

        let datagram = Datagram::new(
            sender.local_addr()?,
            receiver.local_addr()?,
            IpTos::from((IpTosDscp::Le, IpTosEcn::Ect1)),
            None,
            "Hello, world!".as_bytes().to_vec(),
        );

        sender.writable().await?;
        sender.send(&datagram)?;

        receiver.readable().await?;
        let received_datagram = receiver
            .recv(&receiver_addr)
            .expect("receive to succeed")
            .into_iter()
            .next()
            .expect("receive to yield datagram");

        // Assert that the ECN is correct.
        assert_eq!(
            IpTosEcn::from(datagram.tos()),
            IpTosEcn::from(received_datagram.tos())
        );

        Ok(())
    }

    /// Expect [`Socket::recv`] to handle multiple [`Datagram`]s on GRO read.
    #[tokio::test]
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), ignore)]
    async fn many_datagrams_through_gro() -> Result<(), io::Error> {
        const SEGMENT_SIZE: usize = 128;

        let sender = Socket::bind("127.0.0.1:0")?;
        let receiver_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut receiver = Socket::bind(receiver_addr)?;

        // `neqo_common::udp::Socket::send` does not yet
        // (https://github.com/mozilla/neqo/issues/1693) support GSO. Use
        // `quinn_udp` directly.
        let max_gso_segments = sender.state.max_gso_segments();
        let msg = vec![0xAB; SEGMENT_SIZE * max_gso_segments];
        let transmit = Transmit {
            destination: receiver.local_addr()?,
            ecn: EcnCodepoint::from_bits(Into::<u8>::into(IpTos::from((
                IpTosDscp::Le,
                IpTosEcn::Ect1,
            )))),
            contents: &msg,
            segment_size: Some(SEGMENT_SIZE),
            src_ip: None,
        };
        sender.writable().await?;
        sender.inner.try_io(tokio::io::Interest::WRITABLE, || {
            sender.state.send((&sender.inner).into(), &transmit)
        })?;

        // Allow for one GSO sendmmsg to result in multiple GRO recvmmsg.
        let mut num_received = 0;
        while num_received < max_gso_segments {
            receiver.readable().await?;
            receiver
                .recv(&receiver_addr)
                .expect("receive to succeed")
                .into_iter()
                .for_each(|d| {
                    assert_eq!(
                        SEGMENT_SIZE,
                        d.len(),
                        "Expect received datagrams to have same length as sent datagrams."
                    );
                    num_received += 1;
                });
        }

        Ok(())
    }
}
