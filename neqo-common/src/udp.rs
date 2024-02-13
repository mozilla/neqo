// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::{
    io::{self, IoSliceMut},
    net::{SocketAddr, ToSocketAddrs},
    slice,
};

use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
use tokio::io::Interest;

use crate::{Datagram, IpTos};

pub struct Socket {
    socket: tokio::net::UdpSocket,
    state: UdpSocketState,
}

impl Socket {
    /// Calls [`std::net::UdpSocket::bind`] and instantiates [`quinn_udp::UdpSocketState`].
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        let socket = std::net::UdpSocket::bind(addr)?;

        Ok(Self {
            state: quinn_udp::UdpSocketState::new((&socket).into())?,
            socket: tokio::net::UdpSocket::from_std(socket)?,
        })
    }

    /// See [`tokio::net::UdpSocket::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// See [`tokio::net::UdpSocket::writable`].
    pub async fn writable(&self) -> Result<(), io::Error> {
        self.socket.writable().await
    }

    /// See [`tokio::net::UdpSocket::readable`].
    pub async fn readable(&self) -> Result<(), io::Error> {
        self.socket.readable().await
    }

    /// Send the UDP datagram on the specified socket.
    pub fn send(&self, d: Datagram) -> io::Result<usize> {
        let transmit = Transmit {
            destination: d.destination(),
            ecn: EcnCodepoint::from_bits(Into::<u8>::into(d.tos())),
            contents: d.into_data().into(),
            segment_size: None,
            src_ip: None,
        };

        let n = self.socket.try_io(Interest::WRITABLE, || {
            self.state
                .send((&self.socket).into(), slice::from_ref(&transmit))
        })?;

        assert_eq!(n, 1, "only passed one slice");

        Ok(n)
    }

    /// Receive a UDP datagram on the specified socket.
    pub fn recv(&self, local_address: &SocketAddr) -> Result<Option<Datagram>, io::Error> {
        let mut buf = [0; u16::MAX as usize];

        let mut meta = RecvMeta::default();

        match self.socket.try_io(Interest::READABLE, || {
            self.state.recv(
                (&self.socket).into(),
                &mut [IoSliceMut::new(&mut buf)],
                slice::from_mut(&mut meta),
            )
        }) {
            Ok(n) => {
                assert_eq!(n, 1, "only passed one slice");
            }
            Err(ref err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::Interrupted =>
            {
                return Ok(None)
            }
            Err(err) => {
                return Err(err);
            }
        };

        if meta.len == 0 {
            eprintln!("zero length datagram received?");
            return Ok(None);
        }

        if meta.len == buf.len() {
            eprintln!("Might have received more than {} bytes", buf.len());
        }

        Ok(Some(Datagram::new(
            meta.addr,
            *local_address,
            meta.ecn.map(|n| IpTos::from(n as u8)).unwrap_or_default(),
            None, // TODO: get the real TTL https://github.com/quinn-rs/quinn/issues/1749
            &buf[..meta.len],
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::sleep;

    use super::*;
    use crate::{IpTos, IpTosDscp, IpTosEcn};

    #[tokio::test]
    async fn datagram_tos() -> Result<(), io::Error> {
        let sender = Socket::bind("127.0.0.1:0")?;
        let receiver_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let receiver = Socket::bind(receiver_addr)?;

        sleep(Duration::from_millis(100)).await;

        let tos_tx = IpTos::from((IpTosDscp::Le, IpTosEcn::Ce));
        let datagram = Datagram::new(
            sender.local_addr()?,
            receiver.local_addr()?,
            tos_tx,
            None,
            "Hello, world!".as_bytes().to_vec(),
        );

        sender.writable().await?;
        sender.send(datagram.clone())?;

        sleep(Duration::from_millis(100)).await;

        receiver.readable().await?;
        let received_datagram = receiver
            .recv(&receiver_addr)
            .expect("receive to succeed")
            .expect("receive to yield datagram");

        // Assert that the ECN is correct.
        assert_eq!(
            IpTosEcn::from(datagram.tos()),
            IpTosEcn::from(received_datagram.tos())
        );

        Ok(())
    }
}
