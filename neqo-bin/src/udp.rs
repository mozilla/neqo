// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::missing_errors_doc, reason = "Passing up tokio errors.")]

use std::{io, net::SocketAddr, os::fd::AsRawFd as _, ptr};

use libc::{c_int, setsockopt, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};
use neqo_common::{qwarn, Datagram};
use neqo_udp::{DatagramIter, RecvBuf};

/// One megabyte in bytes; the size for the receive and send buffers.
const ONE_MB: c_int = 1 << 20;

/// Ideally this would live in [`neqo-udp`]. [`neqo-udp`] is used in Firefox.
///
/// Firefox uses `cargo vet`. [`tokio`] the dependency of [`neqo-udp`] is not
/// audited as `safe-to-deploy`. `cargo vet` will require `safe-to-deploy` for
/// [`tokio`] even when behind a feature flag.
///
/// See <https://github.com/mozilla/cargo-vet/issues/626>.
pub struct Socket {
    state: quinn_udp::UdpSocketState,
    inner: tokio::net::UdpSocket,
}

impl Socket {
    /// Create a new [`Socket`] bound to the provided address, not managed externally.
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        let socket = std::net::UdpSocket::bind(addr)?;

        // Try to incresase the receive buffer size.
        if unsafe {
            #[expect(clippy::cast_possible_truncation, reason = "size_of::<c_int> is 4")]
            setsockopt(
                socket.as_raw_fd(),
                SOL_SOCKET,
                SO_RCVBUF,
                ptr::from_ref(&ONE_MB).cast(),
                size_of::<c_int>() as u32,
            )
        } != 0
        {
            qwarn!("Failed to set socket recv size");
        }

        // Try to incresase the send buffer size.
        if unsafe {
            #[expect(clippy::cast_possible_truncation, reason = "size_of::<c_int> is 4")]
            setsockopt(
                socket.as_raw_fd(),
                SOL_SOCKET,
                SO_SNDBUF,
                ptr::from_ref(&ONE_MB).cast(),
                size_of::<c_int>() as u32,
            )
        } != 0
        {
            qwarn!("Failed to set socket send size");
        }

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

    /// Send a [`Datagram`] on the given [`Socket`].
    pub fn send(&self, d: &Datagram) -> io::Result<()> {
        self.inner.try_io(tokio::io::Interest::WRITABLE, || {
            neqo_udp::send_inner(&self.state, (&self.inner).into(), d)
        })
    }

    /// Receive a batch of [`Datagram`]s on the given [`Socket`], each set with
    /// the provided local address.
    pub fn recv<'a>(
        &self,
        local_address: SocketAddr,
        recv_buf: &'a mut RecvBuf,
    ) -> Result<Option<DatagramIter<'a>>, io::Error> {
        self.inner
            .try_io(tokio::io::Interest::READABLE, || {
                neqo_udp::recv_inner(local_address, &self.state, &self.inner, recv_buf)
            })
            .map(Some)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }
}
