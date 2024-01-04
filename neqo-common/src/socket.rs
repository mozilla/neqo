// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{self},
    net::SocketAddr,
};

#[cfg(posix_socket)]
use std::{
    io::{Error, ErrorKind, IoSlice, IoSliceMut},
    os::fd::AsRawFd,
};

use nix::sys::socket::{
    setsockopt,
    sockopt::{IpDontFrag, IpRecvTos, IpRecvTtl, Ipv6DontFrag, Ipv6RecvHopLimit, Ipv6RecvTClass},
};
#[cfg(posix_socket)]
use nix::{
    cmsg_space,
    sys::socket::{
        recvmsg, sendmsg, AddressFamily,
        ControlMessage::{IpTos, IpTtl, Ipv6HopLimit, Ipv6TClass},
        ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage,
    },
};

use crate::Datagram;

/// Binds a `std::net::UdpSocket` socket to the specified local address.
///
/// # Arguments
///
/// * `local_addr` - The local `SocketAddr` to bind the socket to.
///
/// # Returns
///
/// The bound UDP socket.
///
/// # Errors
///
/// Returns an `io::Error` if the UDP socket fails to bind to the specified local address.
///
/// # Panics
///
/// Panics if the UDP socket fails to bind to the specified local address.
///
/// # Notes
///
/// This function binds the UDP socket to the specified local address. It also tries to
/// perform additional configuration on the socket, such as setting socket options to
/// request TOS and TTL information for incoming packets. If that additional configuration
/// fails, the function will still return.
///
pub fn bind(local_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    match std::net::UdpSocket::bind(local_addr) {
        Err(e) => {
            eprintln!("Unable to bind UDP socket: {e}");
            Err(e)
        }
        Ok(s) => {
            // Don't let the host stack or network path fragment our IP packets
            // (RFC9000, Section 14).
            let res = match local_addr {
                SocketAddr::V4(..) => setsockopt(&s, IpDontFrag, &true),
                SocketAddr::V6(..) => setsockopt(&s, Ipv6DontFrag, &true),
            };
            debug_assert!(res.is_ok());
            // Request IPv4 type-of-service (TOS) and IPv6 traffic class
            // information for all incoming packets.
            let res = match local_addr {
                SocketAddr::V4(..) => setsockopt(&s, IpRecvTos, &true),
                SocketAddr::V6(..) => setsockopt(&s, Ipv6RecvTClass, &true),
            };
            assert!(res.is_ok());
            // Request IPv4 time-to-live (TTL) and IPv6 hop count
            // information for all incoming packets.
            let res = match local_addr {
                SocketAddr::V4(..) => setsockopt(&s, IpRecvTtl, &true),
                SocketAddr::V6(..) => setsockopt(&s, Ipv6RecvHopLimit, &true),
            };
            debug_assert!(res.is_ok());
            Ok(s)
        }
    }
}

pub trait UdpIo {
    /// Send the UDP datagram on the specified socket.
    ///
    /// # Arguments
    ///
    /// * `d` - The datagram to send.
    ///
    /// # Returns
    ///
    /// An `io::Result` indicating whether the datagram was sent successfully.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the UDP socket fails to send the datagram.
    ///
    fn send(&self, d: &Datagram) -> io::Result<usize>;

    /// Receive a UDP datagram on the specified socket.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to receive the datagram into.
    /// * `tos` - The type-of-service (TOS) or traffic class (TC) value of the received datagram.
    /// * `ttl` - The time-to-live (TTL) or hop limit (HL) value of the received datagram.
    ///
    /// # Returns
    ///
    /// An `io::Result` indicating the size of the received datagram and the source address.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the UDP socket fails to receive the datagram.
    ///
    fn recv(&self, buf: &mut [u8], tos: &mut u8, ttl: &mut u8) -> io::Result<(usize, SocketAddr)>;
}

fn emit_result(result: io::Result<usize>, len: usize) -> usize {
    let sent = result.unwrap();
    if sent != len {
        eprintln!("Only able to send {sent}/{len} bytes of datagram");
    }
    sent
}

#[cfg(posix_socket)]
fn emit_datagram_posix<S: AsRawFd>(socket: &S, d: &Datagram) -> io::Result<usize> {
    let iov = [IoSlice::new(&d[..])];
    let tos = i32::from(d.tos());
    let ttl = i32::from(d.ttl());
    let cmsgs = match d.destination() {
        SocketAddr::V4(..) => [IpTos(&tos), IpTtl(&ttl)],
        SocketAddr::V6(..) => [Ipv6TClass(&tos), Ipv6HopLimit(&ttl)],
    };
    match sendmsg(
        socket.as_raw_fd(),
        &iov,
        &cmsgs,
        MsgFlags::empty(),
        Some(&SockaddrStorage::from(d.destination())),
    ) {
        Ok(res) => Ok(res),
        Err(e) => Err(Error::from_raw_os_error(e as i32)),
    }
}

#[cfg(posix_socket)]
fn to_socket_addr(addr: &SockaddrStorage) -> SocketAddr {
    match addr.family().unwrap() {
        AddressFamily::Inet => {
            let addr = addr.as_sockaddr_in().unwrap();
            SocketAddr::new(std::net::IpAddr::V4(addr.ip()), addr.port())
        }
        AddressFamily::Inet6 => {
            let addr = addr.as_sockaddr_in6().unwrap();
            SocketAddr::new(std::net::IpAddr::V6(addr.ip()), addr.port())
        }
        _ => unreachable!(),
    }
}

/// Use `recvmsg` to receive a UDP datagram and its metadata on the specified socket.
///
/// # Arguments
///
/// * `socket` - The UDP socket to receive the datagram on.
/// * `buf` - The buffer to receive the datagram into.
/// * `tos` - The type-of-service (TOS) or traffic class (TC) value of the received datagram.
/// * `ttl` - The time-to-live (TTL) or hop limit (HL) value of the received datagram.
///
/// # Returns
///
/// An `io::Result` indicating the size of the received datagram and the source address.
///
/// # Errors
///
/// Returns an `io::Error` if the UDP socket fails to receive the datagram.
///
#[cfg(posix_socket)]
pub fn recv_datagram_posix<S: AsRawFd>(
    socket: &S,
    buf: &mut [u8],
    tos: &mut u8,
    ttl: &mut u8,
) -> io::Result<(usize, SocketAddr)> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsg = cmsg_space!(u8, u8);
    let flags = MsgFlags::empty();

    match recvmsg::<SockaddrStorage>(socket.as_raw_fd(), &mut iov, Some(&mut cmsg), flags) {
        Err(e) => Err(Error::from_raw_os_error(e as i32)),
        Ok(res) => {
            for cmsg in res.cmsgs() {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                // All valid values fit in u8.
                match cmsg {
                    ControlMessageOwned::IpTos(t) | ControlMessageOwned::Ipv6TClass(t) => {
                        *tos = t as u8;
                    }
                    ControlMessageOwned::IpTtl(t) | ControlMessageOwned::Ipv6HopLimit(t) => {
                        *ttl = t as u8;
                    }
                    _ => unreachable!(),
                };
            }
            let Some(addr) = res.address else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Unable to retrieve source address from datagram",
                ));
            };
            Ok((res.bytes, to_socket_addr(&addr)))
        }
    }
}

impl UdpIo for std::net::UdpSocket {
    #[cfg(posix_socket)]
    fn send(&self, d: &Datagram) -> io::Result<usize> {
        let res = emit_result(emit_datagram_posix(self, d), d.len());
        Ok(res)
    }

    #[cfg(not(posix_socket))]
    fn send(&self, d: &Datagram) -> io::Result<usize> {
        let res = emit_result(self.send_to(&d[..], d.destination()), d.len());
        Ok(res)
    }

    #[cfg(posix_socket)]
    fn recv(&self, buf: &mut [u8], tos: &mut u8, ttl: &mut u8) -> io::Result<(usize, SocketAddr)> {
        recv_datagram_posix(self, buf, tos, ttl)
    }

    #[cfg(not(posix_socket))]
    fn recv(&self, buf: &mut [u8], tos: &mut u8, ttl: &mut u8) -> io::Result<(usize, SocketAddr)> {
        *tos = 0xff;
        *ttl = 0xff;
        self.recv_from(&mut buf[..])
    }
}

impl UdpIo for mio::net::UdpSocket {
    #[cfg(posix_socket)]
    fn send(&self, d: &Datagram) -> io::Result<usize> {
        let res = emit_result(emit_datagram_posix(self, d), d.len());
        Ok(res)
    }
    #[cfg(not(posix_socket))]
    fn send(&self, d: &Datagram) -> io::Result<usize> {
        let res = emit_result(self.send_to(&d[..], &d.destination()), d.len());
        Ok(res)
    }

    #[cfg(posix_socket)]
    fn recv(&self, buf: &mut [u8], tos: &mut u8, ttl: &mut u8) -> io::Result<(usize, SocketAddr)> {
        recv_datagram_posix(self, buf, tos, ttl)
    }

    #[cfg(not(posix_socket))]
    fn recv(&self, buf: &mut [u8], tos: &mut u8, ttl: &mut u8) -> io::Result<(usize, SocketAddr)> {
        *tos = 0xff;
        *ttl = 0xff;
        self.recv_from(&mut buf[..])
    }
}

/// Send the UDP datagram on the specified socket.
/// 
/// # Arguments
/// 
/// * `socket` - The UDP socket to send the datagram on.
/// * `d` - The datagram to send.
/// 
/// # Returns
/// 
/// An `io::Result` indicating whether the datagram was sent successfully.
/// 
/// # Errors
/// 
/// Returns an `io::Error` if the UDP socket fails to send the datagram.
/// 
pub fn emit_datagram<S: UdpIo>(socket: &S, d: &Datagram) -> io::Result<usize> {
    socket.send(d)
}

/// Receive a UDP datagram on the specified socket.
/// 
/// # Arguments
/// 
/// * `socket` - The UDP socket to receive the datagram on.
/// * `buf` - The buffer to receive the datagram into.
/// * `tos` - The type-of-service (TOS) or traffic class (TC) value of the received datagram.
/// * `ttl` - The time-to-live (TTL) or hop limit (HL) value of the received datagram.
/// 
/// # Returns
/// 
/// An `io::Result` indicating the size of the received datagram and the source address.
/// 
/// # Errors
/// 
/// Returns an `io::Error` if the UDP socket fails to receive the datagram.
/// 
pub fn recv_datagram<S: UdpIo>(
    socket: &S,
    buf: &mut [u8],
    tos: &mut u8,
    ttl: &mut u8,
) -> io::Result<(usize, SocketAddr)> {
    socket.recv(buf, tos, ttl)
}
