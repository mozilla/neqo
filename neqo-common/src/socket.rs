// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{self, Error, ErrorKind, IoSlice, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    os::fd::{AsRawFd, FromRawFd},
};

use nix::{
    cmsg_space,
    errno::Errno::{EAGAIN, EINTR},
    sys::socket::{
        recvmsg, sendmsg, setsockopt,
        sockopt::{
            IpDontFrag, IpRecvTos, IpRecvTtl, Ipv6DontFrag, Ipv6RecvHopLimit, Ipv6RecvTClass,
        },
        AddressFamily,
        ControlMessage::{IpTos, IpTtl, Ipv6HopLimit, Ipv6TClass},
        ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage,
    },
};

use crate::Datagram;

/// Binds a UDP socket to the specified local address.
///
/// # Arguments
///
/// * `local_addr` - The local address to bind the socket to.
///
/// # Returns
///
/// The bound UDP socket.
///
/// # Panics
///
/// Panics if the UDP socket fails to bind to the specified local address or if various
/// socket options cannot be set.
///
/// # Notes
///
/// This function binds the UDP socket to the specified local address and performs additional
/// configuration on the socket, such as setting socket options to request TOS and TTL
/// information for incoming packets.
pub fn bind(local_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = match UdpSocket::bind(local_addr) {
        Err(e) => {
            panic!("Unable to bind UDP socket: {}", e);
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
            s
        }
    };
    Ok(socket)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
pub fn emit_datagram_posix<S: AsRawFd + FromRawFd>(socket: &S, d: &Datagram) -> usize {
    let iov = [IoSlice::new(&d[..])];
    let tos = i32::from(d.tos());
    let ttl = i32::from(d.ttl());
    let cmsgs = match d.destination() {
        SocketAddr::V4(..) => [IpTos(&tos), IpTtl(&ttl)],
        SocketAddr::V6(..) => [Ipv6TClass(&tos), Ipv6HopLimit(&ttl)],
    };
    sendmsg(
        socket.as_raw_fd(),
        &iov,
        &cmsgs,
        MsgFlags::empty(),
        Some(&SockaddrStorage::from(d.destination())),
    )
    .unwrap()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
pub fn emit_datagram_generic<S: AsRawFd + FromRawFd>(socket: &S, d: &Datagram) -> usize {
    // Use the default `UdpSocket::send_to` implementation for non-POSIX platforms.
    // This also means we don't set the TOS and TTL values.
    let sock = unsafe { UdpSocket::from_raw_fd(socket.as_raw_fd()) };
    sock.send_to(&d[..], d.destination()).unwrap()
}

/// Send the UDP datagram on the specified socket.
///
/// # Arguments
///
/// * `fd` - The UDP socket to send the datagram on.
/// * `d` - The datagram to send.
///
/// # Returns
///
/// An `io::Result` indicating whether the datagram was sent successfully.
///
/// # Panics
///
/// Panics if the send call fails.
///
/// # Notes
///
/// On non-POSIX platforms, TOS and TTL will not be sent and hence revert to the system default.
/// TODO: Figure out how to set TOS and TTL at least on Windows.
pub fn emit_datagram<S: AsRawFd + FromRawFd>(socket: &S, d: &Datagram) -> io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
    let sent = emit_datagram_posix(socket, d);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    let sent = emit_datagram_generic(socket, d);
    if sent != d.len() {
        eprintln!("Unable to send all {} bytes of datagram", d.len());
    }
    Ok(())
}

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

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
fn recv_datagram_posix<S: AsRawFd>(
    socket: &S,
    buf: &mut [u8],
    tos: &mut u8,
    ttl: &mut u8,
) -> io::Result<(usize, SocketAddr)> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsg = cmsg_space!(u8, u8);
    let flags = MsgFlags::empty();

    match recvmsg::<SockaddrStorage>(socket.as_raw_fd(), &mut iov, Some(&mut cmsg), flags) {
        Err(e) if e == EAGAIN => Err(Error::new(ErrorKind::WouldBlock, e)),
        Err(e) if e == EINTR => Err(Error::new(ErrorKind::Interrupted, e)),
        Err(e) => panic!("UDP error: {}", e),
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
            Ok((res.bytes, to_socket_addr(&res.address.unwrap())))
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
fn recv_datagram_generic<S: AsRawFd>(
    socket: &S,
    buf: &mut [u8],
    tos: &mut u8,
    ttl: &mut u8,
) -> io::Result<(usize, SocketAddr)> {
    // Use the default `UdpSocket::recv_from` implementation for non-POSIX platforms.
    *tos = *ttl = 0xff;
    let sock = unsafe { UdpSocket::from_raw_fd(socket.as_raw_fd()) };
    sock.recv_from(&mut buf[..])
}

/// Receive a UDP datagram on the specified socket.
///
/// # Arguments
///
/// * `fd` - The UDP socket to receive the datagram on.
/// * `buf` - The buffer to receive the datagram into.
/// * `tos` - The type-of-service (TOS) or traffic class (TC) value of the received datagram.
/// * `ttl` - The time-to-live (TTL) or hop limit (HL) value of the received datagram.
///
/// # Returns
///
/// An `io::Result` indicating the size of the received datagram.
///
/// # Errors
///
/// Returns an `io::ErrorKind::WouldBlock` error if the `recvmsg` call would block.
///
/// # Panics
///
/// Panics if the `recvmsg` call results in any result other than success, EAGAIN, or EINTR.
///
/// # Notes
///
/// On non-POSIX platforms, TOS and TTL will be set to 0xff to indicate they were not retrieved
/// from the packet. TODO: Figure out how to retrieve TOS and TTL at least on Windows.
pub fn recv_datagram<S: AsRawFd>(
    socket: &S,
    buf: &mut [u8],
    tos: &mut u8,
    ttl: &mut u8,
) -> io::Result<(usize, SocketAddr)> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
    return recv_datagram_posix(socket, buf, tos, ttl);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    return recv_datagram(socket, buf, tos, ttl);
}
