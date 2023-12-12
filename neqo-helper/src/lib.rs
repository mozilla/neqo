// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{self, Error, ErrorKind, IoSlice, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    process::exit,
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

use neqo_common::Datagram;

// Bind a UDP socket and set some default socket options.
pub fn bind(local_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = match UdpSocket::bind(local_addr) {
        Err(e) => {
            eprintln!("Unable to bind UDP socket: {}", e);
            exit(1)
        }
        Ok(s) => {
            // Don't let the host stack or network path fragment our IP packets
            // (RFC9000, Section 14).
            let res = match local_addr {
                SocketAddr::V4(..) => setsockopt(&s, IpDontFrag, &true),
                SocketAddr::V6(..) => setsockopt(&s, Ipv6DontFrag, &true),
            };
            assert!(res.is_ok());
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
            assert!(res.is_ok());
            s
        }
    };
    Ok(socket)
}

fn to_sockaddr(addr: SocketAddr) -> SockaddrStorage {
    SockaddrStorage::from(addr)
}

pub fn emit_datagram(fd: i32, d: Datagram) -> io::Result<()> {
    let iov = [IoSlice::new(&d[..])];
    let tos = d.tos() as i32;
    let ttl = d.ttl() as i32;
    let cmsgs = match d.destination() {
        SocketAddr::V4(..) => [IpTos(&tos), IpTtl(&ttl)],
        SocketAddr::V6(..) => [Ipv6TClass(&tos), Ipv6HopLimit(&ttl)],
    };
    let sent = sendmsg(
        fd,
        &iov,
        &cmsgs,
        MsgFlags::empty(),
        Some(&to_sockaddr(d.destination())),
    )
    .unwrap();
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

pub fn recv_datagram(
    fd: i32,
    buf: &mut [u8],
    tos: &mut u8,
    ttl: &mut u8,
) -> io::Result<(usize, SocketAddr)> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsg = cmsg_space!(u8, u8);
    let flags = MsgFlags::empty();

    match recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsg), flags) {
        Err(e) if e == EAGAIN => Err(Error::new(ErrorKind::WouldBlock, e)),
        Err(e) if e == EINTR => Err(Error::new(ErrorKind::Interrupted, e)),
        Err(e) => {
            eprintln!("UDP error: {}", e);
            exit(1)
        }
        Ok(res) => {
            for cmsg in res.cmsgs() {
                match cmsg {
                    ControlMessageOwned::IpTos(t) => *tos = t as u8,
                    ControlMessageOwned::Ipv6TClass(t) => *tos = t as u8,
                    ControlMessageOwned::IpTtl(t) => *ttl = t as u8,
                    ControlMessageOwned::Ipv6HopLimit(t) => *ttl = t as u8,
                    _ => unreachable!(),
                };
            }
            Ok((res.bytes, to_socket_addr(&res.address.unwrap())))
        }
    }
}
