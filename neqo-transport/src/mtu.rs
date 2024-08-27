// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
};

use neqo_common::qtrace;
use static_assertions::assert_cfg;
/// Return the MTU of the interface that is used to reach the given remote socket address.
///
/// # Errors
///
/// This function returns an error if the local interface MTU cannot be determined.
#[allow(clippy::too_many_lines)]
pub fn get_interface_mtu(remote: &SocketAddr) -> Result<usize, Error> {
    // Prepare a default error result.
    let mut res = Err(Error::new(
        ErrorKind::NotFound,
        "Local interface MTU not found",
    ));

    assert_cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ));

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        #[cfg(target_os = "linux")]
        use std::{ffi::c_char, mem, os::fd::AsRawFd};
        use std::{
            ffi::CStr,
            net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
            ptr,
        };

        use libc::{
            freeifaddrs, getifaddrs, ifaddrs, in_addr_t, sa_family_t, sockaddr_in, sockaddr_in6,
            AF_INET, AF_INET6,
        };
        #[cfg(target_os = "macos")]
        use libc::{if_data, AF_LINK};
        #[cfg(target_os = "linux")]
        use libc::{ifreq, ioctl};

        // Make a new socket that is connected to the remote address. We use this to learn which
        // local address is chosen by routing.
        let socket = UdpSocket::bind((
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        ))?;
        socket.connect(remote)?;
        let local_ip = socket.local_addr()?.ip();

        // Get the interface list.
        let mut ifap: *mut ifaddrs = ptr::null_mut(); // Do not modify this pointer.
        if unsafe { getifaddrs(&mut ifap) } != 0 {
            return Err(Error::last_os_error());
        }

        // First, find the name of the interface with the the local IP address determined above.
        let mut cursor = ifap;
        let iface = loop {
            if cursor.is_null() {
                break None;
            }

            let ifa = unsafe { &*cursor };
            if !ifa.ifa_addr.is_null()
                && ((unsafe { *ifa.ifa_addr }).sa_family
                    == sa_family_t::try_from(AF_INET).unwrap_or(sa_family_t::MAX)
                    || (unsafe { *ifa.ifa_addr }).sa_family
                        == sa_family_t::try_from(AF_INET6).unwrap_or(sa_family_t::MAX))
            {
                let saddr_ptr = ifa.ifa_addr as *const u8;
                let found = match local_ip {
                    IpAddr::V4(ip) => {
                        let saddr: sockaddr_in =
                            unsafe { ptr::read_unaligned(saddr_ptr.cast::<sockaddr_in>()) };
                        saddr.sin_addr.s_addr == in_addr_t::to_be(ip.into())
                    }
                    IpAddr::V6(ip) => {
                        let saddr: sockaddr_in6 =
                            unsafe { ptr::read_unaligned(saddr_ptr.cast::<sockaddr_in6>()) };
                        saddr.sin6_addr.s6_addr == ip.octets()
                    }
                };

                if found {
                    break unsafe { CStr::from_ptr(ifa.ifa_name).to_str().ok() };
                }
            }
            cursor = ifa.ifa_next;
        };

        // If we have found the interface name we are looking for, find the MTU.
        if let Some(iface) = iface {
            #[cfg(target_os = "macos")]
            {
                // On macOS, we need to loop again to find the MTU of that interface. We need to do
                // two loops, because `getifaddrs` returns one entry per interface
                // and link type, and the IP addresses are in the AF_INET/AF_INET6
                // entries for an interface, whereas the MTU is (only) in the
                // AF_LINK entry, whose `ifa_addr` contains MAC address information,
                // not IP address information.
                let mut cursor = ifap;
                while !cursor.is_null() {
                    let ifa = unsafe { &*cursor };
                    if !ifa.ifa_addr.is_null()
                        && (unsafe { *ifa.ifa_addr }).sa_family
                            == sa_family_t::try_from(AF_LINK).unwrap_or(sa_family_t::MAX)
                    {
                        if let Some(data) = unsafe { (ifa.ifa_data as *const if_data).as_ref() } {
                            if unsafe { CStr::from_ptr(ifa.ifa_name).to_str().unwrap_or_default() }
                                == iface
                            {
                                res = usize::try_from(data.ifi_mtu).or(res);
                                break;
                            }
                        }
                    }
                    cursor = ifa.ifa_next;
                }
            }
            #[cfg(target_os = "linux")]
            {
                // On Linux, we can get the MTU via an ioctl on the socket.
                let mut ifr: ifreq = unsafe { mem::zeroed() };
                ifr.ifr_name[..iface.len()].copy_from_slice(unsafe {
                    &*(std::ptr::from_ref::<[u8]>(iface.as_bytes()) as *const [c_char])
                });
                if unsafe { ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &ifr) } != 0 {
                    res = Err(Error::last_os_error());
                } else {
                    res = unsafe { usize::try_from(ifr.ifr_ifru.ifru_mtu).or(res) };
                }
            }
        }

        unsafe { freeifaddrs(ifap) };
    }

    #[cfg(target_os = "windows")]
    {
        use std::mem;

        use winapi::{
            shared::{
                in6addr::IN6_ADDR,
                inaddr::IN_ADDR,
                minwindef::DWORD,
                netioapi::{GetIfEntry2, MIB_IF_ROW2},
                winerror::NO_ERROR,
                ws2def::{ADDRESS_FAMILY, AF_INET, AF_INET6, SOCKADDR_IN},
                ws2ipdef::SOCKADDR_IN6,
            },
            um::iphlpapi::GetBestInterfaceEx,
        };

        let mut saddr = match remote {
            SocketAddr::V4(addr) => {
                let saddr = SOCKADDR_IN {
                    sin_family: AF_INET as ADDRESS_FAMILY,
                    sin_port: addr.port().to_be(),
                    sin_addr: IN_ADDR {
                        S_un: unsafe { mem::transmute(addr.ip().octets()) },
                    },
                    sin_zero: [0; 8],
                };
                unsafe { mem::transmute(saddr) }
            }
            SocketAddr::V6(addr) => {
                let saddr = SOCKADDR_IN6 {
                    sin6_family: AF_INET6 as ADDRESS_FAMILY,
                    sin6_port: addr.port().to_be(),
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_addr: IN6_ADDR {
                        u: unsafe { mem::transmute(addr.ip().octets()) },
                    },
                    sin6_scope_id: addr.scope_id(),
                };

                unsafe { mem::transmute(saddr) }
            }
        };
        let mut idx: DWORD = 0;
        if unsafe { GetBestInterfaceEx(saddr, &mut idx) } != NO_ERROR {
            res = Err(Error::last_os_error());
        } else {
            let mut row: MIB_IF_ROW2 = unsafe { mem::zeroed() };
            row.InterfaceIndex = idx;
            res = if unsafe { GetIfEntry2(&mut row) } == NO_ERROR {
                usize::try_from(row.Mtu).or(res)
            } else {
                Err(Error::last_os_error())
            };
        }
    }

    qtrace!("MTU towards {:?} is {:?}", remote, res);
    res
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

    fn check_mtu(addr4: SocketAddr, addr6: SocketAddr, expected: usize) {
        let mtu4 = super::get_interface_mtu(&addr4).unwrap();
        let mtu6 = super::get_interface_mtu(&addr6).unwrap();
        assert_eq!(mtu4, expected);
        assert_eq!(mtu6, expected);
    }

    #[test]
    fn loopback_interface_mtu() {
        let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let addr6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443);
        #[cfg(target_os = "macos")]
        check_mtu(addr4, addr6, 16384);
        #[cfg(target_os = "linux")]
        check_mtu(addr4, addr6, 65536);
    }

    #[test]
    fn default_interface_mtu() {
        // For GitHub CI, this needs to be looked up dynamically.
        let addr4 = "mozilla.com:443".to_socket_addrs().unwrap().next().unwrap();
        let addr6 = "mozilla.com:443".to_socket_addrs().unwrap().next().unwrap();
        check_mtu(addr4, addr6, 1500);
    }
}
