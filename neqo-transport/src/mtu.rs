// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ptr,
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

    assert_cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ));

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::ffi::{c_int, CStr};
        #[cfg(target_os = "linux")]
        use std::{ffi::c_char, mem, os::fd::AsRawFd};

        use libc::{
            freeifaddrs, getifaddrs, ifaddrs, in_addr_t, sockaddr_in, sockaddr_in6, AF_INET,
            AF_INET6,
        };
        #[cfg(target_os = "macos")]
        use libc::{if_data, AF_LINK};
        #[cfg(target_os = "linux")]
        use libc::{ifreq, ioctl};

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
            if !ifa.ifa_addr.is_null() {
                let saddr = unsafe { &*ifa.ifa_addr };
                if matches!(c_int::from(saddr.sa_family), AF_INET | AF_INET6)
                    && match local_ip {
                        IpAddr::V4(ip) => {
                            let saddr: sockaddr_in =
                                unsafe { ptr::read_unaligned(ifa.ifa_addr.cast::<sockaddr_in>()) };
                            saddr.sin_addr.s_addr == in_addr_t::to_be(ip.into())
                        }
                        IpAddr::V6(ip) => {
                            let saddr: sockaddr_in6 =
                                unsafe { ptr::read_unaligned(ifa.ifa_addr.cast::<sockaddr_in6>()) };
                            saddr.sin6_addr.s6_addr == ip.octets()
                        }
                    }
                {
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
                    if !ifa.ifa_addr.is_null() {
                        let saddr = unsafe { &*ifa.ifa_addr };
                        let name = String::from_utf8_lossy(unsafe {
                            CStr::from_ptr(ifa.ifa_name).to_bytes()
                        });
                        if c_int::from(saddr.sa_family) == AF_LINK
                            && !ifa.ifa_data.is_null()
                            && name == iface
                        {
                            let data = unsafe { &*(ifa.ifa_data as *const if_data) };
                            res = usize::try_from(data.ifi_mtu).or(res);
                            break;
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
                    &*(ptr::from_ref::<[u8]>(iface.as_bytes()) as *const [c_char])
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
        use std::{cmp::min, ffi::c_void, slice};

        use windows::Win32::{
            Foundation::NO_ERROR,
            NetworkManagement::IpHelper::{
                FreeMibTable, GetIpInterfaceTable, GetUnicastIpAddressTable, MIB_IPINTERFACE_ROW,
                MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
            },
            Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
        };

        let mut addr_table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut addr_table) } == NO_ERROR {
            let addrs = unsafe {
                slice::from_raw_parts::<MIB_UNICASTIPADDRESS_ROW>(
                    &(*addr_table).Table[0],
                    (*addr_table).NumEntries as usize,
                )
            };
            for addr in addrs {
                let af = unsafe { addr.Address.si_family };
                if (af == AF_INET && local_ip.is_ipv4() || af == AF_INET6 && local_ip.is_ipv6())
                    && match local_ip {
                        IpAddr::V4(ip) => {
                            u32::from(ip).to_be()
                                == unsafe { addr.Address.Ipv4.sin_addr.S_un.S_addr }
                        }
                        IpAddr::V6(ip) => {
                            ip.octets() == unsafe { addr.Address.Ipv6.sin6_addr.u.Byte }
                        }
                    }
                {
                    let mut if_table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
                    if unsafe { GetIpInterfaceTable(af, &mut if_table) } == NO_ERROR {
                        let ifaces = unsafe {
                            slice::from_raw_parts::<MIB_IPINTERFACE_ROW>(
                                &(*if_table).Table[0],
                                (*if_table).NumEntries as usize,
                            )
                        };
                        for iface in ifaces {
                            if iface.InterfaceIndex == addr.InterfaceIndex {
                                // On loopback, the MTU is 4294967295...
                                res = min(iface.NlMtu, 65536).try_into().or(res);
                                break;
                            }
                        }
                        unsafe { FreeMibTable(if_table as *const c_void) };
                    } else {
                        res = Err(Error::last_os_error());
                    }
                    break;
                }
            }
            unsafe { FreeMibTable(addr_table as *const c_void) };
        } else {
            res = Err(Error::last_os_error());
        }
    }

    qtrace!("MTU towards {:?} is {:?}", remote, res);
    res
}

#[cfg(test)]
mod test {
    use std::net::ToSocketAddrs;

    use neqo_common::qwarn;

    fn check_mtu(sockaddr: &str, ipv4: bool, expected: usize) {
        let addr = sockaddr
            .to_socket_addrs()
            .unwrap()
            .find(|a| a.is_ipv4() == ipv4);
        if let Some(addr) = addr {
            match super::get_interface_mtu(&addr) {
                Ok(mtu) => assert_eq!(mtu, expected),
                Err(e) => {
                    // Some GitHub runners don't have IPv6. Just warn if we can't get the MTU.
                    assert!(addr.is_ipv6());
                    qwarn!("Error getting MTU for {}: {}", sockaddr, e);
                }
            }
        } else {
            // Some GitHub runners don't have IPv6. Just warn if we can't get an IPv6 address.
            assert!(!ipv4);
            qwarn!("No IPv6 address found for {}", sockaddr);
        }
    }

    #[test]
    fn loopback_interface_mtu_v4() {
        #[cfg(target_os = "macos")]
        check_mtu("localhost:443", true, 16384);
        #[cfg(not(target_os = "macos"))]
        check_mtu("localhost:443", true, 65536);
    }

    #[test]
    fn loopback_interface_mtu_v6() {
        #[cfg(target_os = "macos")]
        check_mtu("localhost:443", false, 16384);
        #[cfg(not(target_os = "macos"))]
        check_mtu("localhost:443", false, 65536);
    }

    #[test]
    fn default_interface_mtu_v4() {
        check_mtu("ietf.org:443", true, 1500);
    }

    #[test]
    fn default_interface_mtu_v6() {
        check_mtu("ietf.org:443", false, 1500);
    }
}
