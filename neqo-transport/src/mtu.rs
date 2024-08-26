// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
};

use neqo_common::qtrace;
use static_assertions::assert_cfg;

/// Return the MTU of the interface that is used to reach the given remote IP address.
///
/// # Errors
///
/// This function returns an error if the local interface MTU cannot be determined.
pub fn get_interface_mtu(remote_ip: &IpAddr) -> Result<u32, Error> {
    // Prepare a default error result.
    let mut res = Err(Error::new(
        ErrorKind::NotFound,
        "Local interface MTU not found",
    ));

    assert_cfg!(any(target_os = "macos", target_os = "linux"));

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::{ffi::CStr, ptr};
        #[cfg(target_os = "linux")]
        use std::{mem, os::fd::AsRawFd};

        #[cfg(target_os = "macos")]
        use libc::if_data;
        use libc::{freeifaddrs, getifaddrs, ifaddrs, sockaddr_in, sockaddr_in6};
        #[cfg(target_os = "linux")]
        use libc::{ifreq, ioctl};

        // Make a new socket that is connected to the remote address. We use this to learn which
        // local address is chosen by routing.
        let socket = if remote_ip.is_ipv4() {
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?
        } else {
            UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?
        };
        socket.connect((*remote_ip, 10000))?;
        let local_ip = socket.local_addr()?.ip();

        // Get the interface list.
        let mut ifap: *mut ifaddrs = ptr::null_mut();
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
            let found = match local_ip {
                IpAddr::V4(ip) => {
                    let saddr_ptr = ifa.ifa_addr as *const u8;
                    let saddr: sockaddr_in =
                        unsafe { ptr::read_unaligned(saddr_ptr.cast::<sockaddr_in>()) };
                    saddr.sin_addr.s_addr == u32::from_le_bytes(ip.octets())
                }
                IpAddr::V6(ip) => {
                    let saddr_ptr = ifa.ifa_addr as *const u8;
                    let saddr: sockaddr_in6 =
                        unsafe { ptr::read_unaligned(saddr_ptr.cast::<sockaddr_in6>()) };
                    saddr.sin6_addr.s6_addr == ip.octets()
                }
            };

            if found {
                break unsafe { CStr::from_ptr(ifa.ifa_name).to_str().ok() };
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
                    if let Some(data) = unsafe { (ifa.ifa_data as *const if_data).as_ref() } {
                        if unsafe { CStr::from_ptr(ifa.ifa_name).to_str().unwrap_or_default() }
                            == iface
                        {
                            res = Ok(data.ifi_mtu);
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
                ifr.ifr_name[..iface.len()]
                    .copy_from_slice(unsafe { *iface.as_bytes().as_ptr().cast::<&[i8]>() });
                if unsafe { ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &ifr) } != 0 {
                    res = Err(Error::last_os_error());
                } else {
                    res = unsafe { u32::try_from(ifr.ifr_ifru.ifru_mtu).or(res) };
                }
            }
        }

        unsafe { freeifaddrs(ifap) };
    }

    qtrace!("MTU for {:?} is {:?}", remote_ip, res);
    res
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use neqo_common::qdebug;

    fn check_mtu(ip4: IpAddr, ip6: IpAddr, expected: u32) {
        let mtu4 = super::get_interface_mtu(&ip4).unwrap();
        let mtu6 = super::get_interface_mtu(&ip6).unwrap();
        qdebug!(
            "MTU for {:?} is {} and for {:?} is {}",
            ip4,
            mtu4,
            ip6,
            mtu6
        );
        assert_eq!(mtu4, expected);
        assert_eq!(mtu6, expected);
    }

    #[test]
    fn loopback_interface_mtu() {
        let ip4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        #[cfg(target_os = "macos")]
        check_mtu(ip4, ip6, 16384);
        #[cfg(target_os = "linux")]
        check_mtu(ip4, ip6, 65536);
    }

    #[test]
    fn default_interface_mtu() {
        let ip4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let ip6 = IpAddr::V6(Ipv6Addr::new(2001, 4860, 4860, 0, 0, 0, 0, 8888));
        check_mtu(ip4, ip6, 1500);
    }
}
