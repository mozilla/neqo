// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Look up MTU and interface information for a given hostname.

use std::net::{IpAddr, ToSocketAddrs as _};

fn main() {
    let Some(host) = std::env::args().nth(1) else {
        eprintln!("Usage: mtu-lookup <hostname>");
        return;
    };

    let addrs: Vec<IpAddr> = host.parse().map_or_else(
        |_| {
            format!("{host}:0")
                .to_socket_addrs()
                .expect("Failed to resolve hostname")
                .map(|s| s.ip())
                .collect()
        },
        |ip| vec![ip],
    );

    for ip in addrs {
        match mtu::interface_and_mtu(ip) {
            Ok((iface, mtu)) => {
                let v = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
                println!("{v} {ip}: MTU {mtu} on {iface}");
            }
            Err(e) => eprintln!("Error for {ip}: {e}"),
        }
    }
}
