// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Network namespace tests for Linux.
//!
//! These tests verify MTU detection behavior in complex networking scenarios
//! using Linux network namespaces. They require root privileges and will
//! skip automatically if not running as root.
//!
//! Run with: `sudo -E cargo test --package mtu --test netns`

#![cfg(target_os = "linux")]
#![expect(clippy::unwrap_used, reason = "OK in tests.")]

use std::{
    fs::File,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU32, Ordering},
        Once,
    },
};

use mtu::interface_and_mtu;

static COUNTER: AtomicU32 = AtomicU32::new(0);
static SKIP_MESSAGE: Once = Once::new();

fn unique_name(prefix: &str) -> String {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{}_{id}", std::process::id())
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn ip_netns(ns: &str, args: &[&str]) -> bool {
    let mut full_args = vec!["netns", "exec", ns, "ip"];
    full_args.extend(args);
    ip(&full_args)
}

fn ip_netns_output(ns: &str, args: &[&str]) -> Option<String> {
    let mut full_args = vec!["netns", "exec", ns, "ip"];
    full_args.extend(args);
    Command::new("ip")
        .args(&full_args)
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
}

macro_rules! require_root {
    () => {
        if !is_root() {
            SKIP_MESSAGE.call_once(|| {
                eprintln!(
                    "Skipping network namespace tests: not running as root.\n\
                     Run with: sudo -E cargo test --package mtu --test netns"
                );
            });
            return;
        }
    };
}

/// RAII guard for a network namespace.
struct NetNs {
    name: String,
}

impl NetNs {
    fn new(name: &str) -> Option<Self> {
        ip(&["netns", "add", name]).then(|| Self { name: name.into() })
    }

    /// Run a closure inside this namespace.
    fn run<F, T>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> T,
    {
        // Open current namespace to restore later.
        let orig = File::open("/proc/self/ns/net")?;

        // Open target namespace.
        let path = format!("/var/run/netns/{}", self.name);
        let target = File::open(&path)?;

        // Enter target namespace.
        if unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let result = f();

        // Restore original namespace.
        if unsafe { libc::setns(orig.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(result)
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        ip(&["netns", "delete", &self.name]);
    }
}

/// RAII guard for a veth pair.
struct VethPair(String);

impl VethPair {
    fn new(name: &str, peer: &str) -> Option<Self> {
        ip(&["link", "add", name, "type", "veth", "peer", "name", peer]).then(|| Self(name.into()))
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        ip(&["link", "delete", &self.0]);
    }
}

/// A test network with a namespace and connected interfaces.
struct TestNet {
    ns: Option<NetNs>,
    _veths: (Option<VethPair>, Option<VethPair>),
}

impl TestNet {
    /// Create a network with one interface pair.
    fn new(inside_ip: &str, outside_ip: &str, mtu: u32) -> Option<Self> {
        let name = unique_name("ns");
        let vi = unique_name("vi");
        let vo = unique_name("vo");
        let mtu_s = mtu.to_string();

        let ns = NetNs::new(&name)?;
        let veth = VethPair::new(&vi, &vo)?;

        ip(&["link", "set", &vi, "netns", &name]);
        ip_netns(&name, &["addr", "add", inside_ip, "dev", &vi]);
        ip_netns(&name, &["link", "set", &vi, "mtu", &mtu_s]);
        ip_netns(&name, &["link", "set", &vi, "up"]);
        ip_netns(&name, &["link", "set", "lo", "up"]);
        ip(&["addr", "add", outside_ip, "dev", &vo]);
        ip(&["link", "set", &vo, "mtu", &mtu_s]);
        ip(&["link", "set", &vo, "up"]);

        Some(Self {
            ns: Some(ns),
            _veths: (Some(veth), None),
        })
    }

    /// Create a network with two interface pairs (different MTUs).
    fn dual(
        ip1_in: &str,
        ip1_out: &str,
        mtu1: u32,
        ip2_in: &str,
        ip2_out: &str,
        mtu2: u32,
    ) -> Option<Self> {
        let name = unique_name("ns");
        let vi1 = unique_name("v1i");
        let vo1 = unique_name("v1o");
        let vi2 = unique_name("v2i");
        let vo2 = unique_name("v2o");

        let ns = NetNs::new(&name)?;
        let veth1 = VethPair::new(&vi1, &vo1)?;
        let veth2 = VethPair::new(&vi2, &vo2)?;

        ip(&["link", "set", &vi1, "netns", &name]);
        ip(&["link", "set", &vi2, "netns", &name]);

        ip_netns(&name, &["addr", "add", ip1_in, "dev", &vi1]);
        ip_netns(&name, &["link", "set", &vi1, "mtu", &mtu1.to_string()]);
        ip_netns(&name, &["link", "set", &vi1, "up"]);

        ip_netns(&name, &["addr", "add", ip2_in, "dev", &vi2]);
        ip_netns(&name, &["link", "set", &vi2, "mtu", &mtu2.to_string()]);
        ip_netns(&name, &["link", "set", &vi2, "up"]);

        ip_netns(&name, &["link", "set", "lo", "up"]);

        ip(&["addr", "add", ip1_out, "dev", &vo1]);
        ip(&["link", "set", &vo1, "up"]);
        ip(&["addr", "add", ip2_out, "dev", &vo2]);
        ip(&["link", "set", &vo2, "up"]);

        Some(Self {
            ns: Some(ns),
            _veths: (Some(veth1), Some(veth2)),
        })
    }

    /// Create a loopback-only namespace.
    fn loopback() -> Option<Self> {
        let name = unique_name("ns");
        let ns = NetNs::new(&name)?;
        ip_netns(&name, &["link", "set", "lo", "up"]);
        Some(Self {
            ns: Some(ns),
            _veths: (None, None),
        })
    }

    /// Look up interface and MTU for a destination.
    fn lookup(&self, dest: IpAddr) -> io::Result<(String, usize)> {
        self.ns
            .as_ref()
            .expect("namespace exists")
            .run(|| interface_and_mtu(dest))?
    }
}

#[test]
fn custom_mtu_v4() {
    require_root!();
    let net = TestNet::new("10.0.0.1/24", "10.0.0.2/24", 1400).unwrap();
    let (_, mtu) = net.lookup(Ipv4Addr::new(10, 0, 0, 2).into()).unwrap();
    assert_eq!(mtu, 1400);
}

#[test]
fn custom_mtu_v6() {
    require_root!();
    let net = TestNet::new("fd00::1/64", "fd00::2/64", 1280).unwrap();
    let (_, mtu) = net
        .lookup("fd00::2".parse::<Ipv6Addr>().unwrap().into())
        .unwrap();
    assert_eq!(mtu, 1280);
}

#[test]
fn jumbo_mtu() {
    require_root!();
    let net = TestNet::new("10.1.0.1/24", "10.1.0.2/24", 9000).unwrap();
    let (_, mtu) = net.lookup(Ipv4Addr::new(10, 1, 0, 2).into()).unwrap();
    assert_eq!(mtu, 9000);
}

#[test]
fn multiple_interfaces() {
    require_root!();
    let net = TestNet::dual(
        "10.10.0.1/24",
        "10.10.0.2/24",
        1500,
        "10.20.0.1/24",
        "10.20.0.2/24",
        9000,
    )
    .unwrap();

    let (_, mtu1) = net.lookup(Ipv4Addr::new(10, 10, 0, 2).into()).unwrap();
    assert_eq!(mtu1, 1500);

    let (_, mtu2) = net.lookup(Ipv4Addr::new(10, 20, 0, 2).into()).unwrap();
    assert_eq!(mtu2, 9000);
}

#[test]
fn loopback_v4() {
    require_root!();
    let net = TestNet::loopback().unwrap();
    let (iface, mtu) = net.lookup(Ipv4Addr::LOCALHOST.into()).unwrap();
    assert_eq!(iface, "lo");
    assert_eq!(mtu, 65536);
}

#[test]
fn loopback_v6() {
    require_root!();
    let net = TestNet::loopback().unwrap();
    let (iface, mtu) = net.lookup(Ipv6Addr::LOCALHOST.into()).unwrap();
    assert_eq!(iface, "lo");
    assert_eq!(mtu, 65536);
}

/// Verify that MTU lookup respects policy routing rules.
#[test]
fn policy_routing() {
    require_root!();

    let name = unique_name("ns");
    let vi_main = unique_name("vmi");
    let vo_main = unique_name("vmo");
    let vi_vpn = unique_name("vvi");
    let vo_vpn = unique_name("vvo");

    let ns = NetNs::new(&name).unwrap();
    let _veth_main = VethPair::new(&vi_main, &vo_main).unwrap();
    let _veth_vpn = VethPair::new(&vi_vpn, &vo_vpn).unwrap();

    ip(&["link", "set", &vi_main, "netns", &name]);
    ip(&["link", "set", &vi_vpn, "netns", &name]);

    // Main interface: 10.0.1.0/24, MTU 1500.
    ip_netns(&name, &["addr", "add", "10.0.1.1/24", "dev", &vi_main]);
    ip_netns(&name, &["link", "set", &vi_main, "mtu", "1500"]);
    ip_netns(&name, &["link", "set", &vi_main, "up"]);

    // VPN interface: 10.0.2.0/24, MTU 1400.
    ip_netns(&name, &["addr", "add", "10.0.2.1/24", "dev", &vi_vpn]);
    ip_netns(&name, &["link", "set", &vi_vpn, "mtu", "1400"]);
    ip_netns(&name, &["link", "set", &vi_vpn, "up"]);

    ip_netns(&name, &["link", "set", "lo", "up"]);

    // Outside peers.
    ip(&["addr", "add", "10.0.1.2/24", "dev", &vo_main]);
    ip(&["link", "set", &vo_main, "mtu", "1500"]);
    ip(&["link", "set", &vo_main, "up"]);
    ip(&["addr", "add", "10.0.2.2/24", "dev", &vo_vpn]);
    ip(&["link", "set", &vo_vpn, "mtu", "1400"]);
    ip(&["link", "set", &vo_vpn, "up"]);

    // Route in main table via main interface.
    ip_netns(
        &name,
        &[
            "route",
            "add",
            "10.30.0.0/24",
            "via",
            "10.0.1.2",
            "dev",
            &vi_main,
        ],
    );

    // Route in table 100 via VPN interface.
    ip_netns(
        &name,
        &[
            "route",
            "add",
            "10.30.0.0/24",
            "via",
            "10.0.2.2",
            "dev",
            &vi_vpn,
            "table",
            "100",
        ],
    );

    // Policy rule: use table 100.
    ip_netns(
        &name,
        &["rule", "add", "from", "all", "lookup", "100", "prio", "100"],
    );

    // Verify policy routing is active.
    let route = ip_netns_output(&name, &["route", "get", "10.30.0.1"]).unwrap();
    assert!(
        route.contains("via 10.0.2.2"),
        "Policy routing not active: {route}"
    );

    // Test MTU lookup.
    let (_, mtu) = ns
        .run(|| interface_and_mtu(Ipv4Addr::new(10, 30, 0, 1).into()))
        .unwrap()
        .unwrap();
    assert_eq!(mtu, 1400, "Should return VPN interface MTU");

    // Cleanup policy rule (namespace deletion handles the rest).
    ip_netns(
        &name,
        &["rule", "del", "from", "all", "lookup", "100", "prio", "100"],
    );
}
