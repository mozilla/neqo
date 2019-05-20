// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::now;
use neqo_crypto::init;
//use neqo_transport::frame::StreamType;
use neqo_transport::{Connection, ConnectionEvent, Datagram, State};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
// use std::path::PathBuf;
use std::thread;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-interop", about = "A QUIC interop client.")]
struct Args {
    #[structopt(short = "i", long)]
    // Peers to include
    include: Vec<String>,

    #[structopt(short = "e", long)]
    exclude: Vec<String>,
}

trait Handler {
    fn handle(&mut self, client: &mut Connection) -> bool;
}

fn emit_packets(socket: &UdpSocket, out_dgrams: &Vec<Datagram>) {
    for d in out_dgrams {
        let sent = socket.send(&d[..]).expect("Error sending datagram");
        if sent != d.len() {
            eprintln!("Unable to send all {} bytes of datagram", d.len());
        }
    }
}

fn process_loop(
    local_addr: &SocketAddr,
    remote_addr: &SocketAddr,
    socket: &UdpSocket,
    client: &mut Connection,
    handler: &mut Handler,
) -> neqo_transport::connection::State {
    let buf = &mut [0u8; 2048];
    let mut in_dgrams = Vec::new();
    loop {
        client.process_input(in_dgrams.drain(..), now());

        if let State::Closed(..) = client.state() {
            return client.state().clone();
        }

        let exiting = !handler.handle(client);

        let (out_dgrams, _timer) = client.process_output(now());
        emit_packets(&socket, &out_dgrams);

        if exiting {
            return client.state().clone();
        }

        let sz = socket.recv(&mut buf[..]).expect("UDP error");
        if sz == buf.len() {
            eprintln!("Received more than {} bytes", buf.len());
            continue;
        }
        if sz > 0 {
            in_dgrams.push(Datagram::new(
                remote_addr.clone(),
                local_addr.clone(),
                &buf[..sz],
            ));
        }
    }
}

struct PreConnectHandler {}
impl Handler for PreConnectHandler {
    fn handle(&mut self, client: &mut Connection) -> bool {
        match client.state() {
            State::Connected => false,
            State::Closing(..) => false,
            _ => true,
        }
    }
}

#[derive(Default)]
struct PostConnectHandler {
    streams: HashSet<u64>,
}

// This is a bit fancier than actually needed.
impl Handler for PostConnectHandler {
    fn handle(&mut self, client: &mut Connection) -> bool {
        let mut data = vec![0; 4000];
        for event in client.events() {
            match event {
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    if !self.streams.contains(&stream_id) {
                        eprintln!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let (_sz, fin) = client
                        .stream_recv(stream_id, &mut data)
                        .expect("Read should succeed");
                    eprintln!(
                        "READ[{}]: {}",
                        stream_id,
                        String::from_utf8(data.clone()).unwrap()
                    );
                    if fin {
                        eprintln!("<FIN[{}]>", stream_id);
                        client.close(0, "kthxbye!");
                        return false;
                    }
                }
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    eprintln!("stream {} writable", stream_id)
                }
                _ => {
                    eprintln!("Unexpected event {:?}", event);
                }
            }
        }

        true
    }
}

struct Peer {
    label: &'static str,
    host: &'static str,
    port: u16,
}

impl Peer {
    fn addr(&self) -> SocketAddr {
        self.to_socket_addrs()
            .expect("Remote address error")
            .next()
            .expect("No remote addresses")
    }

    fn bind(&self) -> SocketAddr {
        match self.addr() {
            SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
            SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0),
        }
    }

    fn test_enabled(&self, _test: &Test) -> bool {
        true
    }

    fn alpn(&self) -> Vec<String> {
        match self.label {
            "quicly" => vec![String::from("http/0.9")],
            _ => vec![String::from("hq-20")],
        }
    }
}

impl ToSocketAddrs for Peer {
    type Iter = ::std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        // This is idiotic.  There is no path from hostname: String to IpAddr.
        // And no means of controlling name resolution either.
        std::fmt::format(format_args!("{}:{}", self.host, self.port)).to_socket_addrs()
    }
}

#[derive(Debug)]
enum Test {
    Connect,
}

fn run_test<'t>(peer: &Peer, test: &'t Test) -> (&'t Test, String) {
    let socket = UdpSocket::bind(peer.bind()).expect("Unable to bind UDP socket");
    socket.connect(&peer).expect("Unable to connect UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");
    let remote_addr = peer.addr();

    let mut client = Connection::new_client(peer.host, peer.alpn(), local_addr, remote_addr)
        .expect("must succeed");
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h);

    let st = client.state();
    match st {
        State::Connected => (test, String::from("OK")),
        _ => (test, format!("{:?}", st)),
    }
}

fn run_peer(peer: &'static Peer) -> Vec<(&'static Test, String)> {
    let mut results: Vec<(&'static Test, String)> = Vec::new();

    eprintln!("Running tests for {}", peer.label);

    let mut children = Vec::new();

    for test in &TESTS {
        if !peer.test_enabled(&test) {
            continue;
        }

        let child = thread::spawn(move || run_test(peer, test));
        children.push((test, child));
    }

    for child in children {
        match child.1.join() {
            Ok(e) => {
                eprintln!("Test complete {:?}, {:?}", child.0, e);
                results.push(e)
            }
            Err(_) => {
                eprintln!("Thread crashed {:?}", child.0);
                results.push((child.0, String::from("CRASHED")));
            }
        }
    }

    eprintln!("Tests for {} complete {:?}", peer.label, results);
    results
}

const PEERS: [Peer; 4] = [
    Peer {
        label: &"quant",
        host: &"quant.eggert.org",
        port: 4433,
    },
    Peer {
        label: &"quicly",
        host: "kazuhooku.com",
        port: 4433,
    },
    Peer {
        label: &"local",
        host: &"127.0.0.1",
        port: 4433,
    },
    Peer {
        label: &"applequic",
        host: &"192.168.200.19",
        port: 4433,
    },
];

const TESTS: [Test; 1] = [Test::Connect];

fn main() {
    let _tests = vec![Test::Connect];

    let args = Args::from_args();
    init();

    let mut children = Vec::new();

    // Start all the children.
    for peer in &PEERS {
        if args.include.len() > 0 && !args.include.contains(&String::from(peer.label)) {
            continue;
        }
        if args.exclude.contains(&String::from(peer.label)) {
            continue;
        }

        let child = thread::spawn(move || run_peer(&peer));
        children.push((peer, child));
    }

    // Now wait for them.
    for child in children {
        let res = child.1.join().unwrap();
        eprintln!("{} -> {:?}", child.0.label, res);
    }
}
