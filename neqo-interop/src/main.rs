// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::now;
use neqo_crypto::init_db;
//use neqo_transport::frame::StreamType;
use neqo_transport::{Connection, ConnectionEvent, Datagram, State};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::thread;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-client", about = "A basic QUIC client.")]
struct Args {
    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    db: PathBuf,
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
        if let State::Connected = client.state() {
            return false;
        }
        return true;
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
                        println!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let (_sz, fin) = client
                        .stream_recv(stream_id, &mut data)
                        .expect("Read should succeed");
                    println!(
                        "READ[{}]: {}",
                        stream_id,
                        String::from_utf8(data.clone()).unwrap()
                    );
                    if fin {
                        println!("<FIN[{}]>", stream_id);
                        client.close(0, "kthxbye!");
                        return false;
                    }
                }
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    println!("stream {} writable", stream_id)
                }
                _ => {
                    println!("Unexpected event {:?}", event);
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
}

impl ToSocketAddrs for Peer {
    type Iter = ::std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        // This is idiotic.  There is no path from hostname: String to IpAddr.
        // And no means of controlling name resolution either.
        std::fmt::format(format_args!("{}:{}", self.host, self.port)).to_socket_addrs()
    }
}

enum Test {
    Connect,
}

impl Test {
    fn alpn(&self) -> Vec<String> {
        return vec![String::from("http/0.9")];
    }
}

fn run_test(peer: &Peer, test: &Test) -> bool {
    let socket = UdpSocket::bind(peer.bind()).expect("Unable to bind UDP socket");
    socket.connect(&peer).expect("Unable to connect UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");
    let remote_addr = peer.addr();

    let mut client = Connection::new_client(peer.host, test.alpn(), local_addr, remote_addr)
        .expect("must succeed");
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h);

    return true;
}

fn run_peer(peer: &'static Peer) -> Vec<&Test> {
    let results = Vec::new();
    println!("Running tests for {}", peer.label);
    for test in &TESTS {
        if !peer.test_enabled(&test) {
            continue;
        }

        let _child = thread::spawn(move || {
            run_test(peer, test);
        });
    }

    results
}

const PEERS: [Peer; 1] = [Peer {
    label: &"quant",
    host: &"quant.eggert.org",
    port: 4433,
}];

const TESTS: [Test; 1] = [Test::Connect];

fn main() {
    let _tests = vec![Test::Connect];

    let args = Args::from_args();
    init_db(args.db.clone());

    for peer in &PEERS {
        let _child = thread::spawn(move || {
            run_peer(&peer);
        });
    }
}
