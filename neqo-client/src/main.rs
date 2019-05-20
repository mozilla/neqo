// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{hex, now};
use neqo_crypto::init_db;
use neqo_transport::frame::StreamType;
use neqo_transport::{Connection, ConnectionEvent, Datagram, State};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-client", about = "A basic QUIC client.")]
struct Args {
    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    db: PathBuf,

    #[structopt(short = "a", long, default_value = "http/0.9")]
    /// ALPN labels to negotiate.
    ///
    /// This client still only does HTTP/0.9 no matter what the ALPN says.
    alpn: Vec<String>,

    #[structopt(short = "4", long)]
    /// Restrict to IPv4.
    ipv4: bool,
    #[structopt(short = "6", long)]
    /// Restrict to IPv6.
    ipv6: bool,

    host: String,
    port: u16,
}

impl Args {
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
}

impl ToSocketAddrs for Args {
    type Iter = ::std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        // This is idiotic.  There is no path from hostname: String to IpAddr.
        // And no means of controlling name resolution either.
        std::fmt::format(format_args!("{}:{}", self.host, self.port)).to_socket_addrs()
    }
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
            State::Connected => {
                println!("Connected");
                false
            }
            State::Closing(error, ..) => {
                println!("Handshake failure {:?}", error);
                false
            }
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

fn main() {
    let args = Args::from_args();
    init_db(args.db.clone());

    let socket = UdpSocket::bind(args.bind()).expect("Unable to bind UDP socket");
    socket.connect(&args).expect("Unable to connect UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");
    let remote_addr = args.addr();

    println!("Client connecting: {:?} -> {:?}", local_addr, remote_addr);

    let mut client = Connection::new_client(args.host.as_str(), args.alpn, local_addr, remote_addr)
        .expect("must succeed");

    println!("SCID={}", hex(&client.scid()));
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h);

    let client_stream_id = client.stream_create(StreamType::BiDi).unwrap();
    let req: String = "GET /10\r\n".to_string();
    client
        .stream_send(client_stream_id, req.as_bytes())
        .unwrap();

    let mut h2 = PostConnectHandler::default();
    h2.streams.insert(client_stream_id);
    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h2);
}
