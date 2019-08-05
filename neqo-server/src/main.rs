// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::Datagram;
use neqo_crypto::{init_db, AntiReplay};
use neqo_transport::{Connection, ConnectionEvent, FixedConnectionIdManager, State};
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-client", about = "A basic QUIC client.")]
struct Args {
    #[structopt(short = "h", long)]
    /// Optional local address to bind to, defaults to the unspecified address.
    host: Option<String>,
    /// Port number.
    port: u16,

    /// A resource to request.
    request: Vec<String>,

    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    /// NSS database directory.
    db: PathBuf,
    #[structopt(short = "k", long, default_value = "key")]
    /// Name of keys from NSS database.
    key: Vec<String>,

    #[structopt(short = "a", long, default_value = "http/0.9")]
    /// ALPN labels to negotiate.
    ///
    /// This server still only does HTTP/0.9 no matter what the ALPN says.
    alpn: Vec<String>,

    #[structopt(short = "4", long)]
    /// Restrict to IPv4.
    ipv4: bool,
    #[structopt(short = "6", long)]
    /// Restrict to IPv6.
    ipv6: bool,
}

impl Args {
    fn bind(&self) -> SocketAddr {
        match (&self.host, self.ipv4, self.ipv6) {
            (Some(..), ..) => self
                .to_socket_addrs()
                .expect("Remote address error")
                .next()
                .expect("No remote addresses"),
            (_, false, true) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), self.port),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), self.port),
        }
    }
}

impl ToSocketAddrs for Args {
    type Iter = ::std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        let dflt = String::from(match (self.ipv4, self.ipv6) {
            (false, true) => "::",
            _ => "0.0.0.0",
        });
        let h = self.host.as_ref().unwrap_or(&dflt);
        // This is idiotic.  There is no path from hostname: String to IpAddr.
        // And no means of controlling name resolution either.
        fmt::format(format_args!("{}:{}", h, self.port)).to_socket_addrs()
    }
}

// World's dumbest HTTP 0.9 server. Assumes that the whole request is
// in a single write.
// TODO(ekr@rtfm.com): One imagines we could fix this.
fn http_serve(server: &mut Connection, stream: u64) {
    println!("Stream ID {}", stream);
    let mut data = vec![0; 4000];
    server
        .stream_recv(stream, &mut data)
        .expect("Read should succeed");
    let msg = String::from_utf8(data.clone()).unwrap();
    let re = Regex::new(r"GET +/(\d*)(\r)?\n").unwrap();
    let m = re.captures(&msg);
    if m.is_none() {
        println!("Invalid HTTP request: {}", msg);
        return;
    }
    let m = m.unwrap();

    let mut resp: Vec<u8> = vec![];
    if let Some(path) = m.get(1) {
        let path = path.as_str();
        println!("Path = {}", path);
        let count = u32::from_str_radix(path, 10).unwrap();
        for _i in 0..count {
            resp.push(0x58);
        }
    } else {
        resp = b"Hello World".to_vec();
    }
    // TODO(ekr@rtfm.com): This won't work with flow control blocks.
    server.stream_send(stream, &resp).expect("Successful write");
    server.stream_close_send(stream).expect("Stream closed");
}

fn emit_datagram(socket: &UdpSocket, d: Datagram) {
    let sent = socket
        .send_to(&d[..], d.destination())
        .expect("Error sending datagram");
    if sent != d.len() {
        eprintln!("Unable to send all {} bytes of datagram", d.len());
    }
}

fn main() {
    let args = Args::from_args();
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone());
    let anti_replay = AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
        .expect("unable to setup anti-replay");

    // TODO(mt): listen on both v4 and v6.
    let socket = UdpSocket::bind(args.bind()).expect("Unable to bind UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");

    println!("Server waiting for connection on: {:?}", local_addr);

    let buf = &mut [0u8; 2048];
    let mut connections: HashMap<SocketAddr, Connection> = HashMap::new();
    loop {
        // TODO use timer to set socket.set_read_timeout.
        let (sz, remote_addr) = socket.recv_from(&mut buf[..]).expect("UDP error");
        if sz == buf.len() {
            eprintln!("Discarding packet that might be truncated");
            continue;
        }

        let mut server = connections.entry(remote_addr).or_insert_with(|| {
            println!("New connection from {:?}", remote_addr);
            Connection::new_server(
                &args.key,
                &args.alpn,
                &anti_replay,
                FixedConnectionIdManager::new(10),
            )
            .expect("can't create connection")
        });

        if sz > 0 {
            let dgram = Datagram::new(remote_addr, local_addr, &buf[..sz]);
            server.process_input(dgram, Instant::now());
        }
        if let State::Closed(e) = server.state() {
            eprintln!("Closed connection from {:?}: {:?}", remote_addr, e);
            connections.remove(&remote_addr);
            continue;
        }
        if let State::Closing { error, .. } = server.state() {
            eprintln!("Closing connection from {:?}: {:?}", remote_addr, error);
            // TOOD(ekr@rtfm.com): Do I need to remove?
            continue;
        }
        let mut streams = Vec::new();
        for event in server.events() {
            if let ConnectionEvent::RecvStreamReadable { stream_id } = event {
                streams.push(stream_id)
            }
        }

        for stream_id in streams {
            http_serve(&mut server, stream_id);
        }

        let out = server.process_output(Instant::now());
        if let Some(dgram) = out.dgram() {
            emit_datagram(&socket, dgram);
        }
    }
}
