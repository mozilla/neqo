// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::now;
use neqo_crypto::init_db;
use neqo_http3::{Http3Connection, Http3State, RequestStreamServer};
use neqo_transport::{Connection, Datagram};
//use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::exit;

use structopt::StructOpt;

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};

const SERVER: Token = Token(0);

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-http3-server", about = "A basic HTTP3 server.")]
struct Args {
    #[structopt(short = "h", long)]
    /// Optional local address to bind to, defaults to the unspecified address.
    host: Option<String>,

    /// Port number.
    #[structopt(short = "p", long, default_value = "443")]
    port: u16,

    #[structopt(short = "t", long, default_value = "128")]
    max_table_size: u32,

    #[structopt(short = "b", long, default_value = "128")]
    max_blocked_streams: u16,

    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    /// NSS database directory.
    db: PathBuf,

    #[structopt(short = "k", long, default_value = "key")]
    /// Name of keys from NSS database.
    key: Vec<String>,

    #[structopt(short = "a", long, default_value = "h3-20")]
    /// ALPN labels to negotiate.
    ///
    /// This server still only does HTTP3 no matter what the ALPN says.
    alpn: Vec<String>,

    #[structopt(short = "6", long)]
    /// Use IPv6 instead of IPv4.
    ipv6: bool,
}

impl Args {
    fn bind(&self) -> SocketAddr {
        match (&self.host, self.ipv6) {
            (Some(..), ..) => self
                .to_socket_addrs()
                .expect("Remote address error")
                .next()
                .expect("No remote addresses"),
            (None, true) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), self.port),
            (None, false) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), self.port),
        }
    }
}

impl ToSocketAddrs for Args {
    type Iter = ::std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        let dflt = String::from(match self.ipv6 {
            true => "::",
            false => "0.0.0.0",
        });
        let h = self.host.as_ref().unwrap_or(&dflt);
        // This is idiotic.  There is no path from hostname: String to IpAddr.
        // And no means of controlling name resolution either.
        fmt::format(format_args!("{}:{}", h, self.port)).to_socket_addrs()
    }
}

fn http_serve(cr: &mut RequestStreamServer, _error: bool) {
    println!("Serve a request");

    let request_headers = cr.get_request_headers();
    println!("Headers: {:?}", request_headers);

    let mut resp = String::new();

    for header in request_headers {
        if header.0 == String::from(":path") {
            println!("path {}", header.1);
            let length;
            match header.1.trim_matches(|p| p == '/').parse::<u32>() {
                Ok(v) => {
                    length = v;
                }
                Err(_) => {
                    length = 0;
                }
            };

            if length == 0 {
                resp.push_str("Hello World");
            } else {
                for _i in 0..length {
                    resp.push('a');
                }
            }
        }
    }

    cr.set_response(
        &vec![
            (String::from(":status"), String::from("200")),
            (String::from("content-length"), resp.len().to_string()),
        ],
        resp,
    );
}

fn emit_packets(socket: &UdpSocket, out_dgrams: &Vec<Datagram>) {
    for d in out_dgrams {
        let sent = socket
            .send_to(&d[..], d.destination())
            .expect("Error sending datagram");
        if sent != d.len() {
            eprintln!("Unable to send all {} bytes of datagram", d.len());
        }
    }
}

fn main() -> Result<(), io::Error> {
    let args = Args::from_args();
    assert!(args.key.len() > 0, "Need at least one key");

    init_db(args.db.clone());

    // TODO(mt): listen on both v4 and v6.
    let socket = match UdpSocket::bind(&args.bind()) {
        Err(err) => {
            eprintln!("Unable to bind UDP socket: {}", err);
            exit(1)
        }
        Ok(s) => s,
    };

    let local_addr = match socket.local_addr() {
        Err(err) => {
            eprintln!("Socket local address not bound: {}", err);
            exit(1)
        }
        Ok(s) => s,
    };

    let poll = Poll::new()?;

    println!("Server waiting for connection on: {:?}", local_addr);

    poll.register(
        &socket,
        SERVER,
        Ready::readable() | Ready::writable(),
        PollOpt::edge(),
    )?;

    let buf = &mut [0u8; 2048];
    let mut connections: HashMap<SocketAddr, Http3Connection> = HashMap::new();

    let mut events = Events::with_capacity(1024);

    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            match event.token() {
                SERVER => {
                    let mut in_dgrams = HashMap::new();
                    let mut out_dgrams = Vec::new();

                    // Read all datagrams and group by remote host
                    loop {
                        let (sz, remote_addr) = match socket.recv_from(&mut buf[..]) {
                            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                            Err(err) => {
                                eprintln!("UDP recv error: {:?}", err);
                                exit(1);
                            }
                            Ok(res) => res,
                        };

                        if sz == buf.len() {
                            eprintln!("Might have received more than {} bytes", buf.len());
                        }

                        if sz == 0 {
                            eprintln!("zero length datagram received?");
                        } else {
                            let conn_dgrams = in_dgrams.entry(remote_addr).or_insert(Vec::new());
                            conn_dgrams.push(Datagram::new(remote_addr, local_addr, &buf[..sz]));
                        }
                    }

                    // Process each connections' packets
                    for (remote_addr, mut dgrams) in in_dgrams {
                        let server = connections.entry(remote_addr).or_insert_with(|| {
                            println!("New connection from {:?}", remote_addr);
                            Http3Connection::new(
                                Connection::new_server(args.key.clone(), args.alpn.clone())
                                    .expect("must succeed"),
                                args.max_table_size,
                                args.max_blocked_streams,
                            )
                        });
                        server.set_new_stream_callback(http_serve);

                        // TODO use timer to set socket.set_read_timeout.
                        server.process_input(dgrams.drain(..), now());
                        if let Http3State::Closed(e) = server.state() {
                            eprintln!("Closed connection from {:?}: {:?}", remote_addr, e);
                            connections.remove(&remote_addr);
                            continue;
                        }

                        server.process_http3();
                        let (conn_out_dgrams, _timer) = server.process_output(now());
                        out_dgrams.extend(conn_out_dgrams);
                    }
                    emit_packets(&socket, &out_dgrams);
                }
                val => {
                    eprintln!("invalid event token {:?}", val);
                    exit(1);
                }
            }
        }
    }
}
