// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::now;
use neqo_crypto::init_db;
use neqo_http3::{Http3Connection, Http3Event, Http3State};
use neqo_transport::{Connection, Datagram};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::str::FromStr;
use std::string::ParseError;
use structopt::StructOpt;

#[derive(Debug)]
struct Headers {
    pub h: Vec<(String, String)>,
}


// dragana: this is a very stupid parser.
// headers should be in form "[(something1, something2), (something3, something4)]"
impl FromStr for Headers {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = Headers { h: Vec::new() };
        let h1: Vec<&str> = s
            .trim_matches(|p| p == '[' || p == ']')
            .split(")")
            .collect();

        for h in h1 {
            let h2: Vec<&str> = h
                .trim_matches(|p| p == ',')
                .trim()
                .trim_matches(|p| p == '(' || p == ')')
                .split(",")
                .collect();

            if h2.len() == 2 {
                res.h.push((h2[0].trim().to_string(), h2[1].trim().to_string()));
            }
        }

        Ok(res)
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-http3-client", about = "A basic HTTP3 client.")]
struct Args {
    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    db: PathBuf,

    #[structopt(short = "a", long, default_value = "h3")]
    /// ALPN labels to negotiate.
    ///
    /// This client still only does HTTP3 no matter what the ALPN says.
    alpn: Vec<String>,

    #[structopt(short = "4", long)]
    /// Restrict to IPv4.
    ipv4: bool,
    #[structopt(short = "6", long)]
    /// Restrict to IPv6.
    ipv6: bool,

    host: String,
    port: u16,

    method: String,
    scheme: String,
    path: String,
    headers: Headers,

    #[structopt(short = "t", long)]
    max_table_size: u32,

    #[structopt(short = "b", long)]
    max_blocked_streams: u16,
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
    fn handle(&mut self, client: &mut Http3Connection) -> bool;
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
    client: &mut Http3Connection,
    handler: &mut Handler,
) -> neqo_http3::connection::Http3State {
    let buf = &mut [0u8; 2048];
    let mut in_dgrams = Vec::new();
    loop {
        client.process_input(in_dgrams.drain(..), now());

        if let Http3State::Closed(..) = client.state() {
            return client.state();
        }

        let exiting = !handler.handle(client);

        let (out_dgrams, _timer) = client.process_output(now());
        emit_packets(&socket, &out_dgrams);

        if exiting {
            return client.state();
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
    fn handle(&mut self, client: &mut Http3Connection) -> bool {
        if let Http3State::Connected = client.state() {
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
    fn handle(&mut self, client: &mut Http3Connection) -> bool {
        let mut data = vec![0; 4000];
        client.process_http3();
        for event in client.events() {
            match event {
                Http3Event::HeaderReady { stream_id } => {
                    if !self.streams.contains(&stream_id) {
                        println!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let headers = client.get_headers(stream_id);
                    println!("READ HEADERS[{}]: {:?}", stream_id, headers);
                }
                Http3Event::DataReadable { stream_id } => {
                    if !self.streams.contains(&stream_id) {
                        println!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let (_sz, fin) = client
                        .read_data(stream_id, &mut data)
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
                _ => {}
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

    let mut client = Http3Connection::new(
        Connection::new_client(args.host.as_str(), args.alpn, local_addr, remote_addr)
            .expect("must succeed"),
        args.max_table_size,
        args.max_blocked_streams,
    );
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h);

    let client_stream_id = client
        .fetch(
            &args.method,
            &args.scheme,
            &args.host,
            &args.path,
            &args.headers.h,
        )
        .unwrap();

    let mut h2 = PostConnectHandler::default();
    h2.streams.insert(client_stream_id);
    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h2);
}
