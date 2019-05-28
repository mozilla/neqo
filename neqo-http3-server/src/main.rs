// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::now;
use neqo_crypto::init_db;
use neqo_http3::{Http3Connection, Http3State, RequestStreamServer};
use neqo_transport::{Connection, Datagram};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::exit;

use structopt::StructOpt;

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-http3-server", about = "A basic HTTP3 server.")]
struct Args {
    /// List of IP:port to listen on
    #[structopt(default_value = "[::]:4433")]
    hosts: Vec<String>,

    #[structopt(short = "t", long, default_value = "128")]
    max_table_size: u32,

    #[structopt(short = "b", long, default_value = "128")]
    max_blocked_streams: u16,

    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    /// NSS database directory.
    db: PathBuf,

    #[structopt(short = "k", long, default_value = "key")]
    /// Name of key from NSS database.
    key: String,

    #[structopt(short = "a", long, default_value = "h3-20")]
    /// ALPN labels to negotiate.
    ///
    /// This server still only does HTTP3 no matter what the ALPN says.
    alpn: String,
}

impl Args {
    fn host_socket_addrs(&self) -> Vec<SocketAddr> {
        self.hosts
            .iter()
            .filter_map(|host| host.to_socket_addrs().ok())
            .flat_map(|x| x)
            .collect()
    }
}

fn http_serve(cr: &mut RequestStreamServer, _error: bool) {
    println!("Serve a request");

    let request_headers = cr.get_request_headers();
    println!("Headers: {:?}", request_headers);

    let mut resp = String::new();

    for header in request_headers {
        if header.0 == ":path" {
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
        &[
            (String::from(":status"), String::from("200")),
            (String::from("content-length"), resp.len().to_string()),
        ],
        resp,
    );
}

fn emit_packets(socket: &UdpSocket, out_dgrams: &[Datagram]) {
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
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone());

    let poll = Poll::new()?;

    let hosts = args.host_socket_addrs();
    if hosts.is_empty() {
        eprintln!("No valid hosts defined");
        exit(1);
    }

    let mut sockets = Vec::new();

    for (i, host) in hosts.iter().enumerate() {
        let socket = match UdpSocket::bind(&host) {
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

        let res = socket.only_v6();
        let also_v4 = if res.is_ok() && !res.unwrap() {
            " as well as V4"
        } else {
            ""
        };
        println!(
            "Server waiting for connection on: {:?}{}",
            local_addr, also_v4
        );

        poll.register(
            &socket,
            Token(i),
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        )?;
        sockets.push(socket);
    }

    let buf = &mut [0u8; 2048];
    let mut connections: HashMap<SocketAddr, Http3Connection> = HashMap::new();

    let mut events = Events::with_capacity(1024);

    loop {
        poll.poll(&mut events, None)?;
        let mut in_dgrams = HashMap::new();
        let mut out_dgrams = Vec::new();
        for event in &events {
            if let Some(socket) = sockets.get(event.token().0) {
                let local_addr = hosts[event.token().0];

                if !event.readiness().is_readable() {
                    continue;
                }

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
                        let conn_dgrams = in_dgrams.entry(remote_addr).or_insert_with(Vec::new);
                        conn_dgrams.push(Datagram::new(remote_addr, local_addr, &buf[..sz]));
                    }
                }
            }
        }

        // Process each connections' packets
        for (remote_addr, mut dgrams) in in_dgrams {
            let server = connections.entry(remote_addr).or_insert_with(|| {
                println!("New connection from {:?}", remote_addr);
                let mut srv = Http3Connection::new(
                    Connection::new_server(&[args.key.clone()], &[args.alpn.clone()])
                        .expect("must succeed"),
                    args.max_table_size,
                    args.max_blocked_streams,
                );
                srv.set_new_stream_callback(http_serve);
                srv
            });

            // TODO use timer to set socket.set_read_timeout.
            server.process_input(dgrams.drain(..), now());
            if let Http3State::Closed(e) = server.state() {
                eprintln!("Closed connection from {:?}: {:?}", remote_addr, e);
                connections.remove(&remote_addr);
                continue;
            }

            server.process_http3();
            let (conn_out_dgrams, _timer) = server.process_output(now());
            // TODO: each connection might want a different timer, how's that
            // gonna work?
            out_dgrams.extend(conn_out_dgrams);
        }

        // TODO: this maybe isn't cool?
        let first_socket = sockets.first().expect("must have at least one");
        emit_packets(&first_socket, &out_dgrams);
    }
}
