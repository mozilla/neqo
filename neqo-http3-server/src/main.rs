// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]

use neqo_common::{qdebug, qinfo, Datagram};
use neqo_crypto::{init_db, AntiReplay};
use neqo_http3::request_stream_server::{Header, Response};
use neqo_http3::{Http3Connection, Http3State};
use neqo_transport::{Connection, Output};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, Instant};

use structopt::StructOpt;

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::timer::{Builder, Timeout};

const TIMER_TOKEN: Token = Token(0xffff_ffff);

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

    #[structopt(short = "a", long, default_value = "h3-22")]
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

fn http_serve(request_headers: &[Header], _error: bool) -> Response {
    println!("Serve a request");

    println!("Headers: {:?}", request_headers);

    let path_hdr = request_headers.iter().find(|(k, _)| k == ":path");

    let default_ret = b"Hello World".to_vec();

    let response = match path_hdr {
        Some((_, path)) if !path.is_empty() => {
            match path.trim_matches(|p| p == '/').parse::<usize>() {
                Ok(v) => vec![b'a'; v],
                Err(_) => default_ret,
            }
        }
        _ => default_ret,
    };

    (
        vec![
            (String::from(":status"), String::from("200")),
            (String::from("content-length"), response.len().to_string()),
        ],
        response,
    )
}

fn emit_packets(socket: &UdpSocket, out_dgrams: &[Datagram]) {
    for d in out_dgrams {
        let sent = socket
            .send_to(d, &d.destination())
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
    let anti_replay = AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
        .expect("unable to setup anti-replay");

    let poll = Poll::new()?;

    let hosts = args.host_socket_addrs();
    if hosts.is_empty() {
        eprintln!("No valid hosts defined");
        exit(1);
    }

    let mut sockets = Vec::new();

    let mut timer = Builder::default().build::<SocketAddr>();
    poll.register(&timer, TIMER_TOKEN, Ready::readable(), PollOpt::edge())?;

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
    let mut connections: HashMap<SocketAddr, (Http3Connection, Option<Timeout>)> = HashMap::new();

    let mut events = Events::with_capacity(1024);

    loop {
        poll.poll(&mut events, None)?;
        let mut in_dgrams = HashMap::new();
        let mut out_dgrams = Vec::new();
        for event in &events {
            if event.token() == TIMER_TOKEN {
                while let Some(remote_addr) = timer.poll() {
                    qinfo!("Timer expired for {:?}", remote_addr);
                    // Adds an entry to in_dgrams but doesn't add any
                    // packets. This will cause the Connection to be
                    // process()ed.
                    in_dgrams.entry(remote_addr).or_insert_with(Vec::new);
                }
            } else if let Some(socket) = sockets.get(event.token().0) {
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
        for (remote_addr, dgrams) in in_dgrams {
            let (server, svr_timeout) = connections.entry(remote_addr).or_insert_with(|| {
                println!("New connection from {:?}", remote_addr);
                (
                    Http3Connection::new(
                        Connection::new_server(
                            &[args.key.clone()],
                            &[args.alpn.clone()],
                            &anti_replay,
                        )
                        .expect("must succeed"),
                        args.max_table_size,
                        args.max_blocked_streams,
                        Some(Box::new(http_serve)),
                    ),
                    None,
                )
            });

            if dgrams.is_empty() {
                // timer expired
                server.process_timer(Instant::now())
            } else {
                for dgram in dgrams {
                    server.process_input(dgram, Instant::now());
                }
            }
            if let Http3State::Closed(e) = server.state() {
                println!("Closed connection from {:?}: {:?}", remote_addr, e);
                if let Some(svr_timeout) = svr_timeout {
                    timer.cancel_timeout(svr_timeout);
                }
                connections.remove(&remote_addr);
                continue;
            }

            server.process_http3(Instant::now());

            loop {
                match server.process_output(Instant::now()) {
                    Output::Datagram(dgram) => out_dgrams.push(dgram),
                    Output::Callback(new_timeout) => {
                        if let Some(svr_timeout) = svr_timeout {
                            timer.cancel_timeout(svr_timeout);
                        }

                        qinfo!("Setting timeout of {:?} for {:?}", new_timeout, remote_addr);
                        *svr_timeout = Some(timer.set_timeout(new_timeout, remote_addr));
                        break;
                    }
                    Output::None => {
                        qdebug!("Output::None");
                        break;
                    }
                };
            }
        }

        // TODO: this maybe isn't cool?
        let first_socket = sockets.first().expect("must have at least one");
        emit_packets(&first_socket, &out_dgrams);
    }
}
