// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::time::{Duration, Instant};

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::timer::{Builder, Timeout, Timer};
use structopt::StructOpt;

use neqo_common::{qdebug, qinfo, Datagram};
use neqo_crypto::{init_db, AntiReplay};
use neqo_http3::{Http3Server, Http3ServerEvent};
use neqo_qpack::QpackSettings;
use neqo_transport::{FixedConnectionIdManager, Output};

const TIMER_TOKEN: Token = Token(0xffff_ffff);

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-http3-server", about = "A basic HTTP3 server.")]
struct Args {
    /// List of IP:port to listen on
    #[structopt(default_value = "[::]:4433")]
    hosts: Vec<String>,

    #[structopt(
        name = "encoder-table-size",
        short = "e",
        long,
        default_value = "16384"
    )]
    max_table_size_encoder: u64,

    #[structopt(
        name = "decoder-table-size",
        short = "f",
        long,
        default_value = "16384"
    )]
    max_table_size_decoder: u64,

    #[structopt(short = "b", long, default_value = "10")]
    max_blocked_streams: u16,

    #[structopt(
        short = "d",
        long,
        default_value = "./test-fixture/db",
        parse(from_os_str)
    )]
    /// NSS database directory.
    db: PathBuf,

    #[structopt(short = "k", long, default_value = "key")]
    /// Name of key from NSS database.
    key: String,

    #[structopt(short = "a", long, default_value = "h3-27")]
    /// ALPN labels to negotiate.
    ///
    /// This server still only does HTTP3 no matter what the ALPN says.
    alpn: String,

    #[structopt(name = "qlog-dir", long)]
    /// Enable QLOG logging and QLOG traces to this directory
    qlog_dir: Option<PathBuf>,
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

fn process_events(server: &mut Http3Server) {
    while let Some(event) = server.next_event() {
        eprintln!("Event: {:?}", event);
        match event {
            Http3ServerEvent::Headers {
                mut request,
                headers,
                fin,
            } => {
                println!("Headers (request={} fin={}): {:?}", request, fin, headers);

                let default_ret = b"Hello World".to_vec();

                let response = match headers.iter().find(|&(k, _)| k == ":path") {
                    Some((_, path)) if !path.is_empty() => {
                        match path.trim_matches(|p| p == '/').parse::<usize>() {
                            Ok(v) => vec![b'a'; v],
                            Err(_) => default_ret,
                        }
                    }
                    _ => default_ret,
                };

                request
                    .set_response(
                        &[
                            (String::from(":status"), String::from("200")),
                            (String::from("content-length"), response.len().to_string()),
                        ],
                        &response,
                    )
                    .unwrap();
            }
            Http3ServerEvent::Data { request, data, fin } => {
                println!("Data (request={} fin={}): {:?}", request, fin, data);
            }
            _ => {}
        }
    }
}

fn emit_packets(sockets: &mut Vec<UdpSocket>, out_dgrams: &HashMap<SocketAddr, Vec<Datagram>>) {
    for s in sockets {
        if let Some(dgrams) = out_dgrams.get(&s.local_addr().unwrap()) {
            for d in dgrams {
                let sent = s
                    .send_to(d, &d.destination())
                    .expect("Error sending datagram");
                if sent != d.len() {
                    eprintln!("Unable to send all {} bytes of datagram", d.len());
                }
            }
        }
    }
}

fn process(
    server: &mut Http3Server,
    svr_timeout: &mut Option<Timeout>,
    inx: usize,
    mut dgram: Option<Datagram>,
    out_dgrams: &mut Vec<Datagram>,
    timer: &mut Timer<usize>,
) {
    loop {
        match server.process(dgram, Instant::now()) {
            Output::Datagram(dgram) => out_dgrams.push(dgram),
            Output::Callback(new_timeout) => {
                if let Some(svr_timeout) = svr_timeout {
                    timer.cancel_timeout(svr_timeout);
                }

                qinfo!("Setting timeout of {:?} for {}", new_timeout, server);
                *svr_timeout = Some(timer.set_timeout(new_timeout, inx));
                break;
            }
            Output::None => {
                qdebug!("Output::None");
                break;
            }
        };
        dgram = None;
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
    let mut servers = HashMap::new();
    let mut timer = Builder::default().build::<usize>();
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
        servers.insert(
            local_addr,
            (
                {
                    let mut svr = Http3Server::new(
                        Instant::now(),
                        &[args.key.clone()],
                        &[args.alpn.clone()],
                        AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
                            .expect("unable to setup anti-replay"),
                        Rc::new(RefCell::new(FixedConnectionIdManager::new(10))),
                        QpackSettings {
                            max_table_size_encoder: args.max_table_size_encoder,
                            max_table_size_decoder: args.max_table_size_decoder,
                            max_blocked_streams: args.max_blocked_streams,
                        },
                    )
                    .expect("We cannot make a server!");
                    svr.set_qlog_dir(args.qlog_dir.clone());
                    svr
                },
                None,
            ),
        );
    }

    let buf = &mut [0u8; 2048];

    let mut events = Events::with_capacity(1024);

    loop {
        poll.poll(&mut events, None)?;
        let mut out_dgrams = HashMap::new();
        for event in &events {
            if event.token() == TIMER_TOKEN {
                while let Some(inx) = timer.poll() {
                    if let Some(socket) = sockets.get(inx) {
                        qinfo!("Timer expired for {:?}", socket);
                        if let Some((server, svr_timeout)) =
                            servers.get_mut(&socket.local_addr().unwrap())
                        {
                            process(
                                server,
                                svr_timeout,
                                inx,
                                None,
                                &mut out_dgrams
                                    .entry(socket.local_addr().unwrap())
                                    .or_insert_with(Vec::new),
                                &mut timer,
                            );
                        }
                    }
                }
            } else if let Some(socket) = sockets.get(event.token().0) {
                let local_addr = hosts[event.token().0];

                if !event.readiness().is_readable() {
                    continue;
                }

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
                    } else if let Some((server, svr_timeout)) =
                        servers.get_mut(&socket.local_addr().unwrap())
                    {
                        let out = out_dgrams
                            .entry(socket.local_addr().unwrap())
                            .or_insert_with(Vec::new);
                        process(
                            server,
                            svr_timeout,
                            event.token().0,
                            Some(Datagram::new(remote_addr, local_addr, &buf[..sz])),
                            out,
                            &mut timer,
                        );
                        process_events(server);
                        process(server, svr_timeout, event.token().0, None, out, &mut timer);
                    }
                }
            }
        }

        emit_packets(&mut sockets, &out_dgrams);
    }
}
