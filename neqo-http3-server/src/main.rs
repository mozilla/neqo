// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::mem;
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
use neqo_http3::{Error, Http3Server, Http3ServerEvent};
use neqo_qpack::QpackSettings;
use neqo_transport::{FixedConnectionIdManager, Output};

use crate::old_https::Http09Server;

const TIMER_TOKEN: Token = Token(0xffff_ffff);

mod old_https;

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

    #[structopt(short = "a", long, default_value = "h3-29")]
    /// ALPN labels to negotiate.
    ///
    /// This server still only does HTTP3 no matter what the ALPN says.
    alpn: String,

    #[structopt(name = "qlog-dir", long)]
    /// Enable QLOG logging and QLOG traces to this directory
    qlog_dir: Option<PathBuf>,

    #[structopt(name = "qns-mode", long)]
    qns_mode: bool,

    #[structopt(name = "use-old-http", short = "o", long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,
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

fn emit_packet(socket: &mut UdpSocket, out_dgram: Datagram) {
    let sent = socket
        .send_to(&out_dgram, &out_dgram.destination())
        .expect("Error sending datagram");
    if sent != out_dgram.len() {
        eprintln!("Unable to send all {} bytes of datagram", out_dgram.len());
    }
}

fn qns_read_response(filename: &str) -> Option<Vec<u8>> {
    let mut file_path = PathBuf::from("/www");
    file_path.push(filename.trim_matches(|p| p == '/'));

    OpenOptions::new()
        .read(true)
        .open(&file_path)
        .map_err(|_e| eprintln!("Could not open {}", file_path.display()))
        .ok()
        .and_then(|mut f| {
            let mut data = Vec::new();
            match f.read_to_end(&mut data) {
                Ok(sz) => {
                    println!("{} bytes read from {}", sz, file_path.display());
                    Some(data)
                }
                Err(e) => {
                    eprintln!("Error reading data: {:?}", e);
                    None
                }
            }
        })
}

trait HttpServer: Display {
    fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output;
    fn process_events(&mut self, args: &Args);
    fn set_qlog_dir(&mut self, dir: Option<PathBuf>);
}

impl HttpServer for Http3Server {
    fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        self.process(dgram, now)
    }

    fn process_events(&mut self, args: &Args) {
        while let Some(event) = self.next_event() {
            match event {
                Http3ServerEvent::Headers {
                    mut request,
                    headers,
                    fin,
                } => {
                    println!("Headers (request={} fin={}): {:?}", request, fin, headers);

                    let default_ret = b"Hello World".to_vec();

                    let response = headers.and_then(|h| {
                        h.iter().find(|&(k, _)| k == ":path").and_then(|(_, path)| {
                            if args.qns_mode {
                                qns_read_response(path)
                            } else {
                                match path.trim_matches(|p| p == '/').parse::<usize>() {
                                    Ok(v) => Some(vec![b'a'; v]),
                                    Err(_) => Some(default_ret),
                                }
                            }
                        })
                    });

                    if response.is_none() {
                        let _ = request.stream_reset(Error::HttpRequestIncomplete.code());
                        continue;
                    }

                    let response = response.unwrap();

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

    fn set_qlog_dir(&mut self, dir: Option<PathBuf>) {
        Self::set_qlog_dir(self, dir)
    }
}

fn process(
    server: &mut dyn HttpServer,
    svr_timeout: &mut Option<Timeout>,
    inx: usize,
    dgram: Option<Datagram>,
    timer: &mut Timer<usize>,
    socket: &mut UdpSocket,
) -> bool {
    match server.process(dgram, Instant::now()) {
        Output::Datagram(dgram) => {
            emit_packet(socket, dgram);
            true
        }
        Output::Callback(new_timeout) => {
            if let Some(svr_timeout) = svr_timeout {
                timer.cancel_timeout(svr_timeout);
            }

            qinfo!("Setting timeout of {:?} for {}", new_timeout, server);
            *svr_timeout = Some(timer.set_timeout(new_timeout, inx));
            false
        }
        Output::None => {
            qdebug!("Output::None");
            false
        }
    }
}

/// Init Poll for all hosts. Returns the Poll, sockets, and a map of the
/// socketaddrs to instances of the HttpServer handling that addr.
#[allow(clippy::type_complexity)]
fn init_poll(
    hosts: &[SocketAddr],
    args: &Args,
) -> Result<
    (
        Poll,
        Vec<UdpSocket>,
        HashMap<SocketAddr, (Box<dyn HttpServer>, Option<Timeout>)>,
    ),
    io::Error,
> {
    let poll = Poll::new()?;

    let mut sockets = Vec::new();
    let mut servers = HashMap::new();

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
                    let anti_replay =
                        AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
                            .expect("unable to setup anti-replay");
                    let cid_mgr = Rc::new(RefCell::new(FixedConnectionIdManager::new(10)));

                    let mut svr: Box<dyn HttpServer> = if args.use_old_http {
                        Box::new(
                            Http09Server::new(
                                Instant::now(),
                                &[args.key.clone()],
                                &[args.alpn.clone()],
                                anti_replay,
                                cid_mgr,
                            )
                            .expect("We cannot make a server!"),
                        )
                    } else {
                        Box::new(
                            Http3Server::new(
                                Instant::now(),
                                &[args.key.clone()],
                                &[args.alpn.clone()],
                                anti_replay,
                                cid_mgr,
                                QpackSettings {
                                    max_table_size_encoder: args.max_table_size_encoder,
                                    max_table_size_decoder: args.max_table_size_decoder,
                                    max_blocked_streams: args.max_blocked_streams,
                                },
                            )
                            .expect("We cannot make a server!"),
                        )
                    };
                    svr.set_qlog_dir(args.qlog_dir.clone());
                    svr
                },
                None,
            ),
        );
    }

    Ok((poll, sockets, servers))
}

#[allow(clippy::cognitive_complexity)]
fn main() -> Result<(), io::Error> {
    let mut args = Args::from_args();
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone());

    if args.qns_mode {
        match env::var("TESTCASE") {
            Ok(s) if s == "http3" => {}
            Ok(s) if s == "handshake" || s == "transfer" || s == "retry" => {
                args.use_old_http = true;
                args.alpn = "hq-29".into();
            }

            Ok(_) => exit(127),
            Err(_) => exit(1),
        }

        if let Ok(qlogdir) = env::var("QLOGDIR") {
            args.qlog_dir = Some(PathBuf::from(qlogdir));
        }
    }

    let hosts = args.host_socket_addrs();
    if hosts.is_empty() {
        eprintln!("No valid hosts defined");
        exit(1);
    }

    let (poll, mut sockets, mut servers) = init_poll(&hosts, &args)?;

    let mut timer = Builder::default()
        .tick_duration(Duration::from_millis(1))
        .build::<usize>();
    poll.register(&timer, TIMER_TOKEN, Ready::readable(), PollOpt::edge())?;

    let buf = &mut [0u8; 2048];

    let mut events = Events::with_capacity(1024);

    let mut active_servers: HashSet<usize> = HashSet::new();

    loop {
        poll.poll(
            &mut events,
            if active_servers.is_empty() {
                None
            } else {
                Some(Duration::from_millis(0))
            },
        )?;
        for event in &events {
            if event.token() == TIMER_TOKEN {
                while let Some(inx) = timer.poll() {
                    if let Some(socket) = sockets.get_mut(inx) {
                        qinfo!("Timer expired for {:?}", socket);
                        if let Some((ref mut server, svr_timeout)) =
                            servers.get_mut(&socket.local_addr().unwrap())
                        {
                            if process(&mut **server, svr_timeout, inx, None, &mut timer, socket) {
                                active_servers.insert(inx);
                            }
                        }
                    }
                }
            } else if let Some(socket) = sockets.get_mut(event.token().0) {
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
                    } else if let Some((ref mut server, svr_timeout)) =
                        servers.get_mut(&socket.local_addr().unwrap())
                    {
                        let _ = process(
                            &mut **server,
                            svr_timeout,
                            event.token().0,
                            Some(Datagram::new(remote_addr, local_addr, &buf[..sz])),
                            &mut timer,
                            socket,
                        );
                        server.process_events(&args);
                        if process(
                            &mut **server,
                            svr_timeout,
                            event.token().0,
                            None,
                            &mut timer,
                            socket,
                        ) {
                            active_servers.insert(event.token().0);
                        }
                    }
                }
            }
            let curr_active = mem::replace(&mut active_servers, HashSet::new());
            for inx in curr_active {
                if let Some(socket) = sockets.get_mut(inx) {
                    if let Some((ref mut server, svr_timeout)) =
                        servers.get_mut(&socket.local_addr().unwrap())
                    {
                        let _ = process(
                            &mut **server,
                            svr_timeout,
                            event.token().0,
                            None,
                            &mut timer,
                            socket,
                        );
                        server.process_events(&args);
                        if process(
                            &mut **server,
                            svr_timeout,
                            event.token().0,
                            None,
                            &mut timer,
                            socket,
                        ) {
                            active_servers.insert(inx);
                        }
                    }
                }
            }
        }
    }
}
