// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::time::{Duration, Instant};

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::timer::{Builder, Timeout, Timer};
use regex::Regex;
use structopt::StructOpt;

use neqo_common::{qdebug, qinfo, Datagram};
use neqo_crypto::{init_db, AntiReplay, ZeroRttCheckResult, ZeroRttChecker};
use neqo_http3::{Error, Http3Server, Http3ServerEvent};
use neqo_qpack::QpackSettings;
use neqo_transport::server::{ActiveConnectionRef, Server};
use neqo_transport::{ConnectionEvent, ConnectionIdManager, FixedConnectionIdManager, Output};

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
        Http3Server::set_qlog_dir(self, dir)
    }
}

#[derive(Clone, Debug)]
struct DenyZeroRttChecker {}

impl ZeroRttChecker for DenyZeroRttChecker {
    fn check(&self, _token: &[u8]) -> ZeroRttCheckResult {
        ZeroRttCheckResult::Reject
    }
}

#[derive(Default)]
struct Http09ConnState {
    writable: bool,
    data_to_send: Option<(Vec<u8>, usize)>,
}

struct Http09Server {
    server: Server,
    conn_state: HashMap<(ActiveConnectionRef, u64), Http09ConnState>,
}

impl Http09Server {
    fn new(
        now: Instant,
        certs: &[impl AsRef<str>],
        protocols: &[impl AsRef<str>],
        anti_replay: AntiReplay,
        cid_manager: Rc<RefCell<dyn ConnectionIdManager>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            server: Server::new(
                now,
                certs,
                protocols,
                anti_replay,
                Box::new(DenyZeroRttChecker {}),
                cid_manager,
            )?,
            conn_state: HashMap::new(),
        })
    }

    fn stream_readable(&mut self, stream_id: u64, mut conn: &mut ActiveConnectionRef, args: &Args) {
        if stream_id % 4 != 0 {
            eprintln!("Stream {} not client-initiated bidi, ignoring", stream_id);
            return;
        }
        let mut data = vec![0; 4000];
        conn.borrow_mut()
            .stream_recv(stream_id, &mut data)
            .expect("Read should succeed");
        let msg = match String::from_utf8(data) {
            Ok(s) => s,
            Err(_e) => {
                eprintln!("invalid string. Is this HTTP 0.9?");
                conn.borrow_mut().stream_close_send(stream_id).unwrap();
                return;
            }
        };
        let re = if args.qns_mode {
            Regex::new(r"GET +/(\S+)(\r)?\n").unwrap()
        } else {
            Regex::new(r"GET +/(\d+)(\r)?\n").unwrap()
        };
        let m = re.captures(&msg);
        let resp = match m.and_then(|m| m.get(1)) {
            None => Some(b"Hello World".to_vec()),
            Some(path) => {
                let path = path.as_str();
                eprintln!("Path = '{}'", path);
                if args.qns_mode {
                    qns_read_response(path)
                } else {
                    let count = usize::from_str_radix(path, 10).unwrap();
                    Some(vec![b'a'; count])
                }
            }
        };
        let conn_state = self.conn_state.get_mut(&(conn.clone(), stream_id)).unwrap();
        conn_state.data_to_send = resp.map(|r| (r, 0));
        if conn_state.writable {
            self.stream_writable(stream_id, &mut conn);
        }
    }

    fn stream_writable(&mut self, stream_id: u64, conn: &mut ActiveConnectionRef) {
        match self.conn_state.get_mut(&(conn.clone(), stream_id)) {
            None => {
                eprintln!("Unknown stream {}, ignoring event", stream_id);
            }
            Some(conn_state) => {
                conn_state.writable = true;
                if let Some((data, mut offset)) = &mut conn_state.data_to_send {
                    let sent = conn
                        .borrow_mut()
                        .stream_send(stream_id, &data[offset..])
                        .unwrap();
                    eprintln!("Wrote {}", sent);
                    offset += sent;
                    if offset == data.len() {
                        eprintln!("Sent {} on {}, closing", sent, stream_id);
                        conn.borrow_mut().stream_close_send(stream_id).unwrap();
                        self.conn_state.remove(&(conn.clone(), stream_id));
                    } else {
                        conn_state.writable = false;
                    }
                }
            }
        }
    }
}

impl HttpServer for Http09Server {
    fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        self.server.process(dgram, now)
    }

    fn process_events(&mut self, args: &Args) {
        let active_conns = self.server.active_connections();
        for mut acr in active_conns {
            loop {
                let event = match acr.borrow_mut().next_event() {
                    None => break,
                    Some(e) => e,
                };
                match event {
                    ConnectionEvent::NewStream { stream_id } => {
                        self.conn_state.insert(
                            (acr.clone(), stream_id.as_u64()),
                            Http09ConnState::default(),
                        );
                    }
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        self.stream_readable(stream_id, &mut acr, args);
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        self.stream_writable(stream_id.as_u64(), &mut acr);
                    }
                    ConnectionEvent::StateChange { .. } => {}
                    e => eprintln!("unhandled event {:?}", e),
                }
            }
        }
    }

    fn set_qlog_dir(&mut self, dir: Option<PathBuf>) {
        self.server.set_qlog_dir(dir)
    }
}

impl Display for Http09Server {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http 0.9 server ")
    }
}

fn process(
    server: &mut Box<dyn HttpServer>,
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
    let mut args = Args::from_args();
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone());

    if args.qns_mode {
        match env::var("TESTCASE") {
            Ok(s) if s == "http3" => {}
            Ok(s) if s == "handshake" || s == "transfer" || s == "retry" => {
                args.use_old_http = true;
                args.alpn = "hq-29".to_string();
            }

            Ok(_) => exit(127),
            Err(_) => exit(1),
        }

        if let Ok(qlogdir) = env::var("QLOGDIR") {
            args.qlog_dir = Some(PathBuf::from(qlogdir));
        }
    }

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
                    let mut svr: Box<dyn HttpServer> = if args.use_old_http {
                        Box::new(
                            Http09Server::new(
                                Instant::now(),
                                &[args.key.clone()],
                                &[args.alpn.clone()],
                                AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
                                    .expect("unable to setup anti-replay"),
                                Rc::new(RefCell::new(FixedConnectionIdManager::new(10))),
                            )
                            .expect("We cannot make a server!"),
                        )
                    } else {
                        Box::new(
                            Http3Server::new(
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
                        server.process_events(&args);
                        process(server, svr_timeout, event.token().0, None, out, &mut timer);
                    }
                }
            }
        }

        emit_packets(&mut sockets, &out_dgrams);
    }
}
