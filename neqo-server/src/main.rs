// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use std::cell::RefCell;
use std::collections::HashSet;
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
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init_db, AntiReplay, Cipher,
};
use neqo_http3::{Error, Http3Server, Http3ServerEvent};
use neqo_qpack::QpackSettings;
use neqo_transport::{
    server::ValidateAddress, ConnectionParameters,
    FixedConnectionIdManager as RandomConnectionIdGenerator, Output, StreamType,
};

use crate::old_https::Http09Server;

const TIMER_TOKEN: Token = Token(0xffff_ffff);
const ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(10);

mod old_https;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-server", about = "A basic HTTP3 server.")]
struct Args {
    /// List of IP:port to listen on
    #[structopt(default_value = "[::]:4433")]
    hosts: Vec<String>,

    #[structopt(name = "encoder-table-size", long, default_value = "16384")]
    max_table_size_encoder: u64,

    #[structopt(name = "decoder-table-size", long, default_value = "16384")]
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

    #[structopt(name = "qns-test", long)]
    /// Enable special behavior for use with QUIC Network Simulator
    qns_test: Option<String>,

    #[structopt(name = "use-old-http", short = "o", long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,

    #[structopt(subcommand)]
    quic_parameters: QuicParameters,

    #[structopt(name = "retry", long)]
    /// Force a retry
    retry: bool,

    #[structopt(short = "c", long, number_of_values = 1)]
    /// The set of TLS cipher suites to enable.
    /// From: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
    ciphers: Vec<String>,

    #[structopt(name = "preferred-address-v4", long)]
    /// An IPv4 address for the server preferred address.
    preferred_address_v4: Option<String>,

    #[structopt(name = "preferred-address-v6", long)]
    /// An IPv6 address for the server preferred address.
    preferred_address_v6: Option<String>,
}

impl Args {
    fn get_ciphers(&self) -> Vec<Cipher> {
        self.ciphers
            .iter()
            .filter_map(|c| match c.as_str() {
                "TLS_AES_128_GCM_SHA256" => Some(TLS_AES_128_GCM_SHA256),
                "TLS_AES_256_GCM_SHA384" => Some(TLS_AES_256_GCM_SHA384),
                "TLS_CHACHA20_POLY1305_SHA256" => Some(TLS_CHACHA20_POLY1305_SHA256),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    fn listen_addresses(&self) -> Vec<SocketAddr> {
        self.hosts
            .iter()
            .filter_map(|host| host.to_socket_addrs().ok())
            .flatten()
            .collect()
    }

    fn now(&self) -> Instant {
        if self.qns_test.is_some() {
            // When NSS starts its anti-replay it blocks any acceptance of 0-RTT for a
            // single period.  This ensures that an attacker that is able to force a
            // server to reboot is unable to use that to flush the anti-replay buffers
            // and have something replayed.
            //
            // However, this is a massive inconvenience for us when we are testing.
            // As we can't initialize `AntiReplay` in the past (see `neqo_common::time`
            // for why), fast forward time here so that the connections get times from
            // in the future.
            //
            // This is NOT SAFE.  Don't do this.
            Instant::now() + ANTI_REPLAY_WINDOW
        } else {
            Instant::now()
        }
    }
}

#[derive(Debug, StructOpt)]
struct QuicParameters {
    #[structopt(long, default_value = "16")]
    /// Set the MAX_STREAMS_BIDI limit.
    max_streams_bidi: u64,

    #[structopt(long, default_value = "16")]
    /// Set the MAX_STREAMS_UNI limit.
    max_streams_uni: u64,
}

impl QuicParameters {
    fn get(&self) -> ConnectionParameters {
        ConnectionParameters::default()
            .max_streams(StreamType::BiDi, self.max_streams_bidi)
            .unwrap()
            .max_streams(StreamType::UniDi, self.max_streams_uni)
            .unwrap()
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
    fn process_events(&mut self, args: &Args, now: Instant);
    fn set_qlog_dir(&mut self, dir: Option<PathBuf>);
    fn set_ciphers(&mut self, ciphers: &[Cipher]);
    fn validate_address(&mut self, when: ValidateAddress);
}

impl HttpServer for Http3Server {
    fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        self.process(dgram, now)
    }

    fn process_events(&mut self, args: &Args, _now: Instant) {
        while let Some(event) = self.next_event() {
            match event {
                Http3ServerEvent::Headers {
                    mut request,
                    headers,
                    fin,
                } => {
                    println!("Headers (request={} fin={}): {:?}", request, fin, headers);

                    let default_ret = b"Hello World".to_vec();

                    let response =
                        headers
                            .iter()
                            .find(|&(k, _)| k == ":path")
                            .and_then(|(_, path)| {
                                if args.qns_test.is_some() {
                                    qns_read_response(path)
                                } else {
                                    match path.trim_matches(|p| p == '/').parse::<usize>() {
                                        Ok(v) => Some(vec![b'a'; v]),
                                        Err(_) => Some(default_ret),
                                    }
                                }
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

    fn validate_address(&mut self, v: ValidateAddress) {
        self.set_validation(v);
    }

    fn set_ciphers(&mut self, ciphers: &[Cipher]) {
        Self::set_ciphers(self, ciphers);
    }
}

fn read_dgram(
    socket: &mut UdpSocket,
    local_address: &SocketAddr,
) -> Result<Option<Datagram>, io::Error> {
    let buf = &mut [0u8; 2048];
    let (sz, remote_addr) = match socket.recv_from(&mut buf[..]) {
        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
        Err(err) => {
            eprintln!("UDP recv error: {:?}", err);
            return Err(err);
        }
        Ok(res) => res,
    };

    if sz == buf.len() {
        eprintln!("Might have received more than {} bytes", buf.len());
    }

    if sz == 0 {
        eprintln!("zero length datagram received?");
        Ok(None)
    } else {
        Ok(Some(Datagram::new(remote_addr, *local_address, &buf[..sz])))
    }
}

struct ServersRunner {
    args: Args,
    poll: Poll,
    hosts: Vec<SocketAddr>,
    server: Box<dyn HttpServer>,
    timeout: Option<Timeout>,
    sockets: Vec<UdpSocket>,
    active_sockets: HashSet<usize>,
    timer: Timer<usize>,
}

impl ServersRunner {
    pub fn new(args: Args) -> Result<Self, io::Error> {
        let server = Self::create_server(&args);
        let mut runner = Self {
            args,
            poll: Poll::new()?,
            hosts: Vec::new(),
            server,
            timeout: None,
            sockets: Vec::new(),
            active_sockets: HashSet::new(),
            timer: Builder::default()
                .tick_duration(Duration::from_millis(1))
                .build::<usize>(),
        };
        runner.init()?;
        Ok(runner)
    }

    /// Init Poll for all hosts. Create sockets, and a map of the
    /// socketaddrs to instances of the HttpServer handling that addr.
    fn init(&mut self) -> Result<(), io::Error> {
        self.hosts = self.args.listen_addresses();
        if self.hosts.is_empty() {
            eprintln!("No valid hosts defined");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "No hosts"));
        }

        for (i, host) in self.hosts.iter().enumerate() {
            let socket = match UdpSocket::bind(&host) {
                Err(err) => {
                    eprintln!("Unable to bind UDP socket: {}", err);
                    return Err(err);
                }
                Ok(s) => s,
            };

            let local_addr = match socket.local_addr() {
                Err(err) => {
                    eprintln!("Socket local address not bound: {}", err);
                    return Err(err);
                }
                Ok(s) => s,
            };

            let also_v4 = if socket.only_v6().unwrap_or(true) {
                ""
            } else {
                " as well as V4"
            };
            println!(
                "Server waiting for connection on: {:?}{}",
                local_addr, also_v4
            );

            self.poll.register(
                &socket,
                Token(i),
                Ready::readable() | Ready::writable(),
                PollOpt::edge(),
            )?;

            self.sockets.push(socket);
        }

        self.poll
            .register(&self.timer, TIMER_TOKEN, Ready::readable(), PollOpt::edge())?;

        Ok(())
    }

    fn create_server(args: &Args) -> Box<dyn HttpServer> {
        // Note: this is the exception to the case where we use `Args::now`.
        let anti_replay = AntiReplay::new(Instant::now(), ANTI_REPLAY_WINDOW, 7, 14)
            .expect("unable to setup anti-replay");
        let cid_mgr = Rc::new(RefCell::new(RandomConnectionIdGenerator::new(10)));

        let mut svr: Box<dyn HttpServer> = if args.use_old_http {
            Box::new(
                Http09Server::new(
                    args.now(),
                    &[args.key.clone()],
                    &[args.alpn.clone()],
                    anti_replay,
                    cid_mgr,
                    args.quic_parameters.get(),
                )
                .expect("We cannot make a server!"),
            )
        } else {
            let server = Http3Server::new(
                args.now(),
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
            .expect("We cannot make a server!");
            Box::new(server)
        };
        svr.set_ciphers(&args.get_ciphers());
        svr.set_qlog_dir(args.qlog_dir.clone());
        if args.retry {
            svr.validate_address(ValidateAddress::Always);
        }
        svr
    }

    /// Tries to find a socket, but then just falls back to sending from the first.
    fn find_socket(&mut self, addr: SocketAddr) -> &mut UdpSocket {
        let (first, rest) = self.sockets.split_first_mut().unwrap();
        rest.iter_mut()
            .find(|s| {
                s.local_addr()
                    .ok()
                    .map_or(false, |socket_addr| socket_addr == addr)
            })
            .unwrap_or(first)
    }

    fn process(&mut self, inx: usize, dgram: Option<Datagram>) -> bool {
        match self.server.process(dgram, self.args.now()) {
            Output::Datagram(dgram) => {
                let socket = self.find_socket(dgram.source());
                emit_packet(socket, dgram);
                true
            }
            Output::Callback(new_timeout) => {
                if let Some(to) = &self.timeout {
                    self.timer.cancel_timeout(to);
                }

                qinfo!("Setting timeout of {:?} for socket {}", new_timeout, inx);
                self.timeout = Some(self.timer.set_timeout(new_timeout, inx));
                false
            }
            Output::None => {
                qdebug!("Output::None");
                false
            }
        }
    }

    fn process_datagrams_and_events(
        &mut self,
        inx: usize,
        read_socket: bool,
    ) -> Result<(), io::Error> {
        if self.sockets.get_mut(inx).is_some() {
            if read_socket {
                loop {
                    let socket = self.sockets.get_mut(inx).unwrap();
                    let dgram = read_dgram(socket, &self.hosts[inx])?;
                    if dgram.is_none() {
                        break;
                    }
                    let _ = self.process(inx, dgram);
                }
            } else {
                let _ = self.process(inx, None);
            }
            self.server.process_events(&self.args, self.args.now());
            if self.process(inx, None) {
                self.active_sockets.insert(inx);
            }
        }
        Ok(())
    }

    fn process_active_conns(&mut self) -> Result<(), io::Error> {
        let curr_active = mem::take(&mut self.active_sockets);
        for inx in curr_active {
            self.process_datagrams_and_events(inx, false)?;
        }
        Ok(())
    }

    fn process_timeout(&mut self) -> Result<(), io::Error> {
        while let Some(inx) = self.timer.poll() {
            qinfo!("Timer expired for {:?}", inx);
            self.process_datagrams_and_events(inx, false)?;
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), io::Error> {
        let mut events = Events::with_capacity(1024);
        loop {
            // If there are active servers do not block in poll.
            self.poll.poll(
                &mut events,
                if self.active_sockets.is_empty() {
                    None
                } else {
                    Some(Duration::from_millis(0))
                },
            )?;

            for event in &events {
                if event.token() == TIMER_TOKEN {
                    self.process_timeout()?;
                } else {
                    if !event.readiness().is_readable() {
                        continue;
                    }
                    self.process_datagrams_and_events(event.token().0, true)?;
                }
            }
            self.process_active_conns()?;
        }
    }
}

fn main() -> Result<(), io::Error> {
    let mut args = Args::from_args();
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone());

    if let Some(testcase) = args.qns_test.as_ref() {
        match testcase.as_str() {
            "http3" => (),
            "zerortt" => {
                args.use_old_http = true;
                args.alpn = "hq-29".into();
                args.quic_parameters.max_streams_bidi = 100;
            }
            "handshake" | "transfer" | "resumption" | "multiconnect" => {
                args.use_old_http = true;
                args.alpn = "hq-29".into();
            }
            "chacha20" => {
                args.use_old_http = true;
                args.alpn = "hq-29".into();
                args.ciphers.clear();
                args.ciphers
                    .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
            }
            "retry" => {
                args.use_old_http = true;
                args.alpn = "hq-29".into();
                args.retry = true;
            }
            _ => exit(127),
        }
    }

    let mut servers_runner = ServersRunner::new(args)?;
    servers_runner.run()
}
