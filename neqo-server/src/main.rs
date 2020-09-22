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
use neqo_transport::{server::ValidateAddress, FixedConnectionIdManager, Output};

use crate::old_https::Http09Server;

const TIMER_TOKEN: Token = Token(0xffff_ffff);

mod old_https;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-server", about = "A basic HTTP3 server.")]
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

    #[structopt(name = "qns-test", long)]
    /// Enable special behavior for use with QUIC Network Simulator
    qns_test: Option<String>,

    #[structopt(name = "use-old-http", short = "o", long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,

    #[structopt(name = "retry", long)]
    /// Force a retry
    retry: bool,
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
    fn validate_address(&mut self, when: ValidateAddress);
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
                            if args.qns_test.is_some() {
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

    fn validate_address(&mut self, v: ValidateAddress) {
        self.set_validation(v);
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
    sockets: Vec<UdpSocket>,
    servers: HashMap<SocketAddr, (Box<dyn HttpServer>, Option<Timeout>)>,
    timer: Timer<usize>,
    active_servers: HashSet<usize>,
}

impl ServersRunner {
    pub fn new(args: Args) -> Result<Self, io::Error> {
        Ok(Self {
            args,
            poll: Poll::new()?,
            sockets: Vec::new(),
            servers: HashMap::new(),
            timer: Builder::default()
                .tick_duration(Duration::from_millis(1))
                .build::<usize>(),
            hosts: Vec::new(),
            active_servers: HashSet::new(),
        })
    }

    /// Init Poll for all hosts. Create sockets, and a map of the
    /// socketaddrs to instances of the HttpServer handling that addr.
    pub fn init(&mut self) -> Result<(), io::Error> {
        self.hosts = self.args.host_socket_addrs();
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

            self.poll.register(
                &socket,
                Token(i),
                Ready::readable() | Ready::writable(),
                PollOpt::edge(),
            )?;

            self.sockets.push(socket);
            self.servers
                .insert(local_addr, (self.create_server(), None));
        }

        self.poll
            .register(&self.timer, TIMER_TOKEN, Ready::readable(), PollOpt::edge())?;

        Ok(())
    }

    fn create_server(&self) -> Box<dyn HttpServer> {
        let anti_replay = AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
            .expect("unable to setup anti-replay");
        let cid_mgr = Rc::new(RefCell::new(FixedConnectionIdManager::new(10)));

        let mut svr: Box<dyn HttpServer> = if self.args.use_old_http {
            Box::new(
                Http09Server::new(
                    Instant::now(),
                    &[self.args.key.clone()],
                    &[self.args.alpn.clone()],
                    anti_replay,
                    cid_mgr,
                )
                .expect("We cannot make a server!"),
            )
        } else {
            Box::new(
                Http3Server::new(
                    Instant::now(),
                    &[self.args.key.clone()],
                    &[self.args.alpn.clone()],
                    anti_replay,
                    cid_mgr,
                    QpackSettings {
                        max_table_size_encoder: self.args.max_table_size_encoder,
                        max_table_size_decoder: self.args.max_table_size_decoder,
                        max_blocked_streams: self.args.max_blocked_streams,
                    },
                )
                .expect("We cannot make a server!"),
            )
        };
        svr.set_qlog_dir(self.args.qlog_dir.clone());
        if self.args.retry {
            svr.validate_address(ValidateAddress::Always);
        }
        svr
    }

    fn process_datagrams_and_events(
        &mut self,
        inx: usize,
        read_socket: bool,
    ) -> Result<(), io::Error> {
        if let Some(socket) = self.sockets.get_mut(inx) {
            if let Some((ref mut server, svr_timeout)) =
                self.servers.get_mut(&socket.local_addr().unwrap())
            {
                if read_socket {
                    loop {
                        let dgram = read_dgram(socket, &self.hosts[inx])?;
                        if dgram.is_none() {
                            break;
                        }
                        let _ = process(
                            &mut **server,
                            svr_timeout,
                            inx,
                            dgram,
                            &mut self.timer,
                            socket,
                        );
                    }
                } else {
                    let _ = process(
                        &mut **server,
                        svr_timeout,
                        inx,
                        None,
                        &mut self.timer,
                        socket,
                    );
                }
                server.process_events(&self.args);
                if process(
                    &mut **server,
                    svr_timeout,
                    inx,
                    None,
                    &mut self.timer,
                    socket,
                ) {
                    self.active_servers.insert(inx);
                }
            }
        }
        Ok(())
    }

    fn process_active_conns(&mut self) -> Result<(), io::Error> {
        let curr_active = mem::take(&mut self.active_servers);
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
                if self.active_servers.is_empty() {
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
            "handshake" | "transfer" | "resumption" => {
                args.use_old_http = true;
                args.alpn = "hq-29".into();
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
    servers_runner.init()?;
    servers_runner.run()
}
