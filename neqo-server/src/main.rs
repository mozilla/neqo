// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![warn(clippy::pedantic)]

use std::{
    cell::RefCell,
    cmp::min,
    collections::HashMap,
    convert::TryFrom,
    fmt::{self, Display},
    fs::OpenOptions,
    io::{self, Read},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    process::exit,
    rc::Rc,
    time::{Duration, Instant},
};

use clap::Parser;
use futures::{
    future::{select, select_all, Either},
    FutureExt,
};
use neqo_common::{hex, qinfo, qwarn, udp, Datagram, Header};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    generate_ech_keys, init_db, random, AntiReplay, Cipher,
};
use neqo_http3::{
    Error, Http3OrWebTransportStream, Http3Parameters, Http3Server, Http3ServerEvent, StreamId,
};
use neqo_transport::{
    server::ValidateAddress, tparams::PreferredAddress, CongestionControlAlgorithm,
    ConnectionIdGenerator, ConnectionParameters, Output, RandomConnectionIdGenerator, StreamType,
    Version,
};
use tokio::time::Sleep;

use crate::old_https::Http09Server;

const ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(10);

mod old_https;

#[derive(Debug)]
pub enum ServerError {
    ArgumentError(&'static str),
    Http3Error(neqo_http3::Error),
    IoError(io::Error),
    QlogError,
    TransportError(neqo_transport::Error),
}

impl From<io::Error> for ServerError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<neqo_http3::Error> for ServerError {
    fn from(err: neqo_http3::Error) -> Self {
        Self::Http3Error(err)
    }
}

impl From<qlog::Error> for ServerError {
    fn from(_err: qlog::Error) -> Self {
        Self::QlogError
    }
}

impl From<neqo_transport::Error> for ServerError {
    fn from(err: neqo_transport::Error) -> Self {
        Self::TransportError(err)
    }
}

impl Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {self:?}")?;
        Ok(())
    }
}

impl std::error::Error for ServerError {}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List of IP:port to listen on
    #[arg(default_value = "[::]:4433")]
    hosts: Vec<String>,

    #[arg(name = "encoder-table-size", long, default_value = "16384")]
    max_table_size_encoder: u64,

    #[arg(name = "decoder-table-size", long, default_value = "16384")]
    max_table_size_decoder: u64,

    #[arg(short = 'b', long, default_value = "10")]
    max_blocked_streams: u16,

    #[arg(short = 'd', long, default_value = "./test-fixture/db")]
    /// NSS database directory.
    db: PathBuf,

    #[arg(short = 'k', long, default_value = "key")]
    /// Name of key from NSS database.
    key: String,

    #[arg(short = 'a', long, default_value = "h3")]
    /// ALPN labels to negotiate.
    ///
    /// This server still only does HTTP3 no matter what the ALPN says.
    alpn: String,

    #[arg(name = "qlog-dir", long, value_parser=clap::value_parser!(PathBuf))]
    /// Enable QLOG logging and QLOG traces to this directory
    qlog_dir: Option<PathBuf>,

    #[arg(name = "qns-test", long)]
    /// Enable special behavior for use with QUIC Network Simulator
    qns_test: Option<String>,

    #[arg(name = "use-old-http", short = 'o', long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,

    #[command(flatten)]
    quic_parameters: QuicParameters,

    #[arg(name = "retry", long)]
    /// Force a retry
    retry: bool,

    #[arg(short = 'c', long, number_of_values = 1)]
    /// The set of TLS cipher suites to enable.
    /// From: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
    ciphers: Vec<String>,

    #[arg(name = "ech", long)]
    /// Enable encrypted client hello (ECH).
    /// This generates a new set of ECH keys when it is invoked.
    /// The resulting configuration is printed to stdout in hexadecimal format.
    ech: bool,
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
            .chain(self.quic_parameters.preferred_address_v4())
            .chain(self.quic_parameters.preferred_address_v6())
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

fn from_str(s: &str) -> Result<Version, ServerError> {
    let v = u32::from_str_radix(s, 16)
        .map_err(|_| ServerError::ArgumentError("versions need to be specified in hex"))?;
    Version::try_from(v).map_err(|_| ServerError::ArgumentError("unknown version"))
}

#[derive(Debug, Parser)]
struct QuicParameters {
    #[arg(
        short = 'Q',
        long,
        num_args = 1..,
        value_delimiter = ' ',
        number_of_values = 1,
        value_parser = from_str
    )]
    /// A list of versions to support in order of preference, in hex.
    quic_version: Vec<Version>,

    #[arg(long, default_value = "16")]
    /// Set the MAX_STREAMS_BIDI limit.
    max_streams_bidi: u64,

    #[arg(long, default_value = "16")]
    /// Set the MAX_STREAMS_UNI limit.
    max_streams_uni: u64,

    #[arg(long = "idle", default_value = "30")]
    /// The idle timeout for connections, in seconds.
    idle_timeout: u64,

    #[arg(long = "cc", default_value = "newreno")]
    /// The congestion controller to use.
    congestion_control: CongestionControlAlgorithm,

    #[arg(name = "preferred-address-v4", long)]
    /// An IPv4 address for the server preferred address.
    preferred_address_v4: Option<String>,

    #[arg(name = "preferred-address-v6", long)]
    /// An IPv6 address for the server preferred address.
    preferred_address_v6: Option<String>,
}

impl QuicParameters {
    fn get_sock_addr<F>(opt: &Option<String>, v: &str, f: F) -> Option<SocketAddr>
    where
        F: FnMut(&SocketAddr) -> bool,
    {
        let addr = opt
            .iter()
            .filter_map(|spa| spa.to_socket_addrs().ok())
            .flatten()
            .find(f);
        assert_eq!(
            opt.is_some(),
            addr.is_some(),
            "unable to resolve '{}' to an {} address",
            opt.as_ref().unwrap(),
            v,
        );
        addr
    }

    fn preferred_address_v4(&self) -> Option<SocketAddr> {
        Self::get_sock_addr(&self.preferred_address_v4, "IPv4", SocketAddr::is_ipv4)
    }

    fn preferred_address_v6(&self) -> Option<SocketAddr> {
        Self::get_sock_addr(&self.preferred_address_v6, "IPv6", SocketAddr::is_ipv6)
    }

    fn preferred_address(&self) -> Option<PreferredAddress> {
        let v4 = self.preferred_address_v4();
        let v6 = self.preferred_address_v6();
        if v4.is_none() && v6.is_none() {
            None
        } else {
            let v4 = v4.map(|v4| {
                let SocketAddr::V4(v4) = v4 else {
                    unreachable!();
                };
                v4
            });
            let v6 = v6.map(|v6| {
                let SocketAddr::V6(v6) = v6 else {
                    unreachable!();
                };
                v6
            });
            Some(PreferredAddress::new(v4, v6))
        }
    }

    fn get(&self) -> ConnectionParameters {
        let mut params = ConnectionParameters::default()
            .max_streams(StreamType::BiDi, self.max_streams_bidi)
            .max_streams(StreamType::UniDi, self.max_streams_uni)
            .idle_timeout(Duration::from_secs(self.idle_timeout))
            .cc_algorithm(self.congestion_control);
        if let Some(pa) = self.preferred_address() {
            params = params.preferred_address(pa);
        }

        if let Some(first) = self.quic_version.first() {
            params = params.versions(*first, self.quic_version.clone());
        }
        params
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
                    eprintln!("Error reading data: {e:?}");
                    None
                }
            }
        })
}

trait HttpServer: Display {
    fn process(&mut self, dgram: Option<&Datagram>, now: Instant) -> Output;
    fn process_events(&mut self, args: &Args, now: Instant);
    fn set_qlog_dir(&mut self, dir: Option<PathBuf>);
    fn set_ciphers(&mut self, ciphers: &[Cipher]);
    fn validate_address(&mut self, when: ValidateAddress);
    fn enable_ech(&mut self) -> &[u8];
}

struct ResponseData {
    data: Vec<u8>,
    offset: usize,
    remaining: usize,
}

impl From<&[u8]> for ResponseData {
    fn from(data: &[u8]) -> Self {
        Self::from(data.to_vec())
    }
}

impl From<Vec<u8>> for ResponseData {
    fn from(data: Vec<u8>) -> Self {
        let remaining = data.len();
        Self {
            data,
            offset: 0,
            remaining,
        }
    }
}

impl ResponseData {
    fn repeat(buf: &[u8], total: usize) -> Self {
        Self {
            data: buf.to_owned(),
            offset: 0,
            remaining: total,
        }
    }

    fn send(&mut self, stream: &mut Http3OrWebTransportStream) {
        while self.remaining > 0 {
            let end = min(self.data.len(), self.offset + self.remaining);
            let slice = &self.data[self.offset..end];
            match stream.send_data(slice) {
                Ok(0) => {
                    return;
                }
                Ok(sent) => {
                    self.remaining -= sent;
                    self.offset = (self.offset + sent) % self.data.len();
                }
                Err(e) => {
                    qwarn!("Error writing to stream {}: {:?}", stream, e);
                    return;
                }
            }
        }
    }

    fn done(&self) -> bool {
        self.remaining == 0
    }
}

struct SimpleServer {
    server: Http3Server,
    /// Progress writing to each stream.
    remaining_data: HashMap<StreamId, ResponseData>,
    posts: HashMap<Http3OrWebTransportStream, usize>,
}

impl SimpleServer {
    const MESSAGE: &'static [u8] = b"I am the very model of a modern Major-General,\n\
        I've information vegetable, animal, and mineral,\n\
        I know the kings of England, and I quote the fights historical\n\
        From Marathon to Waterloo, in order categorical;\n\
        I'm very well acquainted, too, with matters mathematical,\n\
        I understand equations, both the simple and quadratical,\n\
        About binomial theorem, I'm teeming with a lot o' news,\n\
        With many cheerful facts about the square of the hypotenuse.\n";

    pub fn new(
        args: &Args,
        anti_replay: AntiReplay,
        cid_mgr: Rc<RefCell<dyn ConnectionIdGenerator>>,
    ) -> Self {
        let server = Http3Server::new(
            args.now(),
            &[args.key.clone()],
            &[args.alpn.clone()],
            anti_replay,
            cid_mgr,
            Http3Parameters::default()
                .connection_parameters(args.quic_parameters.get())
                .max_table_size_encoder(args.max_table_size_encoder)
                .max_table_size_decoder(args.max_table_size_decoder)
                .max_blocked_streams(args.max_blocked_streams),
            None,
        )
        .expect("We cannot make a server!");
        Self {
            server,
            remaining_data: HashMap::new(),
            posts: HashMap::new(),
        }
    }
}

impl Display for SimpleServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.server.fmt(f)
    }
}

impl HttpServer for SimpleServer {
    fn process(&mut self, dgram: Option<&Datagram>, now: Instant) -> Output {
        self.server.process(dgram, now)
    }

    fn process_events(&mut self, args: &Args, _now: Instant) {
        while let Some(event) = self.server.next_event() {
            match event {
                Http3ServerEvent::Headers {
                    mut stream,
                    headers,
                    fin,
                } => {
                    println!("Headers (request={stream} fin={fin}): {headers:?}");

                    let post = if let Some(method) = headers.iter().find(|&h| h.name() == ":method")
                    {
                        method.value() == "POST"
                    } else {
                        false
                    };
                    if post {
                        self.posts.insert(stream, 0);
                        continue;
                    }

                    let mut response =
                        if let Some(path) = headers.iter().find(|&h| h.name() == ":path") {
                            if args.qns_test.is_some() {
                                if let Some(data) = qns_read_response(path.value()) {
                                    ResponseData::from(data)
                                } else {
                                    ResponseData::from(Self::MESSAGE)
                                }
                            } else if let Ok(count) =
                                path.value().trim_matches(|p| p == '/').parse::<usize>()
                            {
                                ResponseData::repeat(Self::MESSAGE, count)
                            } else {
                                ResponseData::from(Self::MESSAGE)
                            }
                        } else {
                            stream
                                .cancel_fetch(Error::HttpRequestIncomplete.code())
                                .unwrap();
                            continue;
                        };

                    stream
                        .send_headers(&[
                            Header::new(":status", "200"),
                            Header::new("content-length", response.remaining.to_string()),
                        ])
                        .unwrap();
                    response.send(&mut stream);
                    if response.done() {
                        stream.stream_close_send().unwrap();
                    } else {
                        self.remaining_data.insert(stream.stream_id(), response);
                    }
                }
                Http3ServerEvent::DataWritable { mut stream } => {
                    if self.posts.get_mut(&stream).is_none() {
                        if let Some(remaining) = self.remaining_data.get_mut(&stream.stream_id()) {
                            remaining.send(&mut stream);
                            if remaining.done() {
                                self.remaining_data.remove(&stream.stream_id());
                                stream.stream_close_send().unwrap();
                            }
                        }
                    }
                }

                Http3ServerEvent::Data {
                    mut stream,
                    data,
                    fin,
                } => {
                    if let Some(received) = self.posts.get_mut(&stream) {
                        *received += data.len();
                    }
                    if fin {
                        if let Some(received) = self.posts.remove(&stream) {
                            let msg = received.to_string().as_bytes().to_vec();
                            stream
                                .send_headers(&[Header::new(":status", "200")])
                                .unwrap();
                            stream.send_data(&msg).unwrap();
                            stream.stream_close_send().unwrap();
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn set_qlog_dir(&mut self, dir: Option<PathBuf>) {
        self.server.set_qlog_dir(dir);
    }

    fn validate_address(&mut self, v: ValidateAddress) {
        self.server.set_validation(v);
    }

    fn set_ciphers(&mut self, ciphers: &[Cipher]) {
        self.server.set_ciphers(ciphers);
    }

    fn enable_ech(&mut self) -> &[u8] {
        let (sk, pk) = generate_ech_keys().expect("should create ECH keys");
        self.server
            .enable_ech(random::<1>()[0], "public.example", &sk, &pk)
            .unwrap();
        self.server.ech_config()
    }
}

struct ServersRunner {
    args: Args,
    server: Box<dyn HttpServer>,
    timeout: Option<Pin<Box<Sleep>>>,
    sockets: Vec<(SocketAddr, udp::Socket)>,
}

impl ServersRunner {
    pub fn new(args: Args) -> Result<Self, io::Error> {
        let hosts = args.listen_addresses();
        if hosts.is_empty() {
            eprintln!("No valid hosts defined");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "No hosts"));
        }
        let sockets = hosts
            .into_iter()
            .map(|host| {
                let socket = udp::Socket::bind(host)?;
                let local_addr = socket.local_addr()?;
                println!("Server waiting for connection on: {local_addr:?}");

                Ok((host, socket))
            })
            .collect::<Result<_, io::Error>>()?;
        let server = Self::create_server(&args);

        Ok(Self {
            args,
            server,
            timeout: None,
            sockets,
        })
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
            Box::new(SimpleServer::new(args, anti_replay, cid_mgr))
        };
        svr.set_ciphers(&args.get_ciphers());
        svr.set_qlog_dir(args.qlog_dir.clone());
        if args.retry {
            svr.validate_address(ValidateAddress::Always);
        }
        if args.ech {
            let cfg = svr.enable_ech();
            println!("ECHConfigList: {}", hex(cfg));
        }
        svr
    }

    /// Tries to find a socket, but then just falls back to sending from the first.
    fn find_socket(&mut self, addr: SocketAddr) -> &mut udp::Socket {
        let ((_host, first_socket), rest) = self.sockets.split_first_mut().unwrap();
        rest.iter_mut()
            .map(|(_host, socket)| socket)
            .find(|socket| {
                socket
                    .local_addr()
                    .ok()
                    .map_or(false, |socket_addr| socket_addr == addr)
            })
            .unwrap_or(first_socket)
    }

    async fn process(&mut self, mut dgram: Option<&Datagram>) -> Result<(), io::Error> {
        loop {
            match self.server.process(dgram.take(), self.args.now()) {
                Output::Datagram(dgram) => {
                    let socket = self.find_socket(dgram.source());
                    socket.writable().await?;
                    socket.send(dgram)?;
                }
                Output::Callback(new_timeout) => {
                    qinfo!("Setting timeout of {:?}", new_timeout);
                    self.timeout = Some(Box::pin(tokio::time::sleep(new_timeout)));
                    break;
                }
                Output::None => {
                    break;
                }
            }
        }
        Ok(())
    }

    // Wait for any of the sockets to be readable or the timeout to fire.
    async fn ready(&mut self) -> Result<Ready, io::Error> {
        let sockets_ready = select_all(
            self.sockets
                .iter()
                .map(|(_host, socket)| Box::pin(socket.readable())),
        )
        .map(|(res, inx, _)| match res {
            Ok(()) => Ok(Ready::Socket(inx)),
            Err(e) => Err(e),
        });
        let timeout_ready = self
            .timeout
            .as_mut()
            .map_or(Either::Right(futures::future::pending()), Either::Left)
            .map(|()| Ok(Ready::Timeout));
        select(sockets_ready, timeout_ready).await.factor_first().0
    }

    async fn run(&mut self) -> Result<(), io::Error> {
        loop {
            match self.ready().await? {
                Ready::Socket(inx) => loop {
                    let (host, socket) = self.sockets.get_mut(inx).unwrap();
                    let dgram = socket.recv(host)?;
                    if dgram.is_none() {
                        break;
                    }
                    self.process(dgram.as_ref()).await?;
                },
                Ready::Timeout => {
                    self.timeout = None;
                    self.process(None).await?;
                }
            }

            self.server.process_events(&self.args, self.args.now());
            self.process(None).await?;
        }
    }
}

enum Ready {
    Socket(usize),
    Timeout,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    const HQ_INTEROP: &str = "hq-interop";

    let mut args = Args::parse();
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone());

    if let Some(testcase) = args.qns_test.as_ref() {
        if args.quic_parameters.quic_version.is_empty() {
            // Quic Interop Runner expects the server to support `Version1`
            // only. Exceptions are testcases `versionnegotiation` (not yet
            // implemented) and `v2`.
            if testcase != "v2" {
                args.quic_parameters.quic_version = vec![Version::Version1];
            }
        } else {
            qwarn!("Both -V and --qns-test were set. Ignoring testcase specific versions.");
        }

        match testcase.as_str() {
            "http3" => (),
            "zerortt" => {
                args.use_old_http = true;
                args.alpn = String::from(HQ_INTEROP);
                args.quic_parameters.max_streams_bidi = 100;
            }
            "handshake" | "transfer" | "resumption" | "multiconnect" | "v2" => {
                args.use_old_http = true;
                args.alpn = String::from(HQ_INTEROP);
            }
            "chacha20" => {
                args.use_old_http = true;
                args.alpn = String::from(HQ_INTEROP);
                args.ciphers.clear();
                args.ciphers
                    .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
            }
            "retry" => {
                args.use_old_http = true;
                args.alpn = String::from(HQ_INTEROP);
                args.retry = true;
            }
            _ => exit(127),
        }
    }

    let mut servers_runner = ServersRunner::new(args)?;
    servers_runner.run().await
}
