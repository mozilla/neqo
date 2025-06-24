// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::unwrap_used,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "This is example code."
)]

use std::{
    cell::RefCell,
    fmt::{self, Display},
    fs,
    io::{self},
    net::{SocketAddr, ToSocketAddrs as _},
    num::NonZeroUsize,
    path::PathBuf,
    pin::Pin,
    process::exit,
    rc::Rc,
    time::{Duration, Instant},
};

use clap::Parser;
use futures::{
    future::{select, select_all, Either},
    FutureExt as _,
};
use neqo_common::{qdebug, qerror, qinfo, qwarn, Datagram};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init_db, AntiReplay, Cipher,
};
use neqo_transport::{OutputBatch, RandomConnectionIdGenerator, Version};
use neqo_udp::RecvBuf;
use tokio::time::Sleep;

use crate::SharedArgs;

const ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(10);

mod http09;
mod http3;

#[derive(Debug)]
pub enum Error {
    Argument(&'static str),
    Http3(neqo_http3::Error),
    Io(io::Error),
    Qlog,
    Transport(neqo_transport::Error),
    Crypto(neqo_crypto::Error),
}

impl From<neqo_crypto::Error> for Error {
    fn from(err: neqo_crypto::Error) -> Self {
        Self::Crypto(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<neqo_http3::Error> for Error {
    fn from(err: neqo_http3::Error) -> Self {
        Self::Http3(err)
    }
}

impl From<qlog::Error> for Error {
    fn from(_err: qlog::Error) -> Self {
        Self::Qlog
    }
}

impl From<neqo_transport::Error> for Error {
    fn from(err: neqo_transport::Error) -> Self {
        Self::Transport(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {self:?}")?;
        Ok(())
    }
}

impl std::error::Error for Error {}

type Res<T> = Result<T, Error>;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(flatten)]
    shared: SharedArgs,

    /// List of IP:port to listen on
    #[arg(default_value = "[::]:4433")]
    hosts: Vec<String>,

    #[arg(short = 'd', long, default_value = "./test-fixture/db")]
    /// NSS database directory.
    db: PathBuf,

    #[arg(short = 'k', long, default_value = "key")]
    /// Name of key from NSS database.
    key: String,

    #[arg(name = "retry", long)]
    /// Force a retry
    retry: bool,

    #[arg(name = "ech", long)]
    /// Enable encrypted client hello (ECH).
    /// This generates a new set of ECH keys when it is invoked.
    /// The resulting configuration is printed to stdout in hexadecimal format.
    ech: bool,
}

#[cfg(any(test, feature = "bench"))]
impl Default for Args {
    fn default() -> Self {
        use std::str::FromStr as _;
        Self {
            shared: SharedArgs::default(),
            hosts: vec!["[::]:12345".to_string()],
            db: PathBuf::from_str("../test-fixture/db").unwrap(),
            key: "key".to_string(),
            retry: false,
            ech: false,
        }
    }
}

impl Args {
    fn get_ciphers(&self) -> Vec<Cipher> {
        self.shared
            .ciphers
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
            .chain(self.shared.quic_parameters.preferred_address_v4())
            .chain(self.shared.quic_parameters.preferred_address_v6())
            .collect()
    }

    fn now(&self) -> Instant {
        if self.shared.qns_test.is_some() {
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

    #[cfg(any(test, feature = "bench"))]
    pub fn set_qlog_dir(&mut self, dir: PathBuf) {
        self.shared.qlog_dir = Some(dir);
    }

    pub fn set_hosts(&mut self, hosts: Vec<String>) {
        self.hosts = hosts;
    }
}

fn qns_read_response(filename: &str) -> Result<Vec<u8>, io::Error> {
    let path: PathBuf = ["/www", filename.trim_matches(|p| p == '/')]
        .iter()
        .collect();
    fs::read(path)
}

#[expect(clippy::module_name_repetitions, reason = "This is OK.")]
pub trait HttpServer: Display {
    fn process_multiple(
        &mut self,
        dgram: Option<Datagram<&mut [u8]>>,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch;
    fn process_events(&mut self, now: Instant);
    fn has_events(&self) -> bool;
}

pub struct Runner {
    now: Box<dyn Fn() -> Instant>,
    server: Box<dyn HttpServer>,
    timeout: Option<Pin<Box<Sleep>>>,
    sockets: Vec<(SocketAddr, crate::udp::Socket)>,
    recv_buf: RecvBuf,
}

impl Runner {
    #[must_use]
    pub fn new(
        now: Box<dyn Fn() -> Instant>,
        server: Box<dyn HttpServer>,
        sockets: Vec<(SocketAddr, crate::udp::Socket)>,
    ) -> Self {
        Self {
            now,
            server,
            timeout: None,
            sockets,
            recv_buf: RecvBuf::new(),
        }
    }

    #[must_use]
    pub fn local_addresses(&self) -> Vec<SocketAddr> {
        self.sockets
            .iter()
            .map(|(_, s)| s.local_addr().unwrap())
            .collect()
    }

    /// Tries to find a socket, but then just falls back to sending from the first.
    fn find_socket(
        sockets: &mut [(SocketAddr, crate::udp::Socket)],
        addr: SocketAddr,
    ) -> &mut crate::udp::Socket {
        let ((_host, first_socket), rest) = sockets.split_first_mut().unwrap();
        rest.iter_mut()
            .map(|(_host, socket)| socket)
            .find(|socket| socket.local_addr().is_ok_and(|a| a == addr))
            .unwrap_or(first_socket)
    }

    // Free function (i.e. not taking `&mut self: ServerRunner`) to be callable by
    // `ServerRunner::read_and_process` while holding a reference to
    // `ServerRunner::recv_buf`.
    async fn process_inner(
        server: &mut Box<dyn HttpServer>,
        timeout: &mut Option<Pin<Box<Sleep>>>,
        sockets: &mut [(SocketAddr, crate::udp::Socket)],
        now: &dyn Fn() -> Instant,
        mut input_dgram: Option<Datagram<&mut [u8]>>,
    ) -> Result<(), io::Error> {
        // Each socket has a maximum number of GSO segments it can handle. When
        // calling `server.process_multiple` we don't know which socket will be
        // used. Take the smallest maximum GSO segments from all sockets to
        // ensure that we don't send more segments than any socket can handle.
        //
        // Ideally we would have a way to know which socket will be used. Likely
        // not worth it for a test-only server implementation which is mostly
        // used with a single socket only.
        let smallest_max_gso_segments = sockets
            .iter()
            .map(|(_, socket)| socket.max_gso_segments())
            .min()
            .expect("At least one socket must be present")
            .try_into()
            .inspect_err(|_| qerror!("Socket return GSO size of 0"))
            .map_err(|_| io::Error::from(io::ErrorKind::Unsupported))?;

        loop {
            match server.process_multiple(input_dgram.take(), now(), smallest_max_gso_segments) {
                OutputBatch::DatagramBatch(dgram) => {
                    let socket = Self::find_socket(sockets, dgram.source());
                    loop {
                        // Optimistically attempt sending datagram. In case the
                        // OS buffer is full, wait till socket is writable then
                        // try again.
                        match socket.send(&dgram) {
                            Ok(()) => break,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                socket.writable().await?;
                                // Now try again.
                            }
                            e @ Err(_) => return e,
                        }
                    }
                }
                OutputBatch::Callback(new_timeout) => {
                    qdebug!("Setting timeout of {new_timeout:?}");
                    *timeout = Some(Box::pin(tokio::time::sleep(new_timeout)));
                    break;
                }
                OutputBatch::None => break,
            }
        }
        Ok(())
    }

    async fn read_and_process(&mut self, sockets_index: usize) -> Result<(), io::Error> {
        loop {
            let (host, socket) = &mut self.sockets[sockets_index];
            let Some(input_dgrams) = socket.recv(*host, &mut self.recv_buf)? else {
                break;
            };

            for input_dgram in input_dgrams {
                Self::process_inner(
                    &mut self.server,
                    &mut self.timeout,
                    &mut self.sockets,
                    &self.now,
                    Some(input_dgram),
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn process(&mut self) -> Result<(), io::Error> {
        Self::process_inner(
            &mut self.server,
            &mut self.timeout,
            &mut self.sockets,
            &self.now,
            None,
        )
        .await
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
            .map_or_else(|| Either::Right(futures::future::pending()), Either::Left)
            .map(|()| Ok(Ready::Timeout));
        select(sockets_ready, timeout_ready).await.factor_first().0
    }

    pub async fn run(mut self) -> Res<()> {
        loop {
            self.server.process_events((self.now)());
            self.process().await?;

            if self.server.has_events() {
                continue;
            }

            match self.ready().await? {
                Ready::Socket(sockets_index) => {
                    self.read_and_process(sockets_index).await?;
                }
                Ready::Timeout => {
                    self.timeout = None;
                    self.process().await?;
                }
            }
        }
    }
}

enum Ready {
    Socket(usize),
    Timeout,
}

pub fn server(mut args: Args) -> Res<Runner> {
    neqo_common::log::init(
        args.shared
            .verbose
            .as_ref()
            .map(clap_verbosity_flag::Verbosity::log_level_filter),
    );
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone())?;

    if let Some(testcase) = args.shared.qns_test.as_ref() {
        if args.shared.quic_parameters.quic_version.is_empty() {
            // Quic Interop Runner expects the server to support `Version1`
            // only. Exceptions are testcases `versionnegotiation` (not yet
            // implemented) and `v2`.
            if testcase != "v2" {
                args.shared.quic_parameters.quic_version = vec![Version::Version1];
            }
        } else {
            qwarn!("Both -V and --qns-test were set. Ignoring testcase specific versions");
        }

        // These are the default for all tests except http3.
        args.shared.alpn = String::from("hq-interop");
        // TODO: More options to deduplicate with client?
        match testcase.as_str() {
            "http3" => {
                args.shared.alpn = String::from("h3");
            }
            "zerortt" => args.shared.quic_parameters.max_streams_bidi = 100,
            "handshake" | "transfer" | "resumption" | "multiconnect" | "v2" | "ecn" => {}
            "connectionmigration" => {
                if args.shared.quic_parameters.preferred_address().is_none() {
                    qerror!("No preferred addresses set for connectionmigration test");
                    exit(127);
                }
            }
            "chacha20" => {
                args.shared.ciphers.clear();
                args.shared
                    .ciphers
                    .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
            }
            "retry" => args.retry = true,
            _ => exit(127),
        }
    }

    let hosts = args.listen_addresses();
    if hosts.is_empty() {
        qerror!("No valid hosts defined");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "No hosts").into());
    }
    let sockets: Vec<(SocketAddr, crate::udp::Socket)> = hosts
        .into_iter()
        .map(|host| {
            let socket = crate::udp::Socket::bind(host)?;
            qinfo!(
                "Server waiting for connection on: {:?}",
                socket.local_addr()
            );

            Ok((host, socket))
        })
        .collect::<Result<_, io::Error>>()?;

    // Note: this is the exception to the case where we use `Args::now`.
    let anti_replay = AntiReplay::new(Instant::now(), ANTI_REPLAY_WINDOW, 7, 14)
        .expect("unable to setup anti-replay");
    let cid_mgr = Rc::new(RefCell::new(RandomConnectionIdGenerator::new(10)));

    let server: Box<dyn HttpServer> = if args.shared.alpn == "h3" {
        Box::new(http3::HttpServer::new(&args, anti_replay, cid_mgr))
    } else {
        Box::new(
            http09::HttpServer::new(&args, anti_replay, cid_mgr).expect("We cannot make a server!"),
        )
    };

    Ok(Runner::new(Box::new(move || args.now()), server, sockets))
}
