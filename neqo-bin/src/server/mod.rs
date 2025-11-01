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
    fmt::Display,
    fs,
    future::{poll_fn, Future},
    io::{self},
    net::{SocketAddr, ToSocketAddrs as _},
    num::NonZeroUsize,
    path::PathBuf,
    pin::Pin,
    process::exit,
    rc::Rc,
    task::{Context, Poll},
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
use neqo_udp::{DatagramIter, RecvBuf};
use thiserror::Error;
use tokio::time::Sleep;

use crate::SharedArgs;

const ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(10);

pub mod http09;
pub mod http3;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    Argument(&'static str),
    #[error(transparent)]
    Http3(neqo_http3::Error),
    #[error(transparent)]
    Io(io::Error),
    #[error("qlog error")]
    Qlog,
    #[error(transparent)]
    Transport(neqo_transport::Error),
    #[error(transparent)]
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

pub type Res<T> = Result<T, Error>;

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
    #[must_use]
    pub const fn get_shared(&self) -> &SharedArgs {
        &self.shared
    }

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

    pub fn update_for_tests(&mut self) {
        if let Some(testcase) = self.shared.qns_test.as_ref() {
            if self.shared.quic_parameters.quic_version.is_empty() {
                // Quic Interop Runner expects the server to support `Version1`
                // only. Exceptions are testcases `versionnegotiation` (not yet
                // implemented) and `v2`.
                if testcase != "v2" {
                    self.shared.quic_parameters.quic_version = vec![Version::Version1];
                }
            } else {
                qwarn!("Both -V and --qns-test were set. Ignoring testcase specific versions");
            }

            // These are the default for all tests except http3.
            self.shared.alpn = String::from("hq-interop");
            // TODO: More options to deduplicate with client?
            match testcase.as_str() {
                "http3" => {
                    self.shared.alpn = String::from("h3");
                }
                "zerortt" => self.shared.quic_parameters.max_streams_bidi = 100,
                "handshake" | "transfer" | "resumption" | "multiconnect" | "v2" | "ecn" => {}
                "connectionmigration" => {
                    if self.shared.quic_parameters.preferred_address().is_none() {
                        qerror!("No preferred addresses set for connectionmigration test");
                        exit(127);
                    }
                }
                "chacha20" => {
                    self.shared.ciphers.clear();
                    self.shared
                        .ciphers
                        .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
                }
                "retry" => self.retry = true,
                _ => exit(127),
            }
        }
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
    fn process_multiple<'a>(
        &mut self,
        dgrams: impl IntoIterator<Item = Datagram<&'a mut [u8]>>,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch;
    fn process_events(&mut self, now: Instant);
    fn has_events(&self) -> bool;
    /// Enables an [`HttpServer`] to drive asynchronous operations.
    ///
    /// Needed in Firefox's HTTP/3 proxy test server implementation to drive TCP
    /// and UDP sockets to the proxy target.
    ///
    /// <https://github.com/mozilla-firefox/firefox/blob/main/netwerk/test/http3server/src/main.rs>
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

pub struct Runner<S> {
    now: Box<dyn Fn() -> Instant>,
    server: S,
    timeout: Option<Pin<Box<Sleep>>>,
    sockets: Vec<(SocketAddr, crate::udp::Socket)>,
    recv_buf: RecvBuf,
}

impl<S: HttpServer + Unpin> Runner<S> {
    #[must_use]
    pub fn new(
        server: S,
        now: Box<dyn Fn() -> Instant>,
        sockets: Vec<(SocketAddr, crate::udp::Socket)>,
    ) -> Self {
        Self {
            now,
            server,
            timeout: None,
            sockets,
            recv_buf: RecvBuf::default(),
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
        server: &mut S,
        timeout: &mut Option<Pin<Box<Sleep>>>,
        sockets: &mut [(SocketAddr, crate::udp::Socket)],
        now: &dyn Fn() -> Instant,
        mut input_dgrams: Option<DatagramIter<'_>>,
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
            match server.process_multiple(
                input_dgrams.take().into_iter().flatten(),
                now(),
                smallest_max_gso_segments,
            ) {
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

            Self::process_inner(
                &mut self.server,
                &mut self.timeout,
                &mut self.sockets,
                &self.now,
                Some(input_dgrams),
            )
            .await?;
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

        let server_ready =
            poll_fn(|cx| Pin::new(&mut self.server).poll(cx)).map(|()| Ok(Ready::Server));

        select(
            select(sockets_ready, timeout_ready).map(|either| either.factor_first().0),
            server_ready,
        )
        .map(|either| either.factor_first().0)
        .await
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
                Ready::Server => {
                    // Processing server at top of the loop.
                }
            }
        }
    }
}

enum Ready {
    Socket(usize),
    Timeout,
    Server,
}

#[expect(clippy::type_complexity, reason = "pinned and boxed future")]
pub fn run(
    mut args: Args,
) -> Res<(
    Pin<Box<dyn Future<Output = Res<()>> + 'static>>,
    Vec<SocketAddr>,
)> {
    neqo_common::log::init(
        args.shared
            .verbose
            .as_ref()
            .map(clap_verbosity_flag::Verbosity::log_level_filter),
    );
    args.update_for_tests();
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone())?;

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
    let anti_replay = AntiReplay::new(Instant::now(), ANTI_REPLAY_WINDOW, 7, 14)?;
    let cid_mgr = Rc::new(RefCell::new(RandomConnectionIdGenerator::new(10)));

    if args.shared.alpn == "h3" {
        let runner = Runner::new(
            http3::HttpServer::new(&args, anti_replay, cid_mgr),
            Box::new(move || args.now()),
            sockets,
        );
        let local_addrs = runner.local_addresses();
        Ok((Box::pin(runner.run()), local_addrs))
    } else {
        let runner = Runner::new(
            http09::HttpServer::new(&args, anti_replay, cid_mgr)?,
            Box::new(move || args.now()),
            sockets,
        );
        let local_addrs = runner.local_addresses();
        Ok((Box::pin(runner.run()), local_addrs))
    }
}
