// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is example code.")]

use std::{
    collections::VecDeque,
    fmt::{self, Display},
    fs::{create_dir_all, File, OpenOptions},
    io::{self, BufWriter, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    num::NonZeroUsize,
    path::PathBuf,
    pin::Pin,
    process::exit,
    time::Instant,
};

use clap::Parser;
use futures::{
    future::{select, Either},
    FutureExt as _, TryFutureExt as _,
};
use neqo_common::{qdebug, qerror, qinfo, qlog::Qlog, qwarn, Datagram, Role};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init, Cipher, ResumptionToken,
};
use neqo_transport::{AppError, CloseReason, ConnectionId, OutputBatch, Version};
use neqo_udp::RecvBuf;
use rustc_hash::FxHashMap as HashMap;
use tokio::time::Sleep;
use url::{Host, Origin, Url};

use crate::SharedArgs;

mod http09;
mod http3;

const BUFWRITER_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    Argument(&'static str),
    Http3(neqo_http3::Error),
    Io(io::Error),
    Qlog(qlog::Error),
    Transport(neqo_transport::Error),
    Application(AppError),
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
    fn from(err: qlog::Error) -> Self {
        Self::Qlog(err)
    }
}

impl From<neqo_transport::Error> for Error {
    fn from(err: neqo_transport::Error) -> Self {
        Self::Transport(err)
    }
}

impl From<CloseReason> for Error {
    fn from(err: CloseReason) -> Self {
        match err {
            CloseReason::Transport(e) => Self::Transport(e),
            CloseReason::Application(e) => Self::Application(e),
        }
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "Not a good use of that lint."
)]
pub struct Args {
    #[command(flatten)]
    shared: SharedArgs,

    urls: Vec<Url>,

    #[arg(short = 'm', default_value = "GET")]
    method: String,

    #[arg(short = 'H', long, number_of_values = 2)]
    header: Vec<String>,

    #[arg(name = "max-push", short = 'p', long, default_value = "10")]
    max_concurrent_push_streams: u64,

    #[arg(name = "download-in-series", long)]
    /// Download resources in series using separate connections.
    download_in_series: bool,

    #[arg(name = "concurrency", long, default_value = "100")]
    /// The maximum number of requests to have outstanding at one time.
    concurrency: usize,

    #[arg(name = "output-read-data", long)]
    /// Output received data to stdout
    output_read_data: bool,

    #[arg(name = "output-dir", long)]
    /// Save contents of fetched URLs to a directory
    output_dir: Option<PathBuf>,

    #[arg(short = 'r', long, hide = true)]
    /// Client attempts to resume by making multiple connections to servers.
    /// Requires that 2 or more URLs are listed for each server.
    /// Use this for 0-RTT: the stack always attempts 0-RTT on resumption.
    resume: bool,

    #[arg(name = "key-update", long, hide = true)]
    /// Attempt to initiate a key update immediately after confirming the connection.
    key_update: bool,

    #[arg(name = "ech", long, value_parser = |s: &str| hex::decode(s))]
    /// Enable encrypted client hello (ECH).
    /// This takes an encoded ECH configuration in hexadecimal format.
    ech: Option<Vec<u8>>,

    #[arg(name = "ipv4-only", short = '4', long)]
    /// Connect only over IPv4
    ipv4_only: bool,

    #[arg(name = "ipv6-only", short = '6', long)]
    /// Connect only over IPv6
    ipv6_only: bool,

    /// The test that this client will run. Currently, we only support "upload".
    #[arg(name = "test", long)]
    test: Option<String>,

    /// The request size that will be used for upload test.
    #[arg(name = "upload-size", long, default_value = "100")]
    upload_size: usize,

    /// Print connection stats after close.
    #[arg(name = "stats", long)]
    stats: bool,

    /// The length of the local connection ID.
    #[arg(name = "cid-length", short = 'l', long, default_value = "0",
          value_parser = clap::value_parser!(u8).range(..=20))]
    cid_len: u8,
}

impl Args {
    #[must_use]
    #[cfg(any(test, feature = "bench"))]
    #[expect(clippy::missing_panics_doc, reason = "This is example code.")]
    pub fn new(
        server_addr: Option<SocketAddr>,
        num_requests: usize,
        upload_size: usize,
        download_size: usize,
    ) -> Self {
        use std::{iter::repeat_with, str::FromStr as _};

        let addr = server_addr.map_or("[::1]:12345".into(), |a| format!("[::1]:{}", a.port()));
        Self {
            shared: SharedArgs::default(),
            urls: repeat_with(|| Url::from_str(&format!("http://{addr}/{download_size}")).unwrap())
                .take(num_requests)
                .collect(),
            method: if upload_size == 0 {
                "GET".into()
            } else {
                "POST".into()
            },
            header: vec![],
            max_concurrent_push_streams: 10,
            download_in_series: false,
            concurrency: 100,
            output_read_data: false,
            output_dir: Some("/dev/null".into()),
            resume: false,
            key_update: false,
            ech: None,
            ipv4_only: false,
            ipv6_only: false,
            test: None,
            upload_size,
            stats: false,
            cid_len: 0,
        }
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

    fn update_for_tests(&mut self) {
        let Some(testcase) = self.shared.qns_test.as_ref() else {
            return;
        };

        if self.key_update {
            qerror!("internal option key_update set by user");
            exit(127)
        }

        if self.resume {
            qerror!("internal option resume set by user");
            exit(127)
        }

        // Only use v1 for most QNS tests.
        self.shared.quic_parameters.quic_version = vec![Version::Version1];
        // This is the default for all tests except http3.
        self.shared.alpn = String::from("hq-interop");
        // Wireshark can't reassemble sliced CRYPTO frames, which causes tests to fail.
        // So let's turn that off by default, and only enable for some known-good QNS tests.
        self.shared.quic_parameters.no_sni_slicing = true;
        match testcase.as_str() {
            "http3" => {
                self.shared.quic_parameters.no_sni_slicing = false;
                self.shared.alpn = String::from("h3");
                if let Some(testcase) = &self.test {
                    if testcase.as_str() != "upload" {
                        qerror!("Unsupported test case: {testcase}");
                        exit(127)
                    }

                    self.method = String::from("POST");
                }
            }
            "handshake" | "transfer" | "retry" | "ecn" => {}
            "resumption" => {
                if self.urls.len() < 2 {
                    qerror!("Warning: resumption test won't work without >1 URL");
                    exit(127);
                }
                self.resume = true;
            }
            "zerortt" => {
                if self.urls.len() < 2 {
                    qerror!("Warning: zerortt test won't work without >1 URL");
                    exit(127);
                }
                self.shared.quic_parameters.no_sni_slicing = false;
                self.resume = true;
                // PMTUD probes inflate what we sent in 1-RTT, causing QNS to fail the test.
                self.shared.quic_parameters.no_pmtud = true;
                // If we pace, we might get the initial server flight before sending sufficient
                // 0-RTT data to pass the QNS check. So let's burst.
                self.shared.quic_parameters.no_pacing = true;
            }
            "multiconnect" => {
                self.download_in_series = true;
            }
            "chacha20" => {
                self.shared.ciphers.clear();
                self.shared
                    .ciphers
                    .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
            }
            "keyupdate" => {
                self.key_update = true;
            }
            "v2" => {
                self.shared.quic_parameters.no_sni_slicing = false;
                // Use default version set for this test (which allows compatible vneg.)
                self.shared.quic_parameters.quic_version.clear();
            }
            _ => exit(127),
        }
    }

    #[cfg(any(test, feature = "bench"))]
    pub fn set_qlog_dir(&mut self, dir: PathBuf) {
        self.shared.qlog_dir = Some(dir);
    }
}

fn get_output_file(
    url: &Url,
    output_dir: Option<&PathBuf>,
    all_paths: &mut Vec<PathBuf>,
) -> Option<BufWriter<File>> {
    if let Some(dir) = output_dir {
        let mut out_path = dir.clone();

        let url_path = if url.path() == "/" {
            // If no path is given... call it "root"?
            "root"
        } else {
            // Omit leading slash
            &url.path()[1..]
        };
        out_path.push(url_path);

        if all_paths.contains(&out_path) {
            qerror!("duplicate path {}", out_path.display());
            return None;
        }

        qinfo!("Saving {url} to {out_path:?}");

        if let Some(parent) = out_path.parent() {
            create_dir_all(parent).ok()?;
        }

        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)
            .ok()?;

        all_paths.push(out_path);
        Some(BufWriter::with_capacity(BUFWRITER_BUFFER_SIZE, f))
    } else {
        None
    }
}

enum Ready {
    Socket,
    Timeout,
}

// Wait for the socket to be readable or the timeout to fire.
async fn ready(
    socket: &crate::udp::Socket,
    mut timeout: Option<&mut Pin<Box<Sleep>>>,
) -> Result<Ready, io::Error> {
    let socket_ready = Box::pin(socket.readable()).map_ok(|()| Ready::Socket);
    let timeout_ready = timeout
        .as_mut()
        .map_or_else(|| Either::Right(futures::future::pending()), Either::Left)
        .map(|()| Ok(Ready::Timeout));
    select(socket_ready, timeout_ready).await.factor_first().0
}

/// Handles a given task on the provided [`Client`].
trait Handler {
    type Client: Client;

    fn handle(&mut self, client: &mut Self::Client) -> Res<bool>;
    fn take_token(&mut self) -> Option<ResumptionToken>;
}

enum CloseState {
    NotClosing,
    Closing,
    Closed,
}

/// Network client, e.g. [`neqo_transport::Connection`] or [`neqo_http3::Http3Client`].
trait Client {
    fn process_multiple_output(&mut self, now: Instant, max_datagrams: NonZeroUsize)
        -> OutputBatch;
    fn process_multiple_input<'a>(
        &mut self,
        dgrams: impl IntoIterator<Item = Datagram<&'a mut [u8]>>,
        now: Instant,
    );
    fn has_events(&self) -> bool;
    fn close<S>(&mut self, now: Instant, app_error: AppError, msg: S)
    where
        S: AsRef<str> + Display;
    fn is_closed(&self) -> Result<CloseState, CloseReason>;
    fn stats(&self) -> neqo_transport::Stats;
}

struct Runner<'a, H: Handler> {
    local_addr: SocketAddr,
    socket: &'a mut crate::udp::Socket,
    client: H::Client,
    handler: H,
    timeout: Option<Pin<Box<Sleep>>>,
    args: &'a Args,
    recv_buf: RecvBuf,
}

impl<'a, H: Handler> Runner<'a, H> {
    fn new(
        local_addr: SocketAddr,
        socket: &'a mut crate::udp::Socket,
        client: H::Client,
        handler: H,
        args: &'a Args,
    ) -> Self {
        Self {
            local_addr,
            socket,
            client,
            handler,
            args,
            timeout: None,
            recv_buf: RecvBuf::new(),
        }
    }

    async fn run(mut self) -> Res<Option<ResumptionToken>> {
        loop {
            let handler_done = self.handler.handle(&mut self.client)?;
            self.process_output().await?;
            if self.client.has_events() {
                continue;
            }

            match (handler_done, self.client.is_closed()?) {
                // more work; or no more work, already closing connection
                (true, CloseState::Closing) | (false, _) => {}
                // no more work, closing connection
                (true, CloseState::NotClosing) => {
                    self.client.close(Instant::now(), 0, "kthxbye!");
                    continue;
                }
                // no more work, connection closed, terminating
                (true, CloseState::Closed) => break,
            }

            match ready(self.socket, self.timeout.as_mut()).await? {
                Ready::Socket => self.process_multiple_input().await?,
                Ready::Timeout => {
                    self.timeout = None;
                }
            }
        }

        if self.args.stats {
            qinfo!("{:?}", self.client.stats());
        }

        Ok(self.handler.take_token())
    }

    async fn process_output(&mut self) -> Result<(), io::Error> {
        loop {
            let max_datagrams = self
                .socket
                .max_gso_segments()
                .try_into()
                .inspect_err(|_| qerror!("Socket return GSO size of 0"))
                .map_err(|_| io::Error::from(ErrorKind::Unsupported))?;

            match self
                .client
                .process_multiple_output(Instant::now(), max_datagrams)
            {
                OutputBatch::DatagramBatch(dgram) => loop {
                    // Optimistically attempt sending datagram. In case the OS
                    // buffer is full, wait till socket is writable then try
                    // again.
                    match self.socket.send(&dgram) {
                        Ok(()) => break,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            self.socket.writable().await?;
                            // Now try again.
                        }
                        e @ Err(_) => return e,
                    }
                },
                OutputBatch::Callback(new_timeout) => {
                    qdebug!("Setting timeout of {new_timeout:?}");
                    self.timeout = Some(Box::pin(tokio::time::sleep(new_timeout)));
                    break;
                }
                OutputBatch::None => {
                    qdebug!("Output::None");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_multiple_input(&mut self) -> Res<()> {
        loop {
            let Some(dgrams) = self.socket.recv(self.local_addr, &mut self.recv_buf)? else {
                break;
            };
            self.client.process_multiple_input(dgrams, Instant::now());
            self.process_output().await?;
        }

        Ok(())
    }
}

fn qlog_new(args: &Args, hostname: &str, cid: &ConnectionId) -> Res<Qlog> {
    let Some(qlog_dir) = args.shared.qlog_dir.clone() else {
        return Ok(Qlog::disabled());
    };

    // hostname might be an IPv6 address, e.g. `[::1]`. `:` is an invalid
    // Windows file name character.
    #[cfg(windows)]
    let hostname: String = hostname
        .chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect();

    Qlog::enabled_with_file(
        qlog_dir,
        Role::Client,
        Some("Neqo client qlog".to_string()),
        Some("Neqo client qlog".to_string()),
        format!("client-{hostname}-{cid}"),
    )
    .map_err(Error::Qlog)
}

const fn local_addr_for(remote_addr: &SocketAddr, local_port: u16) -> SocketAddr {
    match remote_addr {
        SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port),
        SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_port),
    }
}

fn urls_by_origin(urls: &[Url]) -> impl Iterator<Item = ((Host, u16), VecDeque<Url>)> {
    urls.iter()
        .fold(
            HashMap::<Origin, VecDeque<Url>>::default(),
            |mut urls, url| {
                urls.entry(url.origin()).or_default().push_back(url.clone());
                urls
            },
        )
        .into_iter()
        .filter_map(|(origin, urls)| match origin {
            Origin::Tuple(_scheme, h, p) => Some(((h, p), urls)),
            Origin::Opaque(x) => {
                qwarn!("Opaque origin {x:?}");
                None
            }
        })
}

#[expect(
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "This is example code."
)]
pub async fn client(mut args: Args) -> Res<()> {
    neqo_common::log::init(
        args.shared
            .verbose
            .as_ref()
            .map(clap_verbosity_flag::Verbosity::log_level_filter),
    );
    init()?;

    args.update_for_tests();

    init()?;

    for ((host, port), mut urls) in urls_by_origin(&args.urls) {
        if args.resume && urls.len() < 2 {
            qerror!("Resumption to {host} cannot work without at least 2 URLs");
            exit(127);
        }

        let remote_addr = format!("{host}:{port}").to_socket_addrs()?.find(|addr| {
            !matches!(
                (addr, args.ipv4_only, args.ipv6_only),
                (SocketAddr::V4(..), false, true) | (SocketAddr::V6(..), true, false)
            )
        });
        let Some(remote_addr) = remote_addr else {
            qerror!("No compatible address found for: {host}");
            exit(1);
        };
        let mut socket = crate::udp::Socket::bind(local_addr_for(&remote_addr, 0))?;
        let real_local = socket.local_addr().unwrap();
        qinfo!(
            "{} Client connecting: {real_local:?} -> {remote_addr:?}",
            args.shared.alpn
        );

        let hostname = format!("{host}");
        let mut token: Option<ResumptionToken> = None;
        let mut first = true;
        while !urls.is_empty() {
            let to_request = if (args.resume && first) || args.download_in_series {
                urls.pop_front().into_iter().collect()
            } else {
                std::mem::take(&mut urls)
            };

            first = false;

            token = if args.shared.alpn == "h3" {
                let client = http3::create_client(&args, real_local, remote_addr, &hostname, token)
                    .expect("failed to create client");

                let handler = http3::Handler::new(to_request, &args);

                Runner::new(real_local, &mut socket, client, handler, &args)
                    .run()
                    .await?
            } else {
                let client =
                    http09::create_client(&args, real_local, remote_addr, &hostname, token)
                        .expect("failed to create client");

                let handler = http09::Handler::new(to_request, &args);

                Runner::new(real_local, &mut socket, client, handler, &args)
                    .run()
                    .await?
            };
        }
    }

    Ok(())
}
