// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::{HashMap, VecDeque},
    fmt::{self, Display},
    fs::{create_dir_all, File, OpenOptions},
    io::{self, BufWriter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    process::exit,
    time::Instant,
};

use clap::Parser;
use futures::{
    future::{select, Either},
    FutureExt, TryFutureExt,
};
use neqo_bin::udp;
use neqo_common::{self as common, qdebug, qinfo, qlog::NeqoQlog, Datagram, Role};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init, Cipher, ResumptionToken,
};
use neqo_http3::{Error, Output};
use neqo_transport::{AppError, ConnectionId, Error as TransportError, Version};
use qlog::{events::EventImportance, streamer::QlogStreamer};
use tokio::time::Sleep;
use url::{Origin, Url};

mod http09;
mod http3;

const BUFWRITER_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum ClientError {
    ArgumentError(&'static str),
    Http3Error(neqo_http3::Error),
    IoError(io::Error),
    QlogError,
    TransportError(neqo_transport::Error),
}

impl From<io::Error> for ClientError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<neqo_http3::Error> for ClientError {
    fn from(err: neqo_http3::Error) -> Self {
        Self::Http3Error(err)
    }
}

impl From<qlog::Error> for ClientError {
    fn from(_err: qlog::Error) -> Self {
        Self::QlogError
    }
}

impl From<neqo_transport::Error> for ClientError {
    fn from(err: neqo_transport::Error) -> Self {
        Self::TransportError(err)
    }
}

impl Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {self:?}")?;
        Ok(())
    }
}

impl std::error::Error for ClientError {}

type Res<T> = Result<T, ClientError>;

/// Track whether a key update is needed.
#[derive(Debug, PartialEq, Eq)]
struct KeyUpdateState(bool);

impl KeyUpdateState {
    pub fn maybe_update<F, E>(&mut self, update_fn: F) -> Res<()>
    where
        F: FnOnce() -> Result<(), E>,
        E: Into<ClientError>,
    {
        if self.0 {
            if let Err(e) = update_fn() {
                let e = e.into();
                match e {
                    ClientError::TransportError(TransportError::KeyUpdateBlocked)
                    | ClientError::Http3Error(Error::TransportError(
                        TransportError::KeyUpdateBlocked,
                    )) => (),
                    _ => return Err(e),
                }
            } else {
                println!("Keys updated");
                self.0 = false;
            }
        }
        Ok(())
    }

    fn needed(&self) -> bool {
        self.0
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[allow(clippy::struct_excessive_bools)] // Not a good use of that lint.
pub struct Args {
    #[command(flatten)]
    shared: neqo_bin::SharedArgs,

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

    #[arg(short = 'r', long)]
    /// Client attempts to resume by making multiple connections to servers.
    /// Requires that 2 or more URLs are listed for each server.
    /// Use this for 0-RTT: the stack always attempts 0-RTT on resumption.
    resume: bool,

    #[arg(name = "key-update", long)]
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

    fn update_for_tests(&mut self) {
        let Some(testcase) = self.shared.qns_test.as_ref() else {
            return;
        };

        // Only use v1 for most QNS tests.
        self.shared.quic_parameters.quic_version = vec![Version::Version1];
        match testcase.as_str() {
            // TODO: Add "ecn" when that is ready.
            "http3" => {
                if let Some(testcase) = &self.test {
                    if testcase.as_str() != "upload" {
                        eprintln!("Unsupported test case: {testcase}");
                        exit(127)
                    }

                    self.method = String::from("POST");
                }
            }
            "handshake" | "transfer" | "retry" => {
                self.shared.use_old_http = true;
            }
            "zerortt" | "resumption" => {
                if self.urls.len() < 2 {
                    eprintln!("Warning: resumption tests won't work without >1 URL");
                    exit(127);
                }
                self.shared.use_old_http = true;
                self.resume = true;
            }
            "multiconnect" => {
                self.shared.use_old_http = true;
                self.download_in_series = true;
            }
            "chacha20" => {
                self.shared.use_old_http = true;
                self.shared.ciphers.clear();
                self.shared
                    .ciphers
                    .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
            }
            "keyupdate" => {
                self.shared.use_old_http = true;
                self.key_update = true;
            }
            "v2" => {
                self.shared.use_old_http = true;
                // Use default version set for this test (which allows compatible vneg.)
                self.shared.quic_parameters.quic_version.clear();
            }
            _ => exit(127),
        }
    }
}

fn get_output_file(
    url: &Url,
    output_dir: &Option<PathBuf>,
    all_paths: &mut Vec<PathBuf>,
) -> Option<BufWriter<File>> {
    if let Some(ref dir) = output_dir {
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
            eprintln!("duplicate path {}", out_path.display());
            return None;
        }

        eprintln!("Saving {url} to {out_path:?}");

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
    socket: &udp::Socket,
    mut timeout: Option<&mut Pin<Box<Sleep>>>,
) -> Result<Ready, io::Error> {
    let socket_ready = Box::pin(socket.readable()).map_ok(|()| Ready::Socket);
    let timeout_ready = timeout
        .as_mut()
        .map_or(Either::Right(futures::future::pending()), Either::Left)
        .map(|()| Ok(Ready::Timeout));
    select(socket_ready, timeout_ready).await.factor_first().0
}

/// Handles a given task on the provided [`Client`].
trait Handler {
    type Client: Client;

    fn handle(&mut self, client: &mut Self::Client) -> Res<bool>;
    fn maybe_key_update(&mut self, c: &mut Self::Client) -> Res<()>;
    fn take_token(&mut self) -> Option<ResumptionToken>;
    fn has_token(&self) -> bool;
}

/// Network client, e.g. [`neqo_transport::Connection`] or [`neqo_http3::Http3Client`].
trait Client {
    fn process(&mut self, dgram: Option<&Datagram>, now: Instant) -> Output;
    fn close<S>(&mut self, now: Instant, app_error: AppError, msg: S)
    where
        S: AsRef<str> + Display;
    fn is_closed(&self) -> bool;
}

struct Runner<'a, H: Handler> {
    local_addr: SocketAddr,
    socket: &'a mut udp::Socket,
    client: H::Client,
    handler: H,
    timeout: Option<Pin<Box<Sleep>>>,
    args: &'a Args,
}

impl<'a, H: Handler> Runner<'a, H> {
    async fn run(mut self) -> Res<Option<ResumptionToken>> {
        loop {
            let handler_done = self.handler.handle(&mut self.client)?;

            match (handler_done, self.args.resume, self.handler.has_token()) {
                    // Handler isn't done. Continue.
                    (false, _, _) => {},
                    // Handler done. Resumption token needed but not present. Continue.
                    (true, true, false) => {
                        qdebug!("Handler done. Waiting for resumption token.");
                    }
                    // Handler is done, no resumption token needed. Close.
                    (true, false, _) |
                    // Handler is done, resumption token needed and present. Close.
                    (true, true, true) => {
                        self.client.close(Instant::now(), 0, "kthxbye!");
                    }
                }

            self.process(None).await?;

            if self.client.is_closed() {
                return Ok(self.handler.take_token());
            }

            match ready(self.socket, self.timeout.as_mut()).await? {
                Ready::Socket => loop {
                    let dgrams = self.socket.recv(&self.local_addr)?;
                    if dgrams.is_empty() {
                        break;
                    }
                    for dgram in &dgrams {
                        self.process(Some(dgram)).await?;
                    }
                    self.handler.maybe_key_update(&mut self.client)?;
                },
                Ready::Timeout => {
                    self.timeout = None;
                }
            }
        }
    }

    async fn process(&mut self, mut dgram: Option<&Datagram>) -> Result<(), io::Error> {
        loop {
            match self.client.process(dgram.take(), Instant::now()) {
                Output::Datagram(dgram) => {
                    self.socket.writable().await?;
                    self.socket.send(dgram)?;
                }
                Output::Callback(new_timeout) => {
                    qinfo!("Setting timeout of {:?}", new_timeout);
                    self.timeout = Some(Box::pin(tokio::time::sleep(new_timeout)));
                    break;
                }
                Output::None => {
                    qdebug!("Output::None");
                    break;
                }
            }
        }

        Ok(())
    }
}

fn qlog_new(args: &Args, hostname: &str, cid: &ConnectionId) -> Res<NeqoQlog> {
    if let Some(qlog_dir) = &args.shared.qlog_dir {
        let mut qlog_path = qlog_dir.clone();
        let filename = format!("{hostname}-{cid}.sqlog");
        qlog_path.push(filename);

        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&qlog_path)?;

        let streamer = QlogStreamer::new(
            qlog::QLOG_VERSION.to_string(),
            Some("Example qlog".to_string()),
            Some("Example qlog description".to_string()),
            None,
            std::time::Instant::now(),
            common::qlog::new_trace(Role::Client),
            EventImportance::Base,
            Box::new(f),
        );

        Ok(NeqoQlog::enabled(streamer, qlog_path)?)
    } else {
        Ok(NeqoQlog::disabled())
    }
}

#[tokio::main]
async fn main() -> Res<()> {
    init();

    let mut args = Args::parse();
    args.update_for_tests();

    let urls_by_origin = args
        .urls
        .clone()
        .into_iter()
        .fold(HashMap::<Origin, VecDeque<Url>>::new(), |mut urls, url| {
            urls.entry(url.origin()).or_default().push_back(url);
            urls
        })
        .into_iter()
        .filter_map(|(origin, urls)| match origin {
            Origin::Tuple(_scheme, h, p) => Some(((h, p), urls)),
            Origin::Opaque(x) => {
                eprintln!("Opaque origin {x:?}");
                None
            }
        });

    for ((host, port), mut urls) in urls_by_origin {
        if args.resume && urls.len() < 2 {
            eprintln!("Resumption to {host} cannot work without at least 2 URLs.");
            exit(127);
        }

        let remote_addr = format!("{host}:{port}").to_socket_addrs()?.find(|addr| {
            !matches!(
                (addr, args.ipv4_only, args.ipv6_only),
                (SocketAddr::V4(..), false, true) | (SocketAddr::V6(..), true, false)
            )
        });
        let Some(remote_addr) = remote_addr else {
            eprintln!("No compatible address found for: {host}");
            exit(1);
        };

        let local_addr = match remote_addr {
            SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
            SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0),
        };

        let mut socket = udp::Socket::bind(local_addr)?;
        let real_local = socket.local_addr().unwrap();
        println!(
            "{} Client connecting: {:?} -> {:?}",
            if args.shared.use_old_http { "H9" } else { "H3" },
            real_local,
            remote_addr,
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

            let key_update = KeyUpdateState(args.key_update);

            token = if args.shared.use_old_http {
                let client =
                    http09::create_client(&args, real_local, remote_addr, &hostname, token)
                        .expect("failed to create client");

                let handler = http09::Handler::new(to_request, &args, key_update);

                Runner {
                    args: &args,
                    client,
                    handler,
                    local_addr: real_local,
                    socket: &mut socket,
                    timeout: None,
                }
                .run()
                .await?
            } else {
                let client = http3::create_client(&args, real_local, remote_addr, &hostname, token)
                    .expect("failed to create client");

                let handler = http3::Handler::new(to_request, &args, key_update);

                Runner {
                    args: &args,
                    client,
                    handler,
                    local_addr: real_local,
                    socket: &mut socket,
                    timeout: None,
                }
                .run()
                .await?
            };
        }
    }

    Ok(())
}
