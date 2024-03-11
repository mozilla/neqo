// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fmt::{self, Display},
    fs::{create_dir_all, File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    process::exit,
    rc::Rc,
    time::Instant,
};

use clap::Parser;
use futures::{
    future::{select, Either},
    FutureExt, TryFutureExt,
};
use neqo_common::{
    self as common, event::Provider, hex, qdebug, qinfo, qlog::NeqoQlog, udp, Datagram, Role,
};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init, AuthenticationStatus, Cipher, ResumptionToken,
};
use neqo_http3::{
    Error, Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Output, Priority,
};
use neqo_transport::{
    Connection, ConnectionId, EmptyConnectionIdGenerator, Error as TransportError, StreamId,
    Version,
};
use qlog::{events::EventImportance, streamer::QlogStreamer};
use tokio::time::Sleep;
use url::{Origin, Url};

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
            "http3" => {}
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
) -> Option<File> {
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
        Some(f)
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

trait StreamHandler {
    fn process_header_ready(&mut self, stream_id: StreamId, fin: bool, headers: Vec<Header>);
    fn process_data_readable(
        &mut self,
        stream_id: StreamId,
        fin: bool,
        data: Vec<u8>,
        sz: usize,
        output_read_data: bool,
    ) -> Res<bool>;
    fn process_data_writable(&mut self, client: &mut Http3Client, stream_id: StreamId);
}

enum StreamHandlerType {
    Download,
    Upload,
}

impl StreamHandlerType {
    fn make_handler(
        handler_type: &Self,
        url: &Url,
        args: &Args,
        all_paths: &mut Vec<PathBuf>,
        client: &mut Http3Client,
        client_stream_id: StreamId,
    ) -> Box<dyn StreamHandler> {
        match handler_type {
            Self::Download => {
                let out_file = get_output_file(url, &args.output_dir, all_paths);
                client.stream_close_send(client_stream_id).unwrap();
                Box::new(DownloadStreamHandler { out_file })
            }
            Self::Upload => Box::new(UploadStreamHandler {
                data: vec![42; args.upload_size],
                offset: 0,
                chunk_size: 32768,
                start: Instant::now(),
            }),
        }
    }
}

struct DownloadStreamHandler {
    out_file: Option<File>,
}

impl StreamHandler for DownloadStreamHandler {
    fn process_header_ready(&mut self, stream_id: StreamId, fin: bool, headers: Vec<Header>) {
        if self.out_file.is_none() {
            println!("READ HEADERS[{stream_id}]: fin={fin} {headers:?}");
        }
    }

    fn process_data_readable(
        &mut self,
        stream_id: StreamId,
        fin: bool,
        data: Vec<u8>,
        sz: usize,
        output_read_data: bool,
    ) -> Res<bool> {
        if let Some(out_file) = &mut self.out_file {
            if sz > 0 {
                out_file.write_all(&data[..sz])?;
            }
            return Ok(true);
        } else if !output_read_data {
            println!("READ[{stream_id}]: {sz} bytes");
        } else if let Ok(txt) = String::from_utf8(data.clone()) {
            println!("READ[{stream_id}]: {txt}");
        } else {
            println!("READ[{}]: 0x{}", stream_id, hex(&data));
        }

        if fin && self.out_file.is_none() {
            println!("<FIN[{stream_id}]>");
        }

        Ok(true)
    }

    fn process_data_writable(&mut self, _client: &mut Http3Client, _stream_id: StreamId) {}
}

struct UploadStreamHandler {
    data: Vec<u8>,
    offset: usize,
    chunk_size: usize,
    start: Instant,
}

impl StreamHandler for UploadStreamHandler {
    fn process_header_ready(&mut self, stream_id: StreamId, fin: bool, headers: Vec<Header>) {
        println!("READ HEADERS[{stream_id}]: fin={fin} {headers:?}");
    }

    fn process_data_readable(
        &mut self,
        stream_id: StreamId,
        _fin: bool,
        data: Vec<u8>,
        _sz: usize,
        _output_read_data: bool,
    ) -> Res<bool> {
        if let Ok(txt) = String::from_utf8(data.clone()) {
            let trimmed_txt = txt.trim_end_matches(char::from(0));
            let parsed: usize = trimmed_txt.parse().unwrap();
            if parsed == self.data.len() {
                let upload_time = Instant::now().duration_since(self.start);
                println!("Stream ID: {stream_id:?}, Upload time: {upload_time:?}");
            }
        } else {
            panic!("Unexpected data [{}]: 0x{}", stream_id, hex(&data));
        }
        Ok(true)
    }

    fn process_data_writable(&mut self, client: &mut Http3Client, stream_id: StreamId) {
        while self.offset < self.data.len() {
            let end = self.offset + self.chunk_size.min(self.data.len() - self.offset);
            let chunk = &self.data[self.offset..end];
            match client.send_data(stream_id, chunk) {
                Ok(amount) => {
                    if amount == 0 {
                        break;
                    }
                    self.offset += amount;
                    if self.offset == self.data.len() {
                        client.stream_close_send(stream_id).unwrap();
                    }
                }
                Err(_) => break,
            };
        }
    }
}

struct URLHandler<'a> {
    url_queue: VecDeque<Url>,
    stream_handlers: HashMap<StreamId, Box<dyn StreamHandler>>,
    all_paths: Vec<PathBuf>,
    handler_type: StreamHandlerType,
    args: &'a Args,
}

impl<'a> URLHandler<'a> {
    fn stream_handler(&mut self, stream_id: StreamId) -> Option<&mut Box<dyn StreamHandler>> {
        self.stream_handlers.get_mut(&stream_id)
    }

    fn process_urls(&mut self, client: &mut Http3Client) {
        loop {
            if self.url_queue.is_empty() {
                break;
            }
            if self.stream_handlers.len() >= self.args.concurrency {
                break;
            }
            if !self.next_url(client) {
                break;
            }
        }
    }

    fn next_url(&mut self, client: &mut Http3Client) -> bool {
        let url = self
            .url_queue
            .pop_front()
            .expect("download_next called with empty queue");
        match client.fetch(
            Instant::now(),
            &self.args.method,
            &url,
            &to_headers(&self.args.header),
            Priority::default(),
        ) {
            Ok(client_stream_id) => {
                println!("Successfully created stream id {client_stream_id} for {url}");

                let handler: Box<dyn StreamHandler> = StreamHandlerType::make_handler(
                    &self.handler_type,
                    &url,
                    self.args,
                    &mut self.all_paths,
                    client,
                    client_stream_id,
                );
                self.stream_handlers.insert(client_stream_id, handler);
                true
            }
            Err(
                Error::TransportError(TransportError::StreamLimitError)
                | Error::StreamLimitError
                | Error::Unavailable,
            ) => {
                self.url_queue.push_front(url);
                false
            }
            Err(e) => {
                panic!("Can't create stream {e}");
            }
        }
    }

    fn done(&mut self) -> bool {
        self.stream_handlers.is_empty() && self.url_queue.is_empty()
    }

    fn on_stream_fin(&mut self, client: &mut Http3Client, stream_id: StreamId) -> bool {
        self.stream_handlers.remove(&stream_id);
        self.process_urls(client);
        if self.done() {
            client.close(Instant::now(), 0, "kthxbye!");
            return false;
        }
        true
    }
}

struct Handler<'a> {
    #[allow(
        unknown_lints,
        clippy::struct_field_names,
        clippy::redundant_field_names
    )]
    url_handler: URLHandler<'a>,
    key_update: KeyUpdateState,
    token: Option<ResumptionToken>,
    output_read_data: bool,
}

impl<'a> Handler<'a> {
    pub fn new(
        url_handler: URLHandler<'a>,
        key_update: KeyUpdateState,
        output_read_data: bool,
    ) -> Self {
        Self {
            url_handler,
            key_update,
            token: None,
            output_read_data,
        }
    }

    fn maybe_key_update(&mut self, c: &mut Http3Client) -> Res<()> {
        self.key_update.maybe_update(|| c.initiate_key_update())?;
        self.url_handler.process_urls(c);
        Ok(())
    }

    fn handle(&mut self, client: &mut Http3Client) -> Res<bool> {
        while let Some(event) = client.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    client.authenticated(AuthenticationStatus::Ok, Instant::now());
                }
                Http3ClientEvent::HeaderReady {
                    stream_id,
                    headers,
                    fin,
                    ..
                } => {
                    if let Some(handler) = self.url_handler.stream_handler(stream_id) {
                        handler.process_header_ready(stream_id, fin, headers);
                    } else {
                        println!("Data on unexpected stream: {stream_id}");
                        return Ok(false);
                    }
                    if fin {
                        return Ok(self.url_handler.on_stream_fin(client, stream_id));
                    }
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    let mut stream_done = false;
                    match self.url_handler.stream_handler(stream_id) {
                        None => {
                            println!("Data on unexpected stream: {stream_id}");
                            return Ok(false);
                        }
                        Some(handler) => loop {
                            let mut data = vec![0; 4096];
                            let (sz, fin) = client
                                .read_data(Instant::now(), stream_id, &mut data)
                                .expect("Read should succeed");

                            handler.process_data_readable(
                                stream_id,
                                fin,
                                data,
                                sz,
                                self.output_read_data,
                            )?;

                            if fin {
                                stream_done = true;
                                break;
                            }

                            if sz == 0 {
                                break;
                            }
                        },
                    }

                    if stream_done {
                        return Ok(self.url_handler.on_stream_fin(client, stream_id));
                    }
                }
                Http3ClientEvent::DataWritable { stream_id } => {
                    match self.url_handler.stream_handler(stream_id) {
                        None => {
                            println!("Data on unexpected stream: {stream_id}");
                            return Ok(false);
                        }
                        Some(handler) => {
                            handler.process_data_writable(client, stream_id);
                            return Ok(true);
                        }
                    }
                }
                Http3ClientEvent::StateChange(Http3State::Connected)
                | Http3ClientEvent::RequestsCreatable => {
                    self.url_handler.process_urls(client);
                }
                Http3ClientEvent::ResumptionToken(t) => self.token = Some(t),
                _ => {
                    println!("Unhandled event {event:?}");
                }
            }
        }

        Ok(true)
    }
}

fn to_headers(values: &[impl AsRef<str>]) -> Vec<Header> {
    values
        .iter()
        .scan(None, |state, value| {
            if let Some(name) = state.take() {
                *state = None;
                Some(Header::new(name, value.as_ref()))
            } else {
                *state = Some(value.as_ref().to_string());
                None
            }
        })
        .collect()
}

struct ClientRunner<'a> {
    local_addr: SocketAddr,
    socket: &'a mut udp::Socket,
    client: Http3Client,
    handler: Handler<'a>,
    timeout: Option<Pin<Box<Sleep>>>,
    args: &'a Args,
}

impl<'a> ClientRunner<'a> {
    fn new(
        args: &'a mut Args,
        socket: &'a mut udp::Socket,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        hostname: &str,
        url_queue: VecDeque<Url>,
        resumption_token: Option<ResumptionToken>,
    ) -> ClientRunner<'a> {
        if let Some(testcase) = &args.test {
            if testcase.as_str() != "upload" {
                eprintln!("Unsupported test case: {testcase}");
                exit(127)
            }
        }

        let client = create_http3_client(args, local_addr, remote_addr, hostname, resumption_token)
            .expect("failed to create client");
        if args.test.is_some() {
            args.method = String::from("POST");
        }
        let key_update = KeyUpdateState(args.key_update);
        let url_handler = URLHandler {
            url_queue,
            stream_handlers: HashMap::new(),
            all_paths: Vec::new(),
            handler_type: if args.test.is_some() {
                StreamHandlerType::Upload
            } else {
                StreamHandlerType::Download
            },
            args,
        };
        let handler = Handler::new(url_handler, key_update, args.output_read_data);

        Self {
            local_addr,
            socket,
            client,
            handler,
            timeout: None,
            args,
        }
    }

    async fn run(mut self) -> Res<Option<ResumptionToken>> {
        loop {
            if !self.handler.handle(&mut self.client)? {
                break;
            }

            self.process(None).await?;

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

            if let Http3State::Closed(..) = self.client.state() {
                break;
            }
        }

        let token = if self.args.test.is_none() && self.args.resume {
            // If we haven't received an event, take a token if there is one.
            // Lots of servers don't provide NEW_TOKEN, but a session ticket
            // without NEW_TOKEN is better than nothing.
            self.handler
                .token
                .take()
                .or_else(|| self.client.take_resumption_token(Instant::now()))
        } else {
            None
        };
        Ok(token)
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

fn create_http3_client(
    args: &mut Args,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    hostname: &str,
    resumption_token: Option<ResumptionToken>,
) -> Res<Http3Client> {
    let mut transport = Connection::new_client(
        hostname,
        &[&args.shared.alpn],
        Rc::new(RefCell::new(EmptyConnectionIdGenerator::default())),
        local_addr,
        remote_addr,
        args.shared.quic_parameters.get(args.shared.alpn.as_str()),
        Instant::now(),
    )?;
    let ciphers = args.get_ciphers();
    if !ciphers.is_empty() {
        transport.set_ciphers(&ciphers)?;
    }
    let mut client = Http3Client::new_with_conn(
        transport,
        Http3Parameters::default()
            .max_table_size_encoder(args.shared.max_table_size_encoder)
            .max_table_size_decoder(args.shared.max_table_size_decoder)
            .max_blocked_streams(args.shared.max_blocked_streams)
            .max_concurrent_push_streams(args.max_concurrent_push_streams),
    );

    let qlog = qlog_new(args, hostname, client.connection_id())?;
    client.set_qlog(qlog);
    if let Some(ech) = &args.ech {
        client.enable_ech(ech).expect("enable ECH");
    }
    if let Some(token) = resumption_token {
        client
            .enable_resumption(Instant::now(), token)
            .expect("enable resumption");
    }

    Ok(client)
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

            token = if args.shared.use_old_http {
                old::ClientRunner::new(
                    &args,
                    &mut socket,
                    real_local,
                    remote_addr,
                    &hostname,
                    to_request,
                    token,
                )?
                .run()
                .await?
            } else {
                ClientRunner::new(
                    &mut args,
                    &mut socket,
                    real_local,
                    remote_addr,
                    &hostname,
                    to_request,
                    token,
                )
                .run()
                .await?
            };
        }
    }

    Ok(())
}

mod old {
    use std::{
        cell::RefCell,
        collections::{HashMap, VecDeque},
        fs::File,
        io::{self, Write},
        net::SocketAddr,
        path::PathBuf,
        pin::Pin,
        rc::Rc,
        time::Instant,
    };

    use neqo_common::{event::Provider, qdebug, qinfo, udp, Datagram};
    use neqo_crypto::{AuthenticationStatus, ResumptionToken};
    use neqo_transport::{
        Connection, ConnectionEvent, EmptyConnectionIdGenerator, Error, Output, State, StreamId,
        StreamType,
    };
    use tokio::time::Sleep;
    use url::Url;

    use super::{get_output_file, qlog_new, ready, Args, KeyUpdateState, Ready, Res};

    struct HandlerOld<'b> {
        streams: HashMap<StreamId, Option<File>>,
        url_queue: VecDeque<Url>,
        all_paths: Vec<PathBuf>,
        args: &'b Args,
        token: Option<ResumptionToken>,
        key_update: KeyUpdateState,
    }

    impl<'b> HandlerOld<'b> {
        fn download_urls(&mut self, client: &mut Connection) {
            loop {
                if self.url_queue.is_empty() {
                    break;
                }
                if self.streams.len() >= self.args.concurrency {
                    break;
                }
                if !self.download_next(client) {
                    break;
                }
            }
        }

        fn download_next(&mut self, client: &mut Connection) -> bool {
            if self.key_update.needed() {
                println!("Deferring requests until after first key update");
                return false;
            }
            let url = self
                .url_queue
                .pop_front()
                .expect("download_next called with empty queue");
            match client.stream_create(StreamType::BiDi) {
                Ok(client_stream_id) => {
                    println!("Created stream {client_stream_id} for {url}");
                    let req = format!("GET {}\r\n", url.path());
                    _ = client
                        .stream_send(client_stream_id, req.as_bytes())
                        .unwrap();
                    client.stream_close_send(client_stream_id).unwrap();
                    let out_file =
                        get_output_file(&url, &self.args.output_dir, &mut self.all_paths);
                    self.streams.insert(client_stream_id, out_file);
                    true
                }
                Err(e @ (Error::StreamLimitError | Error::ConnectionState)) => {
                    println!("Cannot create stream {e:?}");
                    self.url_queue.push_front(url);
                    false
                }
                Err(e) => {
                    panic!("Error creating stream {e:?}");
                }
            }
        }

        /// Read and maybe print received data from a stream.
        // Returns bool: was fin received?
        fn read_from_stream(
            client: &mut Connection,
            stream_id: StreamId,
            output_read_data: bool,
            maybe_out_file: &mut Option<File>,
        ) -> Res<bool> {
            let mut data = vec![0; 4096];
            loop {
                let (sz, fin) = client.stream_recv(stream_id, &mut data)?;
                if sz == 0 {
                    return Ok(fin);
                }

                if let Some(out_file) = maybe_out_file {
                    out_file.write_all(&data[..sz])?;
                } else if !output_read_data {
                    println!("READ[{stream_id}]: {sz} bytes");
                } else {
                    println!(
                        "READ[{}]: {}",
                        stream_id,
                        String::from_utf8(data.clone()).unwrap()
                    );
                }
                if fin {
                    return Ok(true);
                }
            }
        }

        fn maybe_key_update(&mut self, c: &mut Connection) -> Res<()> {
            self.key_update.maybe_update(|| c.initiate_key_update())?;
            self.download_urls(c);
            Ok(())
        }

        fn read(&mut self, client: &mut Connection, stream_id: StreamId) -> Res<()> {
            let mut maybe_maybe_out_file = self.streams.get_mut(&stream_id);
            match &mut maybe_maybe_out_file {
                None => {
                    println!("Data on unexpected stream: {stream_id}");
                    return Ok(());
                }
                Some(maybe_out_file) => {
                    let fin_recvd = Self::read_from_stream(
                        client,
                        stream_id,
                        self.args.output_read_data,
                        maybe_out_file,
                    )?;

                    if fin_recvd {
                        if maybe_out_file.is_none() {
                            println!("<FIN[{stream_id}]>");
                        }
                        self.streams.remove(&stream_id);
                        self.download_urls(client);
                    }
                }
            }
            Ok(())
        }

        /// Handle events on the connection.
        ///
        /// Returns `Ok(true)` when done, i.e. url queue is empty and streams are closed.
        fn handle(&mut self, client: &mut Connection) -> Res<bool> {
            while let Some(event) = client.next_event() {
                match event {
                    ConnectionEvent::AuthenticationNeeded => {
                        client.authenticated(AuthenticationStatus::Ok, Instant::now());
                    }
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        self.read(client, stream_id)?;
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        println!("stream {stream_id} writable");
                    }
                    ConnectionEvent::SendStreamComplete { stream_id } => {
                        println!("stream {stream_id} complete");
                    }
                    ConnectionEvent::SendStreamCreatable { stream_type } => {
                        println!("stream {stream_type:?} creatable");
                        if stream_type == StreamType::BiDi {
                            self.download_urls(client);
                        }
                    }
                    ConnectionEvent::StateChange(
                        State::WaitInitial | State::Handshaking | State::Connected,
                    ) => {
                        println!("{event:?}");
                        self.download_urls(client);
                    }
                    ConnectionEvent::StateChange(State::Confirmed) => {
                        self.maybe_key_update(client)?;
                    }
                    ConnectionEvent::ResumptionToken(token) => {
                        self.token = Some(token);
                    }
                    _ => {
                        println!("Unhandled event {event:?}");
                    }
                }
            }

            if self.streams.is_empty() && self.url_queue.is_empty() {
                // Handler is done.
                return Ok(true);
            }

            Ok(false)
        }
    }

    pub struct ClientRunner<'a> {
        local_addr: SocketAddr,
        socket: &'a mut udp::Socket,
        client: Connection,
        handler: HandlerOld<'a>,
        timeout: Option<Pin<Box<Sleep>>>,
        args: &'a Args,
    }

    impl<'a> ClientRunner<'a> {
        pub fn new(
            args: &'a Args,
            socket: &'a mut udp::Socket,
            local_addr: SocketAddr,
            remote_addr: SocketAddr,
            origin: &str,
            url_queue: VecDeque<Url>,
            token: Option<ResumptionToken>,
        ) -> Res<ClientRunner<'a>> {
            let alpn = match args.shared.alpn.as_str() {
                "hq-29" | "hq-30" | "hq-31" | "hq-32" => args.shared.alpn.as_str(),
                _ => "hq-interop",
            };

            let mut client = Connection::new_client(
                origin,
                &[alpn],
                Rc::new(RefCell::new(EmptyConnectionIdGenerator::default())),
                local_addr,
                remote_addr,
                args.shared.quic_parameters.get(alpn),
                Instant::now(),
            )?;

            if let Some(tok) = token {
                client.enable_resumption(Instant::now(), tok)?;
            }

            let ciphers = args.get_ciphers();
            if !ciphers.is_empty() {
                client.set_ciphers(&ciphers)?;
            }

            client.set_qlog(qlog_new(args, origin, client.odcid().unwrap())?);

            let key_update = KeyUpdateState(args.key_update);
            let handler = HandlerOld {
                streams: HashMap::new(),
                url_queue,
                all_paths: Vec::new(),
                args,
                token: None,
                key_update,
            };

            Ok(Self {
                local_addr,
                socket,
                client,
                handler,
                timeout: None,
                args,
            })
        }

        pub async fn run(mut self) -> Res<Option<ResumptionToken>> {
            loop {
                let handler_done = self.handler.handle(&mut self.client)?;

                match (handler_done, self.args.resume, self.handler.token.is_some()) {
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

                if let State::Closed(..) = self.client.state() {
                    return Ok(self.handler.token.take());
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
}
