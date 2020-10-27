// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use qlog::QlogStreamer;

use neqo_common::{self as common, event::Provider, hex, qlog::NeqoQlog, Datagram, Role};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init, AuthenticationStatus, Cipher, ResumptionToken,
};
use neqo_http3::{
    self, Error, Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Output,
};
use neqo_qpack::QpackSettings;
use neqo_transport::{
    CongestionControlAlgorithm, Connection, ConnectionId, EmptyConnectionIdGenerator,
    Error as TransportError, QuicVersion,
};

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::time::Instant;

use structopt::StructOpt;
use url::{Origin, Url};

#[derive(Debug)]
pub enum ClientError {
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

#[derive(Debug, StructOpt)]
#[structopt(
    name = "neqo-client",
    about = "A basic QUIC HTTP/0.9 and HTTP/3 client."
)]
pub struct Args {
    #[structopt(short = "a", long, default_value = "h3-29")]
    /// ALPN labels to negotiate.
    ///
    /// This client still only does HTTP/3 no matter what the ALPN says.
    alpn: String,

    urls: Vec<Url>,

    #[structopt(short = "m", default_value = "GET")]
    method: String,

    #[structopt(short = "h", long, number_of_values = 2)]
    header: Vec<String>,

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

    #[structopt(name = "max-blocked-streams", short = "b", long, default_value = "10")]
    max_blocked_streams: u16,

    #[structopt(name = "max-push", short = "p", long, default_value = "10")]
    max_concurrent_push_streams: u64,

    #[structopt(name = "use-old-http", short = "o", long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,

    #[structopt(name = "download-in-series", long)]
    /// Download resources in series using separate connections
    download_in_series: bool,

    #[structopt(name = "output-read-data", long)]
    /// Output received data to stdout
    output_read_data: bool,

    #[structopt(name = "qlog-dir", long)]
    /// Enable QLOG logging and QLOG traces to this directory
    qlog_dir: Option<PathBuf>,

    #[structopt(name = "output-dir", long)]
    /// Save contents of fetched URLs to a directory
    output_dir: Option<PathBuf>,

    #[structopt(name = "qns-test", long)]
    /// Enable special behavior for use with QUIC Network Simulator
    qns_test: Option<String>,

    #[structopt(short = "r", long)]
    /// Client attemps to resume connections when there are multiple connections made.
    /// Use this for 0-RTT: the stack always attempts 0-RTT on resumption.
    resume: bool,

    #[structopt(name = "key-update", long)]
    /// Attempt to initiate a key update immediately after confirming the connection.
    key_update: bool,

    #[structopt(short = "c", long, number_of_values = 1)]
    /// The set of TLS cipher suites to enable.
    /// From: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
    ciphers: Vec<String>,
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
}

fn emit_datagram(socket: &UdpSocket, d: Option<Datagram>) -> io::Result<()> {
    if let Some(d) = d {
        let sent = socket.send(&d[..])?;
        if sent != d.len() {
            eprintln!("Unable to send all {} bytes of datagram", d.len());
        }
    }
    Ok(())
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

        eprintln!("Saving {} to {:?}", url.clone().into_string(), out_path);

        let f = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)
        {
            Err(_) => return None,
            Ok(f) => f,
        };

        all_paths.push(out_path);
        Some(f)
    } else {
        None
    }
}

fn process_loop(
    local_addr: &SocketAddr,
    remote_addr: &SocketAddr,
    socket: &UdpSocket,
    client: &mut Http3Client,
    handler: &mut Handler,
) -> Res<neqo_http3::Http3State> {
    let buf = &mut [0u8; 2048];
    loop {
        if let Http3State::Closed(..) = client.state() {
            return Ok(client.state());
        }

        let mut exiting = !handler.handle(client)?;

        loop {
            let output = client.process_output(Instant::now());
            match output {
                Output::Datagram(dgram) => {
                    if let Err(e) = emit_datagram(&socket, Some(dgram)) {
                        eprintln!("UDP write error: {}", e);
                        client.close(Instant::now(), 0, e.to_string());
                        exiting = true;
                        break;
                    }
                }
                Output::Callback(duration) => {
                    socket.set_read_timeout(Some(duration)).unwrap();
                    break;
                }
                Output::None => {
                    // Not strictly necessary, since we're about to exit
                    socket.set_read_timeout(None).unwrap();
                    exiting = true;
                    break;
                }
            }
        }

        if exiting {
            return Ok(client.state());
        }

        match socket.recv(&mut buf[..]) {
            Err(ref err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::Interrupted => {}
            Err(err) => {
                eprintln!("UDP error: {}", err);
                exit(1)
            }
            Ok(sz) => {
                if sz == buf.len() {
                    eprintln!("Received more than {} bytes", buf.len());
                    continue;
                }
                if sz > 0 {
                    let d = Datagram::new(*remote_addr, *local_addr, &buf[..sz]);
                    client.process_input(d, Instant::now());
                    handler.maybe_key_update(client)?;
                }
            }
        };
    }
}

struct Handler<'a> {
    streams: HashMap<u64, Option<File>>,
    url_queue: VecDeque<Url>,
    all_paths: Vec<PathBuf>,
    args: &'a Args,
    key_update: KeyUpdateState,
}

impl<'a> Handler<'a> {
    fn download_urls(&mut self, client: &mut Http3Client) {
        loop {
            if self.url_queue.is_empty() {
                break;
            }
            if !self.download_next(client) {
                break;
            }
        }
    }

    fn download_next(&mut self, client: &mut Http3Client) -> bool {
        if self.key_update.needed() {
            println!("Deferring requests until first key update");
            return false;
        }
        let url = self
            .url_queue
            .pop_front()
            .expect("download_next called with empty queue");
        match client.fetch(
            Instant::now(),
            &self.args.method,
            &url.scheme(),
            &url.host_str().unwrap(),
            &url.path(),
            &to_headers(&self.args.header),
        ) {
            Ok(client_stream_id) => {
                println!(
                    "Successfully created stream id {} for {}",
                    client_stream_id, url
                );
                let _ = client.stream_close_send(client_stream_id);

                let out_file = get_output_file(&url, &self.args.output_dir, &mut self.all_paths);

                self.streams.insert(client_stream_id, out_file);
                true
            }
            e @ Err(Error::TransportError(TransportError::StreamLimitError))
            | e @ Err(Error::StreamLimitError)
            | e @ Err(Error::Unavailable) => {
                println!("Cannot create stream {:?}", e);
                self.url_queue.push_front(url);
                false
            }
            Err(e) => {
                panic!("Can't create stream {}", e);
            }
        }
    }

    fn maybe_key_update(&mut self, c: &mut Http3Client) -> Res<()> {
        self.key_update.maybe_update(|| c.initiate_key_update())?;
        self.download_urls(c);
        Ok(())
    }

    fn done(&mut self) -> bool {
        self.streams.is_empty() && self.url_queue.is_empty()
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
                } => match self.streams.get(&stream_id) {
                    Some(out_file) => {
                        if out_file.is_none() {
                            println!("READ HEADERS[{}]: fin={} {:?}", stream_id, fin, headers);
                        }
                    }
                    None => {
                        println!("Data on unexpected stream: {}", stream_id);
                        return Ok(false);
                    }
                },
                Http3ClientEvent::DataReadable { stream_id } => {
                    let mut stream_done = false;
                    match self.streams.get_mut(&stream_id) {
                        None => {
                            println!("Data on unexpected stream: {}", stream_id);
                            return Ok(false);
                        }
                        Some(out_file) => loop {
                            let mut data = vec![0; 4096];
                            let (sz, fin) = client
                                .read_response_data(Instant::now(), stream_id, &mut data)
                                .expect("Read should succeed");

                            if let Some(out_file) = out_file {
                                if sz > 0 {
                                    out_file.write_all(&data[..sz])?;
                                }
                            } else if !self.args.output_read_data {
                                println!("READ[{}]: {} bytes", stream_id, sz);
                            } else if let Ok(txt) = String::from_utf8(data.clone()) {
                                println!("READ[{}]: {}", stream_id, txt);
                            } else {
                                println!("READ[{}]: 0x{}", stream_id, hex(&data));
                            }

                            if fin {
                                if out_file.is_none() {
                                    println!("<FIN[{}]>", stream_id);
                                }
                                stream_done = true;
                                break;
                            }

                            if sz == 0 {
                                break;
                            }
                        },
                    }

                    if stream_done {
                        self.streams.remove(&stream_id);
                        if self.done() {
                            client.close(Instant::now(), 0, "kthxbye!");
                            return Ok(false);
                        }
                    }
                }
                Http3ClientEvent::StateChange(Http3State::Connected)
                | Http3ClientEvent::RequestsCreatable => {
                    self.download_urls(client);
                }
                _ => {
                    println!("Unhandled event {:?}", event);
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
                Some((name, value.as_ref().to_string())) // TODO use a real type
            } else {
                *state = Some(value.as_ref().to_string());
                None
            }
        })
        .collect()
}

fn client(
    args: &Args,
    socket: UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    hostname: &str,
    urls: &[Url],
) -> Res<()> {
    let quic_protocol = match args.alpn.as_str() {
        "h3-27" => QuicVersion::Draft27,
        "h3-28" => QuicVersion::Draft28,
        "h3-29" => QuicVersion::Draft29,
        "h3-30" => QuicVersion::Draft30,
        _ => QuicVersion::default(),
    };

    let mut transport = Connection::new_client(
        hostname,
        &[&args.alpn],
        Rc::new(RefCell::new(EmptyConnectionIdGenerator::default())),
        local_addr,
        remote_addr,
        &CongestionControlAlgorithm::NewReno,
        quic_protocol,
    )?;
    let ciphers = args.get_ciphers();
    if !ciphers.is_empty() {
        transport.set_ciphers(&ciphers)?;
    }
    let mut client = Http3Client::new_with_conn(
        transport,
        &Http3Parameters {
            qpack_settings: QpackSettings {
                max_table_size_encoder: args.max_table_size_encoder,
                max_table_size_decoder: args.max_table_size_decoder,
                max_blocked_streams: args.max_blocked_streams,
            },
            max_concurrent_push_streams: args.max_concurrent_push_streams,
        },
    );

    let qlog = qlog_new(args, hostname, client.connection_id())?;
    client.set_qlog(qlog);

    let key_update = KeyUpdateState(args.key_update);
    let mut h = Handler {
        streams: HashMap::new(),
        url_queue: VecDeque::from(urls.to_vec()),
        all_paths: Vec::new(),
        args: &args,
        key_update,
    };

    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h)?;

    Ok(())
}

fn qlog_new(args: &Args, hostname: &str, cid: &ConnectionId) -> Res<NeqoQlog> {
    if let Some(qlog_dir) = &args.qlog_dir {
        let mut qlog_path = qlog_dir.to_path_buf();
        let filename = format!("{}-{}.qlog", hostname, cid);
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
            Box::new(f),
        );

        Ok(NeqoQlog::enabled(streamer, qlog_path)?)
    } else {
        Ok(NeqoQlog::disabled())
    }
}

fn main() -> Res<()> {
    init();

    let mut args = Args::from_args();

    if let Some(testcase) = args.qns_test.as_ref() {
        match testcase.as_str() {
            "http3" => {}
            "handshake" | "transfer" | "retry" => {
                args.use_old_http = true;
            }
            "zerortt" | "resumption" => {
                if args.urls.len() < 2 {
                    eprintln!("Warning: resumption tests won't work without >1 URL");
                    exit(127);
                }
                args.use_old_http = true;
                args.resume = true;
            }
            "multiconnect" => {
                args.use_old_http = true;
                args.download_in_series = true;
            }
            "chacha20" => {
                args.use_old_http = true;
                args.ciphers.clear();
                args.ciphers
                    .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
            }
            "keyupdate" => {
                args.use_old_http = true;
                args.key_update = true;
            }
            _ => exit(127),
        }
    }

    let mut urls_by_origin: HashMap<Origin, Vec<Url>> = HashMap::new();
    for url in &args.urls {
        let entry = urls_by_origin.entry(url.origin()).or_default();
        entry.push(url.clone());
    }

    for ((_scheme, host, port), mut urls) in urls_by_origin.into_iter().filter_map(|(k, v)| match k
    {
        Origin::Tuple(s, h, p) => Some(((s, h, p), v)),
        Origin::Opaque(x) => {
            eprintln!("Opaque origin {:?}", x);
            None
        }
    }) {
        let addrs: Vec<_> = format!("{}:{}", host, port).to_socket_addrs()?.collect();
        let remote_addr = *addrs.first().unwrap();

        let local_addr = match remote_addr {
            SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
            SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0),
        };

        let socket = match UdpSocket::bind(local_addr) {
            Err(e) => {
                eprintln!("Unable to bind UDP socket: {}", e);
                exit(1)
            }
            Ok(s) => s,
        };
        socket
            .connect(&remote_addr)
            .expect("Unable to connect UDP socket");

        println!(
            "{} Client connecting: {:?} -> {:?}",
            if args.use_old_http { "H9" } else { "H3" },
            socket.local_addr().unwrap(),
            remote_addr
        );

        if !args.use_old_http {
            client(
                &args,
                socket,
                local_addr,
                remote_addr,
                &format!("{}", host),
                &urls,
            )?;
        } else if !args.download_in_series {
            let token = if args.resume {
                // Download first URL using a separate connection, save the token and use it for
                // the remaining URLs
                if urls.len() < 2 {
                    eprintln!("Warning: resumption tests won't work without >1 URL");
                    exit(127)
                }

                let first_url = urls.remove(0);

                old::old_client(
                    &args,
                    &socket,
                    local_addr,
                    remote_addr,
                    &format!("{}", host),
                    &[first_url],
                    None,
                )?
            } else {
                None
            };

            old::old_client(
                &args,
                &socket,
                local_addr,
                remote_addr,
                &format!("{}", host),
                &urls,
                token,
            )?;
        } else {
            let mut token: Option<ResumptionToken> = None;

            for url in urls {
                token = old::old_client(
                    &args,
                    &socket,
                    local_addr,
                    remote_addr,
                    &format!("{}", host),
                    &[url],
                    token,
                )?;
            }
        }
    }

    Ok(())
}

mod old {
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::fs::File;
    use std::io::{ErrorKind, Write};
    use std::net::{SocketAddr, UdpSocket};
    use std::path::PathBuf;
    use std::process::exit;
    use std::rc::Rc;
    use std::time::Instant;

    use url::Url;

    use super::{qlog_new, KeyUpdateState, Res};

    use neqo_common::{event::Provider, Datagram};
    use neqo_crypto::{AuthenticationStatus, ResumptionToken};
    use neqo_transport::{
        CongestionControlAlgorithm, Connection, ConnectionEvent, EmptyConnectionIdGenerator, Error,
        Output, QuicVersion, State, StreamType,
    };

    use super::{emit_datagram, get_output_file, Args};

    struct HandlerOld<'b> {
        streams: HashMap<u64, Option<File>>,
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
                    println!("Created stream {} for {}", client_stream_id, url);
                    let req = format!("GET {}\r\n", url.path());
                    client
                        .stream_send(client_stream_id, req.as_bytes())
                        .unwrap();
                    let _ = client.stream_close_send(client_stream_id);
                    let out_file =
                        get_output_file(&url, &self.args.output_dir, &mut self.all_paths);
                    self.streams.insert(client_stream_id, out_file);
                    true
                }
                Err(e @ Error::StreamLimitError) | Err(e @ Error::ConnectionState) => {
                    println!("Cannot create stream {:?}", e);
                    self.url_queue.push_front(url);
                    false
                }
                Err(e) => {
                    panic!("Error creating stream {:?}", e);
                }
            }
        }

        /// Read and maybe print received data from a stream.
        // Returns bool: was fin received?
        fn read_from_stream(
            client: &mut Connection,
            stream_id: u64,
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
                    println!("READ[{}]: {} bytes", stream_id, sz);
                } else {
                    println!(
                        "READ[{}]: {}",
                        stream_id,
                        String::from_utf8(data.clone()).unwrap()
                    )
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

        fn handle(&mut self, client: &mut Connection) -> Res<bool> {
            while let Some(event) = client.next_event() {
                match event {
                    ConnectionEvent::AuthenticationNeeded => {
                        client.authenticated(AuthenticationStatus::Ok, Instant::now());
                    }
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        let mut maybe_maybe_out_file = self.streams.get_mut(&stream_id);
                        match &mut maybe_maybe_out_file {
                            None => {
                                println!("Data on unexpected stream: {}", stream_id);
                                return Ok(false);
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
                                        println!("<FIN[{}]>", stream_id);
                                    }
                                    self.streams.remove(&stream_id);
                                    if self.streams.is_empty() && self.url_queue.is_empty() {
                                        client.close(Instant::now(), 0, "kthxbye!");
                                        return Ok(false);
                                    }
                                }
                            }
                        }
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        println!("stream {} writable", stream_id)
                    }
                    ConnectionEvent::SendStreamComplete { stream_id } => {
                        println!("stream {} complete", stream_id);
                    }
                    ConnectionEvent::SendStreamCreatable { stream_type } => {
                        println!("stream {:?} creatable", stream_type);
                        if stream_type == StreamType::BiDi {
                            self.download_urls(client);
                        }
                    }
                    ConnectionEvent::StateChange(State::WaitInitial)
                    | ConnectionEvent::StateChange(State::Handshaking)
                    | ConnectionEvent::StateChange(State::Connected) => {
                        println!("{:?}", event);
                        self.download_urls(client);
                    }
                    ConnectionEvent::StateChange(State::Confirmed) => {
                        self.maybe_key_update(client)?;
                    }
                    ConnectionEvent::ResumptionToken(token) => {
                        self.token = Some(token);
                    }
                    _ => {
                        println!("Unhandled event {:?}", event);
                    }
                }
            }

            Ok(true)
        }
    }

    fn process_loop_old(
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        socket: &UdpSocket,
        client: &mut Connection,
        handler: &mut HandlerOld,
    ) -> Res<State> {
        let buf = &mut [0u8; 2048];
        loop {
            if let State::Closed(..) = client.state() {
                return Ok(client.state().clone());
            }

            let mut exiting = !handler.handle(client)?;

            loop {
                let output = client.process_output(Instant::now());
                match output {
                    Output::Datagram(dgram) => {
                        if let Err(e) = emit_datagram(&socket, Some(dgram)) {
                            eprintln!("UDP write error: {}", e);
                            client.close(Instant::now(), 0, e.to_string());
                            exiting = true;
                            break;
                        }
                    }
                    Output::Callback(duration) => {
                        socket.set_read_timeout(Some(duration)).unwrap();
                        break;
                    }
                    Output::None => {
                        // Not strictly necessary, since we're about to exit
                        socket.set_read_timeout(None).unwrap();
                        exiting = true;
                        break;
                    }
                }
            }

            if exiting {
                return Ok(client.state().clone());
            }

            let sz = match socket.recv(&mut buf[..]) {
                Err(ref err)
                    if err.kind() == ErrorKind::WouldBlock
                        || err.kind() == ErrorKind::Interrupted =>
                {
                    0
                }
                Err(err) => {
                    eprintln!("UDP error: {}", err);
                    exit(1)
                }
                Ok(sz) => sz,
            };
            if sz == buf.len() {
                eprintln!("Received more than {} bytes", buf.len());
                continue;
            }
            if sz > 0 {
                let d = Datagram::new(*remote_addr, *local_addr, &buf[..sz]);
                client.process_input(d, Instant::now());
                handler.maybe_key_update(client)?;
            }
        }
    }

    pub fn old_client(
        args: &Args,
        socket: &UdpSocket,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        origin: &str,
        urls: &[Url],
        token: Option<ResumptionToken>,
    ) -> Res<Option<ResumptionToken>> {
        let (quic_protocol, alpn) = match args.alpn.as_str() {
            "hq-27" => (QuicVersion::Draft27, "hq-27"),
            "hq-28" => (QuicVersion::Draft28, "hq-28"),
            "hq-30" => (QuicVersion::Draft30, "hq-30"),
            _ => (QuicVersion::Draft29, "hq-29"),
        };

        let mut client = Connection::new_client(
            origin,
            &[alpn],
            Rc::new(RefCell::new(EmptyConnectionIdGenerator::default())),
            local_addr,
            remote_addr,
            &CongestionControlAlgorithm::NewReno,
            quic_protocol,
        )?;

        if let Some(tok) = token {
            client.enable_resumption(Instant::now(), tok)?;
        }

        let ciphers = args.get_ciphers();
        if !ciphers.is_empty() {
            client.set_ciphers(&ciphers)?;
        }

        client.set_qlog(qlog_new(args, origin, &client.odcid().unwrap())?);

        let key_update = KeyUpdateState(args.key_update);
        let mut h = HandlerOld {
            streams: HashMap::new(),
            url_queue: VecDeque::from(urls.to_vec()),
            all_paths: Vec::new(),
            args: &args,
            token: None,
            key_update,
        };

        process_loop_old(&local_addr, &remote_addr, &socket, &mut client, &mut h)?;

        let token = if args.resume {
            // If we haven't received an event, take a token if there is one.
            // Lots of servers don't provide NEW_TOKEN, but a session ticket
            // without NEW_TOKEN is better than nothing.
            h.token
                .or_else(|| client.take_resumption_token(Instant::now()))
        } else {
            None
        };
        Ok(token)
    }
}
