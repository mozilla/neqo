// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use qlog::QlogStreamer;

use neqo_common::{self as common, hex, matches, qlog::NeqoQlog, Datagram, Role};
use neqo_crypto::{init, AuthenticationStatus};
use neqo_http3::{self, Header, Http3Client, Http3ClientEvent, Http3State, Output};
use neqo_qpack::QpackSettings;
use neqo_transport::FixedConnectionIdManager;

use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
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

type Res<T> = Result<T, ClientError>;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "neqo-client",
    about = "A basic QUIC HTTP/0.9 and HTTP3 client."
)]
pub struct Args {
    #[structopt(short = "a", long, default_value = "h3-27")]
    /// ALPN labels to negotiate.
    ///
    /// This client still only does HTTP3 no matter what the ALPN says.
    alpn: Vec<String>,

    urls: Vec<Url>,

    #[structopt(short = "m", default_value = "GET")]
    method: String,

    #[structopt(short = "h", long, number_of_values = 2)]
    header: Vec<String>,

    #[structopt(name = "encoder-table-size", short = "e", long, default_value = "128")]
    max_table_size_encoder: u64,

    #[structopt(name = "decoder-table-size", short = "d", long, default_value = "128")]
    max_table_size_decoder: u64,

    #[structopt(name = "max-blocked-streams", short = "b", long, default_value = "128")]
    max_blocked_streams: u16,

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

    #[structopt(name = "qns-mode", long)]
    /// Enable special behavior for use with QUIC Network Simulator
    qns_mode: bool,

    #[structopt(short = "r", long)]
    /// Pre-connect to the server and attempt to resume for the test.
    /// Use this for 0-RTT: the stack always attempts 0-RTT on resumption.
    resume: bool,
}

trait Handler {
    fn handle(&mut self, args: &Args, client: &mut Http3Client) -> Res<bool>;
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
    handler: &mut dyn Handler,
    args: &Args,
) -> Res<neqo_http3::Http3State> {
    let buf = &mut [0u8; 2048];
    loop {
        if let Http3State::Closed(..) = client.state() {
            return Ok(client.state());
        }

        let mut exiting = !handler.handle(args, client)?;

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
                }
            }
        };
    }
}

struct PreConnectHandler {}
impl Handler for PreConnectHandler {
    fn handle(&mut self, _args: &Args, client: &mut Http3Client) -> Res<bool> {
        let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
        if client.events().any(authentication_needed) {
            client.authenticated(AuthenticationStatus::Ok, Instant::now());
        }
        // Keep going until we can send a request.
        Ok(!client.state().active())
    }
}

#[derive(Default)]
struct PostConnectHandler {
    streams: HashMap<u64, Option<File>>,
}

// This is a bit fancier than actually needed.
impl Handler for PostConnectHandler {
    fn handle(&mut self, args: &Args, client: &mut Http3Client) -> Res<bool> {
        let mut data = vec![0; 4000];
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
                        Some(out_file) => {
                            let (sz, fin) = client
                                .read_response_data(Instant::now(), stream_id, &mut data)
                                .expect("Read should succeed");

                            if let Some(out_file) = out_file {
                                if sz > 0 {
                                    out_file.write_all(&data[..sz])?;
                                }
                            } else if !args.output_read_data {
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
                            }
                        }
                    }

                    if stream_done {
                        self.streams.remove(&stream_id);
                        if self.streams.is_empty() {
                            client.close(Instant::now(), 0, "kthxbye!");
                            return Ok(false);
                        }
                    }
                }
                Http3ClientEvent::ZeroRttRejected => {
                    self.streams.clear();
                    eprintln!("TODO: resend requests");
                }
                _ => {}
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

fn pre_connect(
    args: &Args,
    socket: &UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    hostname: &str,
) -> Res<Option<Vec<u8>>> {
    let mut client = Http3Client::new(
        hostname,
        &args.alpn,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        local_addr,
        remote_addr,
        QpackSettings {
            max_table_size_encoder: args.max_table_size_encoder,
            max_table_size_decoder: args.max_table_size_decoder,
            max_blocked_streams: args.max_blocked_streams,
        },
    )?;
    let mut handler = PreConnectHandler {};
    process_loop(
        &local_addr,
        &remote_addr,
        socket,
        &mut client,
        &mut handler,
        &args,
    )?;

    let mut handler = PostConnectHandler::default();
    let client_stream_id = client.fetch("OPTIONS", "https", &hostname, "*", &[])?;
    client.stream_close_send(client_stream_id)?;
    handler.streams.insert(client_stream_id, None);

    process_loop(
        &local_addr,
        &remote_addr,
        socket,
        &mut client,
        &mut handler,
        &args,
    )?;

    Ok(client.resumption_token().to_owned())
}

fn client(
    args: &Args,
    socket: UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    hostname: &str,
    urls: &[Url],
) -> Res<()> {
    let resumption_token = if args.resume {
        eprintln!("Pre-connect to {}", hostname);
        pre_connect(args, &socket, local_addr, remote_addr, hostname)?
    } else {
        None
    };

    let mut client = Http3Client::new(
        hostname,
        &args.alpn,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        local_addr,
        remote_addr,
        QpackSettings {
            max_table_size_encoder: args.max_table_size_encoder,
            max_table_size_decoder: args.max_table_size_decoder,
            max_blocked_streams: args.max_blocked_streams,
        },
    )
    .expect("must succeed");
    if let Some(token) = resumption_token {
        eprintln!("Enabling resumption for {}", hostname);
        client.set_resumption_token(Instant::now(), &token)?;
    } else if args.resume {
        eprintln!("Unable to resume");
    }
    client.set_qlog(qlog_new(args, hostname)?);
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    process_loop(
        &local_addr,
        &remote_addr,
        &socket,
        &mut client,
        &mut h,
        &args,
    )?;

    let mut h2 = PostConnectHandler::default();

    let mut open_paths = Vec::new();

    for url in urls {
        let client_stream_id = client.fetch(
            &args.method,
            &url.scheme(),
            &url.host_str().unwrap(),
            &url.path(),
            &to_headers(&args.header),
        )?;
        client.stream_close_send(client_stream_id)?;

        let out_file = get_output_file(url, &args.output_dir, &mut open_paths);
        h2.streams.insert(client_stream_id, out_file);
    }

    process_loop(
        &local_addr,
        &remote_addr,
        &socket,
        &mut client,
        &mut h2,
        &args,
    )?;

    Ok(())
}

fn qlog_new(args: &Args, origin: &str) -> Res<Option<NeqoQlog>> {
    if let Some(qlog_dir) = &args.qlog_dir {
        let mut qlog_path = qlog_dir.to_path_buf();
        qlog_path.push(format!("{}.qlog", origin));

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

        Ok(Some(NeqoQlog::new(streamer, qlog_path)?))
    } else {
        Ok(None)
    }
}

fn main() -> Res<()> {
    init();

    let mut args = Args::from_args();

    if args.qns_mode {
        match env::var("TESTCASE") {
            Ok(s) if s == "http3" => {}
            Ok(s) if s == "handshake" || s == "transfer" => {
                args.use_old_http = true;
            }
            Ok(s) if s == "multiconnect" => {
                args.use_old_http = true;
                args.download_in_series = true;
            }
            Ok(_) => exit(127),
            Err(_) => exit(1),
        }
    }

    let mut urls_by_origin: HashMap<Origin, Vec<Url>> = HashMap::new();
    for url in &args.urls {
        let entry = urls_by_origin.entry(url.origin()).or_default();
        entry.push(url.clone());
    }

    for ((_scheme, host, port), urls) in urls_by_origin.into_iter().filter_map(|(k, v)| match k {
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

        let hostname = format!("{}", host);
        if !args.use_old_http {
            client(&args, socket, local_addr, remote_addr, &hostname, &urls)?;
        } else if !args.download_in_series {
            old::client(&args, &socket, local_addr, remote_addr, &hostname, &urls)?;
        } else {
            for url in urls {
                old::client(&args, &socket, local_addr, remote_addr, &hostname, &[url])?;
            }
        }
    }

    Ok(())
}

mod old {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{ErrorKind, Write};
    use std::net::{SocketAddr, UdpSocket};
    use std::process::exit;
    use std::rc::Rc;
    use std::time::Instant;

    use url::Url;

    use super::{qlog_new, Res};

    use neqo_common::{matches, Datagram};
    use neqo_crypto::AuthenticationStatus;
    use neqo_transport::{
        Connection, ConnectionEvent, FixedConnectionIdManager, Output, State, StreamType,
    };

    use super::{emit_datagram, get_output_file, Args};

    trait HandlerOld {
        fn handle(&mut self, args: &Args, client: &mut Connection) -> Res<bool>;
    }

    struct PreConnectHandlerOld {}
    impl HandlerOld for PreConnectHandlerOld {
        fn handle(&mut self, _args: &Args, client: &mut Connection) -> Res<bool> {
            let authentication_needed = |e| matches!(e, ConnectionEvent::AuthenticationNeeded);
            if client.events().any(authentication_needed) {
                client.authenticated(AuthenticationStatus::Ok, Instant::now());
            }
            Ok(State::Connected != *dbg!(client.state()))
        }
    }

    #[derive(Default)]
    struct PostConnectHandlerOld {
        streams: HashMap<u64, Option<File>>,
    }

    // This is a bit fancier than actually needed.
    impl HandlerOld for PostConnectHandlerOld {
        fn handle(&mut self, args: &Args, client: &mut Connection) -> Res<bool> {
            let mut data = vec![0; 4000];
            while let Some(event) = client.next_event() {
                match event {
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        let out_file = self.streams.get_mut(&stream_id);
                        if out_file.is_none() {
                            println!("Data on unexpected stream: {}", stream_id);
                            return Ok(false);
                        }

                        let (sz, fin) = client
                            .stream_recv(stream_id, &mut data)
                            .expect("Read should succeed");

                        let mut have_out_file = false;
                        if let Some(Some(out_file)) = out_file {
                            have_out_file = true;
                            if sz > 0 {
                                out_file.write_all(&data[..sz])?;
                            }
                        } else if !args.output_read_data {
                            println!("READ[{}]: {} bytes", stream_id, sz);
                        } else {
                            println!(
                                "READ[{}]: {}",
                                stream_id,
                                String::from_utf8(data.clone()).unwrap()
                            )
                        }
                        if fin {
                            if !have_out_file {
                                println!("<FIN[{}]>", stream_id);
                            }
                            self.streams.remove(&stream_id);
                            if self.streams.is_empty() {
                                client.close(Instant::now(), 0, "kthxbye!");
                                return Ok(false);
                            }
                        }
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        println!("stream {} writable", stream_id)
                    }
                    _ => {
                        println!("Unexpected event {:?}", event);
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
        handler: &mut dyn HandlerOld,
        args: &Args,
    ) -> Res<State> {
        let buf = &mut [0u8; 2048];
        loop {
            if let State::Closed(..) = client.state() {
                return Ok(client.state().clone());
            }

            let mut exiting = !handler.handle(args, client)?;

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
            }
        }
    }

    pub fn client(
        args: &Args,
        socket: &UdpSocket,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        origin: &str,
        urls: &[Url],
    ) -> Res<()> {
        let mut open_paths = Vec::new();

        let mut client = Connection::new_client(
            origin,
            &["hq-27"],
            Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
            local_addr,
            remote_addr,
        )
        .expect("must succeed");
        client.set_qlog(qlog_new(args, origin)?);
        // Temporary here to help out the type inference engine
        let mut h = PreConnectHandlerOld {};
        process_loop_old(
            &local_addr,
            &remote_addr,
            &socket,
            &mut client,
            &mut h,
            &args,
        )?;

        let mut h2 = PostConnectHandlerOld::default();

        for url in urls {
            let client_stream_id = client.stream_create(StreamType::BiDi).unwrap();
            let req = format!("GET {}\r\n", url.path());
            client
                .stream_send(client_stream_id, req.as_bytes())
                .unwrap();
            let _ = client.stream_close_send(client_stream_id);
            let out_file = get_output_file(url, &args.output_dir, &mut open_paths);
            h2.streams.insert(client_stream_id, out_file);
        }

        process_loop_old(
            &local_addr,
            &remote_addr,
            &socket,
            &mut client,
            &mut h2,
            &args,
        )?;

        Ok(())
    }
}
