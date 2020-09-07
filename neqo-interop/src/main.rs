// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use neqo_common::{hex, Datagram};
use neqo_crypto::{init, AuthenticationStatus};
use neqo_http3::{Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3State};
use neqo_qpack::QpackSettings;
use neqo_transport::{
    Connection, ConnectionError, ConnectionEvent, Error, FixedConnectionIdManager, Output,
    QuicVersion, State, StreamType,
};

use std::cell::RefCell;
use std::cmp::min;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::rc::Rc;
// use std::path::PathBuf;
use std::str::FromStr;
use std::string::ParseError;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use structopt::StructOpt;
#[macro_use]
extern crate lazy_static;

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "neqo-interop", about = "A QUIC interop client.")]
struct Args {
    #[structopt(short = "p", long)]
    // Peers to include
    include: Vec<String>,

    #[structopt(short = "P", long)]
    exclude: Vec<String>,

    #[structopt(short = "t", long)]
    include_tests: Vec<String>,

    #[structopt(short = "T", long)]
    exclude_tests: Vec<String>,

    #[structopt(long, default_value = "5")]
    timeout: u64,
}

trait Handler {
    fn handle(&mut self, client: &mut Connection) -> bool;
    fn rewrite_out(&mut self, _dgram: &Datagram) -> Option<Datagram> {
        None
    }
}

fn emit_datagram(socket: &UdpSocket, d: Datagram) {
    let sent = socket.send(&d[..]).expect("Error sending datagram");
    if sent != d.len() {
        eprintln!("Unable to send all {} bytes of datagram", d.len());
    }
}

lazy_static! {
    static ref TEST_TIMEOUT: Mutex<Duration> = Mutex::new(Duration::from_secs(5));
}

struct Timer {
    end: Instant,
}
impl Timer {
    pub fn new() -> Self {
        Self {
            end: Instant::now() + *TEST_TIMEOUT.lock().unwrap(),
        }
    }

    pub fn set_timeout(t: Duration) {
        *TEST_TIMEOUT.lock().unwrap() = t;
    }

    pub fn check(&self) -> Result<Duration, String> {
        if let Some(d) = self.end.checked_duration_since(Instant::now()) {
            if d.as_nanos() > 0 {
                Ok(d)
            } else {
                Err(String::from("Timed out"))
            }
        } else {
            Err(String::from("Timed out"))
        }
    }
}

fn process_loop(
    nctx: &NetworkCtx,
    client: &mut Connection,
    handler: &mut dyn Handler,
) -> Result<State, String> {
    let buf = &mut [0u8; 2048];
    let timer = Timer::new();

    loop {
        if let State::Closed(..) = client.state() {
            return Ok(client.state().clone());
        }

        loop {
            let output = client.process_output(Instant::now());
            match output {
                Output::Datagram(dgram) => {
                    let dgram = handler.rewrite_out(&dgram).unwrap_or(dgram);
                    emit_datagram(&nctx.socket, dgram);
                }
                Output::Callback(duration) => {
                    let delay = min(timer.check()?, duration);
                    nctx.socket.set_read_timeout(Some(delay)).unwrap();
                    break;
                }
                Output::None => {
                    return Ok(client.state().clone());
                }
            }
        }

        if !handler.handle(client) {
            return Ok(client.state().clone());
        }

        let sz = match nctx.socket.recv(&mut buf[..]) {
            Ok(sz) => sz,
            Err(e) => {
                return Err(String::from(match e.kind() {
                    std::io::ErrorKind::WouldBlock => continue,
                    _ => "Read error",
                }));
            }
        };

        if sz == buf.len() {
            eprintln!("Received more than {} bytes", buf.len());
            continue;
        }
        if sz > 0 {
            let received = Datagram::new(nctx.remote_addr, nctx.local_addr, &buf[..sz]);
            client.process_input(received, Instant::now());
        }
    }
}

struct PreConnectHandler {}
impl Handler for PreConnectHandler {
    fn handle(&mut self, client: &mut Connection) -> bool {
        let authentication_needed = |e| matches!(e, ConnectionEvent::AuthenticationNeeded);
        if client.events().any(authentication_needed) {
            client.authenticated(AuthenticationStatus::Ok, Instant::now());
        }
        match client.state() {
            State::Connected => false,
            State::Closing { .. } => false,
            _ => true,
        }
    }
}

// HTTP/0.9 IMPLEMENTATION
#[derive(Default)]
struct H9Handler {
    rbytes: usize,
    rsfin: bool,
    streams: HashSet<u64>,
}

// This is a bit fancier than actually needed.
impl Handler for H9Handler {
    fn handle(&mut self, client: &mut Connection) -> bool {
        let mut data = vec![0; 4000];
        while let Some(event) = client.next_event() {
            eprintln!("Event: {:?}", event);
            match event {
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    if !self.streams.contains(&stream_id) {
                        eprintln!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let (sz, fin) = client
                        .stream_recv(stream_id, &mut data)
                        .expect("Read should succeed");
                    data.truncate(sz);
                    eprintln!("Length={}", sz);
                    self.rbytes += sz;
                    if fin {
                        eprintln!("<FIN[{}]>", stream_id);
                        client.close(Instant::now(), 0, "kthxbye!");
                        self.rsfin = true;
                        return false;
                    }
                }
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    eprintln!("stream {} writable", stream_id)
                }
                _ => {
                    eprintln!("Unexpected event {:?}", event);
                }
            }
        }

        true
    }
}

// HTTP/3 IMPLEMENTATION
#[derive(Debug)]
struct Headers {
    pub h: Vec<Header>,
}

// dragana: this is a very stupid parser.
// headers should be in form "[(something1, something2), (something3, something4)]"
impl FromStr for Headers {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = Self { h: Vec::new() };
        let h1: Vec<&str> = s
            .trim_matches(|p| p == '[' || p == ']')
            .split(')')
            .collect();

        for h in h1 {
            let h2: Vec<&str> = h
                .trim_matches(|p| p == ',')
                .trim()
                .trim_matches(|p| p == '(' || p == ')')
                .split(',')
                .collect();

            if h2.len() == 2 {
                res.h
                    .push((h2[0].trim().to_string(), h2[1].trim().to_string()));
            }
        }

        Ok(res)
    }
}

struct H3Handler {
    streams: HashSet<u64>,
    h3: Http3Client,
    host: String,
    path: String,
}

// TODO(ekr@rtfm.com): Figure out how to merge this.
fn process_loop_h3(
    nctx: &NetworkCtx,
    handler: &mut H3Handler,
    connect: bool,
    close: bool,
) -> Result<State, String> {
    let buf = &mut [0u8; 2048];
    let timer = Timer::new();

    loop {
        if let State::Closed(..) = handler.h3.conn().state() {
            return Ok(handler.h3.conn().state().clone());
        }

        if connect {
            if let Http3State::Connected = handler.h3.state() {
                return Ok(handler.h3.conn().state().clone());
            }
        }

        loop {
            let output = handler.h3.conn().process_output(Instant::now());
            match output {
                Output::Datagram(dgram) => emit_datagram(&nctx.socket, dgram),
                Output::Callback(duration) => {
                    let delay = min(timer.check()?, duration);
                    nctx.socket.set_read_timeout(Some(delay)).unwrap();
                    break;
                }
                Output::None => {
                    return Ok(handler.h3.conn().state().clone());
                }
            }
        }
        if !handler.handle(close) {
            return Ok(handler.h3.conn().state().clone());
        }

        let sz = match nctx.socket.recv(&mut buf[..]) {
            Ok(sz) => sz,
            Err(e) => {
                return Err(String::from(match e.kind() {
                    std::io::ErrorKind::WouldBlock => continue,
                    _ => "Read error",
                }));
            }
        };

        if sz == buf.len() {
            eprintln!("Received more than {} bytes", buf.len());
            continue;
        }
        if sz > 0 {
            let received = Datagram::new(nctx.remote_addr, nctx.local_addr, &buf[..sz]);
            handler.h3.process_input(received, Instant::now());
        }
    }
}

// This is a bit fancier than actually needed.
impl H3Handler {
    fn handle(&mut self, close: bool) -> bool {
        let mut data = vec![0; 4000];
        while let Some(event) = self.h3.next_event() {
            match event {
                Http3ClientEvent::HeaderReady {
                    stream_id,
                    headers,
                    fin,
                } => {
                    if !self.streams.contains(&stream_id) {
                        eprintln!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    eprintln!("READ HEADERS[{}]: fin={} {:?}", stream_id, fin, headers);
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    if !self.streams.contains(&stream_id) {
                        eprintln!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let (_sz, fin) = self
                        .h3
                        .read_response_data(Instant::now(), stream_id, &mut data)
                        .expect("Read should succeed");
                    if let Ok(txt) = String::from_utf8(data.clone()) {
                        eprintln!("READ[{}]: {}", stream_id, txt);
                    } else {
                        eprintln!("READ[{}]: 0x{}", stream_id, hex(&data));
                    }
                    if fin {
                        eprintln!("<FIN[{}]>", stream_id);
                        if close {
                            self.h3.close(Instant::now(), 0, "kthxbye!");
                        }
                        return false;
                    }
                }
                _ => {}
            }
        }

        true
    }
}

struct Peer {
    label: &'static str,
    host: &'static str,
    port: u16,
}

impl Peer {
    fn addr(&self) -> SocketAddr {
        self.to_socket_addrs()
            .expect("Remote address error")
            .next()
            .expect("No remote addresses")
    }

    fn bind(&self) -> SocketAddr {
        match self.addr() {
            SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
            SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0),
        }
    }

    fn test_enabled(&self, _test: &Test) -> bool {
        true
    }
}

impl ToSocketAddrs for Peer {
    type Iter = ::std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        // This is idiotic.  There is no path from hostname: String to IpAddr.
        // And no means of controlling name resolution either.
        std::fmt::format(format_args!("{}:{}", self.host, self.port)).to_socket_addrs()
    }
}

#[derive(Debug, PartialEq)]
enum Test {
    Connect,
    H9,
    H3,
    VN,
    R,
    Z,
    D,
}

impl Test {
    fn alpn(&self) -> Vec<String> {
        match self {
            Self::H3 | Self::R | Self::Z | Self::D => vec![String::from("h3-28")],
            _ => vec![String::from("hq-28")],
        }
    }

    fn label(&self) -> String {
        String::from(match self {
            Self::Connect => "connect",
            Self::H9 => "h9",
            Self::H3 => "h3",
            Self::VN => "vn",
            Self::R => "r",
            Self::Z => "z",
            Self::D => "d",
        })
    }

    fn letters(&self) -> Vec<char> {
        match self {
            Self::Connect => vec!['H'],
            Self::H9 => vec!['D', 'C'],
            Self::H3 => vec!['3', 'C', 'D'],
            Self::VN => vec!['V'],
            Self::R => vec!['R'],
            Self::Z => vec!['Z'],
            Self::D => vec!['d'],
        }
    }
}

struct NetworkCtx {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    socket: UdpSocket,
}

fn test_connect(nctx: &NetworkCtx, test: &Test, peer: &Peer) -> Result<Connection, String> {
    let mut client = Connection::new_client(
        peer.host,
        &test.alpn(),
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        nctx.local_addr,
        nctx.remote_addr,
        QuicVersion::default(),
    )
    .expect("must succeed");
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    let res = process_loop(nctx, &mut client, &mut h);

    let st = match res {
        Ok(st) => st,
        Err(e) => {
            return Err(format!("ERROR: {}", e));
        }
    };

    if st.connected() {
        Ok(client)
    } else {
        Err(format!("{:?}", st))
    }
}

fn test_h9(nctx: &NetworkCtx, client: &mut Connection) -> Result<(), String> {
    let client_stream_id = client.stream_create(StreamType::BiDi).unwrap();
    let req: String = "GET /10\r\n".to_string();
    client
        .stream_send(client_stream_id, req.as_bytes())
        .unwrap();
    let mut hc = H9Handler::default();
    hc.streams.insert(client_stream_id);
    let res = process_loop(nctx, client, &mut hc);

    if let Err(e) = res {
        return Err(format!("ERROR: {}", e));
    }
    if hc.rbytes == 0 {
        return Err(String::from("Empty response"));
    }
    if !hc.rsfin {
        return Err(String::from("No FIN"));
    }
    Ok(())
}

fn connect_h3(nctx: &NetworkCtx, peer: &Peer, client: Connection) -> Result<H3Handler, String> {
    let mut hc = H3Handler {
        streams: HashSet::new(),
        h3: Http3Client::new_with_conn(
            client,
            &Http3Parameters {
                qpack_settings: QpackSettings {
                    max_table_size_encoder: 16384,
                    max_table_size_decoder: 16384,
                    max_blocked_streams: 10,
                },
                max_concurrent_push_streams: 10,
            },
        ),
        host: String::from(peer.host),
        path: String::from("/"),
    };

    if let Err(e) = process_loop_h3(nctx, &mut hc, true, false) {
        return Err(format!("ERROR: {}", e));
    }
    Ok(hc)
}

fn test_h3(nctx: &NetworkCtx, peer: &Peer, client: Connection, test: &Test) -> Result<(), String> {
    let mut hc = connect_h3(nctx, peer, client)?;

    let client_stream_id = hc
        .h3
        .fetch(Instant::now(), "GET", "https", &hc.host, &hc.path, &[])
        .unwrap();
    let _ = hc.h3.stream_close_send(client_stream_id);

    hc.streams.insert(client_stream_id);
    if let Err(e) = process_loop_h3(nctx, &mut hc, false, *test != Test::D) {
        return Err(format!("ERROR: {}", e));
    }

    if *test == Test::D {
        // Send another request, when the first one was send we probably did not have the peer's qpack parameter.
        let client_stream_id = hc
            .h3
            .fetch(
                Instant::now(),
                "GET",
                "https",
                &hc.host,
                &hc.path,
                &[(String::from("something1"), String::from("something2"))],
            )
            .unwrap();
        let _ = hc.h3.stream_close_send(client_stream_id);
        hc.streams.insert(client_stream_id);
        if let Err(e) = process_loop_h3(nctx, &mut hc, false, true) {
            return Err(format!("ERROR: {}", e));
        }

        if hc.h3.qpack_decoder_stats().dynamic_table_references == 0 {
            return Err("ERROR: qpack decoder does not use the dynamic table.".into());
        }
        if hc.h3.qpack_encoder_stats().dynamic_table_references == 0 {
            return Err("ERROR: qpack encoder does not use the dynamic table.".into());
        }
    }

    Ok(())
}

// Return true if 0RTT was negotiated.
fn test_h3_rz(
    nctx: &NetworkCtx,
    peer: &Peer,
    client: Connection,
    test: &Test,
) -> Result<(), String> {
    let mut hc = connect_h3(nctx, peer, client)?;

    // Exchange some data to get http3 control streams and a resumption token.
    let client_stream_id = hc
        .h3
        .fetch(Instant::now(), "GET", "https", &hc.host, &hc.path, &[])
        .unwrap();
    let _ = hc.h3.stream_close_send(client_stream_id);

    hc.streams.insert(client_stream_id);
    if let Err(e) = process_loop_h3(nctx, &mut hc, false, true) {
        return Err(format!("ERROR: {}", e));
    }

    // get resumption ticket
    let res_token = hc
        .h3
        .resumption_token()
        .ok_or("ERROR: no resumption token")?;

    let handler = Http3Client::new(
        peer.host,
        &test.alpn(),
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        nctx.local_addr,
        nctx.remote_addr,
        QuicVersion::default(),
        &Http3Parameters {
            qpack_settings: QpackSettings {
                max_table_size_encoder: 16384,
                max_table_size_decoder: 16384,
                max_blocked_streams: 10,
            },
            max_concurrent_push_streams: 0,
        },
    );
    if handler.is_err() {
        return Err(String::from("ERROR: creating a client failed"));
    }

    let mut hc = H3Handler {
        streams: HashSet::new(),
        h3: handler.unwrap(),
        host: String::from(peer.host),
        path: String::from("/"),
    };

    hc.h3.enable_resumption(Instant::now(), &res_token).unwrap();

    if *test == Test::Z {
        println!("Test 0RTT");
        if Http3State::ZeroRtt != hc.h3.state() {
            return Err("ERROR: zerortt not negotiated".into());
        }

        // SendH3 data during 0rtt
        let client_stream_id = hc
            .h3
            .fetch(Instant::now(), "GET", "https", &hc.host, &hc.path, &[])
            .unwrap();
        let _ = hc.h3.stream_close_send(client_stream_id);
        hc.streams.insert(client_stream_id);
        if let Err(e) = process_loop_h3(nctx, &mut hc, false, true) {
            return Err(format!("ERROR: {}", e));
        }

        let recvd_0rtt_reject = |e| e == Http3ClientEvent::ZeroRttRejected;
        if hc.h3.events().any(recvd_0rtt_reject) {
            return Err("ERROR: 0RTT rejected".into());
        }
    } else {
        println!("Test resumption");
        if let Err(e) = process_loop_h3(nctx, &mut hc, true, true) {
            return Err(format!("ERROR: {}", e));
        }
    }

    if !hc.h3.conn().stats().resumed {
        return Err("ERROR: resumption failed".into());
    }
    Ok(())
}

struct VnHandler {}

impl Handler for VnHandler {
    fn handle(&mut self, client: &mut Connection) -> bool {
        match client.state() {
            State::Connected => false,
            State::Closing { .. } => false,
            _ => true,
        }
    }

    fn rewrite_out(&mut self, d: &Datagram) -> Option<Datagram> {
        let mut payload = d[..].to_vec();
        payload[1] = 0x1a;
        Some(Datagram::new(d.source(), d.destination(), payload))
    }
}

fn test_vn(nctx: &NetworkCtx, peer: &Peer) -> Result<Connection, String> {
    let mut client = Connection::new_client(
        peer.host,
        &["hq-28"],
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        nctx.local_addr,
        nctx.remote_addr,
        QuicVersion::default(),
    )
    .expect("must succeed");
    // Temporary here to help out the type inference engine
    let mut h = VnHandler {};
    let _res = process_loop(nctx, &mut client, &mut h);

    Ok(client)
}

fn run_test<'t>(peer: &Peer, test: &'t Test) -> (&'t Test, String) {
    let socket = UdpSocket::bind(peer.bind()).expect("Unable to bind UDP socket");
    socket.connect(&peer).expect("Unable to connect UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");
    let remote_addr = peer.addr();

    let nctx = NetworkCtx {
        socket,
        local_addr,
        remote_addr,
    };

    if let Test::VN = test {
        let res = test_vn(&nctx, peer);
        return match res {
            Err(e) => (test, format!("ERROR: {}", e)),
            Ok(client) => match client.state() {
                State::Closed(ConnectionError::Transport(Error::VersionNegotiation)) => {
                    (test, String::from("OK"))
                }
                _ => (test, format!("ERROR: Wrong state {:?}", client.state())),
            },
        };
    }

    let mut client = match test_connect(&nctx, test, peer) {
        Ok(client) => client,
        Err(e) => return (test, e),
    };

    let res = match test {
        Test::Connect => {
            return (test, String::from("OK"));
        }
        Test::H9 => test_h9(&nctx, &mut client),
        Test::H3 => test_h3(&nctx, peer, client, test),
        Test::VN => unimplemented!(),
        Test::R => test_h3_rz(&nctx, peer, client, test),
        Test::Z => test_h3_rz(&nctx, peer, client, test),
        Test::D => test_h3(&nctx, peer, client, test),
    };

    if let Err(e) = res {
        return (test, e);
    }

    (test, String::from("OK"))
}

fn run_peer(args: &Args, peer: &'static Peer) -> Vec<(&'static Test, String)> {
    let mut results: Vec<(&'static Test, String)> = Vec::new();

    eprintln!("Running tests for {}", peer.label);

    let mut children = Vec::new();

    for test in &TESTS {
        if !peer.test_enabled(&test) {
            continue;
        }

        if !args.include_tests.is_empty() && !args.include_tests.contains(&test.label()) {
            continue;
        }
        if args.exclude_tests.contains(&test.label()) {
            continue;
        }

        let child = thread::spawn(move || run_test(peer, test));
        children.push((test, child));
    }

    for child in children {
        match child.1.join() {
            Ok(e) => {
                eprintln!("Test complete {:?}, {:?}", child.0, e);
                results.push(e)
            }
            Err(_) => {
                eprintln!("Thread crashed {:?}", child.0);
                results.push((child.0, String::from("CRASHED")));
            }
        }
    }

    eprintln!("Tests for {} complete {:?}", peer.label, results);
    results
}

const PEERS: &[Peer] = &[
    Peer {
        label: "quiche",
        host: "quic.tech",
        port: 4433,
    },
    Peer {
        label: "quiche2",
        host: "quic.tech",
        port: 8443,
    },
    Peer {
        label: "quiche3",
        host: "quic.tech",
        port: 8444,
    },
    Peer {
        label: "quant",
        host: "quant.eggert.org",
        port: 4433,
    },
    Peer {
        label: "quicly",
        host: "quic.examp1e.net",
        port: 443,
    },
    Peer {
        label: "quicly2",
        host: "quic.examp1e.net",
        port: 4433,
    },
    Peer {
        label: "local",
        host: "127.0.0.1",
        port: 4433,
    },
    Peer {
        label: "applequic",
        host: "[2a00:79e1:abc:301:fca8:166e:525f:9b5c]",
        port: 4433,
    },
    Peer {
        label: "f5",
        host: "f5quic.com",
        port: 4433,
    },
    Peer {
        label: "msft",
        host: "quic.westus.cloudapp.azure.com",
        port: 443,
    },
    Peer {
        label: "mvfst",
        host: "fb.mvfst.net",
        port: 443,
    },
    Peer {
        label: "google",
        host: "quic.rocks",
        port: 4433,
    },
    Peer {
        label: "ngtcp2",
        host: "nghttp2.org",
        port: 4433,
    },
    Peer {
        label: "picoquic",
        host: "test.privateoctopus.com",
        port: 4433,
    },
    Peer {
        label: "ats",
        host: "quic.ogre.com",
        port: 4433,
    },
    Peer {
        label: "cloudflare",
        host: "www.cloudflare.com",
        port: 443,
    },
    Peer {
        label: "litespeed",
        host: "http3-test.litespeedtech.com",
        port: 4433,
    },
];

const TESTS: [Test; 7] = [
    Test::Connect,
    Test::H9,
    Test::H3,
    Test::VN,
    Test::R,
    Test::Z,
    Test::D,
];

fn main() {
    let _tests = vec![Test::Connect];

    let args = Args::from_args();
    init();
    Timer::set_timeout(Duration::from_secs(args.timeout));

    let mut children = Vec::new();

    // Start all the children.
    for peer in PEERS {
        if !args.include.is_empty() && !args.include.contains(&String::from(peer.label)) {
            continue;
        }
        if args.exclude.contains(&String::from(peer.label)) {
            continue;
        }

        let at = args.clone();
        let child = thread::spawn(move || run_peer(&at, &peer));
        children.push((peer, child));
    }

    // Now wait for them.
    for child in children {
        let res = child.1.join().unwrap();
        let mut all_letters = HashSet::new();
        for r in &res {
            for l in r.0.letters() {
                if r.1 == "OK" {
                    all_letters.insert(l);
                }
            }
        }
        let mut letter_str = String::from("");
        for l in &['V', 'H', 'D', 'C', 'R', 'Z', 'S', '3'] {
            if all_letters.contains(l) {
                letter_str.push(*l);
            }
        }
        println!("{}: {} -> {:?}", child.0.label, letter_str, res);
    }
}
