// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
use neqo_common::{matches, Datagram};
use neqo_crypto::{init, AuthenticationStatus};
use neqo_http3::{Header, Http3Client, Http3ClientEvent, Http3State, Output};
use neqo_transport::FixedConnectionIdManager;

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::exit;
use std::rc::Rc;
use std::time::Instant;
use structopt::StructOpt;
use url::Url;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "neqo-client",
    about = "A basic QUIC HTTP/0.9 and HTTP3 client."
)]
pub struct Args {
    #[structopt(short = "a", long, default_value = "h3-24")]
    /// ALPN labels to negotiate.
    ///
    /// This client still only does HTTP3 no matter what the ALPN says.
    alpn: Vec<String>,

    url: Url,

    #[structopt(short = "m", default_value = "GET")]
    method: String,

    #[structopt(short = "h", long, number_of_values = 2)]
    header: Vec<String>,

    #[structopt(name = "max-table-size", short = "t", long, default_value = "128")]
    max_table_size: u32,

    #[structopt(name = "max-blocked-streams", short = "b", long, default_value = "128")]
    max_blocked_streams: u16,

    #[structopt(name = "max-push-streams", short = "p", long, default_value = "0")]
    max_push_streams: u64,

    #[structopt(name = "use-old-http", short = "o", long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,

    #[structopt(name = "omit-read-data", long)]
    /// Do not print received data
    omit_read_data: bool,
}

impl Args {
    fn remote_addr(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.to_socket_addrs()?.next().expect("No remote addresses"))
    }

    fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        match self.remote_addr()? {
            SocketAddr::V4(..) => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0)),
            SocketAddr::V6(..) => Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0)),
        }
    }
}

impl ToSocketAddrs for Args {
    type Iter = ::std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        // This is idiotic.  There is no path from hostname: String to IpAddr.
        // And no means of controlling name resolution either.
        if self.url.port_or_known_default().is_none() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid port"));
        }
        std::fmt::format(format_args!(
            "{}:{}",
            self.url.host_str().unwrap_or("localhost"),
            self.url.port_or_known_default().unwrap()
        ))
        .to_socket_addrs()
    }
}

trait Handler {
    fn handle(&mut self, args: &Args, client: &mut Http3Client) -> bool;
}

fn emit_datagram(socket: &UdpSocket, d: Option<Datagram>) {
    if let Some(d) = d {
        let sent = socket.send(&d[..]).expect("Error sending datagram");
        if sent != d.len() {
            eprintln!("Unable to send all {} bytes of datagram", d.len());
        }
    }
}

fn process_loop(
    local_addr: &SocketAddr,
    remote_addr: &SocketAddr,
    socket: &UdpSocket,
    client: &mut Http3Client,
    handler: &mut dyn Handler,
    args: &Args,
) -> neqo_http3::Http3State {
    let buf = &mut [0u8; 2048];
    loop {
        if let Http3State::Closed(..) = client.state() {
            return client.state();
        }

        let mut exiting = !handler.handle(args, client);

        loop {
            let output = client.process_output(Instant::now());
            match output {
                Output::Datagram(dgram) => emit_datagram(&socket, Some(dgram)),
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
        client.process_http3(Instant::now());

        if exiting {
            return client.state();
        }

        match socket.recv(&mut buf[..]) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                // timer expired
                client.process_timer(Instant::now());
            }
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
                    client.process_http3(Instant::now());
                }
            }
        };
    }
}

struct PreConnectHandler {}
impl Handler for PreConnectHandler {
    fn handle(&mut self, _args: &Args, client: &mut Http3Client) -> bool {
        let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
        if client.events().any(authentication_needed) {
            client.authenticated(AuthenticationStatus::Ok, Instant::now());
        }
        Http3State::Connected != client.state()
    }
}

#[derive(Default)]
struct PostConnectHandler {
    streams: HashSet<u64>,
}

// This is a bit fancier than actually needed.
impl Handler for PostConnectHandler {
    fn handle(&mut self, args: &Args, client: &mut Http3Client) -> bool {
        let mut data = vec![0; 4000];
        client.process_http3(Instant::now());
        while let Some(event) = client.next_event() {
            match event {
                Http3ClientEvent::HeaderReady { stream_id } => {
                    if !self.streams.contains(&stream_id) {
                        println!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let headers = client.read_response_headers(stream_id);
                    println!("READ HEADERS[{}]: {:?}", stream_id, headers);
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    if !self.streams.contains(&stream_id) {
                        println!("Data on unexpected stream: {}", stream_id);
                        return false;
                    }

                    let (sz, fin) = client
                        .read_response_data(Instant::now(), stream_id, &mut data)
                        .expect("Read should succeed");
                    if args.omit_read_data {
                        println!("READ[{}]: {} bytes", stream_id, sz);
                    } else {
                        println!(
                            "READ[{}]: {}",
                            stream_id,
                            String::from_utf8(data.clone()).unwrap()
                        )
                    }
                    if fin {
                        println!("<FIN[{}]>", stream_id);
                        client.close(Instant::now(), 0, "kthxbye!");
                        return false;
                    }
                }
                _ => {}
            }
        }

        true
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

fn client(args: Args, socket: UdpSocket, local_addr: SocketAddr, remote_addr: SocketAddr) {
    let mut client = Http3Client::new(
        args.url.host_str().unwrap(),
        &args.alpn,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        local_addr,
        remote_addr,
        (
            args.max_table_size,
            args.max_blocked_streams,
            args.max_push_streams,
        ),
    )
    .expect("must succeed");
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    process_loop(
        &local_addr,
        &remote_addr,
        &socket,
        &mut client,
        &mut h,
        &args,
    );

    let client_stream_id = client.fetch(
        &args.method,
        &args.url.scheme(),
        &args.url.host_str().unwrap(),
        &args.url.path(),
        &to_headers(&args.header),
    );

    if let Err(err) = client_stream_id {
        eprintln!("Could not connect: {:?}", err);
        return;
    }
    let client_stream_id = client_stream_id.unwrap();
    let _ = client.stream_close_send(client_stream_id);

    let mut h2 = PostConnectHandler::default();
    h2.streams.insert(client_stream_id);
    process_loop(
        &local_addr,
        &remote_addr,
        &socket,
        &mut client,
        &mut h2,
        &args,
    );
}

fn main() {
    init();
    let args = Args::from_args();

    let remote_addr = match args.remote_addr() {
        Err(e) => {
            eprintln!("Unable to resolve remote addr: {}", e);
            exit(1)
        }
        Ok(addr) => addr,
    };
    let socket = match args.local_addr().and_then(UdpSocket::bind) {
        Err(e) => {
            eprintln!("Unable to bind UDP socket: {}", e);
            exit(1)
        }
        Ok(s) => s,
    };
    socket.connect(&args).expect("Unable to connect UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");

    println!("Client connecting: {:?} -> {:?}", local_addr, remote_addr);

    if args.use_old_http {
        old::old_client(args, socket, local_addr, remote_addr)
    } else {
        client(args, socket, local_addr, remote_addr)
    }
}

mod old {
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::net::{SocketAddr, UdpSocket};
    use std::process::exit;
    use std::rc::Rc;
    use std::time::Instant;

    use neqo_common::Datagram;
    use neqo_transport::{
        Connection, ConnectionEvent, FixedConnectionIdManager, State, StreamType,
    };

    use super::{emit_datagram, Args};

    trait HandlerOld {
        fn handle(&mut self, args: &Args, client: &mut Connection) -> bool;
    }

    struct PreConnectHandlerOld {}
    impl HandlerOld for PreConnectHandlerOld {
        fn handle(&mut self, _args: &Args, client: &mut Connection) -> bool {
            State::Connected != *dbg!(client.state())
        }
    }

    #[derive(Default)]
    struct PostConnectHandlerOld {
        streams: HashSet<u64>,
    }

    // This is a bit fancier than actually needed.
    impl HandlerOld for PostConnectHandlerOld {
        fn handle(&mut self, args: &Args, client: &mut Connection) -> bool {
            let mut data = vec![0; 4000];
            while let Some(event) = client.next_event() {
                match event {
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        if !self.streams.contains(&stream_id) {
                            println!("Data on unexpected stream: {}", stream_id);
                            return false;
                        }

                        let (sz, fin) = client
                            .stream_recv(stream_id, &mut data)
                            .expect("Read should succeed");
                        if args.omit_read_data {
                            println!("READ[{}]: {} bytes", stream_id, sz);
                        } else {
                            println!(
                                "READ[{}]: {}",
                                stream_id,
                                String::from_utf8(data.clone()).unwrap()
                            )
                        }
                        if fin {
                            println!("<FIN[{}]>", stream_id);
                            client.close(Instant::now(), 0, "kthxbye!");
                            return false;
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

            true
        }
    }

    fn process_loop_old(
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        socket: &UdpSocket,
        client: &mut Connection,
        handler: &mut dyn HandlerOld,
        args: &Args,
    ) -> State {
        let buf = &mut [0u8; 2048];
        loop {
            if let State::Closed(..) = client.state() {
                return client.state().clone();
            }

            let exiting = !handler.handle(args, client);

            let out_dgram = client.process_output(Instant::now());
            emit_datagram(&socket, out_dgram.dgram());

            if exiting {
                return client.state().clone();
            }

            let sz = match socket.recv(&mut buf[..]) {
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

    pub fn old_client(
        args: Args,
        socket: UdpSocket,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) {
        dbg!(args.url.host_str().unwrap());
        dbg!(&args.alpn);
        dbg!(local_addr);
        dbg!(remote_addr);

        let mut client = Connection::new_client(
            args.url.host_str().unwrap(),
            &["http/0.9"],
            Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
            local_addr,
            remote_addr,
        )
        .expect("must succeed");
        // Temporary here to help out the type inference engine
        let mut h = PreConnectHandlerOld {};
        process_loop_old(
            &local_addr,
            &remote_addr,
            &socket,
            &mut client,
            &mut h,
            &args,
        );

        let client_stream_id = client.stream_create(StreamType::BiDi).unwrap();
        let req: String = "GET /10\r\n".to_string();
        client
            .stream_send(client_stream_id, req.as_bytes())
            .unwrap();
        let mut h2 = PostConnectHandlerOld::default();
        h2.streams.insert(client_stream_id);
        process_loop_old(
            &local_addr,
            &remote_addr,
            &socket,
            &mut client,
            &mut h2,
            &args,
        );
    }
}
