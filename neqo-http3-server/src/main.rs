// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![allow(clippy::option_option)]
#![warn(clippy::use_self)]

use chrono::offset::Utc;
use chrono::DateTime;
use qlog::{CommonFields, Configuration, Qlog, TimeUnits, Trace, VantagePoint, VantagePointType};
use std::time::SystemTime;

use neqo_common::{
    log::{NeqoQlog, NeqoQlogRef},
    qdebug, qinfo, Datagram,
};
use neqo_crypto::{init_db, AntiReplay};
use neqo_http3::{Http3Server, Http3ServerEvent};
use neqo_transport::{FixedConnectionIdManager, Output};

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::time::{Duration, Instant};

use structopt::StructOpt;

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::timer::{Builder, Timeout, Timer};

const TIMER_TOKEN: Token = Token(0xffff_ffff);

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-http3-server", about = "A basic HTTP3 server.")]
struct Args {
    /// List of IP:port to listen on
    #[structopt(default_value = "[::]:4433")]
    hosts: Vec<String>,

    #[structopt(short = "t", long, default_value = "128")]
    max_table_size: u32,

    #[structopt(short = "b", long, default_value = "128")]
    max_blocked_streams: u16,

    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    /// NSS database directory.
    db: PathBuf,

    #[structopt(short = "k", long, default_value = "key")]
    /// Name of key from NSS database.
    key: String,

    #[structopt(short = "a", long, default_value = "h3-25")]
    /// ALPN labels to negotiate.
    ///
    /// This server still only does HTTP3 no matter what the ALPN says.
    alpn: String,

    #[structopt(long, default_value = "output.qlog")]
    /// Output QLOG trace to a file.
    qlog: Option<Option<PathBuf>>,
}

impl Args {
    fn host_socket_addrs(&self) -> Vec<SocketAddr> {
        self.hosts
            .iter()
            .filter_map(|host| host.to_socket_addrs().ok())
            .flat_map(|x| x)
            .collect()
    }
}

fn process_events(server: &mut Http3Server) {
    while let Some(event) = server.next_event() {
        eprintln!("Event: {:?}", event);
        match event {
            Http3ServerEvent::Headers {
                mut request,
                headers,
                fin,
            } => {
                println!("Headers (request={} fin={}): {:?}", request, fin, headers);

                let default_ret = b"Hello World".to_vec();

                let response = match headers.iter().find(|&(k, _)| k == ":path") {
                    Some((_, path)) if !path.is_empty() => {
                        match path.trim_matches(|p| p == '/').parse::<usize>() {
                            Ok(v) => vec![b'a'; v],
                            Err(_) => default_ret,
                        }
                    }
                    _ => default_ret,
                };

                request
                    .set_response(
                        &[
                            (String::from(":status"), String::from("200")),
                            (String::from("content-length"), response.len().to_string()),
                        ],
                        response,
                    )
                    .unwrap();
            }
            Http3ServerEvent::Data { request, data, fin } => {
                println!("Data (request={} fin={}): {:?}", request, fin, data);
            }
            _ => {}
        }
    }
}

fn emit_packets(sockets: &mut Vec<UdpSocket>, out_dgrams: &HashMap<SocketAddr, Vec<Datagram>>) {
    for s in sockets {
        if let Some(dgrams) = out_dgrams.get(&s.local_addr().unwrap()) {
            for d in dgrams {
                let sent = s
                    .send_to(d, &d.destination())
                    .expect("Error sending datagram");
                if sent != d.len() {
                    eprintln!("Unable to send all {} bytes of datagram", d.len());
                }
            }
        }
    }
}

fn process(
    server: &mut Http3Server,
    svr_timeout: &mut Option<Timeout>,
    inx: usize,
    mut dgram: Option<Datagram>,
    out_dgrams: &mut Vec<Datagram>,
    timer: &mut Timer<usize>,
) {
    loop {
        match server.process(dgram, Instant::now()) {
            Output::Datagram(dgram) => out_dgrams.push(dgram),
            Output::Callback(new_timeout) => {
                if let Some(svr_timeout) = svr_timeout {
                    timer.cancel_timeout(svr_timeout);
                }

                qinfo!("Setting timeout of {:?} for {}", new_timeout, server);
                *svr_timeout = Some(timer.set_timeout(new_timeout, inx));
                break;
            }
            Output::None => {
                qdebug!("Output::None");
                break;
            }
        };
        dgram = None;
    }
}

fn init_qlog_trace() -> qlog::Trace {
    Trace {
        vantage_point: VantagePoint {
            name: Some("neqo-server".into()),
            ty: VantagePointType::Server,
            flow: None,
        },
        title: Some("neqo-http3-server trace".to_string()),
        description: Some("Example qlog trace description".to_string()),
        configuration: Some(Configuration {
            time_offset: Some("0".into()),
            time_units: Some(TimeUnits::Us),
            original_uris: None,
        }),
        common_fields: Some(CommonFields {
            group_id: None,
            protocol_type: None,
            reference_time: Some({
                let system_time = SystemTime::now();
                let datetime: DateTime<Utc> = system_time.into();
                datetime.to_rfc3339()
            }),
        }),
        event_fields: vec![
            "relative_time".to_string(),
            "category".to_string(),
            "event".to_string(),
            "data".to_string(),
        ],
        events: Vec::new(),
    }
}

fn main() -> Result<(), io::Error> {
    let args = Args::from_args();
    assert!(!args.key.is_empty(), "Need at least one key");

    init_db(args.db.clone());

    let poll = Poll::new()?;

    let hosts = args.host_socket_addrs();
    if hosts.is_empty() {
        eprintln!("No valid hosts defined");
        exit(1);
    }

    let qtrace: NeqoQlogRef = Rc::new(RefCell::new(NeqoQlog::new(
        Instant::now(),
        init_qlog_trace(),
    )));
    let mut qtrace_last_flush_time = Instant::now();

    let mut sockets = Vec::new();
    let mut servers = HashMap::new();
    let mut timer = Builder::default().build::<usize>();
    poll.register(&timer, TIMER_TOKEN, Ready::readable(), PollOpt::edge())?;

    for (i, host) in hosts.iter().enumerate() {
        let socket = match UdpSocket::bind(&host) {
            Err(err) => {
                eprintln!("Unable to bind UDP socket: {}", err);
                exit(1)
            }
            Ok(s) => s,
        };

        let local_addr = match socket.local_addr() {
            Err(err) => {
                eprintln!("Socket local address not bound: {}", err);
                exit(1)
            }
            Ok(s) => s,
        };

        let res = socket.only_v6();
        let also_v4 = if res.is_ok() && !res.unwrap() {
            " as well as V4"
        } else {
            ""
        };
        println!(
            "Server waiting for connection on: {:?}{}",
            local_addr, also_v4
        );

        poll.register(
            &socket,
            Token(i),
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        )?;
        sockets.push(socket);
        servers.insert(
            local_addr,
            (
                Http3Server::new(
                    Instant::now(),
                    &[args.key.clone()],
                    &[args.alpn.clone()],
                    AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
                        .expect("unable to setup anti-replay"),
                    Rc::new(RefCell::new(FixedConnectionIdManager::new(10))),
                    args.max_table_size,
                    args.max_blocked_streams,
                    Some(Rc::clone(&qtrace)),
                )
                .expect("We cannot make a server!"),
                None,
            ),
        );
    }

    let buf = &mut [0u8; 2048];

    let mut events = Events::with_capacity(1024);

    let (mut qlog, qlog_output_path) = if let Some(output_path) = &args.qlog {
        (
            Some(Qlog {
                qlog_version: qlog::QLOG_VERSION.into(),
                title: None,
                description: None,
                summary: None,
                traces: Vec::new(),
            }),
            Some(output_path.clone().unwrap()),
        )
    } else {
        (None, None)
    };

    loop {
        poll.poll(&mut events, None)?;
        let mut out_dgrams = HashMap::new();
        for event in &events {
            if event.token() == TIMER_TOKEN {
                while let Some(inx) = timer.poll() {
                    if let Some(socket) = sockets.get(inx) {
                        qinfo!("Timer expired for {:?}", socket);
                        if let Some((server, svr_timeout)) =
                            servers.get_mut(&socket.local_addr().unwrap())
                        {
                            process(
                                server,
                                svr_timeout,
                                inx,
                                None,
                                &mut out_dgrams
                                    .entry(socket.local_addr().unwrap())
                                    .or_insert_with(Vec::new),
                                &mut timer,
                            );
                        }
                    }
                }
            } else if let Some(socket) = sockets.get(event.token().0) {
                let local_addr = hosts[event.token().0];

                if !event.readiness().is_readable() {
                    continue;
                }

                loop {
                    let (sz, remote_addr) = match socket.recv_from(&mut buf[..]) {
                        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => {
                            eprintln!("UDP recv error: {:?}", err);
                            exit(1);
                        }
                        Ok(res) => res,
                    };

                    if sz == buf.len() {
                        eprintln!("Might have received more than {} bytes", buf.len());
                    }

                    if sz == 0 {
                        eprintln!("zero length datagram received?");
                    } else if let Some((server, svr_timeout)) =
                        servers.get_mut(&socket.local_addr().unwrap())
                    {
                        let out = out_dgrams
                            .entry(socket.local_addr().unwrap())
                            .or_insert_with(Vec::new);
                        process(
                            server,
                            svr_timeout,
                            event.token().0,
                            Some(Datagram::new(remote_addr, local_addr, &buf[..sz])),
                            out,
                            &mut timer,
                        );
                        process_events(server);
                        process(server, svr_timeout, event.token().0, None, out, &mut timer);
                    }
                }
            }
        }

        emit_packets(&mut sockets, &out_dgrams);

        // Consider the time since we last wrote the trace to disk. If it has been more than 5 seconds,
        // flush it. NB: This is a demonstration implementation. The performance overhead for logging
        // traces in this manner is not suitable for production.
        if Instant::now() - qtrace_last_flush_time > Duration::from_secs(5) {
            if let (Some(qlog), Some(qlog_output_path)) = (&mut qlog, &qlog_output_path) {
                match OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&qlog_output_path)
                {
                    Ok(mut f) => {
                        eprintln!("Writing QLOG to {}", qlog_output_path.display());
                        qlog.traces.push(qtrace.borrow().trace.clone());
                        let data = serde_json::to_string_pretty(&qlog)?;
                        f.write_all(data.as_bytes())?;
                        qlog.traces.pop();
                    }
                    Err(e) => {
                        eprintln!("Could not open qlog: {}", e);
                    }
                }
            }
            qtrace_last_flush_time = Instant::now();
        }
    }
}
