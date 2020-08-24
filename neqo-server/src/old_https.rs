// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Instant;

use regex::Regex;

use neqo_common::Datagram;
use neqo_crypto::{AllowZeroRtt, AntiReplay};
use neqo_http3::Error;
use neqo_transport::server::{ActiveConnectionRef, Server};
use neqo_transport::{ConnectionEvent, ConnectionIdManager, Output};

use super::{qns_read_response, Args, HttpServer};

#[derive(Default)]
struct Http09StreamState {
    writable: bool,
    data_to_send: Option<(Vec<u8>, usize)>,
}

pub struct Http09Server {
    server: Server,
    stream_state: HashMap<(ActiveConnectionRef, u64), Http09StreamState>,
}

impl Http09Server {
    pub fn new(
        now: Instant,
        certs: &[impl AsRef<str>],
        protocols: &[impl AsRef<str>],
        anti_replay: AntiReplay,
        cid_manager: Rc<RefCell<dyn ConnectionIdManager>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            server: Server::new(
                now,
                certs,
                protocols,
                anti_replay,
                Box::new(AllowZeroRtt {}),
                cid_manager,
            )?,
            stream_state: HashMap::new(),
        })
    }

    fn stream_readable(&mut self, stream_id: u64, mut conn: &mut ActiveConnectionRef, args: &Args) {
        if stream_id % 4 != 0 {
            eprintln!("Stream {} not client-initiated bidi, ignoring", stream_id);
            return;
        }
        let mut data = vec![0; 4000];
        let (sz, fin) = conn
            .borrow_mut()
            .stream_recv(stream_id, &mut data)
            .expect("Read should succeed");

        if sz == 0 {
            if !fin {
                eprintln!("size 0 but !fin");
            }
            return;
        }

        let msg = match std::str::from_utf8(&data[..sz]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("invalid string. Is this HTTP 0.9? error: {}", e);
                conn.borrow_mut().stream_close_send(stream_id).unwrap();
                return;
            }
        };

        let re = if args.qns_mode {
            Regex::new(r"GET +/(\S+)(\r)?\n").unwrap()
        } else {
            Regex::new(r"GET +/(\d+)(\r)?\n").unwrap()
        };
        let m = re.captures(&msg);
        let resp = match m.and_then(|m| m.get(1)) {
            None => Some(b"Hello World".to_vec()),
            Some(path) => {
                let path = path.as_str();
                eprintln!("Path = '{}'", path);
                if args.qns_mode {
                    qns_read_response(path)
                } else {
                    let count = usize::from_str_radix(path, 10).unwrap();
                    Some(vec![b'a'; count])
                }
            }
        };
        let stream_state = self
            .stream_state
            .get_mut(&(conn.clone(), stream_id))
            .unwrap();
        match stream_state.data_to_send {
            None => stream_state.data_to_send = resp.map(|r| (r, 0)),
            Some(_) => {
                eprintln!("Data already set, doing nothing");
            }
        }
        if stream_state.writable {
            self.stream_writable(stream_id, &mut conn);
        }
    }

    fn stream_writable(&mut self, stream_id: u64, conn: &mut ActiveConnectionRef) {
        match self.stream_state.get_mut(&(conn.clone(), stream_id)) {
            None => {
                eprintln!("Unknown stream {}, ignoring event", stream_id);
            }
            Some(stream_state) => {
                stream_state.writable = true;
                if let Some((data, ref mut offset)) = &mut stream_state.data_to_send {
                    let sent = conn
                        .borrow_mut()
                        .stream_send(stream_id, &data[*offset..])
                        .unwrap();
                    eprintln!("Wrote {}", sent);
                    *offset += sent;
                    self.server.add_to_waiting(conn.clone());
                    if *offset == data.len() {
                        eprintln!("Sent {} on {}, closing", sent, stream_id);
                        conn.borrow_mut().stream_close_send(stream_id).unwrap();
                        self.stream_state.remove(&(conn.clone(), stream_id));
                    } else {
                        stream_state.writable = false;
                    }
                }
            }
        }
    }
}

impl HttpServer for Http09Server {
    fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        self.server.process(dgram, now)
    }

    fn process_events(&mut self, args: &Args) {
        let active_conns = self.server.active_connections();
        for mut acr in active_conns {
            loop {
                let event = match acr.borrow_mut().next_event() {
                    None => break,
                    Some(e) => e,
                };
                match event {
                    ConnectionEvent::NewStream { stream_id } => {
                        self.stream_state.insert(
                            (acr.clone(), stream_id.as_u64()),
                            Http09StreamState::default(),
                        );
                    }
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        self.stream_readable(stream_id, &mut acr, args);
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        self.stream_writable(stream_id.as_u64(), &mut acr);
                    }
                    ConnectionEvent::StateChange { .. } => {}
                    e => eprintln!("unhandled event {:?}", e),
                }
            }
        }
    }

    fn set_qlog_dir(&mut self, dir: Option<PathBuf>) {
        self.server.set_qlog_dir(dir)
    }
}

impl Display for Http09Server {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http 0.9 server ")
    }
}
