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

use neqo_common::{event::Provider, hex, qdebug, Datagram};
use neqo_crypto::{generate_ech_keys, random, AllowZeroRtt, AntiReplay, Cipher};
use neqo_http3::Error;
use neqo_transport::{
    server::{ActiveConnectionRef, Server, ValidateAddress},
    tparams::PreferredAddress,
    ConnectionEvent, ConnectionIdGenerator, ConnectionParameters, Output, State,
};

use super::{qns_read_response, Args, HttpServer};

#[derive(Default)]
struct Http09StreamState {
    writable: bool,
    data_to_send: Option<(Vec<u8>, usize)>,
}

pub struct Http09Server {
    server: Server,
    write_state: HashMap<u64, Http09StreamState>,
    read_state: HashMap<u64, Vec<u8>>,
}

impl Http09Server {
    pub fn new(
        now: Instant,
        certs: &[impl AsRef<str>],
        protocols: &[impl AsRef<str>],
        anti_replay: AntiReplay,
        cid_manager: Rc<RefCell<dyn ConnectionIdGenerator>>,
        preferred_address: Option<PreferredAddress>,
        conn_params: ConnectionParameters,
    ) -> Result<Self, Error> {
        let mut server = Server::new(
            now,
            certs,
            protocols,
            anti_replay,
            Box::new(AllowZeroRtt {}),
            cid_manager,
            conn_params,
        )?;
        if let Some(spa) = preferred_address {
            server.set_preferred_address(spa);
        }
        Ok(Self {
            server,
            write_state: HashMap::new(),
            read_state: HashMap::new(),
        })
    }

    fn save_partial(&mut self, stream_id: u64, partial: Vec<u8>, conn: &mut ActiveConnectionRef) {
        let url_dbg = String::from_utf8(partial.clone())
            .unwrap_or_else(|_| format!("<invalid UTF-8: {}>", hex(&partial)));
        if partial.len() < 4096 {
            qdebug!("Saving partial URL: {}", url_dbg);
            self.read_state.insert(stream_id, partial);
        } else {
            qdebug!("Giving up on partial URL {}", url_dbg);
            conn.borrow_mut().stream_stop_sending(stream_id, 0).unwrap();
        }
    }

    fn write(&mut self, stream_id: u64, data: Option<Vec<u8>>, conn: &mut ActiveConnectionRef) {
        let resp = data.unwrap_or_else(|| Vec::from(&b"404 That request was nonsense\r\n"[..]));
        if let Some(stream_state) = self.write_state.get_mut(&stream_id) {
            match stream_state.data_to_send {
                None => stream_state.data_to_send = Some((resp, 0)),
                Some(_) => {
                    qdebug!("Data already set, doing nothing");
                }
            }
            if stream_state.writable {
                self.stream_writable(stream_id, conn);
            }
        } else {
            self.write_state.insert(
                stream_id,
                Http09StreamState {
                    writable: false,
                    data_to_send: Some((resp, 0)),
                },
            );
        }
    }

    fn stream_readable(&mut self, stream_id: u64, conn: &mut ActiveConnectionRef, args: &Args) {
        if stream_id % 4 != 0 {
            qdebug!("Stream {} not client-initiated bidi, ignoring", stream_id);
            return;
        }
        let mut data = vec![0; 4000];
        let (sz, fin) = conn
            .borrow_mut()
            .stream_recv(stream_id, &mut data)
            .expect("Read should succeed");

        if sz == 0 {
            if !fin {
                qdebug!("size 0 but !fin");
            }
            return;
        }

        data.truncate(sz);
        let buf = if let Some(mut existing) = self.read_state.remove(&stream_id) {
            existing.append(&mut data);
            existing
        } else {
            data
        };

        let msg = if let Ok(s) = std::str::from_utf8(&buf[..]) {
            s
        } else {
            self.save_partial(stream_id, buf, conn);
            return;
        };

        let re = if args.qns_test.is_some() {
            Regex::new(r"GET +/(\S+)(?:\r)?\n").unwrap()
        } else {
            Regex::new(r"GET +/(\d+)(?:\r)?\n").unwrap()
        };
        let m = re.captures(&msg);
        let resp = match m.and_then(|m| m.get(1)) {
            None => {
                self.save_partial(stream_id, buf, conn);
                return;
            }
            Some(path) => {
                let path = path.as_str();
                eprintln!("Path = '{}'", path);
                if args.qns_test.is_some() {
                    qns_read_response(path)
                } else {
                    let count = usize::from_str_radix(path, 10).unwrap();
                    Some(vec![b'a'; count])
                }
            }
        };
        self.write(stream_id, resp, conn);
    }

    fn stream_writable(&mut self, stream_id: u64, conn: &mut ActiveConnectionRef) {
        match self.write_state.get_mut(&stream_id) {
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
                    qdebug!("Wrote {}", sent);
                    *offset += sent;
                    self.server.add_to_waiting(conn.clone());
                    if *offset == data.len() {
                        eprintln!("Sent {} on {}, closing", sent, stream_id);
                        conn.borrow_mut().stream_close_send(stream_id).unwrap();
                        self.write_state.remove(&stream_id);
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

    fn process_events(&mut self, args: &Args, now: Instant) {
        let active_conns = self.server.active_connections();
        for mut acr in active_conns {
            loop {
                let event = match acr.borrow_mut().next_event() {
                    None => break,
                    Some(e) => e,
                };
                eprintln!("Event {:?}", event);
                match event {
                    ConnectionEvent::NewStream { stream_id } => {
                        self.write_state
                            .insert(stream_id.as_u64(), Http09StreamState::default());
                    }
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        self.stream_readable(stream_id, &mut acr, args);
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        self.stream_writable(stream_id.as_u64(), &mut acr);
                    }
                    ConnectionEvent::StateChange(State::Connected) => {
                        acr.connection()
                            .borrow_mut()
                            .send_ticket(now, b"hi!")
                            .unwrap();
                    }
                    ConnectionEvent::StateChange(_)
                    | ConnectionEvent::SendStreamComplete { .. } => (),
                    e => eprintln!("unhandled event {:?}", e),
                }
            }
        }
    }

    fn set_qlog_dir(&mut self, dir: Option<PathBuf>) {
        self.server.set_qlog_dir(dir)
    }

    fn validate_address(&mut self, v: ValidateAddress) {
        self.server.set_validation(v);
    }

    fn set_ciphers(&mut self, ciphers: &[Cipher]) {
        self.server.set_ciphers(ciphers);
    }

    fn enable_ech(&mut self) -> &[u8] {
        let (sk, pk) = generate_ech_keys().expect("generate ECH keys");
        self.server
            .enable_ech(random(1)[0], "public.example", &sk, &pk)
            .expect("enable ECH");
        self.server.ech_config()
    }
}

impl Display for Http09Server {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http 0.9 server ")
    }
}
