// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This file implements a server that can handle multiple connections.

use neqo_common::timer::Timer;
use neqo_common::{hex, qinfo, qtrace, qwarn, Datagram, Decoder};
use neqo_crypto::AntiReplay;

use crate::connection::{Connection, ConnectionIdManager, Output};
use crate::packet::{
    decode_packet_hdr, encode_packet_vn, encode_retry, ConnectionId, ConnectionIdDecoder,
    PacketHdr, PacketType, Version,
};
use crate::QUIC_VERSION;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::time::{Duration, Instant};

pub enum InitialResult {
    Accept,
    Drop,
    Retry(Vec<u8>),
}

/// MIN_INITIAL_PACKET_SIZE is the smallest packet that can be used to establish
/// a new connection across all QUIC versions this server supports.
const MIN_INITIAL_PACKET_SIZE: usize = 1200;
const TIMER_GRANULARITY: Duration = Duration::from_millis(10);
const TIMER_CAPACITY: usize = 1024;
const FIXED_TOKEN: &[u8] = &[1, 2, 3];

type StateRef = Rc<RefCell<ServerConnectionState>>;
type CidMgr = Rc<RefCell<dyn ConnectionIdManager>>;
type ConnectionTableRef = Rc<RefCell<HashMap<ConnectionId, StateRef>>>;

#[derive(Debug)]
struct ServerConnectionState {
    c: Connection,
    // TODO(mt) work out whether this needs to hold anything.
}

impl Deref for ServerConnectionState {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.c
    }
}

impl DerefMut for ServerConnectionState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.c
    }
}

pub struct Server {
    /// The version this server supports (currently just one).
    version: Version,
    /// The names of certificates.
    certs: Vec<String>,
    /// The ALPN values that the server supports.
    protocols: Vec<String>,
    anti_replay: AntiReplay,
    /// A connection ID manager.
    cid_manager: CidMgr,
    connections: ConnectionTableRef,
    waiting: VecDeque<StateRef>,
    timers: Timer<StateRef>,
    require_retry: bool,
}

impl Server {
    pub fn new<CI, PI>(
        now: Instant,
        cid_manager: CidMgr,
        certs: CI,
        protocols: PI,
        anti_replay: AntiReplay,
    ) -> Server
    where
        CI: IntoIterator,
        CI::Item: AsRef<str>,
        PI: IntoIterator,
        PI::Item: AsRef<str>,
    {
        Server {
            version: QUIC_VERSION,
            certs: certs
                .into_iter()
                .map(|x| String::from(x.as_ref()))
                .collect(),
            protocols: protocols
                .into_iter()
                .map(|x| String::from(x.as_ref()))
                .collect(),
            anti_replay,
            cid_manager,
            connections: Rc::new(RefCell::new(Default::default())),
            waiting: Default::default(),
            timers: Timer::new(now, TIMER_GRANULARITY, TIMER_CAPACITY),
            require_retry: false,
        }
    }

    fn create_vn(&self, hdr: &PacketHdr, received: Datagram) -> Datagram {
        let vn = encode_packet_vn(&PacketHdr::new(
            0,
            // Actual version we support and a greased value.
            PacketType::VN(vec![self.version, 0xaaba_cada]),
            Some(0),
            hdr.scid.as_ref().unwrap().clone(),
            Some(hdr.dcid.clone()),
            0, // unused
            0, // unused
        ));
        Datagram::new(received.destination(), received.source(), vn)
    }

    pub fn enable_retry(&mut self, require_retry: bool) {
        self.require_retry = require_retry;
    }

    fn token_is_ok(&self, token: &[u8]) -> bool {
        if token.is_empty() {
            self.require_retry
        } else {
            // TODO(mt) construct better tokens
            token == &FIXED_TOKEN[..]
        }
    }

    fn generate_token(&self) -> Vec<u8> {
        // TODO(mt) construct better tokens
        Vec::from(FIXED_TOKEN)
    }

    fn check_initial(&self, hdr: &PacketHdr) -> InitialResult {
        if let PacketType::Initial(token) = &hdr.tipe {
            if self.token_is_ok(token) {
                return InitialResult::Accept;
            }
            if !token.is_empty() {
                // This is a bad Initial, so ignore it.
                return InitialResult::Drop;
            }
        } else {
            return InitialResult::Drop;
        }

        InitialResult::Retry(encode_retry(&PacketHdr::new(
            0, // tbyte (unused on encode)
            PacketType::Retry {
                odcid: hdr.dcid.clone(),
                token: self.generate_token(),
            },
            Some(self.version),
            hdr.scid.as_ref().unwrap().clone(),
            Some(self.cid_manager.borrow_mut().generate_cid()),
            0, // Packet number
            0, // Epoch
        )))
    }

    fn process_connection(
        &mut self,
        c: StateRef,
        dgram: Option<Datagram>,
        now: Instant,
    ) -> Option<Datagram> {
        let out = c.borrow_mut().process(dgram, now);
        if let Output::Callback(delay) = out {
            self.timers.add(now + delay, c.clone());
        } else {
            self.waiting.push_back(c.clone());
        }
        out.dgram()
    }

    fn get_connection(&self, cid: &ConnectionId) -> Option<StateRef> {
        if let Some(c) = self.connections.borrow().get(cid) {
            Some(c.clone())
        } else {
            None
        }
    }

    fn accept_connection(&mut self, dgram: Datagram, now: Instant) -> Option<Datagram> {
        qinfo!([self] "Accept connection");
        // The internal connection ID manager that we use is not used directly.
        // Instead, wrap it so that we can save connection IDs.
        let cid_mgr = Rc::new(RefCell::new(ServerConnectionIdManager {
            c: None,
            cid_manager: self.cid_manager.clone(),
            connections: self.connections.clone(),
        }));
        let sconn = Connection::new_server(
            &self.certs,
            &self.protocols,
            &self.anti_replay,
            cid_mgr.clone(),
        );
        if let Ok(c) = sconn {
            let c = Rc::new(RefCell::new(ServerConnectionState { c }));
            cid_mgr.borrow_mut().c = Some(c.clone());
            self.process_connection(c, Some(dgram), now)
        } else {
            qwarn!([self] "Unable to create connection");
            None
        }
    }

    fn process_input(&mut self, dgram: Datagram, now: Instant) -> Option<Datagram> {
        qtrace!("Process datagram: {}", hex(&dgram[..]));

        // This is only looking at the first packet header in the datagram.
        // All packets in the datagram are routed to the same connection.
        let res = decode_packet_hdr(self.cid_manager.borrow().as_decoder(), &dgram[..]);
        let hdr = match res {
            Ok(h) => h,
            _ => {
                qtrace!([self] "Discarding {:?}", dgram);
                return None;
            }
        };

        // Finding an existing connection. Should be the most common case.
        if let Some(c) = self.get_connection(&hdr.dcid) {
            return self.process_connection(c, Some(dgram), now);
        }

        if hdr.tipe == PacketType::Short {
            // TODO send a stateless reset here.
            qtrace!([self] "Short header packet for an unknown connection");
            return None;
        }

        if dgram.len() < MIN_INITIAL_PACKET_SIZE {
            qtrace!([self] "Bogus packet");
            return None;
        }

        if hdr.version != Some(self.version) {
            return Some(self.create_vn(&hdr, dgram));
        }

        match self.check_initial(&hdr) {
            InitialResult::Accept => self.accept_connection(dgram, now),
            InitialResult::Retry(payload) => {
                let retry = Datagram::new(dgram.destination(), dgram.source(), payload);
                Some(retry)
            }
            InitialResult::Drop => None,
        }
    }

    fn next_time(&mut self, now: Instant) -> Option<Duration> {
        if self.waiting.is_empty() {
            self.timers.next_time().map(|x| x - now)
        } else {
            Some(Duration::new(0, 0))
        }
    }

    /// Iterate through the pending connections looking for any that might want
    /// to send a datagram.  Stop at the first one that does.
    fn process_next_output(&mut self, now: Instant) -> Option<Datagram> {
        while let Some(c) = self.waiting.pop_front() {
            if let Some(d) = self.process_connection(c, None, now) {
                return Some(d);
            }
        }
        while let Some(c) = self.timers.take_next(now) {
            if let Some(d) = self.process_connection(c, None, now) {
                return Some(d);
            }
        }
        None
    }

    pub fn process(
        &mut self,
        dgram: Option<Datagram>,
        now: Instant,
    ) -> (Option<Datagram>, Option<Duration>) {
        let out = match dgram {
            Some(d) => self.process_input(d, now),
            None => None,
        };

        (
            out.or_else(|| self.process_next_output(now)),
            self.next_time(now),
        )
    }
}

struct ServerConnectionIdManager {
    c: Option<StateRef>,
    connections: ConnectionTableRef,
    cid_manager: CidMgr,
}

impl ConnectionIdDecoder for ServerConnectionIdManager {
    fn decode_cid(&self, dec: &mut Decoder) -> Option<ConnectionId> {
        self.cid_manager.borrow_mut().decode_cid(dec)
    }
}
impl ConnectionIdManager for ServerConnectionIdManager {
    fn generate_cid(&mut self) -> ConnectionId {
        let cid = self.cid_manager.borrow_mut().generate_cid();
        let v = self
            .connections
            .borrow_mut()
            .insert(cid.clone(), self.c.as_ref().unwrap().clone());
        if let Some(v) = v {
            debug_assert!(Rc::ptr_eq(&v, self.c.as_ref().unwrap()));
        }
        cid
    }
    fn as_decoder(&self) -> &dyn ConnectionIdDecoder {
        self
    }
}

impl ::std::fmt::Display for Server {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Server")
    }
}
