// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_variables, dead_code)]
use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::{self, Debug};
use std::mem;
use std::net::SocketAddr;
use std::ops::{AddAssign, Deref, DerefMut};
use std::rc::Rc;

use neqo_common::data::Data;
use neqo_common::varint::*;
use neqo_common::{hex, matches, qdebug, qinfo, qtrace, qwarn};
use neqo_crypto::aead::Aead;
use neqo_crypto::constants::*;
use neqo_crypto::hkdf;
use neqo_crypto::hp::{extract_hp, HpKey};
use rand::prelude::*;

use crate::frame::{decode_frame, AckRange, Frame, FrameType, StreamType};
use crate::nss::*;
use crate::packet::*;
use crate::recv_stream::{RecvStream, RxStreamOrderer, RX_STREAM_DATA_WINDOW};
use crate::send_stream::{SendStream, TxBuffer};
use crate::tparams::consts::*;
use crate::tparams::TransportParametersHandler;
use crate::tracking::RecvdPackets;
use crate::{AppError, ConnectionError, Error, Recvable, Res, Sendable};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

pub const QUIC_VERSION: u32 = 0xff000012;
const NUM_EPOCHS: Epoch = 4;
const MAX_AUTH_TAG: usize = 32;

const TIME_THRESHOLD: f64 = 9.0 / 8.0;
const PACKET_THRESHOLD: u64 = 3;
// TODO granularity
const GRANULARITY: u64 = 1000; // 1ms in microseconds
const INITIAL_RTT: u64 = 100_000; // 100ms in microseconds

const LOCAL_STREAM_LIMIT_BIDI: u64 = 16; // TODO(agrover@mozilla.com): these too low?
const LOCAL_STREAM_LIMIT_UNI: u64 = 16;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, PartialEq, Clone)]
pub enum State {
    Init,
    WaitInitial,
    Handshaking,
    Connected,
    Closing(ConnectionError, FrameType, String),
    Closed(ConnectionError),
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

impl StreamId {
    fn is_bidi(&self) -> bool {
        self.0 & 0x02 == 0
    }

    fn is_uni(&self) -> bool {
        !self.is_bidi()
    }

    fn stream_type(&self) -> StreamType {
        if self.is_bidi() {
            StreamType::BiDi
        } else {
            StreamType::UniDi
        }
    }

    fn is_client_initiated(&self) -> bool {
        self.0 & 0x01 == 0
    }

    fn is_server_initiated(&self) -> bool {
        !self.is_client_initiated()
    }

    fn role(&self) -> Role {
        if self.is_client_initiated() {
            Role::Client
        } else {
            Role::Server
        }
    }

    fn is_self_initiated(&self, role: Role) -> bool {
        match self.role() {
            Role::Client if self.is_client_initiated() => true,
            Role::Server if self.is_server_initiated() => true,
            _ => false,
        }
    }

    fn is_peer_initiated(&self, role: Role) -> bool {
        !self.is_self_initiated(role)
    }

    fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u64> for StreamId {
    fn from(val: u64) -> Self {
        StreamId(val)
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Ord, PartialOrd, Hash)]
pub struct StreamIndex(u64);

impl StreamIndex {
    pub fn new(val: u64) -> StreamIndex {
        StreamIndex(val)
    }

    pub fn to_stream_id(&self, stream_type: StreamType, role: Role) -> StreamId {
        let type_val = match stream_type {
            StreamType::BiDi => 0,
            StreamType::UniDi => 2,
        };
        let role_val = match role {
            Role::Server => 1,
            Role::Client => 0,
        };

        StreamId::from((self.0 << 2) + type_val + role_val)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<StreamId> for StreamIndex {
    fn from(val: StreamId) -> Self {
        StreamIndex(val.as_u64() >> 2)
    }
}

impl AddAssign<u64> for StreamIndex {
    fn add_assign(&mut self, other: u64) {
        *self = StreamIndex::new(self.as_u64() + other)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum PNSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[derive(Debug, PartialEq)]
pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    d: Vec<u8>,
}

impl Datagram {
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, d: V) -> Datagram {
        Datagram {
            src,
            dst,
            d: d.into(),
        }
    }

    pub fn source(&self) -> &SocketAddr {
        &self.src
    }

    pub fn destination(&self) -> &SocketAddr {
        &self.dst
    }
}

impl Deref for Datagram {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

impl DerefMut for Datagram {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.d
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TxMode {
    Normal,
    Pto,
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// A new uni (read) or bidi stream has been opened by the peer.
    NewStream {
        stream_id: u64,
        stream_type: StreamType,
    },
    /// Space available in the buffer for an application write to succeed.
    SendStreamWritable { stream_id: u64 },
    /// New bytes available for reading.
    RecvStreamReadable { stream_id: u64 },
    /// Peer reset the stream.
    RecvStreamReset { stream_id: u64, app_error: AppError },
    /// Peer has acked everything sent on the stream.
    SendStreamComplete { stream_id: u64 },
    /// Peer increased MAX_STREAMS
    SendStreamCreatable { stream_type: StreamType },
    // TODO(agrover@mozilla.com): Are there more?
}

#[derive(Debug, Default)]
pub struct ConnectionEvents {
    events: BTreeSet<ConnectionEvent>,
}

impl ConnectionEvents {
    pub fn new_stream(&mut self, stream_id: StreamId, stream_type: StreamType) {
        self.events.insert(ConnectionEvent::NewStream {
            stream_id: stream_id.as_u64(),
            stream_type,
        });
    }

    pub fn send_stream_writable(&mut self, stream_id: StreamId) {
        self.events.insert(ConnectionEvent::SendStreamWritable {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn recv_stream_readable(&mut self, stream_id: StreamId) {
        self.events.insert(ConnectionEvent::RecvStreamReadable {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn recv_stream_reset(&mut self, stream_id: StreamId, app_error: AppError) {
        self.events.insert(ConnectionEvent::RecvStreamReset {
            stream_id: stream_id.as_u64(),
            app_error,
        });
    }

    pub fn send_stream_complete(&mut self, stream_id: StreamId) {
        self.events.insert(ConnectionEvent::SendStreamComplete {
            stream_id: stream_id.as_u64(),
        });
    }

    pub fn send_stream_creatable(&mut self, stream_type: StreamType) {
        self.events
            .insert(ConnectionEvent::SendStreamCreatable { stream_type });
    }

    fn events(&mut self) -> BTreeSet<ConnectionEvent> {
        mem::replace(&mut self.events, BTreeSet::new())
    }
}

#[derive(Debug, Default)]
pub struct FlowMgr {
    from_conn: VecDeque<Frame>,
    from_send_streams: BTreeMap<StreamId, Frame>,
    from_recv_streams: BTreeMap<StreamId, Frame>,
}

impl FlowMgr {
    pub fn new() -> FlowMgr {
        FlowMgr::default()
    }

    /// Indicate to receiving peer we need more credits
    pub fn stream_data_blocked(&mut self, stream_id: StreamId, stream_data_limit: u64) {
        let frame = Frame::StreamDataBlocked {
            stream_id: stream_id.as_u64(),
            stream_data_limit,
        };
        self.from_send_streams.insert(stream_id, frame);
    }

    /// Indicate to receiving peer the stream is reset
    pub fn stream_reset(
        &mut self,
        stream_id: StreamId,
        application_error_code: AppError,
        final_size: u64,
    ) {
        let frame = Frame::ResetStream {
            stream_id: stream_id.as_u64(),
            application_error_code,
            final_size,
        };
        self.from_send_streams.insert(stream_id, frame);
    }

    /// Indicate to sending peer we are no longer interested in the stream
    pub fn stop_sending(&mut self, stream_id: StreamId, application_error_code: AppError) {
        let frame = Frame::StopSending {
            stream_id: stream_id.as_u64(),
            application_error_code,
        };
        self.from_recv_streams.insert(stream_id, frame);
    }

    /// Update sending peer with more credits
    pub fn max_stream_data(&mut self, stream_id: StreamId, maximum_stream_data: u64) {
        let frame = Frame::MaxStreamData {
            stream_id: stream_id.as_u64(),
            maximum_stream_data,
        };
        self.from_recv_streams.insert(stream_id, frame);
    }

    pub fn streams_blocked(&mut self, stream_limit: StreamIndex, stream_type: StreamType) {
        let frame = Frame::StreamsBlocked {
            stream_type,
            stream_limit,
        };
        self.from_conn.push_back(frame);
    }

    pub fn max_streams(&mut self, stream_limit: StreamIndex, stream_type: StreamType) {
        let frame = Frame::MaxStreams {
            stream_type,
            maximum_streams: stream_limit,
        };
        self.from_conn.push_back(frame);
    }

    /// Used by generator to get a flow control frame.
    // TODO(agrover@mozilla.com): Think more about precedence of possible
    // frames for a given stream, and how things could go wrong with different
    // orderings
    pub fn next(&mut self) -> Option<Frame> {
        if let Some(item) = self.from_conn.pop_front() {
            return Some(item);
        }

        let first_key = self.from_recv_streams.keys().next();
        if let Some(&first_key) = first_key {
            return self.from_recv_streams.remove(&first_key);
        }

        let first_key = self.from_send_streams.keys().next();
        if let Some(&first_key) = first_key {
            return self.from_send_streams.remove(&first_key);
        }

        None
    }

    pub fn peek(&self) -> Option<&Frame> {
        if let Some(item) = self.from_conn.front() {
            Some(item)
        } else {
            if let Some(key) = self.from_recv_streams.keys().next() {
                self.from_recv_streams.get(key)
            } else {
                if let Some(key) = self.from_send_streams.keys().next() {
                    self.from_send_streams.get(key)
                } else {
                    None
                }
            }
        }
    }
}

trait FrameGenerator {
    fn generate(
        &mut self,
        conn: &mut Connection,
        epoch: Epoch,
        tx_mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)>;
}

impl Debug for FrameGenerator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("<FrameGenerator Function>")
    }
}

pub trait FrameGeneratorToken {
    fn acked(&mut self, conn: &mut Connection);
    fn lost(&mut self, conn: &mut Connection);
}

impl Debug for FrameGeneratorToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("<FrameGenerator Token>")
    }
}

#[derive(Debug)]
struct CryptoDxState {
    label: String,
    aead: Aead,
    hpkey: HpKey,
}

impl CryptoDxState {
    fn new<S: Into<String>>(label: S, secret: &SymKey, cipher: Cipher) -> CryptoDxState {
        qinfo!("Making CryptoDxState, cipher={}", cipher);
        CryptoDxState {
            label: label.into(),
            aead: Aead::new(TLS_VERSION_1_3, cipher, secret, "quic ").unwrap(),
            hpkey: extract_hp(TLS_VERSION_1_3, cipher, secret, "quic hp").unwrap(),
        }
    }

    fn new_initial<S: Into<String> + Clone>(label: S, dcid: &[u8]) -> CryptoDxState {
        let cipher = TLS_AES_128_GCM_SHA256;
        let initial_salt = Data::from_hex("ef4fb0abb47470c41befcf8031334fae485e09a0");
        let initial_secret = hkdf::extract(
            TLS_VERSION_1_3,
            cipher,
            Some(
                hkdf::import_key(TLS_VERSION_1_3, cipher, initial_salt.as_vec())
                    .as_ref()
                    .unwrap(),
            ),
            hkdf::import_key(TLS_VERSION_1_3, cipher, dcid)
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        let secret =
            hkdf::expand_label(TLS_VERSION_1_3, cipher, &initial_secret, &[], label.clone())
                .unwrap();

        CryptoDxState::new(label.clone(), &secret, cipher)
    }
}

#[derive(Debug)]
struct CryptoState {
    epoch: Epoch,
    rx: CryptoDxState,
    tx: CryptoDxState,
    recvd: Option<RecvdPackets>,
}

impl CryptoState {
    fn ensure_recvd_state(&mut self, pn: u64) -> &mut RecvdPackets {
        if self.recvd.is_none() {
            self.recvd = Some(RecvdPackets::new("label [TODO]", self.epoch, pn));
        }
        self.recvd.as_mut().unwrap()
    }

    fn recvd_state(&mut self) -> Option<&mut RecvdPackets> {
        self.recvd.as_mut()
    }
}
#[derive(Debug, Default)]
struct CryptoStream {
    tx: TxBuffer,
    rx: RxStreamOrderer,
}

#[derive(Clone, Debug, PartialEq)]
struct Path {
    local: SocketAddr,
    remote: SocketAddr,
}

impl Path {
    fn received_on(&self, d: &Datagram) -> bool {
        self.local == d.dst && self.remote == d.src
    }
}

impl From<&Datagram> for Path {
    fn from(d: &Datagram) -> Self {
        Path {
            local: d.dst,
            remote: d.src,
        }
    }
}

#[allow(unused_variables)]
pub struct Connection {
    version: crate::packet::Version,
    paths: Option<Path>,
    rol: Role,
    state: State,
    tls: Agent,
    tps: Rc<RefCell<TransportParametersHandler>>,
    scid: Vec<u8>,
    dcid: Vec<u8>,
    send_epoch: Epoch,
    recv_epoch: Epoch,
    crypto_streams: [CryptoStream; 4],
    crypto_states: [Option<CryptoState>; 4],
    tx_pns: [u64; 4],
    // TODO(ekr@rtfm.com): Prioritized generators, rather than a vec
    generators: Vec<Box<FrameGenerator>>,
    deadline: u64,
    max_data: u64,
    local_max_stream_idx_uni: StreamIndex,
    local_max_stream_idx_bidi: StreamIndex,
    local_next_stream_idx_uni: StreamIndex,
    local_next_stream_idx_bidi: StreamIndex,
    peer_max_stream_idx_uni: StreamIndex,
    peer_max_stream_idx_bidi: StreamIndex,
    peer_next_stream_idx_uni: StreamIndex,
    peer_next_stream_idx_bidi: StreamIndex,
    highest_stream: Option<u64>,
    connection_ids: HashSet<(u64, Vec<u8>)>, // (sequence number, connection id)
    send_streams: BTreeMap<StreamId, SendStream>,
    recv_streams: BTreeMap<StreamId, RecvStream>,
    pmtu: usize,
    flow_mgr: Rc<RefCell<FlowMgr>>,
    loss_recovery: LossRecovery,
    events: Rc<RefCell<ConnectionEvents>>,
}

impl Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{:?} Connection: {:?} {:?}",
            self.rol, self.state, self.paths
        ))
    }
}

impl Connection {
    pub fn new_client<S: ToString, PA: ToString, PI: IntoIterator<Item = PA>>(
        server_name: S,
        protocols: PI,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Res<Connection> {
        Ok(Connection::new(
            Role::Client,
            Client::new(server_name)?.into(),
            protocols,
            Some(Path {
                local: local_addr,
                remote: remote_addr,
            }),
        ))
    }

    pub fn new_server<
        CS: ToString,
        CI: IntoIterator<Item = CS>,
        PA: ToString,
        PI: IntoIterator<Item = PA>,
    >(
        certs: CI,
        protocols: PI,
    ) -> Res<Connection> {
        Ok(Connection::new(
            Role::Server,
            Server::new(certs)?.into(),
            protocols,
            None,
        ))
    }

    fn configure_agent<A: ToString, I: IntoIterator<Item = A>>(
        agent: &mut Agent,
        protocols: I,
        tphandler: Rc<RefCell<TransportParametersHandler>>,
    ) {
        agent
            .set_version_range(TLS_VERSION_1_3, TLS_VERSION_1_3)
            .expect("Could not enable TLS 1.3");
        agent
            .enable_ciphers(&[TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384])
            .expect("Could not set ciphers");
        agent
            .extension_handler(0xffa5, tphandler)
            .expect("Could not set extension handler");
        agent.set_alpn(protocols).expect("Could not set ALPN");
    }

    fn new<A: ToString, I: IntoIterator<Item = A>>(
        r: Role,
        mut agent: Agent,
        protocols: I,
        paths: Option<Path>,
    ) -> Connection {
        let tphandler = Rc::new(RefCell::new(TransportParametersHandler::default()));
        tphandler.borrow_mut().local.set_integer(
            TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            RX_STREAM_DATA_WINDOW,
        );
        tphandler.borrow_mut().local.set_integer(
            TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            RX_STREAM_DATA_WINDOW,
        );
        tphandler.borrow_mut().local.set_integer(
            TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNI,
            RX_STREAM_DATA_WINDOW,
        );
        tphandler.borrow_mut().local.set_integer(
            TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_BIDI,
            LOCAL_STREAM_LIMIT_BIDI,
        );
        tphandler.borrow_mut().local.set_integer(
            TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_UNI,
            LOCAL_STREAM_LIMIT_UNI,
        );

        Connection::configure_agent(&mut agent, protocols, tphandler.clone());

        let mut c = Connection {
            version: QUIC_VERSION,
            paths,
            rol: r,
            state: match r {
                Role::Client => State::Init,
                Role::Server => State::WaitInitial,
            },
            tls: agent,
            tps: tphandler,
            scid: Vec::new(),
            dcid: Vec::new(),
            send_epoch: 0,
            recv_epoch: 0,
            crypto_streams: [
                CryptoStream::default(),
                CryptoStream::default(),
                CryptoStream::default(),
                CryptoStream::default(),
            ],
            generators: vec![
                Box::new(CryptoGenerator {}),
                Box::new(FlowControlGenerator {}),
                Box::new(StreamGenerator {}),
            ],
            crypto_states: [None, None, None, None],
            tx_pns: [0; 4],
            deadline: 0,
            max_data: 0,
            local_max_stream_idx_bidi: StreamIndex::new(LOCAL_STREAM_LIMIT_BIDI),
            local_max_stream_idx_uni: StreamIndex::new(LOCAL_STREAM_LIMIT_UNI),
            local_next_stream_idx_uni: StreamIndex::new(0),
            local_next_stream_idx_bidi: StreamIndex::new(0),
            peer_max_stream_idx_bidi: StreamIndex::new(0),
            peer_max_stream_idx_uni: StreamIndex::new(0),
            peer_next_stream_idx_uni: StreamIndex::new(0),
            peer_next_stream_idx_bidi: StreamIndex::new(0),
            highest_stream: None,
            connection_ids: HashSet::new(),
            send_streams: BTreeMap::new(),
            recv_streams: BTreeMap::new(),
            pmtu: 1280,
            flow_mgr: Rc::new(RefCell::new(FlowMgr::default())),
            loss_recovery: LossRecovery::new(),
            events: Rc::new(RefCell::new(ConnectionEvents::default())),
        };

        c.scid = c.generate_cid();
        if c.rol == Role::Client {
            let dcid = c.generate_cid();
            c.create_initial_crypto_state(&dcid);
            c.dcid = dcid;
        }

        c
    }

    /// Set ALPN preferences. Strings that appear earlier in the list are given
    /// higher preference.
    pub fn set_alpn<A: ToString, I: IntoIterator<Item = A>>(&mut self, protocols: I) -> Res<()> {
        self.tls.set_alpn(protocols)?;
        Ok(())
    }

    /// Get the current role.
    pub fn role(&self) -> Role {
        self.rol
    }

    /// Get the state of the connection.
    pub fn state(&self) -> &State {
        &self.state
    }

    // This function wraps a call to another function and sets the connection state
    // properly if that call fails.
    fn capture_error<T>(&mut self, frame_type: FrameType, res: Res<T>) -> Res<T> {
        if let Err(v) = &res {
            #[cfg(debug_assertions)]
            let msg = String::from(format!("{:?}", v));
            #[cfg(not(debug_assertions))]
            let msg = String::from("");
            self.set_state(State::Closing(
                ConnectionError::Transport(v.clone()),
                frame_type,
                msg,
            ));
        }
        res
    }

    /// For use with process().  Errors there can be ignored, but this needs to
    /// ensure that the state is updated.
    fn absorb_error(&mut self, res: Res<()>) {
        let _ = self.capture_error(0, res);
    }

    /// Call in to process activity on the connection. Either new packets have
    /// arrived or a timeout has expired (or both).
    pub fn process_input<I>(&mut self, in_dgrams: I, cur_time: u64)
    where
        I: IntoIterator<Item = Datagram>,
    {
        for dgram in in_dgrams {
            let res = self.input(dgram, cur_time);
            self.absorb_error(res);
        }

        self.cleanup_streams();

        if cur_time >= self.deadline {
            // Timer expired.
            match self.state {
                State::Init => {
                    let res = self.client_start();
                    self.absorb_error(res);
                }
                _ => {
                    // Nothing to do.
                }
            }
        }
    }

    /// Get output packets, as a result of receiving packets, or actions taken
    /// by the application.
    pub fn process_output(&mut self, cur_time: u64) -> (Vec<Datagram>, u64) {
        if let State::Closed(..) = self.state {
            (Vec::new(), 0)
        } else {
            self.check_loss_detection_timeout(cur_time);
            (self.output(cur_time), self.loss_recovery.get_timer())
        }
    }

    /// Process input and generate output.
    pub fn process<I>(&mut self, in_dgrams: I, cur_time: u64) -> (Vec<Datagram>, u64)
    where
        I: IntoIterator<Item = Datagram>,
    {
        self.process_input(in_dgrams, cur_time);
        self.process_output(cur_time)
    }

    fn valid_cid(&self, cid: &[u8]) -> bool {
        &self.scid[..] == cid
    }

    fn input(&mut self, d: Datagram, cur_time: u64) -> Res<()> {
        let mut slc = &d[..];

        qdebug!(self, "input {}", hex("", &**d));

        // Handle each packet in the datagram
        while !slc.is_empty() {
            let mut hdr = match decode_packet_hdr(self, slc) {
                Ok(h) => h,
                _ => {
                    qinfo!(self, "Received indecipherable packet header {:?}", slc);
                    return Ok(()); // Drop the remainder of the datagram.
                }
            };

            // TODO(ekr@rtfm.com): Check for bogus versions and reject.
            match self.state {
                State::Init => {
                    qinfo!(self, "Received message while in Init state");
                    return Ok(());
                }
                State::WaitInitial => {
                    // Out DCID is the other side's SCID.
                    let scid = &hdr.scid.as_ref().unwrap().0;
                    if self.rol == Role::Server {
                        if hdr.dcid.len() < 8 {
                            qwarn!(self, "Peer DCID is too short");
                            return Ok(());
                        }
                        self.create_initial_crypto_state(&hdr.dcid);
                    }

                    // Imprint on the remote parameters.
                    self.dcid = scid.clone();
                }
                State::Handshaking | State::Connected => {
                    if !self.valid_cid(&hdr.dcid[..]) {
                        qinfo!(self, "Bad CID {:?}", hdr.dcid);
                        return Ok(());
                    }
                }
                State::Closing(..) | State::Closed(..) => {
                    // Don't bother processing the packet.
                    // output() will generate a new closing packet.
                    return Ok(());
                }
            }

            qdebug!(self, "Received unverified packet {:?}", hdr);

            // Decryption failure, or not having keys is not fatal.
            // If the state isn't available, or we can't decrypt the packet, drop
            // the rest of the datagram on the floor, but don't generate an error.
            // TODO(ekr@rtfm.com): This is incorrect, you need to try to process
            // the other packets.
            let res = match self.ensure_crypto_state(hdr.epoch) {
                Ok(cs) => decrypt_packet(&cs.rx, &PnCtx {}, &mut hdr, slc),
                Err(e) => Err(e),
            };
            slc = &slc[hdr.hdr_len + hdr.body_len()..];
            let body = match res {
                Ok(b) => b,
                _ => {
                    // TODO(mt): Check for stateless reset, which is fatal.
                    continue;
                }
            };

            // TODO(ekr@rtfm.com): Have the server blow away the initial
            // crypto state if this fails? Otherwise, we will get a panic
            // on the assert for doesn't exist.
            // OK, we have a valid packet.

            // TODO(ekr@rtfm.com): Check for duplicates.
            // TODO(ekr@rtfm.com): Mark this packet received.
            // TODO(ekr@rtfm.com): Filter for valid for this epoch.

            if matches!(self.state, State::WaitInitial) {
                self.set_state(State::Handshaking);
            }

            let ack_eliciting = self.input_packet(hdr.epoch, Data::from_slice(&body), cur_time)?;

            // Mark the packet as received.
            self.ensure_crypto_state(hdr.epoch)
                .as_mut()
                .unwrap()
                .ensure_recvd_state(hdr.pn)
                .set_received(cur_time, hdr.pn, ack_eliciting);

            match &self.paths {
                None => {
                    self.paths = Some(Path::from(&d));
                }
                Some(p) => {
                    if !p.received_on(&d) {
                        // Right now, we don't support any form of migration.
                        return Err(Error::InvalidMigration);
                    }
                }
            }
        }

        Ok(())
    }

    // Return whether the packet had ack-eliciting frames.
    fn input_packet(&mut self, epoch: Epoch, mut d: Data, cur_time: u64) -> Res<(bool)> {
        let mut ack_eliciting = false;

        // Handle each frame in the packet
        while d.remaining() > 0 {
            let f = decode_frame(&mut d)?;
            ack_eliciting |= f.ack_eliciting();
            let t = f.get_type();
            let res = self.input_frame(epoch, f, cur_time);
            self.capture_error(t, res)?;
        }

        Ok(ack_eliciting)
    }

    fn output(&mut self, cur_time: u64) -> Vec<Datagram> {
        // Can't iterate over self.paths while it is owned by self.
        let paths = mem::replace(&mut self.paths, None);
        let mut out_dgrams = Vec::new();
        let mut errors = Vec::new();
        for p in &paths {
            let res = match self.output_path(&p, cur_time) {
                Ok(ref mut dgrams) => out_dgrams.append(dgrams),
                Err(e) => errors.push(e),
            };
        }
        self.paths = paths;

        let closing = match self.state {
            State::Closing(..) => true,
            _ => false,
        };
        if !closing && errors.len() > 0 {
            self.absorb_error(Err(errors.pop().unwrap()));
            // We just closed, so run this again to produce CONNECTION_CLOSE.
            self.output(cur_time)
        } else {
            out_dgrams // TODO(ekr@rtfm.com): When to call back next.
        }
    }

    // Iterate through all the generators, inserting as many frames as will
    // fit.
    fn output_path(&mut self, path: &Path, cur_time: u64) -> Res<Vec<Datagram>> {
        let mut out_packets = Vec::new();

        let mut num_initials = 0usize;

        // Frames for different epochs must go in different packets, but then these
        // packets can go in a single datagram
        for epoch in 0..NUM_EPOCHS {
            let mut d = Data::default();
            let mut ds = Vec::new();
            let mut tokens = Vec::new();
            // Try to make our own crypo state and if we can't, skip this
            // epoch.
            if self.ensure_crypto_state(epoch).is_err() {
                continue;
            }

            if let Some(recvd) = self
                .ensure_crypto_state(epoch)
                .as_mut()
                .unwrap()
                .recvd_state()
            {
                let acks = recvd.get_eligible_ack_ranges();
                Frame::encode_ack_frame(&acks, &mut d);
                // TODO(ekr@rtfm.com): Deal with the case where ACKs don't fit
                // in an entire packet.
                assert!(d.written() <= self.pmtu);
            }

            let mut ack_eliciting = false;
            let mut is_crypto_packet = false;
            // Copy generators out so that we can iterate over it and pass
            // self to the functions.
            let mut generators = mem::replace(&mut self.generators, Vec::new());
            for generator in &mut generators {
                // TODO(ekr@rtfm.com): Fix TxMode
                while let Some((frame, token)) =
                    generator.generate(self, epoch, TxMode::Normal, self.pmtu - d.written())
                {
                    //qtrace!("pmtu {} written {}", self.pmtu, d.written());
                    ack_eliciting = ack_eliciting || frame.ack_eliciting();
                    is_crypto_packet = match frame {
                        Frame::Crypto { .. } => true,
                        _ => is_crypto_packet,
                    };
                    frame.marshal(&mut d);
                    assert!(d.written() <= self.pmtu);
                    if d.written() == self.pmtu {
                        // Filled this packet, get another one.
                        ds.push((d, (ack_eliciting, is_crypto_packet, tokens)));
                        d = Data::default();
                        tokens = Vec::new();
                        ack_eliciting = false;
                        is_crypto_packet = false;
                    }
                    if let Some(t) = token {
                        tokens.push(t);
                    }
                }
            }
            self.generators = generators;

            if d.written() > 0 {
                ds.push((d, (ack_eliciting, is_crypto_packet, tokens)))
            }

            for mut d in ds {
                qdebug!(self, "Need to send a packet");

                let mut hdr = PacketHdr::new(
                    0,
                    match epoch {
                        // TODO(ekr@rtfm.com): Retry token
                        0 => {
                            num_initials += 1;
                            PacketType::Initial(Vec::new())
                        }
                        1 => PacketType::ZeroRTT,
                        2 => PacketType::Handshake,
                        3 => PacketType::Short,
                        _ => unimplemented!(), // TODO(ekr@rtfm.com): Key Update.
                    },
                    Some(self.version),
                    ConnectionId(self.dcid.clone()),
                    Some(ConnectionId(self.scid.clone())),
                    self.tx_pns[Connection::pn_space(epoch) as usize],
                    epoch,
                    0,
                );
                self.tx_pns[Connection::pn_space(epoch) as usize] += 1;

                self.loss_recovery.on_packet_sent(
                    Connection::pn_space(epoch),
                    hdr.pn,
                    (d.1).0,
                    (d.1).1,
                    (d.1).2,
                    cur_time,
                );

                // Failure to have the state here is an internal error.
                let cs = self.ensure_crypto_state(hdr.epoch).unwrap();
                let packet = encode_packet(&cs.tx, &mut hdr, d.0.as_mut_vec());
                out_packets.push(packet);

                // TODO(ekr@rtfm.com): Pad the Client Initial.
            }
        }

        // Put packets in UDP datagrams
        let mut out_dgrams = out_packets
            .into_iter()
            .inspect(|p| qdebug!(self, "{}", hex("Packet", p)))
            .fold(Vec::new(), |mut vec: Vec<Datagram>, packet| {
                let new_dgram: bool = vec
                    .last()
                    .map(|dgram| dgram.len() + packet.len() > self.pmtu)
                    .unwrap_or(true);
                if new_dgram {
                    vec.push(Datagram::new(path.local, path.remote, packet));
                } else {
                    vec.last_mut().unwrap().d.extend(packet);
                }
                vec
            });

        // Kludgy padding
        if self.rol == Role::Client {
            for dgram in &mut out_dgrams[..num_initials] {
                dgram.resize(1200, 0);
            }
        }

        out_dgrams
            .iter()
            .for_each(|dgram| qdebug!(self, "Datagram length: {}", dgram.len()));

        return Ok(out_dgrams);
    }

    fn client_start(&mut self) -> Res<()> {
        self.handshake(0, None)?;
        self.set_state(State::WaitInitial);
        Ok(())
    }

    fn send_close(&self) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        if let State::Closing(cerr, frame_type, reason) = self.state() {
            Some((
                Frame::ConnectionClose {
                    close_type: cerr.into(),
                    error_code: match cerr {
                        ConnectionError::Application(e) => *e,
                        ConnectionError::Transport(e) => e.code(),
                    },
                    frame_type: *frame_type,
                    reason_phrase: Vec::from(reason.clone()),
                },
                None,
            ))
        } else {
            None
        }
    }

    pub fn close<S: Into<String>>(&mut self, error: AppError, msg: S) {
        // TODO(mt): Set closing timer.
        self.set_state(State::Closing(
            ConnectionError::Application(error),
            0,
            msg.into(),
        ));
    }

    fn handshake(&mut self, epoch: u16, data: Option<&[u8]>) -> Res<()> {
        qdebug!("Handshake epoch={} data={:0x?}", epoch, data);
        let mut rec: Option<Record> = None;

        if let Some(d) = data {
            qdebug!(self, "Handshake received {:0x?} ", d);
            rec = Some(Record {
                ct: 22, // TODO(ekr@rtfm.com): Symbolic constants for CT. This is handshake.
                epoch,
                data: d.to_vec(),
            });
        }

        let mut m = self.tls.handshake_raw(0, rec);

        if matches!(m, Ok(_)) && *self.tls.state() == HandshakeState::AuthenticationPending {
            // TODO(ekr@rtfm.com): IMPORTANT: This overrides
            // authentication and so is fantastically dangerous.
            // Fix before shipping.
            qwarn!(self, "marking connection as authenticated without checking");
            self.tls.authenticated();
            m = self.tls.handshake_raw(0, None);
        }
        match m {
            Err(e) => {
                qwarn!(self, "Handshake failed");
                return Err(match self.tls.alert() {
                    Some(a) => Error::CryptoAlert(*a),
                    _ => Error::CryptoError(e),
                });
            }
            Ok(msgs) => {
                for m in msgs {
                    qdebug!(self, "Inserting message {:?}", m);
                    assert_eq!(m.ct, 22);
                    self.crypto_streams[m.epoch as usize].tx.send(&m.data);
                }
            }
        }
        if self.tls.state().connected() {
            qinfo!(self, "TLS handshake completed");
            self.set_state(State::Connected);

            self.peer_max_stream_idx_bidi = StreamIndex::new(
                self.tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_BIDI),
            );

            self.peer_max_stream_idx_uni = StreamIndex::new(
                self.tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_UNI),
            );
        }
        Ok(())
    }

    pub fn input_frame(&mut self, epoch: Epoch, frame: Frame, cur_time: u64) -> Res<()> {
        #[allow(unused_variables)]
        match frame {
            Frame::Padding => {
                // Ignore
            }
            Frame::Ping => {
                // Ack elicited with no further handling needed
            }
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
            } => {
                self.handle_ack(
                    epoch,
                    largest_acknowledged,
                    ack_delay,
                    first_ack_range,
                    &ack_ranges,
                    cur_time,
                )?;
            }
            Frame::ResetStream {
                stream_id,
                application_error_code,
                final_size,
            } => {
                let stream = self
                    .recv_streams
                    .get_mut(&stream_id.into())
                    .ok_or_else(|| return Error::InvalidStreamId)?;

                // TODO(agrover@mozilla.com): use final_size for connection MaxData calc
                stream.reset(application_error_code);
            }
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => {
                let stream = self
                    .send_streams
                    .get_mut(&stream_id.into())
                    .ok_or_else(|| return Error::InvalidStreamId)?;

                stream.reset(application_error_code);
            }
            Frame::Crypto { offset, data } => {
                qdebug!(
                    self,
                    "Crypto frame on epoch={} offset={}, data={:0x?}",
                    epoch,
                    offset,
                    &data
                );
                let rx = &mut self.crypto_streams[epoch as usize].rx;
                rx.inbound_frame(offset, data)?;
                if rx.data_ready() {
                    let mut buf = Vec::new();
                    let read = rx.read_to_end(&mut buf)?;
                    qdebug!("Read {} bytes", read);
                    self.handshake(epoch, Some(&buf))?;
                }
            }
            Frame::NewToken { token } => {} // TODO(agrover@mozilla.com): stick the new token somewhere
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
            } => {
                if let Some(rs) = self.obtain_stream(stream_id.into())? {
                    rs.inbound_stream_frame(fin, offset, data)?;
                }
            }
            Frame::MaxData { maximum_data } => self.max_data = max(self.max_data, maximum_data),
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                if let Some(stream) = self.send_streams.get_mut(&stream_id.into()) {
                    stream.max_stream_data(maximum_stream_data);
                }
            }
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {
                let peer_max = match stream_type {
                    StreamType::BiDi => &mut self.peer_max_stream_idx_bidi,
                    StreamType::UniDi => &mut self.peer_max_stream_idx_uni,
                };

                if maximum_streams > *peer_max {
                    *peer_max = maximum_streams;
                    self.events.borrow_mut().send_stream_creatable(stream_type);
                }
            }
            Frame::DataBlocked { data_limit } => {} // TODO(agrover@mozilla.com): use as input to flow control algorithms
            Frame::StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => {
                // TODO(agrover@mozilla.com): terminate connection with
                // SEND_STREAM_ERROR if send-only stream (-transport 19.13)

                // TODO(agrover@mozilla.com): how should we be using
                // currently-unused stream_data_limit?

                if let Some(stream) = self.recv_streams.get_mut(&stream_id.into()) {
                    stream.maybe_send_flowc_update();
                }
            }
            Frame::StreamsBlocked {
                stream_type,
                stream_limit,
            } => {
                let local_max = match stream_type {
                    StreamType::BiDi => &mut self.local_max_stream_idx_bidi,
                    StreamType::UniDi => &mut self.local_max_stream_idx_uni,
                };

                self.flow_mgr
                    .borrow_mut()
                    .max_streams(*local_max, stream_type)
            }
            Frame::NewConnectionId {
                sequence_number,
                connection_id,
                stateless_reset_token,
            } => {
                self.connection_ids.insert((sequence_number, connection_id));
            }
            Frame::RetireConnectionId { sequence_number } => {
                //self.connection_ids.insert((sequence_number, connection_id));
            } // TODO(agrover@mozilla.com): remove from list of connection IDs
            Frame::PathChallenge { data } => {} // TODO(agrover@mozilla.com): generate PATH_RESPONSE
            Frame::PathResponse { data } => {}  // TODO(agrover@mozilla.com): do something
            Frame::ConnectionClose {
                close_type,
                error_code,
                frame_type,
                reason_phrase,
            } => {} // TODO(agrover@mozilla.com): close the connection
        };

        Ok(())
    }

    fn handle_ack(
        &mut self,
        epoch: Epoch,
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: &Vec<AckRange>,
        cur_time: u64,
    ) -> Res<()> {
        qinfo!(
            self,
            "Rx ACK epoch={}, largest_acked={}, first_ack_range={}, ranges={:?}",
            epoch,
            largest_acknowledged,
            first_ack_range,
            ack_ranges
        );

        let acked_ranges =
            Frame::decode_ack_frame(largest_acknowledged, first_ack_range, ack_ranges)?;
        let (mut acked_packets, mut lost_packets) = self.loss_recovery.on_ack_received(
            Connection::pn_space(epoch),
            largest_acknowledged,
            acked_ranges,
            ack_delay,
            cur_time,
        );
        for acked in acked_packets.iter_mut() {
            acked.mark_acked(self);
        }
        for lost in lost_packets.iter_mut() {
            lost.mark_lost(self);
        }

        Ok(())
    }

    fn set_state(&mut self, state: State) {
        if state != self.state {
            qinfo!(self, "State change from {:?} -> {:?}", self.state, state);
            self.state = state;
            match &self.state {
                State::Connected => {
                    if let None = match self.tls.info() {
                        Some(i) => i.alpn(),
                        _ => None,
                    } {
                        // 120 = no_application_protocol
                        let err = Error::CryptoAlert(120);
                        self.set_state(State::Closing(
                            ConnectionError::Transport(err),
                            0,
                            String::from("no ALPN"),
                        ));
                    }
                }
                State::Closing(..) => {
                    self.generators.clear();
                    self.generators.push(Box::new(CloseGenerator {}));
                }
                _ => {}
            }
        }
    }

    // Create the initial crypto state.
    fn create_initial_crypto_state(&mut self, dcid: &[u8]) {
        qinfo!(
            self,
            "Creating initial cipher state role={:?} {}",
            self.rol,
            hex("DCID", dcid)
        );
        //assert!(matches!(None, self.crypto_states[0]));

        let cds = CryptoDxState::new_initial("client in", dcid);
        let sds = CryptoDxState::new_initial("server in", dcid);

        self.crypto_states[0] = Some(match self.rol {
            Role::Client => CryptoState {
                epoch: 0,
                tx: cds,
                rx: sds,
                recvd: None,
            },
            Role::Server => CryptoState {
                epoch: 0,
                tx: sds,
                rx: cds,
                recvd: None,
            },
        });
    }

    // Get a crypto state, making it if possible, otherwise return an error.
    fn ensure_crypto_state(&mut self, epoch: Epoch) -> Res<&mut CryptoState> {
        let cs = &self.crypto_states[epoch as usize];

        // Note: I had originally written an early return, but the
        // familiar non-lexical lifetimes Rust bug for returns
        // tripped me up, so I went with this.
        if matches!(cs, None) {
            qinfo!(self, "No crypto state for epoch {}", epoch);
            assert!(epoch != 0); // This state is made directly.

            let rso = self.tls.read_secret(epoch);
            if matches!(rso, None) {
                qinfo!(self, "Keying material not available for epoch {}", epoch);
                return Err(Error::KeysNotFound);
            }
            let rs = rso.unwrap();
            // This must succced because the secrets are made at the same time.
            let ws = self.tls.write_secret(epoch).unwrap();

            // TODO(ekr@rtfm.com): The match covers up a bug in
            // neqo-crypto where we set up the state too late. Fix when that
            // gets fixed.
            let cipher = match self.tls.info().as_ref() {
                Some(info) => info.cipher_suite(),
                None => TLS_AES_128_GCM_SHA256 as u16,
            };
            self.crypto_states[epoch as usize] = Some(CryptoState {
                epoch: epoch,
                rx: CryptoDxState::new(format!("read_epoch={}", epoch), rs, cipher),
                tx: CryptoDxState::new(format!("write_epoch={}", epoch), ws, cipher),
                recvd: None,
            });
        }

        Ok(self.crypto_states[epoch as usize].as_mut().unwrap())
    }

    fn pn_space(epoch: Epoch) -> PNSpace {
        match epoch {
            0 => PNSpace::Initial,
            1 => PNSpace::ApplicationData,
            2 => PNSpace::Handshake,
            _ => PNSpace::ApplicationData,
        }
    }

    fn cleanup_streams(&mut self) {
        let recv_to_remove = self
            .recv_streams
            .iter()
            .filter(|(_, stream)| stream.is_terminal())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();

        let mut removed_bidi = 0;
        let mut removed_uni = 0;
        for id in &recv_to_remove {
            self.recv_streams.remove(&id);
            if id.is_peer_initiated(self.role()) {
                if id.is_bidi() {
                    removed_bidi += 1;
                } else {
                    removed_uni += 1;
                }
            }
        }

        // Send max_streams updates if we removed peer-initiated recv streams.
        if removed_bidi > 0 {
            self.local_max_stream_idx_bidi += removed_bidi;
            self.flow_mgr
                .borrow_mut()
                .max_streams(self.local_max_stream_idx_bidi, StreamType::BiDi)
        }
        if removed_uni > 0 {
            self.local_max_stream_idx_uni += removed_uni;
            self.flow_mgr
                .borrow_mut()
                .max_streams(self.local_max_stream_idx_uni, StreamType::UniDi)
        }

        let send_to_remove = self
            .send_streams
            .iter()
            .filter(|(_, stream)| stream.is_terminal())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();

        for id in send_to_remove {
            self.send_streams.remove(&id);
        }
    }

    /// Get or make a stream.
    fn obtain_stream(&mut self, stream_id: StreamId) -> Res<Option<&mut RecvStream>> {
        let next_stream_idx = if stream_id.is_bidi() {
            &mut self.local_next_stream_idx_bidi
        } else {
            &mut self.local_next_stream_idx_uni
        };
        let stream_idx: StreamIndex = stream_id.into();

        if stream_idx >= *next_stream_idx {
            // Creating new stream(s)
            match (stream_id.is_client_initiated(), self.rol) {
                (true, Role::Client) | (false, Role::Server) => {
                    qwarn!(
                        "Peer attempted to create local stream: {}",
                        stream_id.as_u64()
                    );
                    return Err(Error::ProtocolViolation);
                }
                _ => {}
            }

            let recv_initial_max_stream_data = if stream_id.is_bidi() {
                if stream_idx > self.local_max_stream_idx_bidi {
                    return Err(Error::StreamLimitError);
                }
                self.tps
                    .borrow()
                    .local
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
            } else {
                if stream_idx > self.local_max_stream_idx_uni {
                    return Err(Error::StreamLimitError);
                }
                self.tps
                    .borrow()
                    .local
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNI)
            };

            loop {
                let next_stream_id =
                    next_stream_idx.to_stream_id(stream_id.stream_type(), stream_id.role());
                self.recv_streams.insert(
                    next_stream_id,
                    RecvStream::new(
                        next_stream_id,
                        recv_initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );

                if next_stream_id.is_uni() {
                    self.events
                        .borrow_mut()
                        .new_stream(next_stream_id, StreamType::UniDi);
                } else {
                    let send_initial_max_stream_data = self
                        .tps
                        .borrow()
                        .remote
                        .as_ref()
                        .expect("remote tparams are valid when State::Connected")
                        .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
                    self.send_streams.insert(
                        next_stream_id,
                        SendStream::new(
                            next_stream_id,
                            send_initial_max_stream_data,
                            self.flow_mgr.clone(),
                            self.events.clone(),
                        ),
                    );
                    self.events
                        .borrow_mut()
                        .new_stream(next_stream_id, StreamType::BiDi);
                }

                *next_stream_idx += 1;
                if *next_stream_idx > stream_idx {
                    break;
                }
            }
        }

        Ok(self.recv_streams.get_mut(&stream_id))
    }

    // Returns new stream id
    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        // Can't make streams before remote tparams are received as part of
        // handshake
        if self.state != State::Connected {
            return Err(Error::ConnectionState);
        }

        Ok(match st {
            StreamType::UniDi => {
                if self.peer_next_stream_idx_uni >= self.peer_max_stream_idx_uni {
                    self.flow_mgr
                        .borrow_mut()
                        .streams_blocked(self.peer_max_stream_idx_uni, StreamType::UniDi);
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .peer_next_stream_idx_uni
                    .to_stream_id(StreamType::UniDi, self.rol);
                self.peer_next_stream_idx_uni += 1;
                let initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNI);

                self.send_streams.insert(
                    new_id,
                    SendStream::new(
                        new_id,
                        initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );
                new_id.as_u64()
            }
            StreamType::BiDi => {
                if self.peer_next_stream_idx_bidi >= self.peer_max_stream_idx_bidi {
                    self.flow_mgr
                        .borrow_mut()
                        .streams_blocked(self.peer_max_stream_idx_bidi, StreamType::BiDi);
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .peer_next_stream_idx_bidi
                    .to_stream_id(StreamType::BiDi, self.rol);
                self.peer_next_stream_idx_bidi += 1;
                let send_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);

                self.send_streams.insert(
                    new_id,
                    SendStream::new(
                        new_id,
                        send_initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );

                let recv_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .local
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);

                self.recv_streams.insert(
                    new_id,
                    RecvStream::new(
                        new_id,
                        recv_initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );
                new_id.as_u64()
            }
        })
    }

    /// Send data on a stream.
    /// Returns how many bytes were successfully sent. Could be less
    /// than total, based on receiver credit space available, etc.
    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Res<usize> {
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| return Error::InvalidStreamId)?;

        stream.send(data)
    }

    pub fn stream_recv(&mut self, stream_id: u64, data: &mut [u8]) -> Res<(usize, bool)> {
        let stream = self
            .recv_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| return Error::InvalidStreamId)?;

        let rb = stream.read(data)?;
        Ok((rb.0 as usize, rb.1))
    }

    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| return Error::InvalidStreamId)?;

        Sendable::close(stream);
        Ok(())
    }

    pub fn stream_reset(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        // TODO(agrover@mozilla.com): reset can create a stream
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| return Error::InvalidStreamId)?;

        Ok(stream.reset(err))
    }

    fn generate_cid(&mut self) -> Vec<u8> {
        let mut v: [u8; 8] = [0; 8];
        rand::thread_rng().fill(&mut v);
        v.to_vec()
    }

    pub fn get_recv_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Recvable)> {
        self.recv_streams
            .iter_mut()
            .map(|(x, y)| (x.as_u64(), y as &mut Recvable))
    }

    pub fn get_recvable_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Recvable)> {
        self.get_recv_streams()
            .filter(|(_, stream)| stream.data_ready())
    }

    pub fn get_send_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Sendable)> {
        self.send_streams
            .iter_mut()
            .map(|(x, y)| (x.as_u64(), y as &mut Sendable))
    }

    pub fn get_sendable_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Sendable)> {
        self.get_send_streams()
            .filter(|(_, stream)| stream.send_data_ready())
    }

    pub fn get_recv_stream_mut(&mut self, stream_id: u64) -> Option<&mut Recvable> {
        self.recv_streams
            .get_mut(&stream_id.into())
            .map(|rs| rs as &mut Recvable)
    }

    pub fn get_send_stream_mut(&mut self, stream_id: u64) -> Option<&mut Sendable> {
        self.send_streams
            .get_mut(&stream_id.into())
            .map(|rs| rs as &mut Sendable)
    }

    pub fn events(&mut self) -> Vec<ConnectionEvent> {
        // Turn it into a vec for simplicity's sake
        self.events.borrow_mut().events().into_iter().collect()
    }

    fn check_loss_detection_timeout(&mut self, cur_time: u64) {
        qdebug!(self, "check_loss_detection_timeout");
        let (mut lost_packets, retransmit_unacked_crypto, send_one_or_two_packets) =
            self.loss_recovery.on_loss_detection_timeout(cur_time);
        if lost_packets.len() > 0 {
            qdebug!(self, "check_loss_detection_timeout loss detected.");
            for lost in lost_packets.iter_mut() {
                lost.mark_lost(self);
            }
        } else if retransmit_unacked_crypto {
            qdebug!(
                self,
                "check_loss_detection_timeout - retransmit_unacked_crypto"
            );
        // TOOD
        } else if send_one_or_two_packets {
            qdebug!(
                self,
                "check_loss_detection_timeout -send_one_or_two_packets"
            );
            // TODO
        }
    }
}

impl ::std::fmt::Display for Connection {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?} {:p}", self.rol, self as *const Connection)
    }
}

impl CryptoCtx for CryptoDxState {
    fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>> {
        let mask = self.hpkey.mask(sample)?;
        qdebug!("HP {} {}", hex("sample", sample), hex("mask", &mask));
        Ok(mask)
    }

    fn aead_decrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
        qinfo!(
            "aead_decrypt label={} pn={} {} {}",
            &self.label,
            pn,
            hex("hdr", hdr),
            hex("body", body)
        );
        let mut out = Vec::with_capacity(body.len());
        out.resize(body.len(), 0);
        let res = self.aead.decrypt(pn, hdr, body, &mut out)?;
        Ok(res.to_vec())
    }

    fn aead_encrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
        qinfo!(
            "aead_encrypt label={} pn={} {} {}",
            self.label,
            pn,
            hex("hdr", hdr),
            hex("body", body)
        );

        let size = body.len() + MAX_AUTH_TAG;
        let mut out = Vec::with_capacity(size);
        out.resize(size, 0);
        let res = self.aead.encrypt(pn, hdr, body, &mut out)?;

        qdebug!("aead_encrypt {}", hex("ct", res),);

        Ok(res.to_vec())
    }
}

impl PacketDecoder for Connection {
    fn get_cid_len(&self) -> usize {
        8
    }
}

// TODO(ekr@rtfm.com): Really implement this.
// TODO(ekr@rtfm.com): This is a kludge.
struct PnCtx {}
impl PacketNumberCtx for PnCtx {
    fn decode_pn(&self, pn: u64) -> Res<PacketNumber> {
        Ok(pn)
    }
}

struct CryptoGenerator {}

impl FrameGenerator for CryptoGenerator {
    fn generate(
        &mut self,
        conn: &mut Connection,
        epoch: u16,
        mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        let tx_stream = &mut conn.crypto_streams[epoch as usize].tx;
        if let Some((offset, data)) = tx_stream.next_bytes(mode) {
            let data_len = data.len();
            let frame = Frame::Crypto {
                offset,
                data: data.to_vec(),
            };
            tx_stream.mark_as_sent(offset, data_len);

            qdebug!(
                conn,
                "Emitting crypto frame epoch={}, offset={}, len={}",
                epoch,
                offset,
                data_len
            );
            Some((
                frame,
                Some(Box::new(CryptoGeneratorToken {
                    epoch: epoch,
                    offset: offset,
                    length: data_len as u64,
                })),
            ))
        } else {
            None
        }
    }
}

struct CryptoGeneratorToken {
    epoch: u16,
    offset: u64,
    length: u64,
}

impl FrameGeneratorToken for CryptoGeneratorToken {
    fn acked(&mut self, conn: &mut Connection) {
        qinfo!(
            conn,
            "Acked crypto frame epoch={} offset={} length={}",
            self.epoch,
            self.offset,
            self.length
        );
        conn.crypto_streams[self.epoch as usize]
            .tx
            .mark_as_acked(self.offset, self.length as usize);
    }
    fn lost(&mut self, conn: &mut Connection) {}
}

struct CloseGenerator {}

impl FrameGenerator for CloseGenerator {
    fn generate(
        &mut self,
        c: &mut Connection,
        e: Epoch,
        mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        c.send_close()
    }
}

/// Calculate the frame header size so we know how much data we can fit
fn stream_frame_hdr_len(stream_id: StreamId, offset: u64, remaining: usize) -> usize {
    let mut hdr_len = 1; // for frame type
    hdr_len += get_varint_len(stream_id.as_u64());
    if offset > 0 {
        hdr_len += get_varint_len(offset);
    }

    // We always specify length
    hdr_len as usize + get_varint_len(remaining as u64) as usize
}

struct StreamGenerator {}

impl FrameGenerator for StreamGenerator {
    fn generate(
        &mut self,
        conn: &mut Connection,
        epoch: u16,
        mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        // only send in 1rtt epoch?
        if epoch != 3 {
            return None;
        }

        for (stream_id, stream) in &mut conn.send_streams {
            if stream.send_data_ready() {
                let fin = stream.final_size();
                if let Some((offset, data)) = stream.next_bytes(mode) {
                    qtrace!(
                        "Stream {} sending bytes {}-{}, epoch {}, mode {:?}, remaining {}",
                        stream_id.as_u64(),
                        offset,
                        offset + data.len() as u64,
                        epoch,
                        mode,
                        remaining
                    );
                    let frame_hdr_len = stream_frame_hdr_len(*stream_id, offset, remaining);
                    let data_len = min(data.len(), remaining - frame_hdr_len);
                    let fin = match fin {
                        None => false,
                        Some(fin) => fin == offset + data_len as u64,
                    };
                    let frame = Frame::Stream {
                        fin,
                        stream_id: stream_id.as_u64(),
                        offset,
                        data: data[..data_len].to_vec(),
                    };
                    stream.mark_as_sent(offset, data_len);
                    return Some((
                        frame,
                        Some(Box::new(StreamGeneratorToken {
                            id: *stream_id,
                            offset: offset,
                            length: data_len as u64,
                        })),
                    ));
                }
            }
        }
        None
    }
}

struct StreamGeneratorToken {
    id: StreamId,
    offset: u64,
    length: u64,
}

impl FrameGeneratorToken for StreamGeneratorToken {
    fn acked(&mut self, conn: &mut Connection) {
        qinfo!(
            conn,
            "Lost frame stream={} offset={} length={}",
            self.id.as_u64(),
            self.offset,
            self.length
        );
        match conn.send_streams.get_mut(&self.id) {
            None => {}
            Some(str) => {
                str.mark_as_acked(self.offset, self.length as usize);
            }
        }
    }
    fn lost(&mut self, conn: &mut Connection) {}
}

// Need to know when reset frame was acked
struct FlowControlGeneratorToken {
    stream_id: StreamId,
    application_error_code: AppError,
    final_size: u64,
}

impl FrameGeneratorToken for FlowControlGeneratorToken {
    fn acked(&mut self, conn: &mut Connection) {
        qinfo!(
            conn,
            "Reset received stream={} err={} final_size={}",
            self.stream_id.as_u64(),
            self.application_error_code,
            self.final_size
        );
        match conn.send_streams.get_mut(&self.stream_id) {
            None => {}
            Some(str) => {
                str.reset_acked();
            }
        }
    }
    fn lost(&mut self, conn: &mut Connection) {}
}

struct FlowControlGenerator {}

impl FrameGenerator for FlowControlGenerator {
    fn generate(
        &mut self,
        conn: &mut Connection,
        epoch: u16,
        mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        if let Some(frame) = conn.flow_mgr.borrow().peek() {
            // A suboptimal way to figure out if the frame fits within remaining
            // space.
            let mut d = Data::default();
            frame.marshal(&mut d);
            if d.written() > remaining {
                qtrace!("flowc frame doesn't fit in remaining");
                None
            } else {
                let frame = conn.flow_mgr.borrow_mut().next().expect("just peeked this");
                match frame {
                    // only set FlowControlGeneratorTokens for reset_stream
                    Frame::ResetStream {
                        stream_id,
                        application_error_code,
                        final_size,
                    } => Some((
                        frame,
                        Some(Box::new(FlowControlGeneratorToken {
                            stream_id: stream_id.into(),
                            application_error_code,
                            final_size,
                        })),
                    )),
                    s => Some((s, None)),
                }
            }
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct SentPacket {
    ack_eliciting: bool,
    //in_flight: bool, // TODO needed only for cc
    is_crypto_packet: bool,
    //size: u64, // TODO needed only for cc
    time_sent: u64,
    tokens: Vec<Box<FrameGeneratorToken>>, // a list of tokens.
}

impl SentPacket {
    pub fn mark_acked(&mut self, conn: &mut Connection) {
        for token in self.tokens.iter_mut() {
            token.acked(conn);
        }
    }

    pub fn mark_lost(&mut self, conn: &mut Connection) {
        for token in self.tokens.iter_mut() {
            token.lost(conn);
        }
    }
}

pub struct LossRecovery {
    loss_detection_timer: u64,
    crypto_count: u32,
    pto_count: u32,
    time_of_last_sent_ack_eliciting_packet: u64,
    time_of_last_sent_crypto_packet: u64,
    largest_acked_packet: [u64; 3],
    pub latest_rtt: u64,
    pub smoothed_rtt: u64,
    pub rttvar: u64,
    pub min_rtt: u64,
    max_ack_delay: u64,
    pub loss_time: [u64; 3],
    sent_packets: [HashMap<u64, SentPacket>; 3],
}

impl LossRecovery {
    pub fn new() -> LossRecovery {
        LossRecovery {
            loss_detection_timer: 0,
            crypto_count: 0,
            pto_count: 0,
            time_of_last_sent_ack_eliciting_packet: 0,
            time_of_last_sent_crypto_packet: 0,
            largest_acked_packet: [0, 0, 0],
            latest_rtt: 0,
            smoothed_rtt: 0,
            rttvar: 0,
            min_rtt: u64::max_value(),
            max_ack_delay: 25_000, // 25ms in microseconds
            loss_time: [0, 0, 0],
            sent_packets: [HashMap::new(), HashMap::new(), HashMap::new()],
        }
    }

    pub fn on_packet_sent(
        &mut self,
        pn_space: PNSpace,
        packet_number: u64,
        ack_eliciting: bool,
        is_crypto_packet: bool,
        tokens: Vec<Box<FrameGeneratorToken>>,
        cur_time_nanos: u64,
    ) {
        let cur_time = cur_time_nanos / 1000; //TODO currently LossRecovery does everything in microseconds.
        qdebug!(self, "packet {} sent.", packet_number);
        self.sent_packets[pn_space as usize].insert(
            packet_number,
            SentPacket {
                time_sent: cur_time,
                ack_eliciting: ack_eliciting,
                is_crypto_packet: is_crypto_packet,
                tokens: tokens,
            },
        );
        if is_crypto_packet {
            self.time_of_last_sent_crypto_packet = cur_time;
        }
        if ack_eliciting {
            self.time_of_last_sent_ack_eliciting_packet = cur_time;
            // TODO implement cc
            //     cc.on_packet_sent(sent_bytes)
        }

        self.set_loss_detection_timer();
    }

    pub fn on_ack_received(
        &mut self,
        pn_space: PNSpace,
        largest_acked: u64,
        acked_ranges: Vec<(u64, u64)>,
        ack_delay: u64,
        cur_time_nanos: u64,
    ) -> (Vec<SentPacket>, Vec<SentPacket>) {
        let cur_time = cur_time_nanos / 1000; //TODO currently LossRecovery does everything in microseconds.
        qdebug!(self, "ack received - largest_acked={}.", largest_acked);
        if self.largest_acked_packet[pn_space as usize] < largest_acked {
            self.largest_acked_packet[pn_space as usize] = largest_acked;
        }

        // If the largest acknowledged is newly acked and
        // ack-eliciting, update the RTT.
        if let Some(sent) = self.sent_packets[pn_space as usize].get(&largest_acked) {
            if sent.ack_eliciting {
                self.latest_rtt = cur_time - sent.time_sent;
                self.update_rtt(ack_delay);
            }
        }

        // TODO Process ECN information if present.

        let mut acked_packets = Vec::new();
        for r in acked_ranges {
            for pn in r.1..r.0 + 1 {
                if let Some(sent_packet) = self.sent_packets[pn_space as usize].remove(&pn) {
                    qdebug!(self, "acked={}", pn);
                    acked_packets.push(sent_packet);
                }
            }
        }

        if acked_packets.len() == 0 {
            return (acked_packets, Vec::new());
        }

        let lost_packets = self.detect_lost_packets(pn_space, cur_time);

        self.crypto_count = 0;
        self.pto_count = 0;

        self.set_loss_detection_timer();

        (acked_packets, lost_packets)
    }

    fn update_rtt(&mut self, mut ack_delay: u64) {
        // min_rtt ignores ack delay.
        self.min_rtt = std::cmp::min(self.min_rtt, self.latest_rtt);
        // Limit ack_delay by max_ack_delay
        ack_delay = std::cmp::min(ack_delay, self.max_ack_delay);
        // Adjust for ack delay if it's plausible.
        if self.latest_rtt - self.min_rtt > ack_delay {
            self.latest_rtt -= ack_delay;
        }
        // Based on {{?RFC6298}}.
        if self.smoothed_rtt == 0 {
            self.smoothed_rtt = self.latest_rtt;
            self.rttvar = self.latest_rtt / 2;
        } else {
            let rttvar_sample;
            if self.smoothed_rtt > self.latest_rtt {
                rttvar_sample = self.smoothed_rtt - self.latest_rtt;
            } else {
                rttvar_sample = self.latest_rtt - self.smoothed_rtt;
            }
            self.rttvar =
                (3.0 / 4.0 * (self.rttvar as f64) + 1.0 / 4.0 * (rttvar_sample as f64)) as u64;
            self.smoothed_rtt = (7.0 / 8.0 * (self.smoothed_rtt as f64)
                + 1.0 / 8.0 * (self.latest_rtt as f64)) as u64;
        }
    }

    fn detect_lost_packets(&mut self, pn_space: PNSpace, cur_time: u64) -> Vec<SentPacket> {
        self.loss_time[pn_space as usize] = 0;

        let loss_delay =
            (TIME_THRESHOLD * (std::cmp::max(self.latest_rtt, self.smoothed_rtt) as f64)) as u64;

        // Packets sent before this time are deemed lost. ( cur_time < loss_delay, can happen in test)
        let lost_send_time = if cur_time < loss_delay {
            0
        } else {
            cur_time - loss_delay
        };

        // Packets with packet numbers before this are deemed lost.
        let lost_pn = if self.largest_acked_packet[pn_space as usize] > PACKET_THRESHOLD {
            self.largest_acked_packet[pn_space as usize] - PACKET_THRESHOLD
        } else {
            0
        };

        qdebug!(
            self,
            "detect lost packets - time={}, pn={}",
            lost_send_time,
            lost_pn
        );

        let mut lost: Vec<u64> = Vec::new();
        for iter in self.sent_packets[pn_space as usize].iter_mut() {
            // Mark packet as lost, or set time when it should be marked.
            // Mark packet as lost, or set time when it should be marked.
            if *iter.0 <= self.largest_acked_packet[pn_space as usize] {
                if iter.1.time_sent <= lost_send_time || *iter.0 <= lost_pn {
                    qdebug!("lost={}", iter.0);
                    lost.push(*iter.0);
                } else {
                    if self.loss_time[pn_space as usize] == 0 {
                        self.loss_time[pn_space as usize] = iter.1.time_sent + loss_delay;
                    } else {
                        self.loss_time[pn_space as usize] = std::cmp::min(
                            self.loss_time[pn_space as usize],
                            iter.1.time_sent + loss_delay,
                        );
                    }
                }
            }
        }

        let mut lost_packets = Vec::new();
        for pn in lost {
            if let Some(sent_packet) = self.sent_packets[pn_space as usize].remove(&pn) {
                lost_packets.push(sent_packet);
            }
        }

        // TODO
        // Inform the congestion controller of lost packets.

        lost_packets
    }

    fn set_loss_detection_timer(&mut self) {
        qdebug!(self, "set_loss_detection_timer.");
        let mut has_crypto_out = false;
        let mut has_ack_eliciting_out = false;

        for pn_space in &[
            PNSpace::Initial,
            PNSpace::Handshake,
            PNSpace::ApplicationData,
        ] {
            if let Some(_) = self.sent_packets[*pn_space as usize]
                .iter()
                .filter(|(x, y)| y.is_crypto_packet)
                .next()
            {
                has_crypto_out = true;
            }
            if let Some(_) = self.sent_packets[*pn_space as usize]
                .iter()
                .filter(|(x, y)| y.ack_eliciting)
                .next()
            {
                has_ack_eliciting_out = true;
            }
        }

        qdebug!(
            self,
            "has_ack_eliciting_out={} has_crypto_out={}",
            has_ack_eliciting_out,
            has_crypto_out
        );
        if !has_ack_eliciting_out && !has_crypto_out {
            self.loss_detection_timer = 0;
            return;
        }

        let (loss_time, _) = self.get_earliest_loss_time();

        if loss_time != 0 {
            self.loss_detection_timer = loss_time;
        } else if has_crypto_out {
            self.set_timer_for_crypto_retransmission();
        } else {
            // Calculate PTO duration
            let mut timeout = self.smoothed_rtt
                + std::cmp::max(4 * self.rttvar, GRANULARITY)
                + self.max_ack_delay;
            timeout = timeout * 2u64.pow(self.pto_count);
            self.loss_detection_timer = self.time_of_last_sent_ack_eliciting_packet + timeout;
        }
        qdebug!(self, "loss_detection_timer={}", self.loss_detection_timer);
    }

    fn set_timer_for_crypto_retransmission(&mut self) {
        let mut timeout;
        if self.smoothed_rtt == 0 {
            timeout = 2 * INITIAL_RTT;
        } else {
            timeout = 2 * self.smoothed_rtt;
        }

        timeout = std::cmp::max(timeout, GRANULARITY);
        timeout = timeout * 2u64.pow(self.crypto_count);
        self.loss_detection_timer = self.time_of_last_sent_crypto_packet + timeout;
    }

    fn get_earliest_loss_time(&self) -> (u64, PNSpace) {
        let mut loss_time = self.loss_time[PNSpace::Initial as usize];
        let mut pn_space = PNSpace::Initial;
        for space in &[PNSpace::Handshake, PNSpace::ApplicationData] {
            if loss_time == 0 {
                loss_time = self.loss_time[*space as usize];
                pn_space = *space;
            } else if self.loss_time[*space as usize] != 0
                && self.loss_time[*space as usize] < loss_time
            {
                loss_time = self.loss_time[*space as usize];
                pn_space = *space;
            }
        }
        (loss_time, pn_space)
    }

    pub fn get_timer(&self) -> u64 {
        self.loss_detection_timer * 1000
    }

    //  there are3 outcome for this function, they correspond to (Vec<SentPacket>, bool, bool):
    //  1) lost packets are detected and a list of the packet is return,
    //  2) crypto timer expired, crypto data should be retransmitted,
    //  3) pto, one or two packets should be transmitted.
    pub fn on_loss_detection_timeout(
        &mut self,
        cur_time_nanos: u64,
    ) -> (Vec<SentPacket>, bool, bool) {
        let cur_time = cur_time_nanos / 1000; //TODO currently LossRecovery does everything in microseconds.
        let mut lost_packets = Vec::new();
        //let mut retransmit_unacked_crypto = false;
        //let mut send_one_or_two_packets = false;
        if cur_time < self.loss_detection_timer {
            return (
                lost_packets, false, false
                //retransmit_unacked_crypto,
                //send_one_or_two_packets,
            );
        }

        let (loss_time, pn_space) = self.get_earliest_loss_time();
        if loss_time != 0 {
            // Time threshold loss Detection
            lost_packets = self.detect_lost_packets(pn_space, cur_time);
        } else {
            let mut has_crypto_out = false;
            let mut iter = self.sent_packets[PNSpace::Initial as usize]
                .iter()
                .filter(|(x, y)| y.ack_eliciting);
            if let Some(_) = iter.next() {
                has_crypto_out = true;
            }

            if !has_crypto_out {
                let mut iter = self.sent_packets[PNSpace::Handshake as usize]
                    .iter()
                    .filter(|(x, y)| y.ack_eliciting);
                if let Some(_) = iter.next() {
                    has_crypto_out = true;
                }
            }

            // Retransmit crypto data if no packets were lost
            // and there are still crypto packets in flight.
            if has_crypto_out {
                // Crypto retransmission timeout.
                //retransmit_unacked_crypto = true;
                //for now just call detect_lost_packets;
                lost_packets = self.detect_lost_packets(pn_space, cur_time);
                self.crypto_count += 1;
            } else {
                // PTO
                //send_one_or_two_packets = true;
                //for now just call detect_lost_packets;
                lost_packets = self.detect_lost_packets(pn_space, cur_time);
                self.pto_count += 1;
            }
        }
        self.set_loss_detection_timer();
        (
            lost_packets,
            false,
            false,
            //retransmit_unacked_crypto,
            //send_one_or_two_packets,
        )
    }
}

impl ::std::fmt::Display for LossRecovery {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "LossRecovery")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::StreamType;

    fn loopback() -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    fn now() -> u64 {
        0
    }

    #[test]
    fn test_conn_stream_create() {
        init_db("./db");

        let mut client =
            Connection::new_client("example.com", &["alpn"], loopback(), loopback()).unwrap();
        let (res, _) = client.process(vec![], now());
        let mut server = Connection::new_server(&["key"], &["alpn"]).unwrap();
        let (res, _) = server.process(res, now());

        let (res, _) = client.process(res, now());
        // client now in State::Connected
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 6);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 4);

        let (res, _) = server.process(res, now());
        // server now in State::Connected
        assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 3);
        assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 7);
        assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 1);
        assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 5);
    }

    #[test]
    fn test_conn_handshake() {
        init_db("./db");
        qdebug!("---- client: generate CH");
        let mut client =
            Connection::new_client("example.com", &["alpn"], loopback(), loopback()).unwrap();
        let (res, _) = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
        let mut server = Connection::new_server(&["key"], &["alpn"]).unwrap();
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: SH..FIN -> FIN");
        let (res, _) = client.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: FIN -> ACKS");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: ACKS -> 0");
        let (res, _) = client.process(res, now());
        assert!(res.is_empty());
        qdebug!("Output={:0x?}", res);

        assert_eq!(*client.state(), State::Connected);
        assert_eq!(*server.state(), State::Connected);
    }

    #[test]
    // tests stream send/recv after connection is established.
    fn test_conn_stream() {
        init_db("./db");

        let mut client =
            Connection::new_client("example.com", &["alpn"], loopback(), loopback()).unwrap();
        let mut server = Connection::new_server(&["key"], &["alpn"]).unwrap();

        qdebug!("---- client");
        let (res, _) = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[0]: CRYPTO[CH]

        qdebug!("---- server");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // TODO(agrover@mozilla.com): ACKs
        // <<-- Initial[0]: CRYPTO[SH] ACK[0]
        // <<-- Handshake[0]: CRYPTO[EE, CERT, CV, FIN]

        qdebug!("---- client");
        let (res, _) = client.process(res, now());
        assert_eq!(res.len(), 1);
        assert_eq!(*client.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[1]: ACK[0]
        // -->> Handshake[0]: CRYPTO[FIN], ACK[0]

        qdebug!("---- server");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        assert_eq!(*server.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // ACKs
        // -->> nothing

        qdebug!("---- client");
        // Send
        let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
        client.stream_send(client_stream_id, &vec![6; 100]).unwrap();
        client.stream_send(client_stream_id, &vec![7; 40]).unwrap();
        client
            .stream_send(client_stream_id, &vec![8; 4000])
            .unwrap();

        // Send to another stream but some data after fin has been set
        let client_stream_id2 = client.stream_create(StreamType::UniDi).unwrap();
        client.stream_send(client_stream_id2, &vec![6; 60]).unwrap();
        client.stream_close_send(client_stream_id2).unwrap();
        client
            .stream_send(client_stream_id2, &vec![7; 50])
            .unwrap_err();
        let (res, _) = client.process(res, now());
        assert_eq!(res.len(), 4);

        qdebug!("---- server");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        assert_eq!(*server.state(), State::Connected);
        qdebug!("Output={:0x?}", res);

        let mut buf = vec![0; 4000];

        let mut iter = server.get_recvable_streams();
        let (stream_id, stream) = iter.next().unwrap();
        let (received, fin) = stream.read(&mut buf).unwrap();
        assert_eq!(received, 4000);
        assert_eq!(fin, false);
        let (received, fin) = stream.read(&mut buf).unwrap();
        assert_eq!(received, 140);
        assert_eq!(fin, false);

        let (stream_id, stream) = iter.next().unwrap();
        let (received, fin) = stream.read(&mut buf).unwrap();
        assert_eq!(received, 60);
        assert_eq!(fin, true);
    }

    /// Drive the handshake between the client and server.
    fn handshake(client: &mut Connection, server: &mut Connection) {
        let mut a = client;
        let mut b = server;
        let mut records = Vec::new();
        let is_done = |c: &mut Connection| match c.state() {
            // TODO(mt): Finish on Closed and not Closing.
            State::Connected | State::Closing(..) | State::Closed(..) => true,
            _ => false,
        };
        while !is_done(a) {
            let (r, _) = a.process(records, now());
            records = r;
            b = mem::replace(&mut a, b);
        }
    }

    fn connect(client: &mut Connection, server: &mut Connection) {
        handshake(client, server);
        assert_eq!(*client.state(), State::Connected);
        assert_eq!(*server.state(), State::Connected);
    }

    fn assert_error(c: &Connection, err: ConnectionError) {
        match c.state() {
            // TODO(mt): Finish on Closed and not Closing.
            State::Closing(e, ..) | State::Closed(e, ..) => {
                assert_eq!(*e, err);
            }
            _ => panic!("bad state {:?}", c.state()),
        }
    }

    #[test]
    fn test_no_alpn() {
        init_db("./db");
        let mut client =
            Connection::new_client("example.com", &["alpn"], loopback(), loopback()).unwrap();
        let mut server = Connection::new_server(&["key"], &["different-alpn"]).unwrap();

        handshake(&mut client, &mut server);
        // TODO (mt): errors are immediate, which means that we never send CONNECTION_CLOSE
        // and the client never sees the server's rejection of its handshake.
        //assert_error(&client, ConnectionError::Transport(Error::CryptoAlert(120)));
        assert_error(&server, ConnectionError::Transport(Error::CryptoAlert(120)));
    }

    // LOSSRECOVERY tests

    fn assert_values(
        lr: &LossRecovery,
        latest_rtt: u64,
        smoothed_rtt: u64,
        rttvar: u64,
        min_rtt: u64,
        loss_time: [u64; 3],
    ) {
        println!(
            "{} {} {} {} {} {} {}",
            lr.latest_rtt,
            lr.smoothed_rtt,
            lr.rttvar,
            lr.min_rtt,
            lr.loss_time[0],
            lr.loss_time[1],
            lr.loss_time[2]
        );
        assert_eq!(lr.latest_rtt, latest_rtt);
        assert_eq!(lr.smoothed_rtt, smoothed_rtt);
        assert_eq!(lr.rttvar, rttvar);
        assert_eq!(lr.min_rtt, min_rtt);
        assert_eq!(lr.loss_time, loss_time);
    }

    #[test]
    fn test_loss_recovery1() {
        let mut lr_module = LossRecovery::new();

        lr_module.on_packet_sent(PNSpace::ApplicationData, 0, true, false, Vec::new(), 0);
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            1,
            true,
            false,
            Vec::new(),
            10_000_000,
        );

        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            2,
            true,
            false,
            Vec::new(),
            20_000_000,
        );

        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            3,
            true,
            false,
            Vec::new(),
            30_000_000,
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            4,
            true,
            false,
            Vec::new(),
            40_000_000,
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            5,
            true,
            false,
            Vec::new(),
            50_000_000,
        );

        // Calculating rtt for the first ack
        lr_module.on_ack_received(PNSpace::ApplicationData, 0, Vec::new(), 2000, 50_000_000);
        assert_values(&lr_module, 50_000, 50_000, 25_000, 50_000, [0, 0, 0]);

        // Calculating rtt for further acks
        lr_module.on_ack_received(PNSpace::ApplicationData, 1, vec![(1, 0)], 2000, 60_000_000);
        assert_values(&lr_module, 50_000, 50_000, 18_750, 50_000, [0, 0, 0]);

        // Calculating rtt for further acks
        lr_module.on_ack_received(PNSpace::ApplicationData, 2, vec![(2, 0)], 2000, 70_000_000);
        assert_values(&lr_module, 50_000, 50_000, 14_062, 50_000, [0, 0, 0]);

        // Calculating rtt for further acks; test min_rtt
        lr_module.on_ack_received(PNSpace::ApplicationData, 3, vec![(3, 0)], 2000, 75_000_000);
        assert_values(&lr_module, 45_000, 49_375, 11_796, 45_000, [0, 0, 0]);

        // Calculating rtt for further acks; test ack_delay
        lr_module.on_ack_received(PNSpace::ApplicationData, 4, vec![(4, 0)], 2000, 95_000_000);
        assert_values(&lr_module, 53_000, 49828, 9_753, 45_000, [0, 0, 0]);

        // Calculating rtt for further acks; test max_ack_delay
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            5,
            vec![(5, 0)],
            28000,
            150_000_000,
        );
        assert_values(&lr_module, 75000, 52974, 13607, 45000, [0, 0, 0]);

        // Calculating rtt for further acks; test acking already acked packet
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            5,
            vec![(5, 0)],
            28000,
            160_000_000,
        );
        assert_values(&lr_module, 75000, 52974, 13607, 45000, [0, 0, 0]);
    }

    // Test crypto timeout.
    #[test]
    fn test_loss_recovery2() {
        let mut lr_module = LossRecovery::new();
        lr_module.on_packet_sent(PNSpace::ApplicationData, 0, true, true, Vec::new(), 0);
        assert_eq!(lr_module.get_timer(), 200_000_000);
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            1,
            true,
            false,
            Vec::new(),
            10_000_000,
        );
        assert_eq!(lr_module.get_timer(), 200_000_000);
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            2,
            true,
            false,
            Vec::new(),
            20_000_000,
        );
        assert_eq!(lr_module.get_timer(), 200_000_000);
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            3,
            true,
            false,
            Vec::new(),
            30_000_000,
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            4,
            true,
            false,
            Vec::new(),
            40_000_000,
        );
        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            5,
            true,
            false,
            Vec::new(),
            50_000_000,
        );

        lr_module.on_packet_sent(
            PNSpace::ApplicationData,
            6,
            true,
            false,
            Vec::new(),
            60_000_000,
        );

        // This is a PTO for crypto packet.
        assert_eq!(lr_module.get_timer(), 200_000_000);

        // Receive an ack for packet 0.
        lr_module.on_ack_received(PNSpace::ApplicationData, 0, vec![(0, 0)], 2000, 100_000_000);
        assert_values(&lr_module, 100_000, 100_000, 50_000, 100_000, [0, 0, 0]);
        assert_eq!(lr_module.get_timer(), 385_000_000);

        // Receive an ack with a gap. ackes 0 and 2.
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            2,
            vec![(0, 0), (2, 2)],
            2000,
            105_000_000,
        );
        assert_values(&lr_module, 85_000, 98_125, 41_250, 85_000, [0, 0, 120_390]);
        assert_eq!(lr_module.get_timer(), 120_390_000);

        // Timer expires, packet 1 is lost. packet 1 is lost
        lr_module.on_loss_detection_timeout(120_390_000);
        assert_values(&lr_module, 85_000, 98_125, 41_250, 85_000, [0, 0, 0]);
        assert_eq!(lr_module.get_timer(), 348_125_000);

        // dupacks loss detection. ackes 0, 2 and 6, markes packet 3 as lost.
        lr_module.on_ack_received(
            PNSpace::ApplicationData,
            6,
            vec![(0, 0), (2, 2), (6, 6)],
            2000,
            130_000_000,
        );
        assert_values(&lr_module, 70_000, 94_609, 37_968, 70_000, [0, 0, 146_435]);
        assert_eq!(lr_module.get_timer(), 146_435_000);

        // Timer expires, packet 4 is lost.
        lr_module.on_loss_detection_timeout(146_500_000);
        assert_values(&lr_module, 70_000, 94_609, 37_968, 70_000, [0, 0, 156_435]);
        assert_eq!(lr_module.get_timer(), 156_435_000);

        // Timer expires, packet 5 is lost.
        lr_module.on_loss_detection_timeout(156_500_000);
        assert_values(&lr_module, 70_000, 94_609, 37_968, 70_000, [0, 0, 0]);

        // there is no more outstanding data - timer is set to 0.
        assert_eq!(lr_module.get_timer(), 0);
    }
}
