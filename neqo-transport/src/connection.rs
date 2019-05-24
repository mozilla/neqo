// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(dead_code)]
use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Debug};
use std::mem;
use std::net::SocketAddr;
use std::ops::{AddAssign, Deref, DerefMut};
use std::rc::Rc;

use neqo_common::{hex, matches, qdebug, qerror, qinfo, qtrace, qwarn, Decoder, Encoder};
use neqo_crypto::aead::Aead;
use neqo_crypto::agent::SecretAgentInfo;
use neqo_crypto::hkdf;
use neqo_crypto::hp::{extract_hp, HpKey};

use crate::dump::*;
use crate::frame::{decode_frame, AckRange, CloseType, Frame, FrameType, StreamType};
use crate::nss::{
    Agent, Cipher, Client, Epoch, HandshakeState, Record, Server, SymKey, TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384, TLS_VERSION_1_3,
};
use crate::packet::{
    decode_packet_hdr, decrypt_packet, encode_packet, ConnectionId, CryptoCtx, PacketDecoder,
    PacketHdr, PacketNumber, PacketNumberDecoder, PacketType,
};
use crate::recv_stream::{RecvStream, RxStreamOrderer, RX_STREAM_DATA_WINDOW};
use crate::send_stream::{SendStream, TxBuffer};
use crate::stats::Stats;
use crate::tparams::consts as tp_const;
use crate::tparams::TransportParametersHandler;
use crate::tracking::RecvdPackets;
use crate::{AppError, ConnectionError, Error, Res};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

pub const QUIC_VERSION: u32 = 0xff00_0014;
const NUM_EPOCHS: Epoch = 4;
const MAX_AUTH_TAG: usize = 32;
const CID_LENGTH: usize = 8;

const TIME_THRESHOLD: f64 = 9.0 / 8.0;
const PACKET_THRESHOLD: u64 = 3;
// TODO granularity
const GRANULARITY: u64 = 1000; // 1ms in microseconds
const INITIAL_RTT: u64 = 100_000; // 100ms in microseconds

const LOCAL_STREAM_LIMIT_BIDI: u64 = 16;
const LOCAL_STREAM_LIMIT_UNI: u64 = 16;
const LOCAL_MAX_DATA: u64 = 0x3FFF_FFFF_FFFF_FFFE; // 2^62-1

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
    Client,
    Server,
}

impl ::std::fmt::Display for Role {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum State {
    Init,
    WaitInitial,
    Handshaking,
    Connected,
    Closing {
        error: ConnectionError,
        frame_type: FrameType,
        msg: String,
        timeout: u64,
    },
    Closed(ConnectionError),
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

impl StreamId {
    fn is_bidi(self) -> bool {
        self.0 & 0x02 == 0
    }

    fn is_uni(self) -> bool {
        !self.is_bidi()
    }

    fn stream_type(self) -> StreamType {
        if self.is_bidi() {
            StreamType::BiDi
        } else {
            StreamType::UniDi
        }
    }

    fn is_client_initiated(self) -> bool {
        self.0 & 0x01 == 0
    }

    fn is_server_initiated(self) -> bool {
        !self.is_client_initiated()
    }

    fn role(self) -> Role {
        if self.is_client_initiated() {
            Role::Client
        } else {
            Role::Server
        }
    }

    fn is_self_initiated(self, my_role: Role) -> bool {
        match my_role {
            Role::Client if self.is_client_initiated() => true,
            Role::Server if self.is_server_initiated() => true,
            _ => false,
        }
    }

    fn is_peer_initiated(self, my_role: Role) -> bool {
        !self.is_self_initiated(my_role)
    }

    fn is_send_only(self, my_role: Role) -> bool {
        self.is_uni() && self.is_self_initiated(my_role)
    }

    fn is_recv_only(self, my_role: Role) -> bool {
        self.is_uni() && self.is_peer_initiated(my_role)
    }

    fn as_u64(self) -> u64 {
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

    pub fn to_stream_id(self, stream_type: StreamType, role: Role) -> StreamId {
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

    pub fn as_u64(self) -> u64 {
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

impl From<Epoch> for PNSpace {
    fn from(epoch: Epoch) -> PNSpace {
        match epoch {
            0 => PNSpace::Initial,
            2 => PNSpace::Handshake,
            _ => PNSpace::ApplicationData,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    pub d: Vec<u8>,
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
    /// Peer has sent STOP_SENDING
    SendStreamStopSending { stream_id: u64, app_error: AppError },
    /// Peer has acked everything sent on the stream.
    SendStreamComplete { stream_id: u64 },
    /// Peer increased MAX_STREAMS
    SendStreamCreatable { stream_type: StreamType },
    /// Connection closed
    ConnectionClosed {
        close_type: CloseType,
        error_code: u16,
        frame_type: u64,
        reason_phrase: String,
    },
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

    pub fn send_stream_stop_sending(&mut self, stream_id: StreamId, app_error: AppError) {
        self.events.insert(ConnectionEvent::SendStreamStopSending {
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

    pub fn connection_closed(
        &mut self,
        close_type: CloseType,
        error_code: u16,
        frame_type: u64,
        reason_phrase: &str,
    ) {
        self.events.insert(ConnectionEvent::ConnectionClosed {
            close_type,
            error_code,
            frame_type,
            reason_phrase: reason_phrase.to_owned(),
        });
    }

    pub fn events(&mut self) -> BTreeSet<ConnectionEvent> {
        mem::replace(&mut self.events, BTreeSet::new())
    }
}

#[derive(Debug, Default)]
pub struct FlowMgr {
    // Discriminant as key ensures only 1 of every frame type will be queued.
    from_conn: HashMap<mem::Discriminant<Frame>, Frame>,

    // (id, discriminant) as key ensures only 1 of every frame type per stream
    // will be queued.
    from_streams: HashMap<(StreamId, mem::Discriminant<Frame>), Frame>,

    // (stream_type, discriminant) as key ensures only 1 of every frame type
    // per stream type will be queued.
    from_stream_types: HashMap<(StreamType, mem::Discriminant<Frame>), Frame>,

    used_data: u64,
    max_data: u64,

    need_close_frame: bool,
}

impl FlowMgr {
    pub fn new() -> FlowMgr {
        FlowMgr::default()
    }

    pub fn conn_credit_avail(&self) -> u64 {
        self.max_data - self.used_data
    }

    pub fn conn_increase_credit_used(&mut self, amount: u64) {
        self.used_data += amount;
        assert!(self.used_data <= self.max_data)
    }

    pub fn conn_increase_max_credit(&mut self, new: u64) {
        self.max_data = max(self.max_data, new)
    }

    // -- frames scoped on connection --

    pub fn data_blocked(&mut self) {
        let frame = Frame::DataBlocked {
            data_limit: self.max_data,
        };
        self.from_conn.insert(mem::discriminant(&frame), frame);
    }

    pub fn path_response(&mut self, data: [u8; 8]) {
        let frame = Frame::PathResponse { data };
        self.from_conn.insert(mem::discriminant(&frame), frame);
    }

    // -- frames scoped on stream --

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
        self.from_streams
            .insert((stream_id, mem::discriminant(&frame)), frame);
    }

    /// Indicate to sending peer we are no longer interested in the stream
    pub fn stop_sending(&mut self, stream_id: StreamId, application_error_code: AppError) {
        let frame = Frame::StopSending {
            stream_id: stream_id.as_u64(),
            application_error_code,
        };
        self.from_streams
            .insert((stream_id, mem::discriminant(&frame)), frame);
    }

    /// Update sending peer with more credits
    pub fn max_stream_data(&mut self, stream_id: StreamId, maximum_stream_data: u64) {
        let frame = Frame::MaxStreamData {
            stream_id: stream_id.as_u64(),
            maximum_stream_data,
        };
        self.from_streams
            .insert((stream_id, mem::discriminant(&frame)), frame);
    }

    /// Indicate to receiving peer we need more credits
    pub fn stream_data_blocked(&mut self, stream_id: StreamId, stream_data_limit: u64) {
        let frame = Frame::StreamDataBlocked {
            stream_id: stream_id.as_u64(),
            stream_data_limit,
        };
        self.from_streams
            .insert((stream_id, mem::discriminant(&frame)), frame);
    }

    // -- frames scoped on stream type --

    pub fn max_streams(&mut self, stream_limit: StreamIndex, stream_type: StreamType) {
        let frame = Frame::MaxStreams {
            stream_type,
            maximum_streams: stream_limit,
        };
        self.from_stream_types
            .insert((stream_type, mem::discriminant(&frame)), frame);
    }

    pub fn streams_blocked(&mut self, stream_limit: StreamIndex, stream_type: StreamType) {
        let frame = Frame::StreamsBlocked {
            stream_type,
            stream_limit,
        };
        self.from_stream_types
            .insert((stream_type, mem::discriminant(&frame)), frame);
    }

    pub fn peek(&self) -> Option<&Frame> {
        if let Some(key) = self.from_conn.keys().next() {
            self.from_conn.get(key)
        } else if let Some(key) = self.from_streams.keys().next() {
            self.from_streams.get(key)
        } else if let Some(key) = self.from_stream_types.keys().next() {
            self.from_stream_types.get(key)
        } else {
            None
        }
    }

    fn need_close_frame(&self) -> bool {
        self.need_close_frame
    }

    fn set_need_close_frame(&mut self, new: bool) {
        self.need_close_frame = new
    }
}

impl Iterator for FlowMgr {
    type Item = Frame;
    /// Used by generator to get a flow control frame.
    fn next(&mut self) -> Option<Frame> {
        let first_key = self.from_conn.keys().next();
        if let Some(&first_key) = first_key {
            return self.from_conn.remove(&first_key);
        }

        let first_key = self.from_streams.keys().next();
        if let Some(&first_key) = first_key {
            return self.from_streams.remove(&first_key);
        }

        let first_key = self.from_stream_types.keys().next();
        if let Some(&first_key) = first_key {
            return self.from_stream_types.remove(&first_key);
        }

        None
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
        const INITIAL_SALT: &[u8] = &[
            0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef, 0xcf, 0x80, 0x31, 0x33,
            0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0,
        ];
        let initial_secret = hkdf::extract(
            TLS_VERSION_1_3,
            cipher,
            Some(
                hkdf::import_key(TLS_VERSION_1_3, cipher, INITIAL_SALT)
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
    fn obtain_recvd_state(&mut self, pn: u64) -> &mut RecvdPackets {
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
    role: Role,
    state: State,
    tls: Agent,
    tps: Rc<RefCell<TransportParametersHandler>>,
    scid: ConnectionId,
    dcid: ConnectionId,
    retry_token: Option<Vec<u8>>,
    send_epoch: Epoch,
    recv_epoch: Epoch,
    crypto_streams: [CryptoStream; 4],
    crypto_states: [Option<CryptoState>; 4],
    tx_pns: [u64; 3],
    // TODO(ekr@rtfm.com): Prioritized generators, rather than a vec
    generators: Vec<Box<FrameGenerator>>,
    deadline: u64,
    local_max_stream_idx_uni: StreamIndex,
    local_max_stream_idx_bidi: StreamIndex,
    local_next_stream_idx_uni: StreamIndex,
    local_next_stream_idx_bidi: StreamIndex,
    peer_max_stream_idx_uni: StreamIndex,
    peer_max_stream_idx_bidi: StreamIndex,
    peer_next_stream_idx_uni: StreamIndex,
    peer_next_stream_idx_bidi: StreamIndex,
    highest_stream: Option<u64>,
    connection_ids: HashMap<u64, (Vec<u8>, [u8; 16])>, // (sequence number, (connection id, reset token))
    send_streams: BTreeMap<StreamId, SendStream>,
    recv_streams: BTreeMap<StreamId, RecvStream>,
    pmtu: usize,
    flow_mgr: Rc<RefCell<FlowMgr>>,
    loss_recovery: LossRecovery,
    events: Rc<RefCell<ConnectionEvents>>,
    token: Option<Vec<u8>>,
    send_vn: Option<ConnectionId>,
    send_retry: Option<PacketType>, // This will be PacketType::Retry.
    stats: Stats,
}

impl Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{:?} Connection: {:?} {:?}",
            self.role, self.state, self.paths
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
            tp_const::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            RX_STREAM_DATA_WINDOW,
        );
        tphandler.borrow_mut().local.set_integer(
            tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            RX_STREAM_DATA_WINDOW,
        );
        tphandler
            .borrow_mut()
            .local
            .set_integer(tp_const::INITIAL_MAX_STREAM_DATA_UNI, RX_STREAM_DATA_WINDOW);
        tphandler
            .borrow_mut()
            .local
            .set_integer(tp_const::INITIAL_MAX_STREAMS_BIDI, LOCAL_STREAM_LIMIT_BIDI);
        tphandler
            .borrow_mut()
            .local
            .set_integer(tp_const::INITIAL_MAX_STREAMS_UNI, LOCAL_STREAM_LIMIT_UNI);
        tphandler
            .borrow_mut()
            .local
            .set_integer(tp_const::INITIAL_MAX_DATA, LOCAL_MAX_DATA);
        tphandler
            .borrow_mut()
            .local
            .set_empty(tp_const::DISABLE_MIGRATION);

        Connection::configure_agent(&mut agent, protocols, tphandler.clone());

        let mut c = Connection {
            version: QUIC_VERSION,
            paths,
            role: r,
            state: match r {
                Role::Client => State::Init,
                Role::Server => State::WaitInitial,
            },
            tls: agent,
            tps: tphandler,
            scid: ConnectionId::default(),
            dcid: ConnectionId::default(),
            retry_token: None,
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
            tx_pns: [0; 3],
            deadline: 0,
            local_max_stream_idx_bidi: StreamIndex::new(LOCAL_STREAM_LIMIT_BIDI),
            local_max_stream_idx_uni: StreamIndex::new(LOCAL_STREAM_LIMIT_UNI),
            local_next_stream_idx_uni: StreamIndex::new(0),
            local_next_stream_idx_bidi: StreamIndex::new(0),
            peer_max_stream_idx_bidi: StreamIndex::new(0),
            peer_max_stream_idx_uni: StreamIndex::new(0),
            peer_next_stream_idx_uni: StreamIndex::new(0),
            peer_next_stream_idx_bidi: StreamIndex::new(0),
            highest_stream: None,
            connection_ids: HashMap::new(),
            send_streams: BTreeMap::new(),
            recv_streams: BTreeMap::new(),
            pmtu: 1280,
            flow_mgr: Rc::new(RefCell::new(FlowMgr::default())),
            loss_recovery: LossRecovery::new(),
            events: Rc::new(RefCell::new(ConnectionEvents::default())),
            token: None,
            send_vn: None,
            send_retry: None,
            stats: Stats::default(),
        };

        c.scid = ConnectionId::generate(CID_LENGTH);
        if c.role == Role::Client {
            let dcid = ConnectionId::generate(CID_LENGTH);
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

    /// Return the resumption token.
    pub fn resumption_token(&self) -> Option<&Vec<u8>> {
        self.tls.resumption_token()
    }

    /// Enable resumption, using a token previously provided.
    pub fn set_resumption_token(&mut self, token: &[u8]) -> Res<()> {
        self.tls.set_resumption_token(token)?;
        Ok(())
    }

    /// Get the current role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get the state of the connection.
    pub fn state(&self) -> &State {
        &self.state
    }

    // Get the SCID.
    pub fn scid(&self) -> ConnectionId {
        self.scid.clone()
    }

    /// Get statistics
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    // This function wraps a call to another function and sets the connection state
    // properly if that call fails.
    fn capture_error<T>(&mut self, cur_time: u64, frame_type: FrameType, res: Res<T>) -> Res<T> {
        if let Err(v) = &res {
            #[cfg(debug_assertions)]
            let msg = format!("{:?}", v);
            #[cfg(not(debug_assertions))]
            let msg = String::from("");
            self.set_state(State::Closing {
                error: ConnectionError::Transport(v.clone()),
                frame_type,
                msg,
                timeout: self.get_closing_period_time(cur_time),
            });
        }
        res
    }

    /// For use with process().  Errors there can be ignored, but this needs to
    /// ensure that the state is updated.
    fn absorb_error(&mut self, cur_time: u64, res: Res<()>) {
        let _ = self.capture_error(cur_time, 0, res);
    }

    /// Call in to process activity on the connection. Either new packets have
    /// arrived or a timeout has expired (or both).
    pub fn process_input<I>(&mut self, in_dgrams: I, cur_time: u64)
    where
        I: IntoIterator<Item = Datagram>,
    {
        for dgram in in_dgrams {
            let res = self.input(dgram, cur_time);
            self.absorb_error(cur_time, res);
        }

        self.cleanup_streams();

        if cur_time >= self.deadline {
            // Timer expired.
            if let State::Init = self.state {
                let res = self.client_start();
                self.absorb_error(cur_time, res);
            }
        }
    }

    /// Get output packets, as a result of receiving packets, or actions taken
    /// by the application.
    pub fn process_output(&mut self, cur_time: u64) -> (Vec<Datagram>, u64) {
        match &self.state {
            State::Closing { error, timeout, .. } => {
                if *timeout < cur_time {
                    (self.output(cur_time), 0)
                } else {
                    // Close timeout expired, move to Closed
                    let st = State::Closed(error.clone());
                    self.set_state(st);
                    (Vec::new(), 0)
                }
            }
            State::Closed(..) => (Vec::new(), 0),
            _ => {
                self.check_loss_detection_timeout(cur_time);
                (self.output(cur_time), self.loss_recovery.get_timer())
            }
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

        qinfo!([self] "input {}", hex( &**d));

        // Handle each packet in the datagram
        while !slc.is_empty() {
            let mut hdr = match decode_packet_hdr(self, slc) {
                Ok(h) => h,
                _ => {
                    qinfo!([self] "Received indecipherable packet header {:?}", slc);
                    return Ok(()); // Drop the remainder of the datagram.
                }
            };
            self.stats.packets_rx += 1;
            match (&hdr.tipe, &self.state, &self.role) {
                (PacketType::VN(_), State::WaitInitial, Role::Client) => {
                    self.set_state(State::Closed(ConnectionError::Transport(
                        Error::VersionNegotiation,
                    )));
                    return Err(Error::VersionNegotiation);
                }
                (PacketType::Retry { odcid, token }, State::WaitInitial, Role::Client) => {
                    if *odcid != self.dcid {
                        qwarn!("received Retry, but not for us, dropping it");
                        return Ok(());
                    }
                    if token.is_empty() {
                        qwarn!("received Retry, but no token, dropping it");
                        return Ok(());
                    }
                    if self.retry_token.is_some() {
                        qwarn!("received another Retry, dropping it");
                        return Ok(());
                    }
                    self.retry_token = Some(token.clone());
                    self.dcid = hdr.scid.as_ref().expect("no SCID on Retry").clone();
                    return Ok(());
                }
                (PacketType::VN(_), ..) | (PacketType::Retry { .. }, ..) => {
                    qwarn!("dropping {:?}", hdr.tipe);
                    return Ok(());
                }
                _ => {}
            };

            if let Some(version) = hdr.version {
                if version != self.version {
                    qwarn!(
                        "hdr version {:?} and self.version {} disagree",
                        hdr.version,
                        self.version,
                    );
                    qwarn!([self] "Sending VN on next output");
                    self.send_vn = Some(hdr.scid.unwrap().clone());
                    return Ok(());
                }
            }

            match self.state {
                State::Init => {
                    qinfo!([self] "Received message while in Init state");
                    return Ok(());
                }
                State::WaitInitial => {
                    qinfo!([self] "Received packet in WaitInitial");
                    // Out DCID is the other side's SCID.
                    let scid = hdr.scid.as_ref().unwrap();
                    if self.role == Role::Server {
                        if hdr.dcid.len() < 8 {
                            qwarn!([self] "Peer DCID is too short");
                            return Ok(());
                        }
                        self.create_initial_crypto_state(&hdr.dcid);
                    }

                    // Imprint on the remote parameters.
                    self.dcid = scid.clone();
                }
                State::Handshaking | State::Connected => {
                    if !self.valid_cid(&hdr.dcid[..]) {
                        qinfo!([self] "Bad CID {}", hex(&hdr.dcid));
                        return Ok(());
                    }
                }
                State::Closing { .. } => {
                    // Don't bother processing the packet. Instead ask to get a
                    // new close frame.
                    self.flow_mgr.borrow_mut().set_need_close_frame(true);
                    return Ok(());
                }
                State::Closed(..) => {
                    // Do nothing.
                    return Ok(());
                }
            }

            qdebug!([self] "Received unverified packet {:?}", hdr);

            // Decryption failure, or not having keys is not fatal.
            // If the state isn't available, or we can't decrypt the packet, drop
            // the rest of the datagram on the floor, but don't generate an error.
            let largest_acknowledged = self
                .loss_recovery
                .space(PNSpace::from(hdr.epoch))
                .largest_acknowledged();
            let res = match self.obtain_crypto_state(hdr.epoch) {
                Ok(cs) => {
                    let pn_decoder = PacketNumberDecoder::new(largest_acknowledged);
                    decrypt_packet(&cs.rx, pn_decoder, &mut hdr, slc)
                }
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
            dump_packet(self, "rx", &hdr, &body);

            // TODO(ekr@rtfm.com): Have the server blow away the initial
            // crypto state if this fails? Otherwise, we will get a panic
            // on the assert for doesn't exist.
            // OK, we have a valid packet.

            // TODO(ekr@rtfm.com): Filter for valid for this epoch.

            if matches!(self.state, State::WaitInitial) {
                self.set_state(State::Handshaking);
            }

            let ack_eliciting = self.input_packet(hdr.epoch, Decoder::from(&body[..]), cur_time)?;
            let mut tmp = self.obtain_crypto_state(hdr.epoch); // Keep the Res alive.
            let rstate = tmp.as_mut().unwrap().obtain_recvd_state(hdr.pn);
            if rstate.was_received(hdr.pn) {
                qdebug!([self] "Received duplicate packet epoch={} pn={}", hdr.epoch, hdr.pn);
                self.stats.dups_rx += 1;
                continue;
            }
            rstate.set_received(cur_time, hdr.pn, ack_eliciting);

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
    fn input_packet(&mut self, epoch: Epoch, mut d: Decoder, cur_time: u64) -> Res<(bool)> {
        let mut ack_eliciting = false;

        // Handle each frame in the packet
        while d.remaining() > 0 {
            let f = decode_frame(&mut d)?;
            ack_eliciting |= f.ack_eliciting();
            let t = f.get_type();
            let res = self.input_frame(epoch, f, cur_time);
            self.capture_error(cur_time, t, res)?;
        }

        Ok(ack_eliciting)
    }

    fn output_vn(&mut self, scid: ConnectionId) -> Datagram {
        qinfo!("Sending VN Packet instead of normal output");
        let supported_versions = vec![QUIC_VERSION, 0x4a4a_4a4a];
        let hdr = PacketHdr::new(
            0,
            PacketType::VN(supported_versions),
            Some(0),
            scid.clone(),
            Some(self.scid.clone()),
            0, // unused
            0, // unused
        );
        let cs = self.obtain_crypto_state(hdr.epoch).unwrap();
        let packet = encode_packet(&cs.tx, &hdr, &[]);
        self.stats.packets_tx += 1;
        if let Some(path) = &self.paths {
            Datagram::new(path.local, path.remote, packet)
        } else {
            unreachable!()
        }
    }

    fn output(&mut self, cur_time: u64) -> Vec<Datagram> {
        if let Some(scid) = self.send_vn.take() {
            return vec![self.output_vn(scid)];
        }

        // Can't call a method on self while iterating over self.paths
        let paths = mem::replace(&mut self.paths, None);
        let mut out_dgrams = Vec::new();
        let mut errors = Vec::new();
        for p in &paths {
            match self.output_path(&p, cur_time) {
                Ok(ref mut dgrams) => out_dgrams.append(dgrams),
                Err(e) => errors.push(e),
            };
        }
        self.paths = paths;

        let closing = match self.state {
            State::Closing { .. } => true,
            _ => false,
        };
        if !closing && !errors.is_empty() {
            self.absorb_error(cur_time, Err(errors.pop().unwrap()));
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

        let mut initial_only = false;

        // Frames for different epochs must go in different packets, but then these
        // packets can go in a single datagram
        for epoch in 0..NUM_EPOCHS {
            let mut encoder = Encoder::default();
            let mut ds = Vec::new();
            let mut tokens = Vec::new();
            // Try to make our own crypo state and if we can't, skip this
            // epoch.
            if self.obtain_crypto_state(epoch).is_err() {
                continue;
            }

            if let Some(recvd) = self
                .obtain_crypto_state(epoch)
                .as_mut()
                .unwrap()
                .recvd_state()
            {
                let acks = recvd.get_eligible_ack_ranges();
                Frame::encode_ack_frame(&acks, &mut encoder);
                // TODO(ekr@rtfm.com): Deal with the case where ACKs don't fit
                // in an entire packet.
                assert!(encoder.len() <= self.pmtu);
            }

            let mut ack_eliciting = false;
            let mut is_crypto_packet = false;
            // Copy generators out so that we can iterate over it and pass
            // self to the functions.
            let mut generators = mem::replace(&mut self.generators, Vec::new());
            for generator in &mut generators {
                // TODO(ekr@rtfm.com): Fix TxMode
                while let Some((frame, token)) =
                    generator.generate(self, epoch, TxMode::Normal, self.pmtu - encoder.len())
                {
                    //qtrace!("pmtu {} written {}", self.pmtu, d.written());
                    ack_eliciting = ack_eliciting || frame.ack_eliciting();
                    is_crypto_packet = match frame {
                        Frame::Crypto { .. } => true,
                        _ => is_crypto_packet,
                    };
                    frame.marshal(&mut encoder);
                    if let Some(t) = token {
                        tokens.push(t);
                    }
                    assert!(encoder.len() <= self.pmtu);
                    if encoder.len() == self.pmtu {
                        // Filled this packet, get another one.
                        ds.push((encoder, ack_eliciting, is_crypto_packet, tokens));
                        encoder = Encoder::default();
                        tokens = Vec::new();
                        ack_eliciting = false;
                        is_crypto_packet = false;
                    }
                }
            }
            self.generators = generators;

            if encoder.len() > 0 {
                ds.push((encoder, ack_eliciting, is_crypto_packet, tokens))
            }

            for (encoded, ack_eliciting, is_crypto, tokens) in ds {
                qdebug!([self] "Need to send a packet");

                initial_only = epoch == 0;
                let hdr = PacketHdr::new(
                    0,
                    match epoch {
                        0 => {
                            let token = match &self.retry_token {
                                Some(v) => v.clone(),
                                _ => Vec::new(),
                            };
                            PacketType::Initial(token)
                        }
                        1 => PacketType::ZeroRTT,
                        2 => PacketType::Handshake,
                        3 => PacketType::Short,
                        _ => unimplemented!(), // TODO(ekr@rtfm.com): Key Update.
                    },
                    Some(self.version),
                    self.dcid.clone(),
                    Some(self.scid.clone()),
                    self.tx_pns[PNSpace::from(epoch) as usize],
                    epoch,
                );
                self.tx_pns[PNSpace::from(epoch) as usize] += 1;
                self.stats.packets_tx += 1;
                self.loss_recovery.on_packet_sent(
                    PNSpace::from(epoch),
                    hdr.pn,
                    ack_eliciting,
                    is_crypto,
                    tokens,
                    cur_time,
                );

                // Failure to have the state here is an internal error.
                let cs = self.obtain_crypto_state(hdr.epoch).unwrap();
                let packet = encode_packet(&cs.tx, &hdr, &encoded);
                dump_packet(self, "tx", &hdr, &encoded);
                out_packets.push(packet);
            }
        }

        // Put packets in UDP datagrams
        let mut out_dgrams = out_packets
            .into_iter()
            .inspect(|p| qdebug!([self] "packet {}", hex(p)))
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

        // Pad Initial packets sent by the client to 1200 bytes.
        if self.role == Role::Client && initial_only && !out_dgrams.is_empty() {
            qdebug!([self] "pad Initial to 1200");
            out_dgrams.last_mut().unwrap().resize(1200, 0);
        }

        out_dgrams
            .iter()
            .for_each(|dgram| qdebug!([self] "Datagram length: {}", dgram.len()));

        Ok(out_dgrams)
    }

    fn client_start(&mut self) -> Res<()> {
        qinfo!([self] "client_start SCID={}", hex(&self.scid));
        self.handshake(0, None)?;
        self.set_state(State::WaitInitial);
        Ok(())
    }

    fn get_closing_period_time(&self, cur_time: u64) -> u64 {
        // Spec says close time should be at least PTO times 3.
        cur_time + (self.loss_recovery.rtt_vals.pto() * 3)
    }

    /// Close the connection.
    pub fn close<S: Into<String>>(&mut self, cur_time: u64, error: AppError, msg: S) {
        self.set_state(State::Closing {
            error: ConnectionError::Application(error),
            frame_type: 0,
            msg: msg.into(),
            timeout: self.get_closing_period_time(cur_time),
        });
    }

    fn handshake(&mut self, epoch: u16, data: Option<&[u8]>) -> Res<()> {
        qdebug!("Handshake epoch={} data={:0x?}", epoch, data);
        let mut rec: Option<Record> = None;

        if let Some(d) = data {
            qdebug!([self] "Handshake received {:0x?} ", d);
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
            qwarn!([self] "marking connection as authenticated without checking");
            self.tls.authenticated();
            m = self.tls.handshake_raw(0, None);
        }
        match m {
            Err(e) => {
                qwarn!([self] "Handshake failed");
                return Err(match self.tls.alert() {
                    Some(a) => Error::CryptoAlert(*a),
                    _ => Error::CryptoError(e),
                });
            }
            Ok(msgs) => {
                for m in msgs {
                    qdebug!([self] "Inserting message {:?}", m);
                    assert_eq!(m.ct, 22);
                    self.crypto_streams[m.epoch as usize].tx.send(&m.data);
                }
            }
        }
        if self.tls.state().connected() {
            qinfo!([self] "TLS handshake completed");

            if self.tls.info().map(SecretAgentInfo::alpn).is_none() {
                // 120 = no_application_protocol
                let err = Error::CryptoAlert(120);
                return Err(err);
            }

            self.set_state(State::Connected);

            self.peer_max_stream_idx_bidi = StreamIndex::new(
                self.tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(tp_const::INITIAL_MAX_STREAMS_BIDI),
            );

            self.peer_max_stream_idx_uni = StreamIndex::new(
                self.tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(tp_const::INITIAL_MAX_STREAMS_UNI),
            );
            self.flow_mgr.borrow_mut().conn_increase_max_credit(
                self.tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(tp_const::INITIAL_MAX_DATA),
            );
        }
        Ok(())
    }

    fn input_frame(&mut self, epoch: Epoch, frame: Frame, cur_time: u64) -> Res<()> {
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
                    ack_ranges,
                    cur_time,
                )?;
            }
            Frame::ResetStream {
                stream_id,
                application_error_code,
                ..
            } => {
                // TODO(agrover@mozilla.com): use final_size for connection MaxData calc
                if let (_, Some(rs)) = self.obtain_stream(stream_id.into())? {
                    rs.reset(application_error_code);
                }
            }
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => {
                self.events
                    .borrow_mut()
                    .send_stream_stop_sending(stream_id.into(), application_error_code);
                if let (Some(ss), _) = self.obtain_stream(stream_id.into())? {
                    ss.reset(application_error_code);
                }
            }
            Frame::Crypto { offset, data } => {
                qdebug!(
                    [self]
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
            Frame::NewToken { token } => self.token = Some(token),
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
            } => {
                if let (_, Some(rs)) = self.obtain_stream(stream_id.into())? {
                    rs.inbound_stream_frame(fin, offset, data)?;
                }
            }
            Frame::MaxData { maximum_data } => self
                .flow_mgr
                .borrow_mut()
                .conn_increase_max_credit(maximum_data),
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                if let (Some(ss), _) = self.obtain_stream(stream_id.into())? {
                    ss.set_max_stream_data(maximum_stream_data);
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
            Frame::DataBlocked { data_limit } => {
                // Should never happen since we set data limit to 2^62-1
                qwarn!([self] "Received DataBlocked with data limit {}", data_limit);
            }
            Frame::StreamDataBlocked { stream_id, .. } => {
                // TODO(agrover@mozilla.com): how should we be using
                // currently-unused stream_data_limit?

                let stream_id: StreamId = stream_id.into();

                // Terminate connection with STREAM_STATE_ERROR if send-only
                // stream (-transport 19.13)
                if stream_id.is_send_only(self.role()) {
                    return Err(Error::StreamStateError);
                }

                if let (_, Some(rs)) = self.obtain_stream(stream_id)? {
                    rs.maybe_send_flowc_update();
                }
            }
            Frame::StreamsBlocked { stream_type, .. } => {
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
                self.connection_ids
                    .insert(sequence_number, (connection_id, stateless_reset_token));
            }
            Frame::RetireConnectionId { sequence_number } => {
                self.connection_ids.remove(&sequence_number);
            }
            Frame::PathChallenge { data } => self.flow_mgr.borrow_mut().path_response(data),
            Frame::PathResponse { .. } => {
                // Should never see this, we don't support migration atm and
                // do not send path challenges
                qwarn!([self] "Received Path Response");
            }
            Frame::ConnectionClose {
                close_type,
                error_code,
                frame_type,
                reason_phrase,
            } => {
                let reason_phrase = String::from_utf8_lossy(&reason_phrase);
                qinfo!([self]
                       "ConnectionClose received. Closing. Close type: {:?} Error code: {} frame type {:x} reason {}",
                       close_type,
                       error_code,
                       frame_type,
                       reason_phrase);
                self.events.borrow_mut().connection_closed(
                    close_type,
                    error_code,
                    frame_type,
                    &reason_phrase,
                );
                self.set_state(State::Closed(ConnectionError::Application(error_code)));
            }
        };

        Ok(())
    }

    fn handle_ack(
        &mut self,
        epoch: Epoch,
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: Vec<AckRange>,
        cur_time: u64,
    ) -> Res<()> {
        qinfo!(
            [self]
            "Rx ACK epoch={}, largest_acked={}, first_ack_range={}, ranges={:?}",
            epoch,
            largest_acknowledged,
            first_ack_range,
            ack_ranges
        );

        let acked_ranges =
            Frame::decode_ack_frame(largest_acknowledged, first_ack_range, ack_ranges)?;
        let (mut acked_packets, mut lost_packets) = self.loss_recovery.on_ack_received(
            PNSpace::from(epoch),
            largest_acknowledged,
            acked_ranges,
            ack_delay,
            cur_time,
        );
        for acked in &mut acked_packets {
            acked.mark_acked(self);
        }
        for lost in &mut lost_packets {
            lost.mark_lost(self);
        }

        Ok(())
    }

    fn set_state(&mut self, state: State) {
        if state != self.state {
            qinfo!([self] "State change from {:?} -> {:?}", self.state, state);
            self.state = state;
            match &self.state {
                State::Connected => {}
                State::Closing { .. } => {
                    self.send_streams.clear();
                    self.recv_streams.clear();
                    self.generators.clear();
                    self.generators.push(Box::new(CloseGenerator {}));
                    self.flow_mgr.borrow_mut().set_need_close_frame(true);
                }
                State::Closed(..) => {
                    // Equivalent to spec's "draining" state -- never send anything.
                    self.send_streams.clear();
                    self.recv_streams.clear();
                    self.generators.clear();
                }
                _ => {}
            }
        }
    }

    // Create the initial crypto state.
    fn create_initial_crypto_state(&mut self, dcid: &[u8]) {
        qinfo!(
            [self]
            "Creating initial cipher state role={:?} dcid={}",
            self.role,
            hex(dcid)
        );
        //assert!(matches!(None, self.crypto_states[0]));

        let cds = CryptoDxState::new_initial("client in", dcid);
        let sds = CryptoDxState::new_initial("server in", dcid);

        self.crypto_states[0] = Some(match self.role {
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

    // Get a crypto state, making it if necessary, otherwise return an error.
    fn obtain_crypto_state(&mut self, epoch: Epoch) -> Res<&mut CryptoState> {
        let cs = &mut self.crypto_states[epoch as usize];

        match cs {
            Some(ref mut cs) => Ok(cs),
            None => {
                qtrace!("No crypto state for epoch {}", epoch);
                assert!(epoch != 0); // This state is made directly.

                let rs = self.tls.read_secret(epoch).ok_or_else(|| {
                    qtrace!("Keying material not available for epoch {}", epoch);
                    Error::KeysNotFound
                })?;
                let ws = self
                    .tls
                    .write_secret(epoch)
                    .expect("ws must exist if rs exists");

                // TODO(ekr@rtfm.com): The match covers up a bug in
                // neqo-crypto where we set up the state too late. Fix when that
                // gets fixed.
                let cipher = match self.tls.info().as_ref() {
                    Some(info) => info.cipher_suite(),
                    None => TLS_AES_128_GCM_SHA256 as u16,
                };
                *cs = Some(CryptoState {
                    epoch,
                    rx: CryptoDxState::new(format!("read_epoch={}", epoch), rs, cipher),
                    tx: CryptoDxState::new(format!("write_epoch={}", epoch), ws, cipher),
                    recvd: None,
                });
                Ok(cs.as_mut().unwrap())
            }
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

    /// Get or make a stream, and implicitly open additional streams as
    /// indicated by its stream id.
    fn obtain_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Res<(Option<&mut SendStream>, Option<&mut RecvStream>)> {
        if self.state != State::Connected {
            return Err(Error::ConnectionState);
        }

        // May require creating new stream(s)
        if stream_id.is_peer_initiated(self.role()) {
            let next_stream_idx = if stream_id.is_bidi() {
                &mut self.local_next_stream_idx_bidi
            } else {
                &mut self.local_next_stream_idx_uni
            };
            let stream_idx: StreamIndex = stream_id.into();

            if stream_idx >= *next_stream_idx {
                let recv_initial_max_stream_data = if stream_id.is_bidi() {
                    if stream_idx > self.local_max_stream_idx_bidi {
                        qwarn!([self] "peer bidi stream create blocked, next={:?} max={:?}",
                               stream_idx,
                               self.local_max_stream_idx_bidi);
                        return Err(Error::StreamLimitError);
                    }
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
                } else {
                    if stream_idx > self.local_max_stream_idx_uni {
                        qwarn!([self] "peer uni stream create blocked, next={:?} max={:?}",
                               stream_idx,
                               self.local_max_stream_idx_uni);
                        return Err(Error::StreamLimitError);
                    }
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_UNI)
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
                            .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
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
        }

        Ok((
            self.send_streams.get_mut(&stream_id),
            self.recv_streams.get_mut(&stream_id),
        ))
    }

    /// Create a stream.
    // Returns new stream id
    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        // Can't make streams before remote tparams are received as part of
        // handshake. Can't make streams when closing/closed.
        if self.state != State::Connected {
            return Err(Error::ConnectionState);
        }

        Ok(match st {
            StreamType::UniDi => {
                if self.peer_next_stream_idx_uni >= self.peer_max_stream_idx_uni {
                    self.flow_mgr
                        .borrow_mut()
                        .streams_blocked(self.peer_max_stream_idx_uni, StreamType::UniDi);
                    qwarn!([self] "local uni stream create blocked, next={:?} max={:?}",
                           self.peer_next_stream_idx_uni,
                           self.peer_max_stream_idx_uni);
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .peer_next_stream_idx_uni
                    .to_stream_id(StreamType::UniDi, self.role);
                self.peer_next_stream_idx_uni += 1;
                let initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_UNI);

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
                    qwarn!([self] "local bidi stream create blocked, next={:?} max={:?}",
                           self.peer_next_stream_idx_bidi,
                           self.peer_max_stream_idx_bidi);
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .peer_next_stream_idx_bidi
                    .to_stream_id(StreamType::BiDi, self.role);
                self.peer_next_stream_idx_bidi += 1;
                let send_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);

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
                    .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);

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
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.send(data)
    }

    /// Close the stream. Enqueued data will be sent.
    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.close();
        Ok(())
    }

    /// Abandon transmission of in-flight and future stream data.
    pub fn stream_reset_send(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.reset(err);
        Ok(())
    }

    /// Read buffered data from stream. bool says whether read bytes includes
    /// the final data on stream.
    pub fn stream_recv(&mut self, stream_id: u64, data: &mut [u8]) -> Res<(usize, bool)> {
        let stream = self
            .recv_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        let rb = stream.read(data)?;
        Ok((rb.0 as usize, rb.1))
    }

    /// Application is no longer interested in this stream.
    pub fn stream_stop_sending(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        let stream = self
            .recv_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.stop_sending(err);
        Ok(())
    }

    /// Get events that indicate state changes on the connection.
    pub fn events(&mut self) -> Vec<ConnectionEvent> {
        // Turn it into a vec for simplicity's sake
        self.events.borrow_mut().events().into_iter().collect()
    }

    fn check_loss_detection_timeout(&mut self, cur_time: u64) {
        qdebug!([self] "check_loss_detection_timeout");
        let (mut lost_packets, retransmit_unacked_crypto, send_one_or_two_packets) =
            self.loss_recovery.on_loss_detection_timeout(cur_time);
        if !lost_packets.is_empty() {
            qdebug!([self] "check_loss_detection_timeout loss detected.");
            for lost in lost_packets.iter_mut() {
                lost.mark_lost(self);
            }
        } else if retransmit_unacked_crypto {
            qdebug!(
                [self]
                "check_loss_detection_timeout - retransmit_unacked_crypto"
            );
        // TODO
        } else if send_one_or_two_packets {
            qdebug!(
                [self]
                "check_loss_detection_timeout -send_one_or_two_packets"
            );
            // TODO
        }
    }
}

impl ::std::fmt::Display for Connection {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?} {:p}", self.role, self as *const Connection)
    }
}

impl CryptoCtx for CryptoDxState {
    fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>> {
        let mask = self.hpkey.mask(sample)?;
        qdebug!("HP sample={} mask={}", hex(sample), hex(&mask));
        Ok(mask)
    }

    fn aead_decrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
        qinfo!(
            [self.label]
            "aead_decrypt pn={} hdr={} body={}",
            pn,
            hex(hdr),
            hex(body)
        );
        let mut out = vec![0; body.len()];
        let res = self.aead.decrypt(pn, hdr, body, &mut out)?;
        Ok(res.to_vec())
    }

    fn aead_encrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
        qdebug!(
            [self.label]
            "aead_encrypt pn={} hdr={} body={}",
            pn,
            hex(hdr),
            hex(body)
        );

        let size = body.len() + MAX_AUTH_TAG;
        let mut out = vec![0; size];
        let res = self.aead.encrypt(pn, hdr, body, &mut out)?;

        qdebug!([self.label] "aead_encrypt ct={}", hex(res),);

        Ok(res.to_vec())
    }
}

impl PacketDecoder for Connection {
    fn get_cid_len(&self) -> usize {
        CID_LENGTH
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
            assert!(data_len <= remaining);
            let frame = Frame::Crypto {
                offset,
                data: data.to_vec(),
            };
            tx_stream.mark_as_sent(offset, data_len);

            qdebug!(
                [conn]
                "Emitting crypto frame epoch={}, offset={}, len={}",
                epoch,
                offset,
                data_len
            );
            Some((
                frame,
                Some(Box::new(CryptoGeneratorToken {
                    epoch,
                    offset,
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
            [conn]
            "Acked crypto frame epoch={} offset={} length={}",
            self.epoch,
            self.offset,
            self.length
        );
        conn.crypto_streams[self.epoch as usize]
            .tx
            .mark_as_acked(self.offset, self.length as usize);
    }
    fn lost(&mut self, _conn: &mut Connection) {
        // TODO(agrover@mozilla.com): @ekr: resend?
    }
}

struct CloseGenerator {}

impl FrameGenerator for CloseGenerator {
    fn generate(
        &mut self,
        c: &mut Connection,
        _e: Epoch,
        _mode: TxMode,
        _remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        if let State::Closing {
            error: cerr,
            frame_type,
            msg: reason,
            ..
        } = c.state()
        {
            if c.flow_mgr.borrow().need_close_frame() {
                c.flow_mgr.borrow_mut().set_need_close_frame(false);
                return Some((
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
                ));
            }
        } else {
            qerror!(
                "CloseGenerator.generate() called when in {:?}, not State::Closing",
                c.state()
            );
        }

        None
    }
}

/// Calculate the frame header size so we know how much data we can fit
fn stream_frame_hdr_len(stream_id: StreamId, offset: u64, remaining: usize) -> usize {
    let mut hdr_len = 1; // for frame type
    hdr_len += Encoder::varint_len(stream_id.as_u64());
    if offset > 0 {
        hdr_len += Encoder::varint_len(offset);
    }

    // We always include a length field.
    hdr_len + Encoder::varint_len(remaining as u64)
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
                stream.mark_as_sent(offset, data_len, fin);
                return Some((
                    frame,
                    Some(Box::new(StreamGeneratorToken {
                        id: *stream_id,
                        offset,
                        length: data_len as u64,
                        fin,
                    })),
                ));
            }
        }
        None
    }
}

struct StreamGeneratorToken {
    id: StreamId,
    offset: u64,
    length: u64,
    fin: bool,
}

impl FrameGeneratorToken for StreamGeneratorToken {
    fn acked(&mut self, conn: &mut Connection) {
        qinfo!(
            [conn]
            "Acked frame stream={} offset={} length={} fin={}",
            self.id.as_u64(),
            self.offset,
            self.length,
            self.fin
        );
        if let Some(ss) = conn.send_streams.get_mut(&self.id) {
            ss.mark_as_acked(self.offset, self.length as usize, self.fin);
        }
    }
    fn lost(&mut self, conn: &mut Connection) {
        qinfo!(
            [conn]
            "Lost frame stream={} offset={} length={} fin={}",
            self.id.as_u64(),
            self.offset,
            self.length,
            self.fin
        );
        if let Some(ss) = conn.send_streams.get_mut(&self.id) {
            ss.mark_as_lost(self.offset, self.length as usize, self.fin);
        }
    }
}

struct FlowControlGeneratorToken(Frame);

impl FrameGeneratorToken for FlowControlGeneratorToken {
    fn acked(&mut self, conn: &mut Connection) {
        if let Frame::ResetStream {
            stream_id,
            application_error_code,
            final_size,
        } = self.0
        {
            qinfo!(
                [conn]
                "Reset received stream={} err={} final_size={}",
                stream_id,
                application_error_code,
                final_size
            );
            if let Some(ss) = conn.send_streams.get_mut(&stream_id.into()) {
                ss.reset_acked()
            }
        }
    }

    fn lost(&mut self, conn: &mut Connection) {
        match self.0 {
            // Always resend ResetStream if lost
            Frame::ResetStream {
                stream_id,
                application_error_code,
                final_size,
            } => {
                qinfo!(
                    [conn]
                    "Reset lost stream={} err={} final_size={}",
                    stream_id,
                    application_error_code,
                    final_size
                );
                if conn.send_streams.contains_key(&stream_id.into()) {
                    conn.flow_mgr.borrow_mut().stream_reset(
                        stream_id.into(),
                        application_error_code,
                        final_size,
                    );
                }
            }
            // Resend MaxStreams if lost (with updated value)
            Frame::MaxStreams { stream_type, .. } => {
                let local_max = match stream_type {
                    StreamType::BiDi => &mut conn.local_max_stream_idx_bidi,
                    StreamType::UniDi => &mut conn.local_max_stream_idx_uni,
                };

                conn.flow_mgr
                    .borrow_mut()
                    .max_streams(*local_max, stream_type)
            }
            // Only resend "*Blocked" frames if still blocked
            Frame::DataBlocked { .. } => {
                if conn.flow_mgr.borrow().conn_credit_avail() == 0 {
                    conn.flow_mgr.borrow_mut().data_blocked()
                }
            }
            Frame::StreamDataBlocked { stream_id, .. } => {
                if let Some(ss) = conn.send_streams.get(&stream_id.into()) {
                    if ss.credit_avail() == 0 {
                        conn.flow_mgr
                            .borrow_mut()
                            .stream_data_blocked(stream_id.into(), ss.max_stream_data())
                    }
                }
            }
            Frame::StreamsBlocked { stream_type, .. } => match stream_type {
                StreamType::UniDi => {
                    if conn.peer_next_stream_idx_uni >= conn.peer_max_stream_idx_uni {
                        conn.flow_mgr
                            .borrow_mut()
                            .streams_blocked(conn.peer_max_stream_idx_uni, StreamType::UniDi);
                    }
                }
                StreamType::BiDi => {
                    if conn.peer_next_stream_idx_bidi >= conn.peer_max_stream_idx_bidi {
                        conn.flow_mgr
                            .borrow_mut()
                            .streams_blocked(conn.peer_max_stream_idx_bidi, StreamType::BiDi);
                    }
                }
            },
            // Resend StopSending
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => conn
                .flow_mgr
                .borrow_mut()
                .stop_sending(stream_id.into(), application_error_code),
            // Resend MaxStreamData if not SizeKnown
            // (maybe_send_flowc_update() checks this.)
            Frame::MaxStreamData { stream_id, .. } => {
                if let Some(rs) = conn.recv_streams.get_mut(&stream_id.into()) {
                    rs.maybe_send_flowc_update()
                }
            }
            Frame::PathResponse { .. } => qinfo!("Path Response lost, not re-sent"),
            _ => qwarn!("Unexpected Flow frame {:?} lost, not re-sent", self.0),
        }
    }
}

struct FlowControlGenerator {}

impl FrameGenerator for FlowControlGenerator {
    fn generate(
        &mut self,
        conn: &mut Connection,
        _epoch: u16,
        _mode: TxMode,
        remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        if let Some(frame) = conn.flow_mgr.borrow().peek() {
            // A suboptimal way to figure out if the frame fits within remaining
            // space.
            let mut d = Encoder::default();
            frame.marshal(&mut d);
            if d.len() > remaining {
                qtrace!("flowc frame doesn't fit in remaining");
                return None;
            }
        } else {
            return None;
        }
        // There is enough space we can add this frame to the packet.
        let frame = conn.flow_mgr.borrow_mut().next().expect("just peeked this");
        Some((
            frame.clone(),
            Some(Box::new(FlowControlGeneratorToken(frame))),
        ))
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

#[derive(Debug, Default)]
struct RttVals {
    latest_rtt: u64,
    smoothed_rtt: u64,
    rttvar: u64,
    min_rtt: u64,
    max_ack_delay: u64,
}

impl RttVals {
    fn update_rtt(&mut self, latest_rtt: u64, mut ack_delay: u64) {
        self.latest_rtt = latest_rtt;
        // min_rtt ignores ack delay.
        self.min_rtt = min(self.min_rtt, self.latest_rtt);
        // Limit ack_delay by max_ack_delay
        ack_delay = min(ack_delay, self.max_ack_delay);
        // Adjust for ack delay if it's plausible.
        if self.latest_rtt - self.min_rtt > ack_delay {
            self.latest_rtt -= ack_delay;
        }
        // Based on {{?RFC6298}}.
        if self.smoothed_rtt == 0 {
            self.smoothed_rtt = self.latest_rtt;
            self.rttvar = self.latest_rtt / 2;
        } else {
            let rttvar_sample = if self.smoothed_rtt > self.latest_rtt {
                self.smoothed_rtt - self.latest_rtt
            } else {
                self.latest_rtt - self.smoothed_rtt
            };
            self.rttvar =
                (3.0 / 4.0 * (self.rttvar as f64) + 1.0 / 4.0 * (rttvar_sample as f64)) as u64;
            self.smoothed_rtt = (7.0 / 8.0 * (self.smoothed_rtt as f64)
                + 1.0 / 8.0 * (self.latest_rtt as f64)) as u64;
        }
    }

    fn pto(&self) -> u64 {
        self.smoothed_rtt + max(4 * self.rttvar, GRANULARITY) + self.max_ack_delay
    }

    fn timer_for_crypto_retransmission(&mut self, crypto_count: u32) -> u64 {
        let mut timeout = if self.smoothed_rtt == 0 {
            2 * INITIAL_RTT
        } else {
            2 * self.smoothed_rtt
        };

        timeout = max(timeout, GRANULARITY);
        timeout * 2u64.pow(crypto_count)
    }
}

#[derive(Debug, Default)]
struct LossRecoverySpace {
    largest_acked: u64,
    loss_time: u64,
    sent_packets: HashMap<u64, SentPacket>,
}

impl LossRecoverySpace {
    pub fn largest_acknowledged(&self) -> u64 {
        self.largest_acked
    }

    // Update the largest acknowledged and return the packet that this corresponds to.
    fn update_largest_acked(&mut self, largest_acked: u64) -> Option<&SentPacket> {
        if largest_acked > self.largest_acked {
            self.largest_acked = largest_acked;
        }
        self.sent_packets.get(&largest_acked)
    }

    // Remove all the acked packets.
    fn remove_acked(&mut self, acked_ranges: Vec<(u64, u64)>) -> Vec<SentPacket> {
        let mut acked_packets = Vec::new();
        for (end, start) in acked_ranges {
            // ^^ Notabug: see Frame::decode_ack_frame()
            for pn in start..=end {
                if let Some(sent) = self.sent_packets.remove(&pn) {
                    qdebug!("acked={}", pn);
                    acked_packets.push(sent);
                }
            }
        }
        acked_packets
    }
}

#[derive(Debug, Default)]
struct LossRecovery {
    loss_detection_timer: u64,
    crypto_count: u32,
    pto_count: u32,
    time_of_last_sent_ack_eliciting_packet: u64,
    time_of_last_sent_crypto_packet: u64,
    rtt_vals: RttVals,
    packet_spaces: [LossRecoverySpace; 3],
}

impl LossRecovery {
    fn new() -> LossRecovery {
        LossRecovery {
            rtt_vals: RttVals {
                min_rtt: u64::max_value(),
                max_ack_delay: 25_000, // 25ms in microseconds
                ..RttVals::default()
            },

            ..LossRecovery::default()
        }
    }

    pub fn space(&self, pn_space: PNSpace) -> &LossRecoverySpace {
        &self.packet_spaces[pn_space as usize]
    }
    fn space_mut(&mut self, pn_space: PNSpace) -> &mut LossRecoverySpace {
        &mut self.packet_spaces[pn_space as usize]
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
        qdebug!([self] "packet {} sent.", packet_number);
        self.space_mut(pn_space).sent_packets.insert(
            packet_number,
            SentPacket {
                time_sent: cur_time,
                ack_eliciting,
                is_crypto_packet,
                tokens,
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

    /// Returns (acked packets, lost packets)
    pub fn on_ack_received(
        &mut self,
        pn_space: PNSpace,
        largest_acked: u64,
        acked_ranges: Vec<(u64, u64)>,
        ack_delay: u64,
        cur_time_nanos: u64,
    ) -> (Vec<SentPacket>, Vec<SentPacket>) {
        let cur_time = cur_time_nanos / 1000; //TODO currently LossRecovery does everything in microseconds.
        qdebug!([self] "ack received - largest_acked={}.", largest_acked);

        let last_sent = self.space_mut(pn_space).update_largest_acked(largest_acked);
        // If the largest acknowledged is newly acked and
        // ack-eliciting, update the RTT.
        if let Some(sent) = last_sent {
            if sent.ack_eliciting {
                let latest_rtt = cur_time - sent.time_sent;
                self.rtt_vals.update_rtt(latest_rtt, ack_delay);
            }
        }

        // TODO Process ECN information if present.

        let acked_packets = self.space_mut(pn_space).remove_acked(acked_ranges);
        if acked_packets.is_empty() {
            return (acked_packets, Vec::new());
        }

        let lost_packets = self.detect_lost_packets(pn_space, cur_time);

        self.crypto_count = 0;
        self.pto_count = 0;

        self.set_loss_detection_timer();

        (acked_packets, lost_packets)
    }

    fn detect_lost_packets(&mut self, pn_space: PNSpace, cur_time: u64) -> Vec<SentPacket> {
        self.space_mut(pn_space).loss_time = 0;

        let loss_delay = (TIME_THRESHOLD
            * (max(self.rtt_vals.latest_rtt, self.rtt_vals.smoothed_rtt) as f64))
            as u64;

        // Packets sent before this time are deemed lost.
        // (cur_time < loss_delay, can happen in test)
        let lost_send_time = if cur_time < loss_delay {
            0
        } else {
            cur_time - loss_delay
        };

        // Packets with packet numbers before this are deemed lost.
        let lost_pn = self
            .space_mut(pn_space)
            .largest_acked
            .saturating_sub(PACKET_THRESHOLD);

        qdebug!(
            [self]
            "detect lost packets - time={}, pn={}",
            lost_send_time,
            lost_pn
        );

        let packet_space = self.space_mut(pn_space);

        let mut lost = Vec::new();
        for (pn, packet) in &packet_space.sent_packets {
            // Mark packet as lost, or set time when it should be marked.
            if *pn <= packet_space.largest_acked {
                if packet.time_sent <= lost_send_time || *pn <= lost_pn {
                    qdebug!("lost={}", pn);
                    lost.push(*pn);
                } else if packet_space.loss_time == 0 {
                    packet_space.loss_time = packet.time_sent + loss_delay;
                } else {
                    packet_space.loss_time =
                        min(packet_space.loss_time, packet.time_sent + loss_delay);
                }
            }
        }

        let mut lost_packets = Vec::new();
        for pn in lost {
            if let Some(sent_packet) = packet_space.sent_packets.remove(&pn) {
                lost_packets.push(sent_packet);
            }
        }

        // TODO
        // Inform the congestion controller of lost packets.

        lost_packets
    }

    fn set_loss_detection_timer(&mut self) {
        qdebug!([self] "set_loss_detection_timer.");
        let mut has_crypto_out = false;
        let mut has_ack_eliciting_out = false;

        for pn_space in &[
            PNSpace::Initial,
            PNSpace::Handshake,
            PNSpace::ApplicationData,
        ] {
            let packet_space = &mut self.packet_spaces[*pn_space as usize];

            if packet_space
                .sent_packets
                .values()
                .any(|sp| sp.is_crypto_packet)
            {
                has_crypto_out = true;
            }

            if packet_space
                .sent_packets
                .values()
                .any(|sp| sp.ack_eliciting)
            {
                has_ack_eliciting_out = true;
            }
        }

        qdebug!(
            [self]
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
            self.loss_detection_timer = self.time_of_last_sent_crypto_packet
                + self
                    .rtt_vals
                    .timer_for_crypto_retransmission(self.crypto_count);
        } else {
            // Calculate PTO duration
            let timeout = self.rtt_vals.pto() * 2u64.pow(self.pto_count);
            self.loss_detection_timer = self.time_of_last_sent_ack_eliciting_packet + timeout;
        }
        qdebug!([self] "loss_detection_timer={}", self.loss_detection_timer);
    }

    #[allow(clippy::if_same_then_else)]
    fn get_earliest_loss_time(&self) -> (u64, PNSpace) {
        let mut loss_time = self.packet_spaces[PNSpace::Initial as usize].loss_time;
        let mut pn_space = PNSpace::Initial;
        for space in &[PNSpace::Handshake, PNSpace::ApplicationData] {
            let packet_space = &self.packet_spaces[*space as usize];

            if loss_time == 0 {
                loss_time = packet_space.loss_time;
                pn_space = *space;
            } else if packet_space.loss_time != 0 && packet_space.loss_time < loss_time {
                loss_time = packet_space.loss_time;
                pn_space = *space;
            }
        }
        (loss_time, pn_space)
    }

    pub fn get_timer(&self) -> u64 {
        self.loss_detection_timer * 1000
    }

    //  The 3 return values for this function: (Vec<SentPacket>, bool, bool).
    //  1) A list of detected lost packets
    //  2) Crypto timer expired, crypto data should be retransmitted,
    //  3) PTO, one or two packets should be transmitted.
    pub fn on_loss_detection_timeout(
        &mut self,
        cur_time_nanos: u64,
    ) -> (Vec<SentPacket>, bool, bool) {
        let cur_time = cur_time_nanos / 1000; //TODO(dragana) currently LossRecovery does everything in microseconds.
        let mut lost_packets = Vec::new();
        //TODO(dragana) enable retransmit_unacked_crypto and send_one_or_two_packets when functionanlity to send not-lost packet is there.
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
            let has_crypto_out = self
                .space(PNSpace::Initial)
                .sent_packets
                .values()
                .chain(self.space(PNSpace::Handshake).sent_packets.values())
                .any(|sp| sp.ack_eliciting);

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
#[allow(unused_variables)]
mod tests {
    use super::*;
    use crate::frame::StreamType;
    use neqo_crypto::init_db;

    fn loopback() -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    fn now() -> u64 {
        0
    }

    #[test]
    fn test_stream_id_methods() {
        let id1 = StreamIndex::new(4).to_stream_id(StreamType::BiDi, Role::Client);
        assert_eq!(id1.is_bidi(), true);
        assert_eq!(id1.is_uni(), false);
        assert_eq!(id1.is_client_initiated(), true);
        assert_eq!(id1.is_server_initiated(), false);
        assert_eq!(id1.role(), Role::Client);
        assert_eq!(id1.is_self_initiated(Role::Client), true);
        assert_eq!(id1.is_self_initiated(Role::Server), false);
        assert_eq!(id1.is_peer_initiated(Role::Client), false);
        assert_eq!(id1.is_peer_initiated(Role::Server), true);
        assert_eq!(id1.is_send_only(Role::Server), false);
        assert_eq!(id1.is_send_only(Role::Client), false);
        assert_eq!(id1.is_recv_only(Role::Server), false);
        assert_eq!(id1.is_recv_only(Role::Client), false);
        assert_eq!(id1.as_u64(), 16);

        let id2 = StreamIndex::new(8).to_stream_id(StreamType::UniDi, Role::Server);
        assert_eq!(id2.is_bidi(), false);
        assert_eq!(id2.is_uni(), true);
        assert_eq!(id2.is_client_initiated(), false);
        assert_eq!(id2.is_server_initiated(), true);
        assert_eq!(id2.role(), Role::Server);
        assert_eq!(id2.is_self_initiated(Role::Client), false);
        assert_eq!(id2.is_self_initiated(Role::Server), true);
        assert_eq!(id2.is_peer_initiated(Role::Client), true);
        assert_eq!(id2.is_peer_initiated(Role::Server), false);
        assert_eq!(id2.is_send_only(Role::Server), true);
        assert_eq!(id2.is_send_only(Role::Client), false);
        assert_eq!(id2.is_recv_only(Role::Server), false);
        assert_eq!(id2.is_recv_only(Role::Client), true);
        assert_eq!(id2.as_u64(), 35);
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
        assert_eq!(res.first().unwrap().len(), 1200);
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

        let active_streams = server
            .events()
            .into_iter()
            .filter_map(|evt| match evt {
                ConnectionEvent::NewStream { stream_id, .. } => Some(stream_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut iter = active_streams.iter();
        let stream_id = iter.next().unwrap();
        let (received, fin) = server.stream_recv(*stream_id, &mut buf).unwrap();
        assert_eq!(received, 4000);
        assert_eq!(fin, false);
        let (received, fin) = server.stream_recv(*stream_id, &mut buf).unwrap();
        assert_eq!(received, 140);
        assert_eq!(fin, false);

        let stream_id = iter.next().unwrap();
        let (received, fin) = server.stream_recv(*stream_id, &mut buf).unwrap();
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
            State::Connected | State::Closing { .. } | State::Closed(..) => true,
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
            State::Closing { error, .. } | State::Closed(error) => {
                assert_eq!(*error, err);
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
            lr.rtt_vals.latest_rtt,
            lr.rtt_vals.smoothed_rtt,
            lr.rtt_vals.rttvar,
            lr.rtt_vals.min_rtt,
            lr.space(PNSpace::Initial).loss_time,
            lr.space(PNSpace::Handshake).loss_time,
            lr.space(PNSpace::ApplicationData).loss_time,
        );
        assert_eq!(lr.rtt_vals.latest_rtt, latest_rtt);
        assert_eq!(lr.rtt_vals.smoothed_rtt, smoothed_rtt);
        assert_eq!(lr.rtt_vals.rttvar, rttvar);
        assert_eq!(lr.rtt_vals.min_rtt, min_rtt);
        assert_eq!(lr.space(PNSpace::Initial).loss_time, loss_time[0]);
        assert_eq!(lr.space(PNSpace::Handshake).loss_time, loss_time[1]);
        assert_eq!(lr.space(PNSpace::ApplicationData).loss_time, loss_time[2]);
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

        // Receive an ack with a gap. acks 0 and 2.
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

    #[test]
    #[test]
    fn test_dup_server_flight1() {
        init_db("./db");
        qdebug!("---- client: generate CH");
        let mut client =
            Connection::new_client("example.com", &["alpn"], loopback(), loopback()).unwrap();
        let (res, _) = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        assert_eq!(res.first().unwrap().len(), 1200);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
        let mut server = Connection::new_server(&["key"], &["alpn"]).unwrap();
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: SH..FIN -> FIN");
        let (res2, _) = client.process(res.clone(), now());
        assert_eq!(res2.len(), 1);
        qdebug!("Output={:0x?}", res);

        assert_eq!(2, client.stats().packets_rx);
        assert_eq!(0, client.stats().dups_rx);

        qdebug!("---- Dup, ignored");
        let (res2, _) = client.process(res.clone(), now());
        assert_eq!(res2.len(), 0);
        qdebug!("Output={:0x?}", res);

        // Four packets total received, two of them are dups
        assert_eq!(4, client.stats().packets_rx);
        assert_eq!(2, client.stats().dups_rx);
    }
}
