#![allow(unused_variables, dead_code)]

use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Debug};
use std::mem;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use neqo_common::data::Data;
use neqo_common::varint::*;
use neqo_crypto::aead::Aead;
use neqo_crypto::constants::*;
use neqo_crypto::hkdf;
use neqo_crypto::hp::{extract_hp, HpKey};
use rand::prelude::*;

use crate::frame::{decode_frame, Frame, FrameType, StreamType};
use crate::nss::*;
use crate::packet::*;
use crate::recv_stream::{RecvStream, RxStreamOrderer, RX_STREAM_DATA_WINDOW};
use crate::send_stream::{SendStream, TxBuffer};
use crate::tparams::consts::*;
use crate::tparams::TransportParametersHandler;
use crate::tracking::RecvdPackets;
use crate::{hex, AppError, ConnectionError, Error, Recvable, Res, Sendable};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

pub const QUIC_VERSION: u32 = 0xff000012;
const NUM_EPOCHS: Epoch = 4;
const MAX_AUTH_TAG: usize = 32;

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

#[derive(Debug, Default)]
pub struct FlowMgr {
    stream_data_blockeds: BTreeMap<u64, Frame>, // stream_id, stream_data_limit
    max_stream_datas: BTreeMap<u64, Frame>,     // stream_id, max_stream_data
}

impl FlowMgr {
    pub fn new() -> FlowMgr {
        FlowMgr::default()
    }

    /// Indicate to peer we need more credits
    pub fn stream_data_blocked(&mut self, stream_id: u64, stream_data_limit: u64) {
        let frame = Frame::StreamDataBlocked {
            stream_id,
            stream_data_limit,
        };
        self.stream_data_blockeds.insert(stream_id, frame);
    }

    /// Update peer with more credits
    pub fn max_stream_data(&mut self, stream_id: u64, maximum_stream_data: u64) {
        let frame = Frame::MaxStreamData {
            stream_id,
            maximum_stream_data,
        };
        self.max_stream_datas.insert(stream_id, frame);
    }

    /// Used by generator to get a flow control frame.
    pub fn next(&mut self) -> Option<Frame> {
        let first_key = self.stream_data_blockeds.keys().next();
        if let Some(&first_key) = first_key {
            return self.stream_data_blockeds.remove(&first_key);
        }

        let first_key = self.max_stream_datas.keys().next();
        if let Some(&first_key) = first_key {
            return self.max_stream_datas.remove(&first_key);
        }

        None
    }

    pub fn peek(&self) -> Option<&Frame> {
        if let Some(key) = self.stream_data_blockeds.keys().next() {
            self.stream_data_blockeds.get(key)
        } else {
            if let Some(key) = self.max_stream_datas.keys().next() {
                self.max_stream_datas.get(key)
            } else {
                None
            }
        }
    }
}

type FrameGeneratorFn = fn(&mut Connection, Epoch, TxMode, usize) -> Option<Frame>;
struct FrameGenerator(FrameGeneratorFn);

impl Debug for FrameGenerator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("<FrameGenerator Function>")
    }
}

impl Deref for FrameGenerator {
    type Target = FrameGeneratorFn;
    fn deref(&self) -> &Self::Target {
        &self.0
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
        log!(Level::Error, "Making CryptoDxState, cipher={}", cipher);
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
    generators: Vec<FrameGenerator>,
    deadline: u64,
    max_data: u64,
    max_streams: u64,
    highest_stream: Option<u64>,
    connection_ids: HashSet<(u64, Vec<u8>)>, // (sequence number, connection id)
    next_uni_stream_id: u64,
    next_bi_stream_id: u64,
    send_streams: BTreeMap<u64, SendStream>, // stream id, stream
    recv_streams: BTreeMap<u64, RecvStream>, // stream id, stream
    outgoing_pkts: Vec<Packet>,              // (offset, data)
    pmtu: usize,
    flow_mgr: Rc<RefCell<FlowMgr>>,
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

        Connection::configure_agent(&mut agent, protocols, Rc::clone(&tphandler));

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
                FrameGenerator(generate_crypto_frames),
                FrameGenerator(generate_flowc_frames),
                FrameGenerator(generate_stream_frames),
            ],
            crypto_states: [None, None, None, None],
            tx_pns: [0; 4],
            deadline: 0,
            max_data: 0,
            max_streams: 0,
            highest_stream: None,
            connection_ids: HashSet::new(),
            next_uni_stream_id: 0,
            next_bi_stream_id: 0,
            send_streams: BTreeMap::new(),
            recv_streams: BTreeMap::new(),
            outgoing_pkts: Vec::new(),
            pmtu: 1280,
            flow_mgr: Rc::new(RefCell::new(FlowMgr::default())),
        };

        c.scid = c.generate_cid();
        if c.rol == Role::Client {
            c.dcid = c.generate_cid();
            c.create_initial_crypto_state(&c.dcid.clone()); // Stupid borrow checker.
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
    pub fn process<I>(&mut self, in_dgrams: I, cur_time: u64) -> Vec<Datagram>
    where
        I: IntoIterator<Item = Datagram>,
    {
        for dgram in in_dgrams {
            let res = self.input(dgram, cur_time);
            self.absorb_error(res);
        }

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
        if let State::Closed(..) = self.state {
            Vec::new()
        } else {
            self.output()
        }
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
                State::Handshaking => {
                    // No-op.rs
                }
                State::Connected => {
                    // No-op.
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

            let ack_eliciting = self.input_packet(hdr.epoch, Data::from_slice(&body))?;

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
    fn input_packet(&mut self, epoch: Epoch, mut d: Data) -> Res<(bool)> {
        let mut ack_eliciting = false;

        // Handle each frame in the packet
        while d.remaining() > 0 {
            let f = decode_frame(&mut d)?;
            ack_eliciting |= f.ack_eliciting();
            let t = f.get_type();
            let res = self.input_frame(epoch, f);
            self.capture_error(t, res)?;
        }

        Ok(ack_eliciting)
    }

    fn output(&mut self) -> Vec<Datagram> {
        // Can't iterate over self.paths while it is owned by self.
        let paths = mem::replace(&mut self.paths, None);
        let mut out_dgrams = Vec::new();
        let mut errors = Vec::new();
        for p in &paths {
            let res = match self.output_path(&p) {
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
            self.output()
        } else {
            out_dgrams // TODO(ekr@rtfm.com): When to call back next.
        }
    }

    // Iterate through all the generators, inserting as many frames as will
    // fit.
    fn output_path(&mut self, path: &Path) -> Res<Vec<Datagram>> {
        let mut out_packets = Vec::new();

        let mut num_initials = 0usize;

        // TODO(ekr@rtfm.com): Be smarter about what epochs we actually have.

        // Frames for different epochs must go in different packets, but then these
        // packets can go in a single datagram
        for epoch in 0..NUM_EPOCHS {
            let mut d = Data::default();
            let mut ds = Vec::new();

            // Try to make our own crypo state and if we can't, skip this
            // epoch.
            if self.ensure_crypto_state(epoch).is_err() {
                continue;
            }

            // TODO(ekr@rtfm.com): Suppress bare acks when we're not piggybacking.
            if let Some(recvd) = self
                .ensure_crypto_state(epoch)
                .as_mut()
                .unwrap()
                .recvd_state()
            {
                let acks = recvd.get_eligible_ack_ranges();
                Frame::encode_ack_frame(acks, &mut d);
                // TODO(ekr@rtfm.com): Deal with the case where ACKs don't fit
                // in an entire packet.
                assert!(d.written() <= self.pmtu);
            }

            for i in 0..self.generators.len() {
                // TODO(ekr@rtfm.com): Fix TxMode

                let left = self.pmtu - d.written();
                while let Some(frame) = self.generators[i](self, epoch, TxMode::Normal, left) {
                    //qtrace!("pmtu {} written {}", self.pmtu, d.written());
                    frame.marshal(&mut d);
                    assert!(d.written() <= self.pmtu);
                    if d.written() == self.pmtu {
                        // Filled this packet, get another one.
                        ds.push(d);
                        d = Data::default();
                    }
                }
            }
            if d.written() > 0 {
                ds.push(d)
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
                // Failure to have the state here is an internal error.
                let cs = self.ensure_crypto_state(hdr.epoch).unwrap();
                let packet = encode_packet(&cs.tx, &mut hdr, d.as_mut_vec())?;
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
        for dgram in &mut out_dgrams[..num_initials] {
            dgram.resize(1200, 0);
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

    fn send_close(&self) -> Option<Frame> {
        if let State::Closing(cerr, frame_type, reason) = self.state() {
            Some(Frame::ConnectionClose {
                close_type: cerr.into(),
                error_code: match cerr {
                    ConnectionError::Application(e) => *e,
                    ConnectionError::Transport(e) => e.code(),
                },
                frame_type: *frame_type,
                reason_phrase: Vec::from(reason.clone()),
            })
        } else {
            None
        }
    }

    fn generate_close(
        c: &mut Connection,
        e: Epoch,
        mode: TxMode,
        remaining: usize,
    ) -> Option<Frame> {
        c.send_close()
    }

    #[allow(dead_code, unused_variables)]
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

        if matches!(m, Ok((HandshakeState::AuthenticationPending, _))) {
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
            Ok((_, msgs)) => {
                for m in msgs {
                    qdebug!(self, "Inserting message {:?}", m);
                    assert_eq!(m.ct, 22);
                    self.crypto_streams[m.epoch as usize].tx.send(&m.data);
                }
            }
        }
        if *self.tls.state() == HandshakeState::Complete {
            qinfo!(self, "TLS handshake completed");
            self.set_state(State::Connected);
        }
        Ok(())
    }

    pub fn input_frame(&mut self, epoch: Epoch, frame: Frame) -> Res<()> {
        #[allow(unused_variables)]
        match frame {
            Frame::Padding => {
                qdebug!(self, "padding!");
            }
            Frame::Ping => {} // TODO(agrover@mozilla.com): generate ack
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
            } => {} // TODO(agrover@mozilla.com): remove acked ranges from list of in-flight packets
            Frame::ResetStream {
                stream_id,
                application_error_code,
                final_size,
            } => {} // TODO(agrover@mozilla.com): reset a stream
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => {
                let stream = self
                    .send_streams
                    .get_mut(&stream_id)
                    .ok_or_else(|| return Error::InvalidStreamId)?;

                stream.reset(application_error_code)?
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
                self.process_inbound_stream_frame(fin, stream_id, offset, data)?;
            }
            Frame::MaxData { maximum_data } => self.max_data = max(self.max_data, maximum_data),
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                if let Some(stream) = self.send_streams.get_mut(&stream_id) {
                    stream.max_stream_data(maximum_stream_data);
                }
            }
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {} // TODO(agrover@mozilla.com): adjust self.max_streams?
            Frame::DataBlocked { data_limit } => {} // TODO(agrover@mozilla.com): use as input to flow control algorithms
            Frame::StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => {
                // TODO(agrover@mozilla.com): terminate connection with
                // SEND_STREAM_ERROR if send-only stream (-transport 19.13)

                // TODO(agrover@mozilla.com): how should we be using
                // currently-unused stream_data_limit?

                if let Some(stream) = self.recv_streams.get_mut(&stream_id) {
                    stream.maybe_send_flowc_update();
                }
            }
            Frame::StreamsBlocked {
                stream_type,
                stream_limit,
            } => {} // TODO(agrover@mozilla.com): do something
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
                    self.generators
                        .push(FrameGenerator(Connection::generate_close));
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

    fn pn_space(epoch: Epoch) -> Epoch {
        if epoch >= 3 {
            return 1;
        }
        return epoch;
    }
    pub fn process_inbound_stream_frame(
        &mut self,
        fin: bool,
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
    ) -> Res<()> {
        // TODO(agrover@mozilla.com): more checking here

        let max_data_if_new_stream = match stream_id & 0x2 == 0 {
            true => self
                .tps
                .borrow()
                .local
                .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE),
            false => self
                .tps
                .borrow()
                .local
                .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNI),
        };

        let stream = self
            .recv_streams
            .entry(stream_id)
            .or_insert(RecvStream::new(
                stream_id,
                max_data_if_new_stream,
                self.flow_mgr.clone(),
            ));

        stream.inbound_stream_frame(fin, offset, data)?;
        stream.maybe_send_flowc_update();

        Ok(())
    }

    // Returns new stream id
    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        // TODO(agrover@mozilla.com): Check against max_stream_id

        // Can't make streams before remote tparams are received as part of
        // handshake
        if self.state != State::Connected {
            return Err(Error::ConnectionState);
        }

        let role_val = match self.rol {
            Role::Server => 1,
            Role::Client => 0,
        };

        Ok(match st {
            StreamType::UniDi => {
                let new_id = (self.next_uni_stream_id << 2) + 2 + role_val;
                self.next_uni_stream_id += 1;
                let initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNI);

                self.send_streams.insert(
                    new_id,
                    SendStream::new(new_id, initial_max_stream_data, self.flow_mgr.clone()),
                );
                new_id
            }
            StreamType::BiDi => {
                let new_id = (self.next_bi_stream_id << 2) + role_val;
                self.next_bi_stream_id += 1;
                let send_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote
                    .as_ref()
                    .expect("remote tparams are valid when State::Connected")
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);

                self.send_streams.insert(
                    new_id,
                    SendStream::new(new_id, send_initial_max_stream_data, self.flow_mgr.clone()),
                );

                let recv_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .local
                    .get_integer(TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);

                self.recv_streams.insert(
                    new_id,
                    RecvStream::new(new_id, recv_initial_max_stream_data, self.flow_mgr.clone()),
                );
                new_id
            }
        })
    }

    /// Send data on a stream.
    /// Returns how many bytes were successfully sent. Could be less
    /// than total, based on receiver credit space available, etc.
    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Res<usize> {
        let stream = self
            .send_streams
            .get_mut(&stream_id)
            .ok_or_else(|| return Error::InvalidStreamId)?;

        stream.send(data)
    }

    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        let stream = self
            .send_streams
            .get_mut(&stream_id)
            .ok_or_else(|| return Error::InvalidStreamId)?;

        Sendable::close(stream);
        Ok(())
    }

    pub fn stream_reset(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        // TODO(agrover@mozilla.com): reset can create a stream
        let stream = self
            .send_streams
            .get_mut(&stream_id)
            .ok_or_else(|| return Error::InvalidStreamId)?;

        stream.reset(err)
    }

    fn generate_cid(&mut self) -> Vec<u8> {
        let mut v: [u8; 8] = [0; 8];
        rand::thread_rng().fill(&mut v);
        v.to_vec()
    }

    pub fn label(&self) -> String {
        format!("{:?} {:p}", self.rol, self as *const Connection)
    }

    pub fn get_recv_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Recvable)> {
        self.recv_streams
            .iter_mut()
            .map(|(x, y)| (*x, y as &mut Recvable))
    }

    pub fn get_recvable_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Recvable)> {
        self.get_recv_streams()
            .filter(|(_, stream)| stream.data_ready())
    }

    pub fn get_send_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Sendable)> {
        self.send_streams
            .iter_mut()
            .map(|(x, y)| (*x, y as &mut Sendable))
    }

    pub fn get_sendable_streams(&mut self) -> impl Iterator<Item = (u64, &mut dyn Sendable)> {
        self.get_send_streams()
            .filter(|(_, stream)| stream.send_data_ready())
    }
}

impl CryptoCtx for CryptoDxState {
    fn compute_mask(&self, sample: &[u8]) -> Res<Vec<u8>> {
        let mask = self.hpkey.mask(sample)?;
        log!(
            Level::Debug,
            "HP {} {}",
            hex("sample", sample),
            hex("mask", &mask)
        );
        Ok(mask)
    }

    fn aead_decrypt(&self, pn: PacketNumber, hdr: &[u8], body: &[u8]) -> Res<Vec<u8>> {
        log!(
            Level::Info,
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
        log!(
            Level::Info,
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

        log!(Level::Debug, "aead_encrypt {}", hex("ct", res),);

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

fn generate_crypto_frames(
    conn: &mut Connection,
    epoch: u16,
    mode: TxMode,
    remaining: usize,
) -> Option<Frame> {
    let tx_stream = &mut conn.crypto_streams[epoch as usize].tx;
    if let Some((offset, data)) = tx_stream.next_bytes(mode) {
        let data_len = data.len();
        let frame = Frame::Crypto {
            offset,
            data: data.to_vec(),
        };
        tx_stream.mark_as_sent(offset, data_len);

        Some(frame)
    } else {
        None
    }
}

/// Calculate the frame header size so we know how much data we can fit
fn stream_frame_hdr_len(stream_id: u64, offset: u64, remaining: usize) -> usize {
    let mut hdr_len = 1; // for frame type
    hdr_len += get_varint_len(stream_id);
    if offset > 0 {
        hdr_len += get_varint_len(offset);
    }

    // We always specify length
    hdr_len as usize + get_varint_len(remaining as u64) as usize
}

fn generate_stream_frames(
    conn: &mut Connection,
    epoch: u16,
    mode: TxMode,
    remaining: usize,
) -> Option<Frame> {
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
                    stream_id,
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
                    Some(fin) => {
                        if fin == offset + data_len as u64 {
                            true
                        } else {
                            false
                        }
                    }
                };
                let frame = Some(Frame::Stream {
                    fin,
                    stream_id: *stream_id,
                    offset,
                    data: data[..data_len].to_vec(),
                });
                stream.mark_as_sent(offset, data_len);
                return frame;
            }
        }
    }
    None
}

fn generate_flowc_frames(
    conn: &mut Connection,
    epoch: u16,
    mode: TxMode,
    remaining: usize,
) -> Option<Frame> {
    if let Some(frame) = conn.flow_mgr.borrow().peek() {
        // A suboptimal way to figure out if the frame fits within remaining
        // space.
        let mut d = Data::default();
        frame.marshal(&mut d);
        if d.written() > remaining {
            qtrace!("flowc frame doesn't fit in remaining");
            None
        } else {
            conn.flow_mgr.borrow_mut().next()
        }
    } else {
        qtrace!("no flowc frames");
        None
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
        let res = client.process(vec![], now());
        let mut server = Connection::new_server(&["key"], &["alpn"]).unwrap();
        let res = server.process(res, now());

        let res = client.process(res, now());
        // client now in State::Connected
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 6);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 4);

        let res = server.process(res, now());
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
        let res = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
        let mut server = Connection::new_server(&["key"], &["alpn"]).unwrap();
        let res = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: SH..FIN -> FIN");
        let res = client.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: FIN -> ACKS");
        let res = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: ACKS -> 0");
        let res = client.process(res, now());
        assert!(res.is_empty());
        qdebug!("Output={:0x?}", res);

        assert_eq!(*client.state(), State::Connected);
        assert_eq!(*server.state(), State::Connected);
    }

    #[test]
    // tests stream send/recv after connection is established.
    // TODO(agrover@mozilla.com): Add a test that sends data before connection
    // is fully established.
    fn test_conn_stream() {
        init_db("./db");

        let mut client =
            Connection::new_client("example.com", &["alpn"], loopback(), loopback()).unwrap();
        let mut server = Connection::new_server(&["key"], &["alpn"]).unwrap();

        qdebug!("---- client");
        let res = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[0]: CRYPTO[CH]

        qdebug!("---- server");
        let res = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // TODO(agrover@mozilla.com): ACKs
        // <<-- Initial[0]: CRYPTO[SH] ACK[0]
        // <<-- Handshake[0]: CRYPTO[EE, CERT, CV, FIN]

        qdebug!("---- client");
        let res = client.process(res, now());
        assert_eq!(res.len(), 1);
        assert_eq!(*client.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[1]: ACK[0]
        // -->> Handshake[0]: CRYPTO[FIN], ACK[0]

        qdebug!("---- server");
        let res = server.process(res, now());
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
        let res = client.process(res, now());
        assert_eq!(res.len(), 4);

        qdebug!("---- server");
        let res = server.process(res, now());
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
            records = a.process(records, now());
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
}
