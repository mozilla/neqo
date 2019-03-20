#![allow(unused_variables, dead_code)]

use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Debug};
use std::mem;
use std::net::SocketAddr;
use std::ops::Deref;
use std::rc::Rc;
use std::time::Instant;

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
use crate::stream::{RecvStream, Recvable, RxStreamOrderer, SendStream, Sendable, TxBuffer};
use crate::tparams::TransportParametersHandler;
use crate::{hex, AppError, ConnectionError, Error, Res};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

const QUIC_VERSION: u32 = 0xff000012;
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
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.d.deref()
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TxMode {
    Normal,
    Pto,
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
    rx: CryptoDxState,
    tx: CryptoDxState,
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
    deadline: Instant,
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
    ) -> Connection {
        Connection::new(
            Role::Client,
            Client::new(server_name)
                .expect("Could not create client")
                .into(),
            protocols,
            Some(Path {
                local: local_addr,
                remote: remote_addr,
            }),
        )
    }

    pub fn new_server<
        CS: ToString,
        CI: IntoIterator<Item = CS>,
        PA: ToString,
        PI: IntoIterator<Item = PA>,
    >(
        certs: CI,
        protocols: PI,
    ) -> Connection {
        Connection::new(
            Role::Server,
            Server::new(certs).expect("Could not create server").into(),
            protocols,
            None,
        )
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
                FrameGenerator(generate_stream_frames),
            ],
            crypto_states: [None, None, None, None],
            tx_pns: [0; 4],
            deadline: Instant::now(),
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

    /// Call in to process activity on the connection. Either new packets have
    /// arrived or a timeout has expired (or both).
    pub fn process<V: IntoIterator<Item = Datagram>>(&mut self, d: V) -> Res<Vec<Datagram>> {
        for dgram in d {
            let res = self.input(dgram);
            self.capture_error(0, res)?;
        }

        if Instant::now() >= self.deadline {
            // Timer expired.
            match self.state {
                State::Init => {
                    self.client_start()?;
                }
                _ => {
                    // Nothing to do.
                }
            }
        }

        // Can't iterate over self.paths while it is owned by self.
        let paths = mem::replace(&mut self.paths, None);
        let mut out_dgrams = Vec::new();
        for p in &paths {
            out_dgrams.append(&mut self.output(&p)?);
        }
        self.paths = paths;
        Ok(out_dgrams) // TODO(ekr@rtfm.com): When to call back next.
    }

    fn input(&mut self, d: Datagram) -> Res<()> {
        let mut slc = &d[..];

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
            slc = &slc[hdr.hdr_len + hdr.plain_body_len()..];
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

            self.input_packet(hdr.epoch, Data::from_slice(&body))?;

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

    fn input_packet(&mut self, epoch: Epoch, mut d: Data) -> Res<()> {
        // Handle each frame in the packet
        while d.remaining() > 0 {
            let f = decode_frame(&mut d)?;
            let t = f.get_type();
            let res = self.input_frame(epoch, f);
            self.capture_error(t, res)?;
        }

        Ok(())
    }

    // Iterate through all the generators, inserting as many frames as will
    // fit.
    fn output(&mut self, path: &Path) -> Res<Vec<Datagram>> {
        let mut out_packets = Vec::new();

        // TODO(ekr@rtfm.com): Be smarter about what epochs we actually have.

        // Frames for different epochs must go in different packets, but then these
        // packets can go in a single datagram
        for epoch in 0..NUM_EPOCHS {
            let mut d = Data::default();
            let mut ds = Vec::new();
            for i in 0..self.generators.len() {
                // TODO(ekr@rtfm.com): Fix TxMode

                let left = self.pmtu - d.remaining();
                while let Some(frame) = self.generators[i](self, epoch, TxMode::Normal, left) {
                    qtrace!("pmtu {} remaining {}", self.pmtu, d.remaining());
                    frame.marshal(&mut d)?;
                    assert!(d.remaining() <= self.pmtu);
                    if d.remaining() == self.pmtu {
                        // Filled this packet, get another one.
                        ds.push(d);
                        d = Data::default();
                    }
                }
            }
            if d.remaining() > 0 {
                ds.push(d)
            }

            for mut d in ds {
                qdebug!(self, "Need to send a packet");

                let mut hdr = PacketHdr::new(
                    0,
                    match epoch {
                        // TODO(ekr@rtfm.com): Retry token
                        0 => PacketType::Initial(Vec::new()),
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
        let out_dgrams = out_packets
            .into_iter()
            .inspect(|p| qdebug!(self, "{}", hex("Packet", p)))
            .fold(Vec::new(), |mut vec: Vec<Datagram>, packet| {
                let new_dgram: bool = vec
                    .last()
                    .map(|dgram| dgram.d.len() + packet.len() > self.pmtu)
                    .unwrap_or(true);
                if new_dgram {
                    vec.push(Datagram::new(path.local, path.remote, packet));
                } else {
                    vec.last_mut().unwrap().d.extend(packet);
                }
                vec
            });

        out_dgrams
            .iter()
            .for_each(|dgram| qdebug!(self, "Datagram length: {}", dgram.d.len()));

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
            } => {} // TODO(agrover@mozilla.com): lookup stream and modify its max_stream_data
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {} // TODO(agrover@mozilla.com): adjust self.max_streams?
            Frame::DataBlocked { data_limit } => {} // TODO(agrover@mozilla.com): use as input to flow control algorithms
            Frame::StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => {} // TODO(agrover@mozilla.com): generate MaxStreamData
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
            "Creating initial cipher state DCID={:?} role={:?}",
            dcid,
            self.rol
        );
        //assert!(matches!(None, self.crypto_states[0]));

        let cds = CryptoDxState::new_initial("client in", dcid);
        let sds = CryptoDxState::new_initial("server in", dcid);

        self.crypto_states[0] = Some(match self.rol {
            Role::Client => CryptoState { tx: cds, rx: sds },
            Role::Server => CryptoState { tx: sds, rx: cds },
        });
    }

    // Get a crypto state, making it if possible, otherwise return an error.
    fn ensure_crypto_state(&mut self, epoch: Epoch) -> Res<&CryptoState> {
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
                rx: CryptoDxState::new(format!("read_epoch={}", epoch), rs, cipher),
                tx: CryptoDxState::new(format!("write_epoch={}", epoch), ws, cipher),
            });
        }

        Ok(self.crypto_states[epoch as usize].as_ref().unwrap())
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

        let stream_type = match stream_id & 0x1 == 0 {
            true => StreamType::BiDi,
            false => StreamType::UniDi,
        };

        // TODO(agrover@mozilla.com): May create a stream so check against streams_max
        let stream = self
            .recv_streams
            .entry(stream_id)
            .or_insert(RecvStream::new());

        stream.inbound_stream_frame(fin, offset, data)?;

        Ok(())
    }

    // Returns new stream id
    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        // TODO(agrover@mozilla.com): Check against max_stream_id
        let role_val = match self.rol {
            Role::Server => 1,
            Role::Client => 0,
        };
        Ok(match st {
            StreamType::BiDi => {
                let new_id = (self.next_bi_stream_id << 2) + role_val;
                self.next_bi_stream_id += 1;
                self.send_streams.insert(new_id, SendStream::new());
                new_id
            }
            StreamType::UniDi => {
                let new_id = (self.next_uni_stream_id << 2) + 2 + role_val;
                self.next_uni_stream_id += 1;
                self.send_streams.insert(new_id, SendStream::new());
                self.recv_streams.insert(new_id, RecvStream::new());
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
            .filter(|(_, stream)| stream.recv_data_ready())
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

    for (stream_id, stream) in &mut conn.get_sendable_streams() {
        if stream.send_data_ready() {
            let fin = Sendable::final_size(stream);
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
                let frame_hdr_len = stream_frame_hdr_len(stream_id, offset, remaining);
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
                    stream_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::StreamType;

    fn loopback() -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    #[test]
    fn test_conn_stream_create() {
        init_db("./db");

        let mut client = Connection::new_client("example.com", &["alpn"], loopback(), loopback());
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 6);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 4);

        let mut server = Connection::new_server(&["key"], &["alpn"]);
        assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 3);
        assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 7);
        assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 1);
        assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 5);
    }

    #[test]
    fn test_conn_handshake() {
        init_db("./db");
        // 0 -> CH
        qdebug!("---- client");
        let mut client = Connection::new_client("example.com", &["alpn"], loopback(), loopback());
        let res = client.process(Vec::new()).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        // CH -> SH
        qdebug!("---- server");
        let mut server = Connection::new_server(&["key"], &["alpn"]);
        let res = server.process(res).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        // SH -> 0
        qdebug!("---- client");
        let res = client.process(res).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        // 0 -> EE, CERT, CV, FIN
        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());
        qdebug!("Output={:0x?}", res);

        // EE, CERT, CV, FIN -> FIN
        qdebug!("---- client");
        let res = client.process(res).unwrap();
        assert!(res.is_empty());
        qdebug!("Output={:0x?}", res);

        // FIN -> 0
        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());

        assert_eq!(*client.state(), State::Connected);
        assert_eq!(*server.state(), State::Connected);
    }

    #[test]
    // tests stream send/recv after connection is established.
    // TODO(agrover@mozilla.com): Add a test that sends data before connection
    // is fully established.
    fn test_conn_stream() {
        init_db("./db");

        let mut client = Connection::new_client("example.com", &["alpn"], loopback(), loopback());
        let mut server = Connection::new_server(&["key"], &["alpn"]);

        qdebug!("---- client");
        let res = client.process(Vec::new()).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[0]: CRYPTO[CH]

        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // TODO(agrover@mozilla.com): ACKs
        // <<-- Initial[0]: CRYPTO[SH] ACK[0]
        // <<-- Handshake[0]: CRYPTO[EE, CERT, CV, FIN]

        qdebug!("---- client");
        let res = client.process(res).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(*client.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[1]: ACK[0]
        // -->> Handshake[0]: CRYPTO[FIN], ACK[0]

        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());
        assert_eq!(*server.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
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
        let res = client.process(res).unwrap();
        assert_eq!(res.len(), 4);

        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());
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
            State::Connected | State::Closing(..) | State::Closed(..) => true,
            _ => false,
        };
        while !is_done(a) || !is_done(b) {
            records = match a.process(records) {
                Ok(r) => r,
                _ => {
                    // If this returns an error, we will pick the error up when we check the state.
                    return;
                }
            };
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
            State::Closing(e, ..) | State::Closed(e, ..) => {
                assert_eq!(*e, err);
            }
            _ => panic!("bad state {:?}", c.state()),
        }
    }

    #[test]
    fn test_no_alpn() {
        init_db("./db");
        let mut client = Connection::new_client("example.com", &["alpn"], loopback(), loopback());
        let mut server = Connection::new_server(&["key"], &["different-alpn"]);

        handshake(&mut client, &mut server);
        // TODO (mt): errors are immediate, which means that we never send CONNECTION_CLOSE
        // and the client never sees the server's rejection of its handshake.
        //assert_error(&client, ConnectionError::Transport(Error::CryptoAlert(120)));
        assert_error(&server, ConnectionError::Transport(Error::CryptoAlert(120)));
    }
}
