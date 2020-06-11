// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// The class implementing a QUIC connection.

use std::cell::RefCell;
use std::cmp::{max, min, Ordering};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{self, Debug};
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use smallvec::SmallVec;

use neqo_common::{
    hex, hex_snip_middle, matches, qdebug, qerror, qinfo, qlog::NeqoQlog, qtrace, qwarn, Datagram,
    Decoder, Encoder, Role,
};
use neqo_crypto::agent::CertificateInfo;
use neqo_crypto::{
    Agent, AntiReplay, AuthenticationStatus, Cipher, Client, HandshakeState, SecretAgentInfo,
    Server,
};

use crate::cid::{ConnectionId, ConnectionIdDecoder, ConnectionIdManager, ConnectionIdRef};
use crate::crypto::{Crypto, CryptoDxState};
use crate::dump::*;
use crate::events::{ConnectionEvent, ConnectionEvents};
use crate::flow_mgr::FlowMgr;
use crate::frame::{
    AckRange, CloseError, Frame, FrameType, StreamType, FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
};
use crate::packet::{
    DecryptedPacket, PacketBuilder, PacketNumber, PacketType, PublicPacket, QuicVersion,
};
use crate::path::Path;
use crate::qlog;
use crate::recovery::{LossRecovery, RecoveryToken, SendProfile, GRANULARITY};
use crate::recv_stream::{RecvStream, RecvStreams, RX_STREAM_DATA_WINDOW};
use crate::send_stream::{SendStream, SendStreams};
use crate::stats::Stats;
use crate::stream_id::{StreamId, StreamIndex, StreamIndexes};
use crate::tparams::{
    self, TransportParameter, TransportParameterId, TransportParameters, TransportParametersHandler,
};
use crate::tracking::{AckTracker, PNSpace, SentPacket};
use crate::{AppError, ConnectionError, Error, Res, LOCAL_IDLE_TIMEOUT};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

pub const LOCAL_STREAM_LIMIT_BIDI: u64 = 16;
pub const LOCAL_STREAM_LIMIT_UNI: u64 = 16;

const LOCAL_MAX_DATA: u64 = 0x3FFF_FFFF_FFFF_FFFF; // 2^62-1

#[derive(Clone, Debug, PartialEq, Ord, Eq)]
/// The state of the Connection.
pub enum State {
    Init,
    WaitInitial,
    Handshaking,
    Connected,
    Confirmed,
    Closing {
        error: ConnectionError,
        timeout: Instant,
    },
    Draining {
        error: ConnectionError,
        timeout: Instant,
    },
    Closed(ConnectionError),
}

impl State {
    #[must_use]
    pub fn connected(&self) -> bool {
        matches!(self, Self::Connected | Self::Confirmed)
    }

    #[must_use]
    pub fn closed(&self) -> bool {
        matches!(self, Self::Closing { .. } | Self::Draining { .. } | Self::Closed(_))
    }
}

// Implement Ord so that we can enforce monotonic state progression.
impl PartialOrd for State {
    #[allow(clippy::match_same_arms)] // Lint bug: rust-lang/rust-clippy#860
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if mem::discriminant(self) == mem::discriminant(other) {
            return Some(Ordering::Equal);
        }
        Some(match (self, other) {
            (Self::Init, _) => Ordering::Less,
            (_, Self::Init) => Ordering::Greater,
            (Self::WaitInitial, _) => Ordering::Less,
            (_, Self::WaitInitial) => Ordering::Greater,
            (Self::Handshaking, _) => Ordering::Less,
            (_, Self::Handshaking) => Ordering::Greater,
            (Self::Connected, _) => Ordering::Less,
            (_, Self::Connected) => Ordering::Greater,
            (Self::Confirmed, _) => Ordering::Less,
            (_, Self::Confirmed) => Ordering::Greater,
            (Self::Closing { .. }, _) => Ordering::Less,
            (_, Self::Closing { .. }) => Ordering::Greater,
            (Self::Draining { .. }, _) => Ordering::Less,
            (_, Self::Draining { .. }) => Ordering::Greater,
            (Self::Closed(_), _) => unreachable!(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ZeroRttState {
    Init,
    Sending,
    AcceptedClient,
    AcceptedServer,
    Rejected,
}

#[derive(Clone, Debug, PartialEq)]
/// Type returned from process() and `process_output()`. Users are required to
/// call these repeatedly until `Callback` or `None` is returned.
pub enum Output {
    /// Connection requires no action.
    None,
    /// Connection requires the datagram be sent.
    Datagram(Datagram),
    /// Connection requires `process_input()` be called when the `Duration`
    /// elapses.
    Callback(Duration),
}

impl Output {
    /// Convert into an `Option<Datagram>`.
    #[must_use]
    pub fn dgram(self) -> Option<Datagram> {
        match self {
            Self::Datagram(dg) => Some(dg),
            _ => None,
        }
    }

    /// Get a reference to the Datagram, if any.
    pub fn as_dgram_ref(&self) -> Option<&Datagram> {
        match self {
            Self::Datagram(dg) => Some(dg),
            _ => None,
        }
    }

    /// Ask how long the caller should wait before calling back.
    #[must_use]
    pub fn callback(&self) -> Duration {
        match self {
            Self::Callback(t) => *t,
            _ => Duration::new(0, 0),
        }
    }
}

/// Used by inner functions like Connection::output.
enum SendOption {
    /// Yes, please send this datagram.
    Yes(Datagram),
    /// Don't send.  If this was blocked on the pacer (the arg is true).
    No(bool),
}

impl Default for SendOption {
    fn default() -> Self {
        Self::No(false)
    }
}

/// Alias the common form for ConnectionIdManager.
type CidMgr = Rc<RefCell<dyn ConnectionIdManager>>;

/// An FixedConnectionIdManager produces random connection IDs of a fixed length.
pub struct FixedConnectionIdManager {
    len: usize,
}
impl FixedConnectionIdManager {
    pub fn new(len: usize) -> Self {
        Self { len }
    }
}
impl ConnectionIdDecoder for FixedConnectionIdManager {
    fn decode_cid<'a>(&self, dec: &mut Decoder<'a>) -> Option<ConnectionIdRef<'a>> {
        dec.decode(self.len).map(ConnectionIdRef::from)
    }
}
impl ConnectionIdManager for FixedConnectionIdManager {
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::generate(self.len)
    }
    fn as_decoder(&self) -> &dyn ConnectionIdDecoder {
        self
    }
}

struct RetryInfo {
    token: Vec<u8>,
    retry_source_cid: ConnectionId,
}

impl RetryInfo {
    fn new(retry_source_cid: ConnectionId, token: Vec<u8>) -> Self {
        Self {
            token,
            retry_source_cid,
        }
    }
}

#[derive(Debug, Clone)]
/// There's a little bit of different behavior for resetting idle timeout. See
/// -transport 10.2 ("Idle Timeout").
enum IdleTimeoutState {
    Init,
    PacketReceived(Instant),
    AckElicitingPacketSent(Instant),
}

#[derive(Debug, Clone)]
/// There's a little bit of different behavior for resetting idle timeout. See
/// -transport 10.2 ("Idle Timeout").
struct IdleTimeout {
    timeout: Duration,
    state: IdleTimeoutState,
}

impl Default for IdleTimeout {
    fn default() -> Self {
        Self {
            timeout: LOCAL_IDLE_TIMEOUT,
            state: IdleTimeoutState::Init,
        }
    }
}

impl IdleTimeout {
    pub fn set_peer_timeout(&mut self, peer_timeout: Duration) {
        self.timeout = min(self.timeout, peer_timeout);
    }

    pub fn expiry(&self, pto: Duration) -> Option<Instant> {
        match self.state {
            IdleTimeoutState::Init => None,
            IdleTimeoutState::PacketReceived(t) | IdleTimeoutState::AckElicitingPacketSent(t) => {
                Some(t + max(self.timeout, pto * 3))
            }
        }
    }

    fn on_packet_sent(&mut self, now: Instant) {
        // Only reset idle timeout if we've received a packet since the last
        // time we reset the timeout here.
        match self.state {
            IdleTimeoutState::AckElicitingPacketSent(_) => {}
            IdleTimeoutState::Init | IdleTimeoutState::PacketReceived(_) => {
                self.state = IdleTimeoutState::AckElicitingPacketSent(now);
            }
        }
    }

    fn on_packet_received(&mut self, now: Instant) {
        self.state = IdleTimeoutState::PacketReceived(now);
    }

    pub fn expired(&self, now: Instant, pto: Duration) -> bool {
        if let Some(expiry) = self.expiry(pto) {
            now >= expiry
        } else {
            false
        }
    }
}

/// `StateSignaling` manages whether we need to send HANDSHAKE_DONE and CONNECTION_CLOSE.
/// Valid state transitions are:
/// * Idle -> HandshakeDone: at the server when the handshake completes
/// * HandshakeDone -> Idle: when a HANDSHAKE_DONE frame is sent
/// * Idle/HandshakeDone -> Closing/Draining: when closing or draining
/// * Closing/Draining -> CloseSent: after sending CONNECTION_CLOSE
/// * CloseSent -> Closing: any time a new CONNECTION_CLOSE is needed
/// * -> Reset: from any state in case of a stateless reset
#[derive(Debug, Clone, PartialEq)]
enum StateSignaling {
    Idle,
    HandshakeDone,
    /// These states save the frame that needs to be sent.
    Closing(Frame),
    Draining(Frame),
    /// This state saves the frame that might need to be sent again.
    /// If it is `None`, then we are draining and don't send.
    CloseSent(Option<Frame>),
    Reset,
}

impl StateSignaling {
    pub fn handshake_done(&mut self) {
        if *self != Self::Idle {
            debug_assert!(false, "StateSignaling must be in Idle state.");
            return;
        }
        *self = Self::HandshakeDone
    }

    pub fn send_done(&mut self) -> Option<(Frame, Option<RecoveryToken>)> {
        if *self == Self::HandshakeDone {
            *self = Self::Idle;
            Some((Frame::HandshakeDone, Some(RecoveryToken::HandshakeDone)))
        } else {
            None
        }
    }

    fn make_close_frame(
        error: ConnectionError,
        frame_type: FrameType,
        message: impl AsRef<str>,
    ) -> Frame {
        let reason_phrase = message.as_ref().as_bytes().to_owned();
        Frame::ConnectionClose {
            error_code: CloseError::from(error),
            frame_type,
            reason_phrase,
        }
    }

    pub fn close(
        &mut self,
        error: ConnectionError,
        frame_type: FrameType,
        message: impl AsRef<str>,
    ) {
        if *self != Self::Reset {
            *self = Self::Closing(Self::make_close_frame(error, frame_type, message));
        }
    }

    pub fn drain(
        &mut self,
        error: ConnectionError,
        frame_type: FrameType,
        message: impl AsRef<str>,
    ) {
        if *self != Self::Reset {
            *self = Self::Draining(Self::make_close_frame(error, frame_type, message));
        }
    }

    /// If a close is pending, take a frame.
    pub fn close_frame(&mut self) -> Option<Frame> {
        match self {
            Self::Closing(frame) => {
                // When we are closing, we might need to send the close frame again.
                let frame = mem::replace(frame, Frame::Padding);
                *self = Self::CloseSent(Some(frame.clone()));
                Some(frame)
            }
            Self::Draining(frame) => {
                // When we are draining, just send once.
                let frame = mem::replace(frame, Frame::Padding);
                *self = Self::CloseSent(None);
                Some(frame)
            }
            _ => None,
        }
    }

    /// If a close can be sent again, prepare to send it again.
    pub fn send_close(&mut self) {
        if let Self::CloseSent(Some(frame)) = self {
            let frame = mem::replace(frame, Frame::Padding);
            *self = Self::Closing(frame);
        }
    }

    /// We just got a stateless reset.  Terminate.
    pub fn reset(&mut self) {
        *self = Self::Reset;
    }
}

/// A QUIC Connection
///
/// First, create a new connection using `new_client()` or `new_server()`.
///
/// For the life of the connection, handle activity in the following manner:
/// 1. Perform operations using the `stream_*()` methods.
/// 1. Call `process_input()` when a datagram is received or the timer
/// expires. Obtain information on connection state changes by checking
/// `events()`.
/// 1. Having completed handling current activity, repeatedly call
/// `process_output()` for packets to send, until it returns `Output::Callback`
/// or `Output::None`.
///
/// After the connection is closed (either by calling `close()` or by the
/// remote) continue processing until `state()` returns `Closed`.
pub struct Connection {
    role: Role,
    state: State,
    tps: Rc<RefCell<TransportParametersHandler>>,
    /// What we are doing with 0-RTT.
    zero_rtt_state: ZeroRttState,
    /// This object will generate connection IDs for the connection.
    cid_manager: CidMgr,
    /// Network paths.  Right now, this tracks at most one path, so it uses `Option`.
    path: Option<Path>,
    /// The connection IDs that we will accept.
    /// This includes any we advertise in NEW_CONNECTION_ID that haven't been bound to a path yet.
    /// During the handshake at the server, it also includes the randomized DCID pick by the client.
    valid_cids: Vec<ConnectionId>,
    retry_info: Option<RetryInfo>,

    /// Since we need to communicate this to our peer in tparams, setting this
    /// value is part of constructing the struct.
    local_initial_source_cid: ConnectionId,
    /// Checked against tparam value from peer
    remote_initial_source_cid: Option<ConnectionId>,
    /// Checked against tparam value from peer
    remote_original_destination_cid: Option<ConnectionId>,

    pub(crate) crypto: Crypto,
    pub(crate) acks: AckTracker,
    idle_timeout: IdleTimeout,
    pub(crate) indexes: StreamIndexes,
    connection_ids: HashMap<u64, (Vec<u8>, [u8; 16])>, // (sequence number, (connection id, reset token))
    pub(crate) send_streams: SendStreams,
    pub(crate) recv_streams: RecvStreams,
    pub(crate) flow_mgr: Rc<RefCell<FlowMgr>>,
    state_signaling: StateSignaling,
    loss_recovery: LossRecovery,
    events: ConnectionEvents,
    token: Option<Vec<u8>>,
    stats: Stats,
    qlog: Option<NeqoQlog>,

    quic_version: QuicVersion,
}

impl Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} Connection: {:?} {:?}",
            self.role, self.state, self.path
        )
    }
}

impl Connection {
    /// Create a new QUIC connection with Client role.
    pub fn new_client(
        server_name: &str,
        protocols: &[impl AsRef<str>],
        cid_manager: CidMgr,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        quic_version: QuicVersion,
    ) -> Res<Self> {
        let dcid = ConnectionId::generate_initial();
        let mut c = Self::new(
            Role::Client,
            Client::new(server_name)?.into(),
            cid_manager,
            None,
            protocols,
            None,
            quic_version,
        )?;
        c.crypto.states.init(Role::Client, &dcid);
        c.remote_original_destination_cid = Some(dcid);
        c.initialize_path(local_addr, remote_addr);
        Ok(c)
    }

    /// Create a new QUIC connection with Server role.
    pub fn new_server(
        certs: &[impl AsRef<str>],
        protocols: &[impl AsRef<str>],
        anti_replay: &AntiReplay,
        cid_manager: CidMgr,
        quic_version: QuicVersion,
    ) -> Res<Self> {
        Self::new(
            Role::Server,
            Server::new(certs)?.into(),
            cid_manager,
            Some(anti_replay),
            protocols,
            None,
            quic_version,
        )
    }

    fn set_tp_defaults(tps: &mut TransportParameters) {
        tps.set_integer(
            tparams::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            RX_STREAM_DATA_WINDOW,
        );
        tps.set_integer(
            tparams::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            RX_STREAM_DATA_WINDOW,
        );
        tps.set_integer(tparams::INITIAL_MAX_STREAM_DATA_UNI, RX_STREAM_DATA_WINDOW);
        tps.set_integer(tparams::INITIAL_MAX_STREAMS_BIDI, LOCAL_STREAM_LIMIT_BIDI);
        tps.set_integer(tparams::INITIAL_MAX_STREAMS_UNI, LOCAL_STREAM_LIMIT_UNI);
        tps.set_integer(tparams::INITIAL_MAX_DATA, LOCAL_MAX_DATA);
        tps.set_integer(
            tparams::IDLE_TIMEOUT,
            u64::try_from(LOCAL_IDLE_TIMEOUT.as_millis()).unwrap(),
        );
        tps.set_empty(tparams::DISABLE_MIGRATION);
    }

    fn new(
        role: Role,
        agent: Agent,
        cid_manager: CidMgr,
        anti_replay: Option<&AntiReplay>,
        protocols: &[impl AsRef<str>],
        path: Option<Path>,
        quic_version: QuicVersion,
    ) -> Res<Self> {
        let tphandler = Rc::new(RefCell::new(TransportParametersHandler::default()));
        Self::set_tp_defaults(&mut tphandler.borrow_mut().local);
        let local_initial_source_cid = cid_manager.borrow_mut().generate_cid();
        tphandler.borrow_mut().local.set_bytes(
            tparams::INITIAL_SOURCE_CONNECTION_ID,
            local_initial_source_cid.to_vec(),
        );

        let crypto = Crypto::new(agent, protocols, tphandler.clone(), anti_replay)?;

        Ok(Self {
            role,
            state: State::Init,
            cid_manager,
            path,
            valid_cids: Vec::new(),
            tps: tphandler,
            zero_rtt_state: ZeroRttState::Init,
            retry_info: None,
            local_initial_source_cid,
            remote_initial_source_cid: None,
            remote_original_destination_cid: None,
            crypto,
            acks: AckTracker::default(),
            idle_timeout: IdleTimeout::default(),
            indexes: StreamIndexes::new(),
            connection_ids: HashMap::new(),
            send_streams: SendStreams::default(),
            recv_streams: RecvStreams::default(),
            flow_mgr: Rc::new(RefCell::new(FlowMgr::default())),
            state_signaling: StateSignaling::Idle,
            loss_recovery: LossRecovery::new(),
            events: ConnectionEvents::default(),
            token: None,
            stats: Stats::default(),
            qlog: None,
            quic_version,
        })
    }

    /// Get the local path.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_ref()
    }

    /// Set or clear the qlog for this connection.
    pub fn set_qlog(&mut self, qlog: Option<NeqoQlog>) {
        self.qlog = qlog;
    }

    /// Get the qlog (if any) for this connection.
    pub fn qlog_mut(&mut self) -> &mut Option<NeqoQlog> {
        &mut self.qlog
    }

    /// Set a local transport parameter, possibly overriding a default value.
    pub fn set_local_tparam(&self, tp: TransportParameterId, value: TransportParameter) -> Res<()> {
        if *self.state() == State::Init {
            self.tps.borrow_mut().local.set(tp, value);
            Ok(())
        } else {
            qerror!("Current state: {:?}", self.state());
            qerror!("Cannot set local tparam when not in an initial connection state.");
            Err(Error::ConnectionState)
        }
    }

    /// `odcid` is their original choice for our CID, which we get from the Retry token.
    /// `remote_cid` is the value from the Source Connection ID field of
    ///   an incoming packet: what the peer wants us to use now.
    /// `retry_cid` is what we asked them to use when we sent the Retry.
    pub(crate) fn set_retry_cids(
        &mut self,
        odcid: ConnectionId,
        remote_cid: ConnectionId,
        retry_cid: ConnectionId,
    ) {
        debug_assert_eq!(self.role, Role::Server);
        qtrace!(
            [self],
            "Retry CIDs: odcid={} remote={} retry={}",
            odcid,
            remote_cid,
            retry_cid
        );
        // We advertise "our" choices in transport parameters.
        let local_tps = &mut self.tps.borrow_mut().local;
        local_tps.set_bytes(tparams::ORIGINAL_DESTINATION_CONNECTION_ID, odcid.to_vec());
        local_tps.set_bytes(tparams::RETRY_SOURCE_CONNECTION_ID, retry_cid.to_vec());

        // ...and save their choices for later validation.
        self.remote_initial_source_cid = Some(remote_cid);
    }

    fn retry_sent(&self) -> bool {
        self.tps
            .borrow()
            .local
            .get_bytes(tparams::RETRY_SOURCE_CONNECTION_ID)
            .is_some()
    }

    /// Set ALPN preferences. Strings that appear earlier in the list are given
    /// higher preference.
    pub fn set_alpn(&mut self, protocols: &[impl AsRef<str>]) -> Res<()> {
        self.crypto.tls.set_alpn(protocols)?;
        Ok(())
    }

    /// Enable a set of ciphers.
    pub fn enable_ciphers(&mut self, ciphers: &[Cipher]) -> Res<()> {
        if self.state != State::Init {
            qerror!([self], "Cannot enable ciphers in state {:?}", self.state);
            return Err(Error::ConnectionState);
        }
        self.crypto.tls.enable_ciphers(ciphers)?;
        Ok(())
    }

    /// Access the latest resumption token on the connection.
    pub fn resumption_token(&self) -> Option<Vec<u8>> {
        if self.state < State::Connected {
            return None;
        }
        match self.crypto.tls {
            Agent::Client(ref c) => match c.resumption_token() {
                Some(ref t) => {
                    qtrace!("TLS token {}", hex(&t));
                    let mut enc = Encoder::default();
                    let rtt = self.loss_recovery.rtt();
                    let rtt = u64::try_from(rtt.as_millis()).unwrap_or(0);
                    enc.encode_varint(rtt);
                    enc.encode_vvec_with(|enc_inner| {
                        self.tps
                            .borrow()
                            .remote
                            .as_ref()
                            .expect("should have transport parameters")
                            .encode(enc_inner);
                    });
                    enc.encode(&t[..]);
                    qinfo!("resumption token {}", hex_snip_middle(&enc[..]));
                    Some(enc.into())
                }
                None => None,
            },
            Agent::Server(_) => None,
        }
    }

    /// Enable resumption, using a token previously provided.
    /// This can only be called once and only on the client.
    /// After calling the function, it should be possible to attempt 0-RTT
    /// if the token supports that.
    pub fn set_resumption_token(&mut self, now: Instant, token: &[u8]) -> Res<()> {
        if self.state != State::Init {
            qerror!([self], "set token in state {:?}", self.state);
            return Err(Error::ConnectionState);
        }
        qinfo!([self], "resumption token {}", hex_snip_middle(token));
        let mut dec = Decoder::from(token);

        let smoothed_rtt = match dec.decode_varint() {
            Some(v) => Duration::from_millis(v),
            _ => return Err(Error::InvalidResumptionToken),
        };

        let tp_slice = match dec.decode_vvec() {
            Some(v) => v,
            _ => return Err(Error::InvalidResumptionToken),
        };
        qtrace!([self], "  transport parameters {}", hex(&tp_slice));
        let mut dec_tp = Decoder::from(tp_slice);
        let tp = TransportParameters::decode(&mut dec_tp)?;

        let tok = dec.decode_remainder();
        qtrace!([self], "  TLS token {}", hex(&tok));
        match self.crypto.tls {
            Agent::Client(ref mut c) => c.set_resumption_token(&tok)?,
            Agent::Server(_) => return Err(Error::WrongRole),
        }

        self.tps.borrow_mut().remote_0rtt = Some(tp);

        if smoothed_rtt > GRANULARITY {
            self.loss_recovery.set_initial_rtt(smoothed_rtt);
        }
        self.set_initial_limits();
        // Start up TLS, which has the effect of setting up all the necessary
        // state for 0-RTT.  This only stages the CRYPTO frames.
        self.client_start(now)
    }

    /// Send a TLS session ticket.
    pub fn send_ticket(&mut self, now: Instant, extra: &[u8]) -> Res<()> {
        let tps = &self.tps;
        match self.crypto.tls {
            Agent::Server(ref mut s) => {
                let mut enc = Encoder::default();
                enc.encode_vvec_with(|mut enc_inner| {
                    tps.borrow().local.encode(&mut enc_inner);
                });
                enc.encode(extra);
                let records = s.send_ticket(now, &enc)?;
                qinfo!([self], "send session ticket {}", hex(&enc));
                self.crypto.buffer_records(records)?;
                Ok(())
            }
            Agent::Client(_) => Err(Error::WrongRole),
        }
    }

    pub fn tls_info(&self) -> Option<&SecretAgentInfo> {
        self.crypto.tls.info()
    }

    /// Get the peer's certificate chain and other info.
    pub fn peer_certificate(&self) -> Option<CertificateInfo> {
        self.crypto.tls.peer_certificate()
    }

    /// Call by application when the peer cert has been verified
    pub fn authenticated(&mut self, status: AuthenticationStatus, now: Instant) {
        self.crypto.tls.authenticated(status);
        let res = self.handshake(now, PNSpace::Handshake, None);
        self.absorb_error(now, res);
    }

    /// Get the role of the connection.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get the state of the connection.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Get the 0-RTT state of the connection.
    pub fn zero_rtt_state(&self) -> &ZeroRttState {
        &self.zero_rtt_state
    }

    /// Get collected statistics.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    // This function wraps a call to another function and sets the connection state
    // properly if that call fails.
    fn capture_error<T>(&mut self, now: Instant, frame_type: FrameType, res: Res<T>) -> Res<T> {
        if let Err(v) = &res {
            #[cfg(debug_assertions)]
            let msg = format!("{:?}", v);
            #[cfg(not(debug_assertions))]
            let msg = "";
            let error = ConnectionError::Transport(v.clone());
            match &self.state {
                State::Closing { error: err, .. }
                | State::Draining { error: err, .. }
                | State::Closed(err) => {
                    qwarn!([self], "Closing again after error {:?}", err);
                }
                State::WaitInitial => {
                    // We don't have any state yet, so don't bother with
                    // the closing state, just send one CONNECTION_CLOSE.
                    self.state_signaling.close(error.clone(), frame_type, msg);
                    self.set_state(State::Closed(error));
                }
                _ => {
                    self.state_signaling.close(error.clone(), frame_type, msg);
                    self.set_state(State::Closing {
                        error,
                        timeout: self.get_closing_period_time(now),
                    });
                }
            }
        }
        res
    }

    /// For use with process_input(). Errors there can be ignored, but this
    /// needs to ensure that the state is updated.
    fn absorb_error<T>(&mut self, now: Instant, res: Res<T>) -> Option<T> {
        self.capture_error(now, 0, res).ok()
    }

    pub fn process_timer(&mut self, now: Instant) {
        if let State::Closing { error, timeout } | State::Draining { error, timeout } = &self.state
        {
            if *timeout <= now {
                // Close timeout expired, move to Closed
                let st = State::Closed(error.clone());
                self.set_state(st);
                qinfo!("Closing timer expired");
                return;
            }
        }
        if let State::Closed(_) = self.state {
            qdebug!("Timer fired while closed");
            return;
        }

        if self.idle_timeout.expired(now, self.loss_recovery.raw_pto()) {
            qinfo!([self], "idle timeout expired");
            self.set_state(State::Closed(ConnectionError::Transport(
                Error::IdleTimeout,
            )));
            return;
        }

        let res = self.crypto.states.check_key_update(now);
        self.absorb_error(now, res);

        let lost = self.loss_recovery.timeout(now);
        self.handle_lost_packets(&lost);
    }

    /// Call in to process activity on the connection. Either new packets have
    /// arrived or a timeout has expired (or both).
    pub fn process_input(&mut self, d: Datagram, now: Instant) {
        let res = self.input(d, now);
        self.absorb_error(now, res);
        self.cleanup_streams();
    }

    /// Just like above but returns frames parsed from the datagram
    #[cfg(test)]
    pub fn test_process_input(&mut self, dgram: Datagram, now: Instant) -> Vec<(Frame, PNSpace)> {
        let res = self.input(dgram, now);
        let frames = self.absorb_error(now, res).unwrap_or_default();
        self.cleanup_streams();
        frames
    }

    /// Get the time that we next need to be called back, relative to `now`.
    fn next_delay(&mut self, now: Instant, paced: bool) -> Duration {
        qtrace!([self], "Get callback delay {:?}", now);

        // Only one timer matters when closing...
        if let State::Closing { timeout, .. } | State::Draining { timeout, .. } = self.state {
            return timeout.duration_since(now);
        }

        let mut delays = SmallVec::<[_; 5]>::new();
        if let Some(ack_time) = self.acks.ack_time(now) {
            qtrace!([self], "Delayed ACK timer {:?}", ack_time);
            delays.push(ack_time);
        }

        if let Some(idle_time) = self.idle_timeout.expiry(self.loss_recovery.raw_pto()) {
            qtrace!([self], "Idle timer {:?}", idle_time);
            delays.push(idle_time);
        }

        if let Some(lr_time) = self.loss_recovery.next_timeout() {
            qtrace!([self], "Loss recovery timer {:?}", lr_time);
            delays.push(lr_time);
        }

        if let Some(key_update_time) = self.crypto.states.update_time() {
            qtrace!([self], "Key update timer {:?}", key_update_time);
            delays.push(key_update_time);
        }

        if paced {
            if let Some(pace_time) = self.loss_recovery.next_paced() {
                qtrace!([self], "Pacing timer {:?}", pace_time);
                delays.push(pace_time);
            }
        }

        // Should always at least have idle timeout, once connected
        assert!(!delays.is_empty());
        let earliest = delays.into_iter().min().unwrap();

        // TODO(agrover, mt) - need to analyze and fix #47
        // rather than just clamping to zero here.
        qdebug!(
            [self],
            "delay duration {:?}",
            max(now, earliest).duration_since(now)
        );
        debug_assert!(earliest > now);
        max(now, earliest).duration_since(now)
    }

    /// Get output packets, as a result of receiving packets, or actions taken
    /// by the application.
    /// Returns datagrams to send, and how long to wait before calling again
    /// even if no incoming packets.
    pub fn process_output(&mut self, now: Instant) -> Output {
        qtrace!([self], "process_output {:?} {:?}", self.state, now);

        if self.state == State::Init {
            if self.role == Role::Client {
                let res = self.client_start(now);
                self.absorb_error(now, res);
            }
        } else {
            self.process_timer(now);
        }

        match self.output(now) {
            SendOption::Yes(dgram) => Output::Datagram(dgram),
            SendOption::No(paced) => match self.state {
                State::Closed(_) => Output::None,
                State::Closing { timeout, .. } | State::Draining { timeout, .. } => {
                    Output::Callback(timeout.duration_since(now))
                }
                _ => Output::Callback(self.next_delay(now, paced)),
            },
        }
    }

    /// Process input and generate output.
    pub fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        if let Some(d) = dgram {
            self.process_input(d, now);
        }
        self.process_output(now)
    }

    fn is_valid_cid(&self, cid: &ConnectionIdRef) -> bool {
        self.valid_cids.iter().any(|c| c == cid) || self.path.iter().any(|p| p.valid_local_cid(cid))
    }

    fn handle_retry(&mut self, packet: PublicPacket) -> Res<()> {
        qinfo!([self], "received Retry");
        if self.retry_info.is_some() {
            qinfo!([self], "Dropping extra Retry");
            self.stats.dropped_rx += 1;
            return Ok(());
        }
        if packet.token().is_empty() {
            qinfo!([self], "Dropping Retry without a token");
            self.stats.dropped_rx += 1;
            return Ok(());
        }
        if !packet.is_valid_retry(&self.remote_original_destination_cid.as_ref().unwrap()) {
            qinfo!([self], "Dropping Retry with bad integrity tag");
            self.stats.dropped_rx += 1;
            return Ok(());
        }
        if let Some(p) = &mut self.path {
            // At this point, we shouldn't have a remote connection ID for the path.
            p.set_remote_cid(packet.scid());
        } else {
            qinfo!([self], "No path, but we received a Retry");
            return Err(Error::InternalError);
        };

        qinfo!(
            [self],
            "Valid Retry received, token={} scid={}",
            hex(packet.token()),
            packet.scid()
        );

        self.retry_info = Some(RetryInfo::new(
            ConnectionId::from(packet.scid()),
            packet.token().to_vec(),
        ));

        let lost_packets = self.loss_recovery.retry();
        self.handle_lost_packets(&lost_packets);

        // Switching crypto state here might not happen eventually.
        // https://github.com/quicwg/base-drafts/issues/2823
        self.crypto.states.init(self.role, packet.scid());
        Ok(())
    }

    fn discard_keys(&mut self, space: PNSpace) {
        if self.crypto.discard(space) {
            qinfo!([self], "Drop packet number space {}", space);
            self.loss_recovery.discard(space);
            self.acks.drop_space(space);
        }
    }

    fn token_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
        // rustc might decide to optimize this and make this non-constant-time
        // with respect to `t`, but it doesn't appear to currently.
        let mut c = 0;
        for (&a, &b) in a.iter().zip(b) {
            c |= a ^ b;
        }
        c == 0
    }

    fn is_stateless_reset(&self, d: &Datagram) -> bool {
        if d.len() < 16 {
            return false;
        }
        let token = <&[u8; 16]>::try_from(&d[d.len() - 16..]).unwrap();
        // TODO(mt) only check the path that matches the datagram.
        self.path
            .as_ref()
            .map(|p| p.reset_token())
            .flatten()
            .map_or(false, |t| Self::token_equal(t, token))
    }

    fn check_stateless_reset(&mut self, d: &Datagram, now: Instant) -> Res<()> {
        if self.is_stateless_reset(d) {
            // Failing to process a packet in a datagram might
            // indicate that there is a stateless reset present.
            qdebug!([self], "Stateless reset: {}", hex(&d[d.len() - 16..]));
            self.state_signaling.reset();
            self.set_state(State::Draining {
                error: ConnectionError::Transport(Error::StatelessReset),
                timeout: self.get_closing_period_time(now),
            });
            Err(Error::StatelessReset)
        } else {
            Ok(())
        }
    }

    fn input(&mut self, d: Datagram, now: Instant) -> Res<Vec<(Frame, PNSpace)>> {
        let mut slc = &d[..];
        let mut frames = Vec::new();

        qtrace!([self], "input {}", hex(&**d));

        // Handle each packet in the datagram
        while !slc.is_empty() {
            let (packet, remainder) =
                match PublicPacket::decode(slc, self.cid_manager.borrow().as_decoder()) {
                    Ok((packet, remainder)) => (packet, remainder),
                    Err(e) => {
                        qdebug!([self], "Garbage packet: {}", e);
                        qtrace!([self], "Garbage packet contents: {}", hex(slc));
                        self.stats.dropped_rx += 1;
                        break;
                    }
                };
            self.stats.packets_rx += 1;
            match (packet.packet_type(), &self.state, &self.role) {
                (PacketType::Initial, State::Init, Role::Server) => {
                    if !packet.is_valid_initial() {
                        self.stats.dropped_rx += 1;
                        break;
                    }
                    qinfo!(
                        [self],
                        "Received valid Initial packet with scid {:?} dcid {:?}",
                        packet.scid(),
                        packet.dcid()
                    );
                    self.set_state(State::WaitInitial);
                    self.loss_recovery.start_pacer(now);
                    self.crypto.states.init(self.role, &packet.dcid());

                    // We need to make sure that we set this transport parameter.
                    // This has to happen prior to processing the packet so that
                    // the TLS handshake has all it needs.
                    if !self.retry_sent() {
                        self.tps.borrow_mut().local.set_bytes(
                            tparams::ORIGINAL_DESTINATION_CONNECTION_ID,
                            packet.dcid().to_vec(),
                        )
                    }
                }
                (PacketType::VersionNegotiation, State::WaitInitial, Role::Client) => {
                    self.set_state(State::Closed(ConnectionError::Transport(
                        Error::VersionNegotiation,
                    )));
                    return Err(Error::VersionNegotiation);
                }
                (PacketType::Retry, State::WaitInitial, Role::Client) => {
                    self.handle_retry(packet)?;
                    break;
                }
                (PacketType::VersionNegotiation, ..)
                | (PacketType::Retry, ..)
                | (PacketType::OtherVersion, ..) => {
                    qwarn!("dropping {:?}", packet.packet_type());
                    self.stats.dropped_rx += 1;
                    break;
                }
                _ => {}
            };

            match self.state {
                State::Init => {
                    qinfo!([self], "Received message while in Init state");
                    self.stats.dropped_rx += 1;
                    break;
                }
                State::WaitInitial => {}
                State::Handshaking | State::Connected | State::Confirmed => {
                    if !self.is_valid_cid(packet.dcid()) {
                        qinfo!([self], "Ignoring packet with CID {:?}", packet.dcid());
                        self.stats.dropped_rx += 1;
                        break;
                    }
                    if self.role == Role::Server && packet.packet_type() == PacketType::Handshake {
                        // Server has received a Handshake packet -> discard Initial keys and states
                        self.discard_keys(PNSpace::Initial);
                    }
                }
                State::Closing { .. } => {
                    // Don't bother processing the packet. Instead ask to get a
                    // new close frame.
                    self.state_signaling.send_close();
                    break;
                }
                State::Draining { .. } | State::Closed(..) => {
                    // Do nothing.
                    self.stats.dropped_rx += 1;
                    break;
                }
            }

            qtrace!([self], "Received unverified packet {:?}", packet);

            let pto = self.loss_recovery.pto();
            let payload = packet.decrypt(&mut self.crypto.states, now + pto);
            if let Ok(payload) = payload {
                // TODO(ekr@rtfm.com): Have the server blow away the initial
                // crypto state if this fails? Otherwise, we will get a panic
                // on the assert for doesn't exist.
                // OK, we have a valid packet.
                self.idle_timeout.on_packet_received(now);
                dump_packet(
                    self,
                    "-> RX",
                    payload.packet_type(),
                    payload.pn(),
                    &payload[..],
                );
                qlog::packet_received(&mut self.qlog, &payload)?;
                let res = self.process_packet(&payload, now);
                if res.is_err() && self.path.is_none() {
                    // We need to make a path for sending an error message.
                    // But this connection is going to be closed.
                    self.remote_initial_source_cid = Some(ConnectionId::from(packet.scid()));
                    self.initialize_path(d.destination(), d.source());
                }
                frames.extend(res?);
                if self.state == State::WaitInitial {
                    self.start_handshake(&packet, &d)?;
                }
                self.process_migrations(&d)?;
            } else {
                // Decryption failure, or not having keys is not fatal.
                // If the state isn't available, or we can't decrypt the packet, drop
                // the rest of the datagram on the floor, but don't generate an error.
                self.stats.dropped_rx += 1;
                if slc.len() == d.len() {
                    self.check_stateless_reset(&d, now)?
                }
            }
            slc = remainder;
        }
        if slc.len() == d.len() {
            self.check_stateless_reset(&d, now)?
        }
        Ok(frames)
    }

    fn process_packet(
        &mut self,
        packet: &DecryptedPacket,
        now: Instant,
    ) -> Res<Vec<(Frame, PNSpace)>> {
        // TODO(ekr@rtfm.com): Have the server blow away the initial
        // crypto state if this fails? Otherwise, we will get a panic
        // on the assert for doesn't exist.
        // OK, we have a valid packet.

        let space = PNSpace::from(packet.packet_type());
        if self.acks.get_mut(space).unwrap().is_duplicate(packet.pn()) {
            qdebug!([self], "Duplicate packet from {} pn={}", space, packet.pn());
            self.stats.dups_rx += 1;
            return Ok(vec![]);
        }

        let mut ack_eliciting = false;
        let mut d = Decoder::from(&packet[..]);
        let mut consecutive_padding = 0;
        #[allow(unused_mut)]
        let mut frames = Vec::new();
        while d.remaining() > 0 {
            let mut f = Frame::decode(&mut d)?;

            // Skip padding
            while f == Frame::Padding && d.remaining() > 0 {
                consecutive_padding += 1;
                f = Frame::decode(&mut d)?;
            }
            if consecutive_padding > 0 {
                qdebug!(
                    [self],
                    "PADDING frame repeated {} times",
                    consecutive_padding
                );
                consecutive_padding = 0;
            }

            if cfg!(test) {
                frames.push((f.clone(), space));
            }
            ack_eliciting |= f.ack_eliciting();
            let t = f.get_type();
            let res = self.input_frame(packet.packet_type(), f, now);
            self.capture_error(now, t, res)?;
        }
        self.acks
            .get_mut(space)
            .unwrap()
            .set_received(now, packet.pn(), ack_eliciting);

        Ok(frames)
    }

    fn initialize_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) {
        debug_assert!(self.path.is_none());
        self.path = Some(Path::new(
            local_addr,
            remote_addr,
            self.local_initial_source_cid.clone(),
            // Ideally we know what the peer wants us to use for the remote CID.
            // But we will use our own guess if necessary.
            self.remote_initial_source_cid
                .as_ref()
                .or_else(|| self.remote_original_destination_cid.as_ref())
                .unwrap()
                .clone(),
        ));
    }

    fn start_handshake(&mut self, packet: &PublicPacket, d: &Datagram) -> Res<()> {
        self.remote_initial_source_cid = Some(ConnectionId::from(packet.scid()));
        if self.role == Role::Server {
            assert_eq!(packet.packet_type(), PacketType::Initial);

            // A server needs to accept the client's selected CID during the handshake.
            self.valid_cids.push(ConnectionId::from(packet.dcid()));
            // Install a path.
            self.initialize_path(d.destination(), d.source());

            self.zero_rtt_state = match self.crypto.enable_0rtt(self.role) {
                Ok(true) => {
                    qdebug!([self], "Accepted 0-RTT");
                    ZeroRttState::AcceptedServer
                }
                _ => ZeroRttState::Rejected,
            };
        } else {
            qdebug!([self], "Changing to use Server CID={}", packet.scid());
            let p = self
                .path
                .iter_mut()
                .find(|p| p.received_on(&d))
                .expect("should have a path for sending Initial");
            p.set_remote_cid(packet.scid());
        }
        self.set_state(State::Handshaking);
        Ok(())
    }

    fn process_migrations(&self, d: &Datagram) -> Res<()> {
        if self.path.iter().any(|p| p.received_on(&d)) {
            Ok(())
        } else {
            // Right now, we don't support any form of migration.
            // So generate an error if a packet is received on a new path.
            Err(Error::InvalidMigration)
        }
    }

    fn output(&mut self, now: Instant) -> SendOption {
        qtrace!([self], "output {:?}", now);
        if let Some(mut path) = self.path.take() {
            let res = match &self.state {
                State::Init
                | State::WaitInitial
                | State::Handshaking
                | State::Connected
                | State::Confirmed => self.output_path(&mut path, now),
                State::Closing { .. } | State::Draining { .. } | State::Closed(_) => {
                    if let Some(frame) = self.state_signaling.close_frame() {
                        self.output_close(&path, &frame)
                    } else {
                        Ok(SendOption::default())
                    }
                }
            };
            let out = self.absorb_error(now, res).unwrap_or_default();
            self.path = Some(path);
            out
        } else {
            SendOption::default()
        }
    }

    fn build_packet_header(
        path: &Path,
        space: PNSpace,
        encoder: Encoder,
        tx: &CryptoDxState,
        retry_info: &Option<RetryInfo>,
        quic_version: QuicVersion,
    ) -> (PacketType, PacketNumber, PacketBuilder) {
        let pt = match space {
            PNSpace::Initial => PacketType::Initial,
            PNSpace::Handshake => PacketType::Handshake,
            PNSpace::ApplicationData => {
                if tx.is_0rtt() {
                    PacketType::ZeroRtt
                } else {
                    PacketType::Short
                }
            }
        };
        let mut builder = if pt == PacketType::Short {
            qdebug!("Building Short dcid {}", path.remote_cid());
            PacketBuilder::short(encoder, tx.key_phase(), path.remote_cid())
        } else {
            qdebug!(
                "Building {:?} dcid {} scid {}",
                pt,
                path.remote_cid(),
                path.local_cid(),
            );

            PacketBuilder::long(
                encoder,
                pt,
                quic_version,
                path.remote_cid(),
                path.local_cid(),
            )
        };
        if pt == PacketType::Initial {
            builder.initial_token(if let Some(info) = retry_info {
                &info.token
            } else {
                &[]
            });
        }
        // TODO(mt) work out packet number length based on `4*path CWND/path MTU`.
        let pn = tx.next_pn();
        builder.pn(pn, 3);
        (pt, pn, builder)
    }

    fn output_close(&mut self, path: &Path, frame: &Frame) -> Res<SendOption> {
        let mut encoder = Encoder::with_capacity(path.mtu());
        for space in PNSpace::iter() {
            let tx = if let Some(tx_state) = self.crypto.states.tx(*space) {
                tx_state
            } else {
                continue;
            };

            // ConnectionClose frame not allowed for 0RTT.
            if tx.is_0rtt() {
                continue;
            }

            let (_, _, mut builder) =
                Self::build_packet_header(path, *space, encoder, tx, &None, self.quic_version);
            // ConnectionError::Application is only allowed at 1RTT.
            if *space == PNSpace::ApplicationData {
                frame.marshal(&mut builder);
            } else {
                frame.sanitize_close().marshal(&mut builder);
            }

            encoder = builder.build(tx)?;
        }

        Ok(SendOption::Yes(path.datagram(encoder)))
    }

    /// Add frames to the provided builder and
    /// return whether any of them were ACK eliciting.
    #[allow(clippy::useless_let_if_seq)]
    fn add_frames(
        &mut self,
        builder: &mut PacketBuilder,
        space: PNSpace,
        limit: usize,
        profile: &SendProfile,
        now: Instant,
    ) -> (Vec<RecoveryToken>, bool) {
        let mut tokens = Vec::new();
        let mut ack_eliciting = false;

        if profile.pto() {
            // Add a PING on a PTO.  This might get a more expedient ACK.
            builder.encode_varint(Frame::Ping.get_type());
            ack_eliciting = true;
        }

        // All useful frames are at least 2 bytes.
        while builder.len() + 2 < limit {
            let remaining = limit - builder.len();
            // Try to get a frame from frame sources
            let mut frame = self.acks.get_frame(now, space);
            // If we are CC limited we can only send acks!
            if !profile.ack_only(space) {
                if frame.is_none() && space == PNSpace::ApplicationData && self.role == Role::Server
                {
                    frame = self.state_signaling.send_done();
                }
                if frame.is_none() {
                    frame = self.crypto.streams.get_frame(space, remaining)
                }
                if frame.is_none() {
                    frame = self.flow_mgr.borrow_mut().get_frame(space, remaining);
                }
                if frame.is_none() {
                    frame = self.send_streams.get_frame(space, remaining);
                }
            }

            if let Some((frame, token)) = frame {
                ack_eliciting |= frame.ack_eliciting();
                debug_assert_ne!(frame, Frame::Padding);
                frame.marshal(builder);
                if let Some(t) = token {
                    tokens.push(t);
                }
            } else {
                return (tokens, ack_eliciting);
            }
        }
        (tokens, ack_eliciting)
    }

    /// Build a datagram, possibly from multiple packets (for different PN
    /// spaces) and each containing 1+ frames.
    fn output_path(&mut self, path: &mut Path, now: Instant) -> Res<SendOption> {
        let mut initial_sent = None;
        let mut needs_padding = false;

        // Determine how we are sending packets (PTO, etc..).
        let profile = self.loss_recovery.send_profile(now, path.mtu());
        qdebug!([self], "output_path send_profile {:?}", profile);

        // Frames for different epochs must go in different packets, but then these
        // packets can go in a single datagram
        let mut encoder = Encoder::with_capacity(profile.limit());
        for space in PNSpace::iter() {
            // Ensure we have tx crypto state for this epoch, or skip it.
            let tx = if let Some(tx_state) = self.crypto.states.tx(*space) {
                tx_state
            } else {
                continue;
            };

            let header_start = encoder.len();
            let (pt, pn, mut builder) = Self::build_packet_header(
                path,
                *space,
                encoder,
                tx,
                &self.retry_info,
                self.quic_version,
            );
            let payload_start = builder.len();

            // Work out if we have space left.
            if builder.len() + tx.expansion() > profile.limit() {
                // No space for a packet of this type.
                encoder = builder.abort();
                continue;
            }

            // Add frames to the packet.
            let limit = profile.limit() - tx.expansion();
            let (tokens, ack_eliciting) =
                self.add_frames(&mut builder, *space, limit, &profile, now);
            if builder.is_empty() {
                // Nothing to include in this packet.
                encoder = builder.abort();
                continue;
            }

            dump_packet(self, "TX ->", pt, pn, &builder[payload_start..]);
            qlog::packet_sent(&mut self.qlog, pt, pn, &builder[payload_start..])?;

            self.stats.packets_tx += 1;
            encoder = builder.build(self.crypto.states.tx(*space).unwrap())?;
            debug_assert!(encoder.len() <= path.mtu());

            // Normal packets are in flight if they include PADDING frames,
            // but we don't send those.
            let in_flight = !profile.pto() && ack_eliciting;
            if in_flight {
                self.idle_timeout.on_packet_sent(now);
            }
            let sent = SentPacket::new(
                now,
                ack_eliciting,
                tokens,
                encoder.len() - header_start,
                in_flight,
            );
            if pt == PacketType::Initial && self.role == Role::Client {
                // Packets containing Initial packets might need padding, and we want to
                // track that padding along with the Initial packet.  So defer tracking.
                initial_sent = Some((pn, sent));
                needs_padding = true;
            } else {
                if pt != PacketType::ZeroRtt {
                    needs_padding = false;
                }
                self.loss_recovery.on_packet_sent(*space, pn, sent);
            }

            if *space == PNSpace::Handshake {
                if self.role == Role::Client {
                    // Client can send Handshake packets -> discard Initial keys and states
                    self.discard_keys(PNSpace::Initial);
                } else if self.state == State::Confirmed {
                    // We could discard handshake keys in set_state, but wait until after sending an ACK.
                    self.discard_keys(PNSpace::Handshake);
                }
            }
        }

        if encoder.is_empty() {
            Ok(SendOption::No(profile.paced()))
        } else {
            // Pad Initial packets sent by the client to mtu bytes.
            let mut packets: Vec<u8> = encoder.into();
            if let Some((initial_pn, mut initial)) = initial_sent.take() {
                if needs_padding {
                    qdebug!([self], "pad Initial to path MTU {}", path.mtu());
                    initial.size += path.mtu() - packets.len();
                    packets.resize(path.mtu(), 0);
                }
                self.loss_recovery
                    .on_packet_sent(PNSpace::Initial, initial_pn, initial);
            }
            Ok(SendOption::Yes(path.datagram(packets)))
        }
    }

    pub fn initiate_key_update(&mut self) -> Res<()> {
        if self.state == State::Confirmed {
            let la = self
                .loss_recovery
                .largest_acknowledged_pn(PNSpace::ApplicationData);
            qinfo!([self], "Initiating key update");
            self.crypto.states.initiate_key_update(la)
        } else {
            Err(Error::NotConnected)
        }
    }

    #[cfg(test)]
    pub fn get_epochs(&self) -> (Option<usize>, Option<usize>) {
        self.crypto.states.get_epochs()
    }

    fn client_start(&mut self, now: Instant) -> Res<()> {
        qinfo!([self], "client_start");
        debug_assert_eq!(self.role, Role::Client);
        qlog::client_connection_started(&mut self.qlog, self.path.as_ref().unwrap())?;
        self.loss_recovery.start_pacer(now);

        self.handshake(now, PNSpace::Initial, None)?;
        self.set_state(State::WaitInitial);
        self.zero_rtt_state = if self.crypto.enable_0rtt(self.role)? {
            qdebug!([self], "Enabled 0-RTT");
            ZeroRttState::Sending
        } else {
            ZeroRttState::Init
        };
        Ok(())
    }

    fn get_closing_period_time(&self, now: Instant) -> Instant {
        // Spec says close time should be at least PTO times 3.
        now + (self.loss_recovery.pto() * 3)
    }

    /// Close the connection.
    pub fn close(&mut self, now: Instant, app_error: AppError, msg: impl AsRef<str>) {
        let error = ConnectionError::Application(app_error);
        let timeout = self.get_closing_period_time(now);
        self.state_signaling.close(error.clone(), 0, msg);
        self.set_state(State::Closing { error, timeout });
    }

    fn set_initial_limits(&mut self) {
        let tps = self.tps.borrow();
        let remote = tps.remote();
        self.indexes.remote_max_stream_bidi =
            StreamIndex::new(remote.get_integer(tparams::INITIAL_MAX_STREAMS_BIDI));
        self.indexes.remote_max_stream_uni =
            StreamIndex::new(remote.get_integer(tparams::INITIAL_MAX_STREAMS_UNI));
        self.flow_mgr
            .borrow_mut()
            .conn_increase_max_credit(remote.get_integer(tparams::INITIAL_MAX_DATA));

        let peer_timeout = remote.get_integer(tparams::IDLE_TIMEOUT);
        if peer_timeout > 0 {
            self.idle_timeout
                .set_peer_timeout(Duration::from_millis(peer_timeout));
        }
    }

    /// Process the final set of transport parameters.
    fn process_tps(&mut self) -> Res<()> {
        self.validate_cids()?;
        if let Some(token) = self
            .tps
            .borrow()
            .remote
            .as_ref()
            .unwrap()
            .get_bytes(tparams::STATELESS_RESET_TOKEN)
        {
            let reset_token = <[u8; 16]>::try_from(token).unwrap().to_owned();
            self.path.as_mut().unwrap().set_reset_token(reset_token);
        }
        self.set_initial_limits();
        Ok(())
    }

    fn validate_cids(&mut self) -> Res<()> {
        match self.quic_version {
            QuicVersion::Draft27 => self.validate_cids_draft_27(),
            _ => self.validate_cids_draft_28_plus(),
        }
    }

    fn validate_cids_draft_27(&mut self) -> Res<()> {
        if let Some(info) = &self.retry_info {
            debug_assert!(!info.token.is_empty());
            let tph = self.tps.borrow();
            let tp = tph
                .remote()
                .get_bytes(tparams::ORIGINAL_DESTINATION_CONNECTION_ID);
            if self
                .remote_original_destination_cid
                .as_ref()
                .map(ConnectionId::as_cid_ref)
                != tp.map(ConnectionIdRef::from)
            {
                return Err(Error::InvalidRetry);
            }
        }
        Ok(())
    }

    fn validate_cids_draft_28_plus(&mut self) -> Res<()> {
        let tph = self.tps.borrow();
        let remote_tps = tph.remote.as_ref().unwrap();

        let tp = remote_tps.get_bytes(tparams::INITIAL_SOURCE_CONNECTION_ID);
        if self
            .remote_initial_source_cid
            .as_ref()
            .map(ConnectionId::as_cid_ref)
            != tp.map(ConnectionIdRef::from)
        {
            qwarn!(
                "{} ISCID test failed: self cid {:?} != tp cid {:?}",
                self.role,
                self.remote_initial_source_cid,
                tp.map(hex),
            );
            return Err(Error::ProtocolViolation);
        }

        if self.role == Role::Client {
            let tp = remote_tps.get_bytes(tparams::ORIGINAL_DESTINATION_CONNECTION_ID);
            if self
                .remote_original_destination_cid
                .as_ref()
                .map(ConnectionId::as_cid_ref)
                != tp.map(ConnectionIdRef::from)
            {
                qwarn!(
                    "{} ODCID test failed: self cid {:?} != tp cid {:?}",
                    self.role,
                    self.remote_original_destination_cid,
                    tp.map(hex),
                );
                return Err(Error::ProtocolViolation);
            }

            let tp = remote_tps.get_bytes(tparams::RETRY_SOURCE_CONNECTION_ID);
            let expected = self
                .retry_info
                .as_ref()
                .map(|ri| ri.retry_source_cid.as_cid_ref());
            if expected != tp.map(ConnectionIdRef::from) {
                qwarn!(
                    "{} RSCID test failed. self cid {:?} != tp cid {:?}",
                    self.role,
                    expected,
                    tp.map(hex),
                );
                return Err(Error::ProtocolViolation);
            }
        }

        Ok(())
    }

    fn handshake(&mut self, now: Instant, space: PNSpace, data: Option<&[u8]>) -> Res<()> {
        qtrace!([self], "Handshake space={} data={:0x?}", space, data);

        let try_update = data.is_some();
        match self.crypto.handshake(now, space, data)? {
            HandshakeState::Authenticated(_) | HandshakeState::InProgress => (),
            HandshakeState::AuthenticationPending => self.events.authentication_needed(),
            HandshakeState::Complete(_) => {
                if !self.state.connected() {
                    self.set_connected(now)?;
                }
            }
            _ => {
                unreachable!("Crypto state should not be new or failed after successful handshake")
            }
        }

        // There is a chance that this could be called less often, but getting the
        // conditions right is a little tricky, so call it on every  CRYPTO frame.
        if try_update {
            self.crypto.install_keys(self.role);
        }

        Ok(())
    }

    fn handle_max_data(&mut self, maximum_data: u64) {
        let conn_was_blocked = self.flow_mgr.borrow().conn_credit_avail() == 0;
        let conn_credit_increased = self
            .flow_mgr
            .borrow_mut()
            .conn_increase_max_credit(maximum_data);

        if conn_was_blocked && conn_credit_increased {
            for (id, ss) in &mut self.send_streams {
                if ss.avail() > 0 {
                    // These may not actually all be writable if one
                    // uses up all the conn credit. Not our fault.
                    self.events.send_stream_writable(*id)
                }
            }
        }
    }

    fn input_frame(&mut self, ptype: PacketType, frame: Frame, now: Instant) -> Res<()> {
        if !frame.is_allowed(ptype) {
            qerror!("frame not allowed: {:?} {:?}", frame, ptype);
            return Err(Error::ProtocolViolation);
        }
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
                    PNSpace::from(ptype),
                    largest_acknowledged,
                    ack_delay,
                    first_ack_range,
                    ack_ranges,
                    now,
                )?;
            }
            Frame::ResetStream {
                stream_id,
                application_error_code,
                ..
            } => {
                // TODO(agrover@mozilla.com): use final_size for connection MaxData calc
                if let (_, Some(rs)) = self.obtain_stream(stream_id)? {
                    rs.reset(application_error_code);
                }
            }
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => {
                self.events
                    .send_stream_stop_sending(stream_id, application_error_code);
                if let (Some(ss), _) = self.obtain_stream(stream_id)? {
                    ss.reset(application_error_code);
                }
            }
            Frame::Crypto { offset, data } => {
                let space = PNSpace::from(ptype);
                qtrace!(
                    [self],
                    "Crypto frame on space={} offset={}, data={:0x?}",
                    space,
                    offset,
                    &data
                );
                self.crypto.streams.inbound_frame(space, offset, data)?;
                if self.crypto.streams.data_ready(space) {
                    let mut buf = Vec::new();
                    let read = self.crypto.streams.read_to_end(space, &mut buf);
                    qdebug!("Read {} bytes", read);
                    self.handshake(now, space, Some(&buf))?;
                }
            }
            Frame::NewToken { token } => self.token = Some(token),
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
                ..
            } => {
                if let (_, Some(rs)) = self.obtain_stream(stream_id)? {
                    rs.inbound_stream_frame(fin, offset, data)?;
                }
            }
            Frame::MaxData { maximum_data } => self.handle_max_data(maximum_data),
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                if let (Some(ss), _) = self.obtain_stream(stream_id)? {
                    ss.set_max_stream_data(maximum_stream_data);
                }
            }
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {
                let remote_max = match stream_type {
                    StreamType::BiDi => &mut self.indexes.remote_max_stream_bidi,
                    StreamType::UniDi => &mut self.indexes.remote_max_stream_uni,
                };

                if maximum_streams > *remote_max {
                    *remote_max = maximum_streams;
                    self.events.send_stream_creatable(stream_type);
                }
            }
            Frame::DataBlocked { data_limit } => {
                // Should never happen since we set data limit to max
                qwarn!(
                    [self],
                    "Received DataBlocked with data limit {}",
                    data_limit
                );
                // But if it does, open it up all the way
                self.flow_mgr.borrow_mut().max_data(LOCAL_MAX_DATA);
            }
            Frame::StreamDataBlocked { stream_id, .. } => {
                // TODO(agrover@mozilla.com): how should we be using
                // currently-unused stream_data_limit?

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
                    StreamType::BiDi => &mut self.indexes.local_max_stream_bidi,
                    StreamType::UniDi => &mut self.indexes.local_max_stream_uni,
                };

                self.flow_mgr
                    .borrow_mut()
                    .max_streams(*local_max, stream_type)
            }
            Frame::NewConnectionId {
                sequence_number,
                connection_id,
                stateless_reset_token,
                ..
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
                qwarn!([self], "Received Path Response");
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason_phrase,
            } => {
                let reason_phrase = String::from_utf8_lossy(&reason_phrase);
                qinfo!(
                    [self],
                    "ConnectionClose received. Error code: {:?} frame type {:x} reason {}",
                    error_code,
                    frame_type,
                    reason_phrase
                );
                let (detail, frame_type) = if let CloseError::Application(_) = error_code {
                    // Use a transport error here because we want to send
                    // NO_ERROR in this case.
                    (
                        Error::PeerApplicationError(error_code.code()),
                        FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
                    )
                } else {
                    (
                        Error::PeerError(error_code.code()),
                        FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
                    )
                };
                let error = ConnectionError::Transport(detail);
                self.state_signaling.drain(error.clone(), frame_type, "");
                self.set_state(State::Draining {
                    error,
                    timeout: self.get_closing_period_time(now),
                });
            }
            Frame::HandshakeDone => {
                if self.role == Role::Server || !self.state.connected() {
                    return Err(Error::ProtocolViolation);
                }
                self.set_state(State::Confirmed);
                self.discard_keys(PNSpace::Handshake);
            }
        };

        Ok(())
    }

    /// Given a set of `SentPacket` instances, ensure that the source of the packet
    /// is told that they are lost.  This gives the frame generation code a chance
    /// to retransmit the frame as needed.
    fn handle_lost_packets(&mut self, lost_packets: &[SentPacket]) {
        for lost in lost_packets {
            for token in &lost.tokens {
                qdebug!([self], "Lost: {:?}", token);
                match token {
                    RecoveryToken::Ack(_) => {}
                    RecoveryToken::Stream(st) => self.send_streams.lost(&st),
                    RecoveryToken::Crypto(ct) => self.crypto.lost(&ct),
                    RecoveryToken::Flow(ft) => self.flow_mgr.borrow_mut().lost(
                        &ft,
                        &mut self.send_streams,
                        &mut self.recv_streams,
                        &mut self.indexes,
                    ),
                    RecoveryToken::HandshakeDone => self.state_signaling.handshake_done(),
                }
            }
        }
    }

    fn handle_ack(
        &mut self,
        space: PNSpace,
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: Vec<AckRange>,
        now: Instant,
    ) -> Res<()> {
        qinfo!(
            [self],
            "Rx ACK space={}, largest_acked={}, first_ack_range={}, ranges={:?}",
            space,
            largest_acknowledged,
            first_ack_range,
            ack_ranges
        );

        let acked_ranges =
            Frame::decode_ack_frame(largest_acknowledged, first_ack_range, &ack_ranges)?;
        let (acked_packets, lost_packets) = self.loss_recovery.on_ack_received(
            space,
            largest_acknowledged,
            acked_ranges,
            Duration::from_millis(ack_delay),
            now,
        );
        for acked in acked_packets {
            for token in acked.tokens {
                match token {
                    RecoveryToken::Ack(at) => self.acks.acked(&at),
                    RecoveryToken::Stream(st) => self.send_streams.acked(&st),
                    RecoveryToken::Crypto(ct) => self.crypto.acked(ct),
                    RecoveryToken::Flow(ft) => {
                        self.flow_mgr.borrow_mut().acked(ft, &mut self.send_streams)
                    }
                    RecoveryToken::HandshakeDone => (),
                }
            }
        }
        self.handle_lost_packets(&lost_packets);
        Ok(())
    }

    /// When the server rejects 0-RTT we need to drop a bunch of stuff.
    fn client_0rtt_rejected(&mut self) {
        if !matches!(self.zero_rtt_state, ZeroRttState::Sending) {
            return;
        }
        qdebug!([self], "0-RTT rejected");

        // Tell 0-RTT packets that they were "lost".
        let dropped = self.loss_recovery.drop_0rtt();
        self.handle_lost_packets(&dropped);

        self.send_streams.clear();
        self.recv_streams.clear();
        self.indexes = StreamIndexes::new();
        self.crypto.states.discard_0rtt_keys();
        self.events.client_0rtt_rejected();
    }

    fn set_connected(&mut self, now: Instant) -> Res<()> {
        qinfo!([self], "TLS connection complete");
        if self.crypto.tls.info().map(SecretAgentInfo::alpn).is_none() {
            qwarn!([self], "No ALPN. Closing connection.");
            // 120 = no_application_protocol
            return Err(Error::CryptoAlert(120));
        }
        if self.role == Role::Server {
            // Remove the randomized client CID from the list of acceptable CIDs.
            debug_assert_eq!(1, self.valid_cids.len());
            self.valid_cids.clear();
            // Generate a qlog event that the server connection started.
            qlog::server_connection_started(&mut self.qlog, self.path.as_ref().unwrap())?;
        } else {
            self.zero_rtt_state = if self.crypto.tls.info().unwrap().early_data_accepted() {
                ZeroRttState::AcceptedClient
            } else {
                self.client_0rtt_rejected();
                ZeroRttState::Rejected
            };
        }

        // Setting application keys has to occur after 0-RTT rejection.
        let pto = self.loss_recovery.pto();
        self.crypto.install_application_keys(now + pto)?;
        self.process_tps()?;
        self.set_state(State::Connected);
        self.stats.resumed = self.crypto.tls.info().unwrap().resumed();
        if self.role == Role::Server {
            self.state_signaling.handshake_done();
            self.set_state(State::Confirmed);
        }
        qinfo!([self], "Connection established");
        qlog::connection_tparams_set(&mut self.qlog, &*self.tps.borrow())?;
        Ok(())
    }

    fn set_state(&mut self, state: State) {
        if state > self.state {
            qinfo!([self], "State change from {:?} -> {:?}", self.state, state);
            self.state = state.clone();
            if self.state.closed() {
                self.send_streams.clear();
                self.recv_streams.clear();
            }
            self.events.connection_state_change(state);
        } else if mem::discriminant(&state) != mem::discriminant(&self.state) {
            // Only tolerate a regression in state if the new state is closing
            // and the connection is already closed.
            debug_assert!(matches!(state, State::Closing { .. } | State::Draining { .. }));
            debug_assert!(self.state.closed());
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
            if id.is_remote_initiated(self.role()) {
                if id.is_bidi() {
                    removed_bidi += 1;
                } else {
                    removed_uni += 1;
                }
            }
        }

        // Send max_streams updates if we removed remote-initiated recv streams.
        if removed_bidi > 0 {
            self.indexes.local_max_stream_bidi += removed_bidi;
            self.flow_mgr
                .borrow_mut()
                .max_streams(self.indexes.local_max_stream_bidi, StreamType::BiDi)
        }
        if removed_uni > 0 {
            self.indexes.local_max_stream_uni += removed_uni;
            self.flow_mgr
                .borrow_mut()
                .max_streams(self.indexes.local_max_stream_uni, StreamType::UniDi)
        }

        self.send_streams.clear_terminal();
    }

    /// Get or make a stream, and implicitly open additional streams as
    /// indicated by its stream id.
    fn obtain_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Res<(Option<&mut SendStream>, Option<&mut RecvStream>)> {
        if !self.state.connected()
            && !matches!(
                (&self.state, &self.zero_rtt_state),
                (State::Handshaking, ZeroRttState::AcceptedServer)
            )
        {
            return Err(Error::ConnectionState);
        }

        // May require creating new stream(s)
        if stream_id.is_remote_initiated(self.role()) {
            let next_stream_idx = if stream_id.is_bidi() {
                &mut self.indexes.local_next_stream_bidi
            } else {
                &mut self.indexes.local_next_stream_uni
            };
            let stream_idx: StreamIndex = stream_id.into();

            if stream_idx >= *next_stream_idx {
                let recv_initial_max_stream_data = if stream_id.is_bidi() {
                    if stream_idx > self.indexes.local_max_stream_bidi {
                        qwarn!(
                            [self],
                            "remote bidi stream create blocked, next={:?} max={:?}",
                            stream_idx,
                            self.indexes.local_max_stream_bidi
                        );
                        return Err(Error::StreamLimitError);
                    }
                    // From the local perspective, this is a remote- originated BiDi stream. From
                    // the remote perspective, this is a local-originated BiDi stream. Therefore,
                    // look at the local transport parameters for the
                    // INITIAL_MAX_STREAM_DATA_BIDI_REMOTE value to decide how much this endpoint
                    // will allow its peer to send.
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
                } else {
                    if stream_idx > self.indexes.local_max_stream_uni {
                        qwarn!(
                            [self],
                            "remote uni stream create blocked, next={:?} max={:?}",
                            stream_idx,
                            self.indexes.local_max_stream_uni
                        );
                        return Err(Error::StreamLimitError);
                    }
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tparams::INITIAL_MAX_STREAM_DATA_UNI)
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
                        self.events.new_stream(next_stream_id);
                    } else {
                        // From the local perspective, this is a remote- originated BiDi stream.
                        // From the remote perspective, this is a local-originated BiDi stream.
                        // Therefore, look at the remote's transport parameters for the
                        // INITIAL_MAX_STREAM_DATA_BIDI_LOCAL value to decide how much this endpoint
                        // is allowed to send its peer.
                        let send_initial_max_stream_data = self
                            .tps
                            .borrow()
                            .remote()
                            .get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
                        self.send_streams.insert(
                            next_stream_id,
                            SendStream::new(
                                next_stream_id,
                                send_initial_max_stream_data,
                                self.flow_mgr.clone(),
                                self.events.clone(),
                            ),
                        );
                        self.events.new_stream(next_stream_id);
                    }

                    *next_stream_idx += 1;
                    if *next_stream_idx > stream_idx {
                        break;
                    }
                }
            }
        }

        Ok((
            self.send_streams.get_mut(stream_id).ok(),
            self.recv_streams.get_mut(&stream_id),
        ))
    }

    /// Create a stream.
    // Returns new stream id
    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        // Can't make streams while closing, otherwise rely on the stream limits.
        match self.state {
            State::Closing { .. } | State::Closed { .. } => return Err(Error::ConnectionState),
            State::WaitInitial | State::Handshaking => {
                if !matches!(self.zero_rtt_state, ZeroRttState::Sending) {
                    return Err(Error::ConnectionState);
                }
            }
            _ => (),
        }
        if self.tps.borrow().remote.is_none() && self.tps.borrow().remote_0rtt.is_none() {
            return Err(Error::ConnectionState);
        }

        Ok(match st {
            StreamType::UniDi => {
                if self.indexes.remote_next_stream_uni >= self.indexes.remote_max_stream_uni {
                    self.flow_mgr
                        .borrow_mut()
                        .streams_blocked(self.indexes.remote_max_stream_uni, StreamType::UniDi);
                    qwarn!(
                        [self],
                        "local uni stream create blocked, next={:?} max={:?}",
                        self.indexes.remote_next_stream_uni,
                        self.indexes.remote_max_stream_uni
                    );
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .indexes
                    .remote_next_stream_uni
                    .to_stream_id(StreamType::UniDi, self.role);
                self.indexes.remote_next_stream_uni += 1;
                let initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote()
                    .get_integer(tparams::INITIAL_MAX_STREAM_DATA_UNI);

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
                if self.indexes.remote_next_stream_bidi >= self.indexes.remote_max_stream_bidi {
                    self.flow_mgr
                        .borrow_mut()
                        .streams_blocked(self.indexes.remote_max_stream_bidi, StreamType::BiDi);
                    qwarn!(
                        [self],
                        "local bidi stream create blocked, next={:?} max={:?}",
                        self.indexes.remote_next_stream_bidi,
                        self.indexes.remote_max_stream_bidi
                    );
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .indexes
                    .remote_next_stream_bidi
                    .to_stream_id(StreamType::BiDi, self.role);
                self.indexes.remote_next_stream_bidi += 1;
                // From the local perspective, this is a local- originated BiDi stream. From the
                // remote perspective, this is a remote-originated BiDi stream. Therefore, look at
                // the remote transport parameters for the INITIAL_MAX_STREAM_DATA_BIDI_REMOTE value
                // to decide how much this endpoint is allowed to send its peer.
                let send_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote()
                    .get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);

                self.send_streams.insert(
                    new_id,
                    SendStream::new(
                        new_id,
                        send_initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );
                // From the local perspective, this is a local- originated BiDi stream. From the
                // remote perspective, this is a remote-originated BiDi stream. Therefore, look at
                // the local transport parameters for the INITIAL_MAX_STREAM_DATA_BIDI_LOCAL value
                // to decide how much this endpoint will allow its peer to send.
                let recv_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .local
                    .get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);

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
    /// # Errors
    /// `InvalidStreamId` the stream does not exist,
    /// `InvalidInput` if length of `data` is zero,
    /// `FinalSizeError` if the stream has already been closed.
    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Res<usize> {
        self.send_streams.get_mut(stream_id.into())?.send(data)
    }

    /// Send all data or nothing on a stream. May cause DATA_BLOCKED or
    /// STREAM_DATA_BLOCKED frames to be sent.
    /// Returns true if data was successfully sent, otherwise false.
    /// # Errors
    /// `InvalidStreamId` the stream does not exist,
    /// `InvalidInput` if length of `data` is zero,
    /// `FinalSizeError` if the stream has already been closed.
    pub fn stream_send_atomic(&mut self, stream_id: u64, data: &[u8]) -> Res<bool> {
        let val = self
            .send_streams
            .get_mut(stream_id.into())?
            .send_atomic(data);
        if let Ok(val) = val {
            debug_assert!(
                val == 0 || val == data.len(),
                "Unexpected value {} when trying to send {} bytes atomically",
                val,
                data.len()
            );
        }
        val.map(|v| v == data.len())
    }

    /// Bytes that stream_send() is guaranteed to accept for sending.
    /// i.e. that will not be blocked by flow credits or send buffer max
    /// capacity.
    pub fn stream_avail_send_space(&self, stream_id: u64) -> Res<usize> {
        Ok(self.send_streams.get(stream_id.into())?.avail())
    }

    /// Close the stream. Enqueued data will be sent.
    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        self.send_streams.get_mut(stream_id.into())?.close();
        Ok(())
    }

    /// Abandon transmission of in-flight and future stream data.
    pub fn stream_reset_send(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        self.send_streams.get_mut(stream_id.into())?.reset(err);
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

    /// Get all current events. Best used just in debug/testing code, use
    /// next_event() instead.
    pub fn events(&mut self) -> impl Iterator<Item = ConnectionEvent> {
        self.events.events()
    }

    /// Return true if there are outstanding events.
    pub fn has_events(&self) -> bool {
        self.events.has_events()
    }

    /// Get events that indicate state changes on the connection. This method
    /// correctly handles cases where handling one event can obsolete
    /// previously-queued events, or cause new events to be generated.
    pub fn next_event(&mut self) -> Option<ConnectionEvent> {
        self.events.next_event()
    }
}

impl ::std::fmt::Display for Connection {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?} {:p}", self.role, self as *const Self)
    }
}

#[cfg(test)]
mod tests;
