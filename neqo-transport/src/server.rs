// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This file implements a server that can handle multiple connections.

use std::{
    cell::RefCell,
    cmp::min,
    collections::VecDeque,
    fmt::{self, Display, Formatter},
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    path::PathBuf,
    rc::Rc,
    time::Instant,
};

use neqo_common::{
    Buffer as _, Datagram, Role, Tos, datagram, event::Provider as _, hex::Hex, qdebug, qerror,
    qinfo, qlog::Qlog, qtrace, qwarn,
};
use nss::{
    AntiReplay, Cipher, PrivateKey, PublicKey, ZeroRttCheckResult, ZeroRttChecker,
    encode_ech_config,
};
use rustc_hash::FxHashSet as HashSet;

pub use crate::addr_valid::ValidateAddress;
use crate::{
    ConnectionParameters, OutputBatch, Res, Version,
    addr_valid::{AddressValidation, AddressValidationResult},
    cid::{ConnectionId, ConnectionIdGenerator, ConnectionIdRef},
    connection::{BatchMeta, Connection, Output, State},
    packet::{self, MIN_INITIAL_PACKET_SIZE, Public},
    saved::SavedDatagram,
};

/// A `ServerZeroRttChecker` is a simple wrapper around a single checker.
/// It uses `RefCell` so that the wrapped checker can be shared between
/// multiple connections created by the server.
#[derive(Clone, Debug)]
struct ServerZeroRttChecker {
    checker: Rc<RefCell<Box<dyn ZeroRttChecker>>>,
}

impl ServerZeroRttChecker {
    pub fn new(checker: Box<dyn ZeroRttChecker>) -> Self {
        Self {
            checker: Rc::new(RefCell::new(checker)),
        }
    }
}

impl ZeroRttChecker for ServerZeroRttChecker {
    fn check(&self, token: &[u8]) -> ZeroRttCheckResult {
        self.checker.borrow().check(token)
    }
}

/// `InitialDetails` holds important information for processing `Initial` packets.
struct InitialDetails {
    src_cid: ConnectionId,
    dst_cid: ConnectionId,
    token: Vec<u8>,
    version: Version,
}

impl InitialDetails {
    fn new(packet: &Public) -> Self {
        Self {
            src_cid: ConnectionId::from(packet.scid()),
            dst_cid: ConnectionId::from(packet.dcid()),
            token: packet.token().to_vec(),
            version: packet.version().expect("packet has version"),
        }
    }
}

struct EchConfig {
    config: u8,
    public_name: String,
    sk: PrivateKey,
    pk: PublicKey,
    encoded: Vec<u8>,
}

impl EchConfig {
    fn new(config: u8, public_name: &str, sk: &PrivateKey, pk: &PublicKey) -> Res<Self> {
        let encoded = encode_ech_config(config, public_name, pk)?;
        Ok(Self {
            config,
            public_name: String::from(public_name),
            sk: sk.clone(),
            pk: pk.clone(),
            encoded,
        })
    }
}

pub struct Server {
    /// The names of certificates.
    certs: Vec<String>,
    /// The ALPN values that the server supports.
    protocols: Vec<String>,
    /// The cipher suites that the server supports.
    ciphers: Vec<Cipher>,
    /// Anti-replay configuration for 0-RTT.
    anti_replay: AntiReplay,
    /// A function for determining if 0-RTT can be accepted.
    zero_rtt_checker: ServerZeroRttChecker,
    /// A connection ID generator.
    cid_generator: Rc<RefCell<dyn ConnectionIdGenerator>>,
    /// Connection parameters.
    conn_params: ConnectionParameters,
    /// All connections.
    connections: Vec<Rc<RefCell<Connection>>>,
    /// Address validation logic, which determines whether we send a Retry.
    address_validation: Rc<RefCell<AddressValidation>>,
    /// Directory to create qlog traces in
    qlog_dir: Option<PathBuf>,
    /// Encrypted client hello (ECH) configuration.
    ech_config: Option<EchConfig>,
    /// Remaining datagrams of a batch of datagrams provided via
    /// [`Server::process_multiple`]. An earlier datagram in the batch required
    /// an immediate return without further processing of the remaining
    /// datagrams. To be processed on consecutive calls to
    /// [`Server::process_multiple`].
    saved_datagrams: VecDeque<SavedDatagram>,
}

impl Server {
    /// Construct a new server.
    /// * `now` is the time that the server is instantiated.
    /// * `certs` is a list of the certificates that should be configured.
    /// * `protocols` is the preference list of ALPN values.
    /// * `anti_replay` is an anti-replay context.
    /// * `zero_rtt_checker` determines whether 0-RTT should be accepted. This will be passed the
    ///   value of the `extra` argument that was passed to `Connection::send_ticket` to see if it is
    ///   OK.
    /// * `cid_generator` is responsible for generating connection IDs and parsing them; connection
    ///   IDs produced by the manager cannot be zero-length.
    /// # Errors
    /// When address validation state cannot be created.
    pub fn new<A1: AsRef<str>, A2: AsRef<str>>(
        now: Instant,
        certs: &[A1],
        protocols: &[A2],
        anti_replay: AntiReplay,
        zero_rtt_checker: Box<dyn ZeroRttChecker>,
        cid_generator: Rc<RefCell<dyn ConnectionIdGenerator>>,
        conn_params: ConnectionParameters,
    ) -> Res<Self> {
        let validation = AddressValidation::new(now, ValidateAddress::Never)?;
        Ok(Self {
            certs: certs.iter().map(|x| String::from(x.as_ref())).collect(),
            protocols: protocols.iter().map(|x| String::from(x.as_ref())).collect(),
            ciphers: Vec::new(),
            anti_replay,
            zero_rtt_checker: ServerZeroRttChecker::new(zero_rtt_checker),
            cid_generator,
            conn_params,
            connections: Vec::new(),
            address_validation: Rc::new(RefCell::new(validation)),
            qlog_dir: None,
            ech_config: None,
            saved_datagrams: VecDeque::new(),
        })
    }

    /// Set or clear directory to create logs of connection events in QLOG format.
    pub fn set_qlog_dir(&mut self, dir: Option<PathBuf>) {
        self.qlog_dir = dir;
    }

    /// Set the policy for address validation.
    pub fn set_validation(&self, v: ValidateAddress) {
        self.address_validation.borrow_mut().set_validation(v);
    }

    /// Set the cipher suites that should be used.  Set an empty value to use
    /// default values.
    pub fn set_ciphers<A: AsRef<[Cipher]>>(&mut self, ciphers: A) {
        self.ciphers = Vec::from(ciphers.as_ref());
    }

    /// # Errors
    /// When the configuration is invalid.
    pub fn enable_ech(
        &mut self,
        config: u8,
        public_name: &str,
        sk: &PrivateKey,
        pk: &PublicKey,
    ) -> Res<()> {
        self.ech_config = Some(EchConfig::new(config, public_name, sk, pk)?);
        Ok(())
    }

    #[must_use]
    pub fn ech_config(&self) -> &[u8] {
        self.ech_config.as_ref().map_or(&[], |cfg| &cfg.encoded)
    }

    /// Writes address validation fuzzing corpus data.
    #[cfg(feature = "build-fuzzing-corpus")]
    fn write_addr_valid_corpus(peer: std::net::SocketAddr, token: &[u8]) {
        let mut d = Vec::new();
        match peer.ip() {
            std::net::IpAddr::V4(ip) => {
                let bytes = ip.octets();
                d.push(u8::try_from(bytes.len()).expect("IP address len fits in u8"));
                d.extend_from_slice(&bytes);
            }
            std::net::IpAddr::V6(ip) => {
                let bytes = ip.octets();
                d.push(u8::try_from(bytes.len()).expect("IP address len fits in u8"));
                d.extend_from_slice(&bytes);
            }
        }
        d.extend_from_slice(&peer.port().to_be_bytes());
        d.extend_from_slice(token);
        neqo_common::write_item_to_fuzzing_corpus("addr_valid", &d);
    }

    fn handle_initial(
        &mut self,
        initial: InitialDetails,
        dgram: Datagram<impl AsRef<[u8]> + AsMut<[u8]>>,
        now: Instant,
        send_buffer: &mut Vec<u8>,
    ) -> Option<BatchMeta> {
        qdebug!("[{self}] Handle initial");
        #[cfg(feature = "build-fuzzing-corpus")]
        Self::write_addr_valid_corpus(dgram.source(), &initial.token);
        let res = self
            .address_validation
            .borrow()
            .validate(&initial.token, dgram.source(), now);
        match res {
            AddressValidationResult::Invalid => None,
            AddressValidationResult::Pass => {
                self.accept_connection(initial, dgram, None, now, send_buffer)
            }
            AddressValidationResult::ValidRetry(orig_dcid) => {
                self.accept_connection(initial, dgram, Some(orig_dcid), now, send_buffer)
            }
            AddressValidationResult::Validate => {
                qinfo!("[{self}] Send retry for {:?}", initial.dst_cid);

                // > This Destination Connection ID MUST be at least 8 bytes in length.
                //
                // <https://www.rfc-editor.org/rfc/rfc9000.html#section-7.2>
                if initial.dst_cid.len() < 8 {
                    qerror!(
                        "[{self}] DCID too short ({} bytes), dropping packet",
                        initial.dst_cid.len()
                    );
                    return None;
                }

                let res = self.address_validation.borrow().generate_retry_token(
                    &initial.dst_cid,
                    dgram.source(),
                    now,
                );
                let Ok(token) = res else {
                    qerror!("[{self}] unable to generate token, dropping packet");
                    return None;
                };
                let Some(new_dcid) = self.cid_generator.borrow_mut().generate_cid() else {
                    qerror!("[{self}] no connection ID for retry, dropping packet");
                    return None;
                };
                let res = packet::Builder::retry(
                    initial.version,
                    &initial.src_cid,
                    &new_dcid,
                    &token,
                    &initial.dst_cid,
                );
                let Ok(p) = res else {
                    qerror!("[{self}] unable to encode retry, dropping packet");
                    return None;
                };
                qdebug!(
                    "[{self}] type={:?} path:{} {}->{} {:?} len {}",
                    packet::Type::Retry,
                    initial.dst_cid,
                    dgram.destination(),
                    dgram.source(),
                    Tos::default(),
                    p.len(),
                );
                // Retry needs its own scratch space for the pseudo-header, so copy.
                let d = Datagram::new(dgram.destination(), dgram.source(), Tos::default(), p);
                datagram::Batch::copy_from(&d, send_buffer)
                    .ok()
                    .map(|b| b.meta())
            }
        }
    }

    fn create_qlog_trace(&self, odcid: ConnectionIdRef<'_>, now: Instant) -> Qlog {
        self.qlog_dir
            .as_ref()
            .map_or_else(Qlog::disabled, |qlog_dir| {
                Qlog::enabled_with_file(
                    qlog_dir.clone(),
                    Role::Server,
                    Some("Neqo server qlog".to_string()),
                    Some("Neqo server qlog".to_string()),
                    format!("server-{odcid}"),
                    now,
                )
                .unwrap_or_else(|e| {
                    qerror!("failed to create Qlog: {e}");
                    Qlog::disabled()
                })
            })
    }

    fn setup_connection(
        &self,
        c: &mut Connection,
        initial: InitialDetails,
        orig_dcid: Option<ConnectionId>,
        now: Instant,
    ) {
        let zcheck = self.zero_rtt_checker.clone();
        if c.server_enable_0rtt(&self.anti_replay, zcheck).is_err() {
            qwarn!("[{self}] Unable to enable 0-RTT");
        }
        if let Some(odcid) = &orig_dcid {
            // There was a retry, so set the connection IDs for.
            c.set_retry_cids(odcid, initial.src_cid, &initial.dst_cid);
        }
        c.set_validation(&self.address_validation);
        c.set_qlog(self.create_qlog_trace(orig_dcid.unwrap_or(initial.dst_cid).as_cid_ref(), now));
        if let Some(cfg) = &self.ech_config
            && c.server_enable_ech(cfg.config, &cfg.public_name, &cfg.sk, &cfg.pk)
                .is_err()
        {
            qwarn!("[{self}] Unable to enable ECH");
        }
    }

    fn accept_connection(
        &mut self,
        initial: InitialDetails,
        dgram: Datagram<impl AsRef<[u8]> + AsMut<[u8]>>,
        orig_dcid: Option<ConnectionId>,
        now: Instant,
        send_buffer: &mut Vec<u8>,
    ) -> Option<BatchMeta> {
        qinfo!(
            "[{self}] Accept connection {:?}",
            orig_dcid.as_ref().unwrap_or(&initial.dst_cid)
        );
        // The internal connection ID manager that we use is not used directly.
        // Instead, wrap it so that we can save connection IDs.

        let mut params = self.conn_params.clone();
        params.get_versions_mut().set_initial(initial.version);
        let sconn = Connection::new_server(
            &self.certs,
            &self.protocols,
            Rc::clone(&self.cid_generator),
            params,
        );

        match sconn {
            Ok(mut c) => {
                self.setup_connection(&mut c, initial, orig_dcid, now);
                // Straight into the caller's buffer, so the first flight is not
                // built into a throwaway one and copied.
                let meta = c
                    .process_multiple(Some(dgram), now, send_buffer, NonZeroUsize::MIN)
                    .meta();
                self.connections.push(Rc::new(RefCell::new(c)));
                meta
            }
            Err(e) => {
                qwarn!("[{self}] Unable to create connection");
                if e == crate::Error::VersionNegotiation {
                    crate::qlog::server_version_information_failed(
                        &mut self.create_qlog_trace(
                            orig_dcid.unwrap_or(initial.dst_cid).as_cid_ref(),
                            now,
                        ),
                        self.conn_params.get_versions().all(),
                        initial.version.wire_version(),
                        now,
                    );
                }
                None
            }
        }
    }

    /// Defer `dgrams` to a later call, so output can be returned now.
    fn save_for_later<A: AsRef<[u8]> + AsMut<[u8]>, I: IntoIterator<Item = Datagram<A>>>(
        &mut self,
        dgrams: I,
        now: Instant,
    ) {
        self.saved_datagrams
            .extend(dgrams.into_iter().map(|d| SavedDatagram {
                d: d.to_owned(),
                t: now,
            }));
    }

    /// Process new input datagrams on the connection.
    pub fn process_multiple_input<
        'b,
        A: AsRef<[u8]> + AsMut<[u8]>,
        I: IntoIterator<Item = Datagram<A>>,
    >(
        &mut self,
        dgrams: I,
        now: Instant,
        send_buffer: &'b mut Vec<u8>,
    ) -> OutputBatch<'b> {
        send_buffer.clear();

        // Process input datagrams from previous call.
        while let Some(SavedDatagram { d, t }) = self.saved_datagrams.pop_front() {
            // Metadata only, so the borrow ends here.
            if let Some(meta) = self.process_input(std::iter::once(d), t, &mut *send_buffer) {
                self.save_for_later(dgrams, now);
                return OutputBatch::rebuild(Some(&meta), send_buffer);
            }
        }

        // Process input datagrams from this call.
        let meta = self.process_input(dgrams, now, &mut *send_buffer);
        OutputBatch::rebuild(meta.as_ref(), send_buffer)
    }

    /// Process a new input datagram, writing any response into `send_buffer`.
    fn process_input<A: AsRef<[u8]> + AsMut<[u8]>, I: IntoIterator<Item = Datagram<A>>>(
        &mut self,
        dgrams: I,
        now: Instant,
        send_buffer: &mut Vec<u8>,
    ) -> Option<BatchMeta> {
        let mut dgrams = dgrams.into_iter();
        while let Some(mut dgram) = dgrams.next() {
            qtrace!("Process datagram: {}", Hex::new(&dgram[..]));

            // This is only looking at the first packet header in the datagram.
            // All packets in the datagram are routed to the same connection.
            let len = dgram.len();
            let destination = dgram.destination();
            let source = dgram.source();
            let res =
                Public::decode_server(&mut dgram[..], self.cid_generator.borrow().as_decoder());
            let Ok((packet, _remainder)) = res else {
                qtrace!("[{self}] Discarding {dgram:?}");
                continue;
            };

            // Finding an existing connection. Should be the most common case.
            if let Some(c) = self
                .connections
                .iter_mut()
                .find(|c| c.borrow().is_valid_local_cid(packet.dcid()))
            {
                c.borrow_mut().process_input(dgram, now);
                continue;
            }

            if packet.packet_type() == packet::Type::Short {
                // TODO send a stateless reset here.
                qtrace!("[{self}] Short header packet for an unknown connection");
                continue;
            }

            // An `Initial` always has a version; treat a missing one as unsupported.
            if packet.packet_type() == packet::Type::OtherVersion
                || (packet.packet_type() == packet::Type::Initial
                    && packet
                        .version()
                        .is_none_or(|v| !self.conn_params.get_versions().all().contains(&v)))
            {
                if len < MIN_INITIAL_PACKET_SIZE {
                    qdebug!("[{self}] Unsupported version: too short");
                    continue;
                }

                qdebug!("[{self}] Unsupported version: {:x}", packet.wire_version());
                // `version_negotiation` appends, so measure what it wrote.
                let start = send_buffer.position();
                packet::Builder::version_negotiation(
                    &packet.scid()[..],
                    &packet.dcid()[..],
                    packet.wire_version(),
                    self.conn_params.get_versions().all(),
                    &mut *send_buffer,
                );
                let vn_len = send_buffer.position() - start;
                qdebug!(
                    "[{self}] type={:?} path:{} {destination}->{source} {:?} len {vn_len}",
                    packet::Type::VersionNegotiation,
                    packet.dcid(),
                    Tos::default(),
                );

                crate::qlog::server_version_information_failed(
                    &mut self.create_qlog_trace(packet.dcid(), now),
                    self.conn_params.get_versions().all(),
                    packet.wire_version(),
                    now,
                );

                self.save_for_later(dgrams, now);

                // Always `Some`, as a Version Negotiation packet is not empty.
                let datagram_size = NonZeroUsize::new(vn_len)?;
                return Some((destination, source, Tos::default(), datagram_size));
            }

            match packet.packet_type() {
                packet::Type::Initial => {
                    if len < MIN_INITIAL_PACKET_SIZE {
                        qdebug!("[{self}] Drop initial: too short");
                        continue;
                    }
                    // Copy values from `packet` because they are currently still borrowing from
                    // `dgram`.
                    let initial = InitialDetails::new(&packet);
                    if let Some(meta) = self.handle_initial(initial, dgram, now, send_buffer) {
                        self.save_for_later(dgrams, now);
                        return Some(meta);
                    }
                }
                packet::Type::ZeroRtt => {
                    qdebug!(
                        "[{self}] Dropping 0-RTT for unknown connection {}",
                        ConnectionId::from(packet.dcid())
                    );
                }
                packet::Type::OtherVersion => unreachable!(),
                _ => {
                    qtrace!("[{self}] Not an initial packet");
                }
            }
        }

        None
    }

    /// Iterate through the pending connections looking for any that might want
    /// to send a datagram.  Stop at the first one that does.
    fn process_next_output<'b>(
        &mut self,
        now: Instant,
        send_buffer: &'b mut Vec<u8>,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch<'b> {
        assert!(
            self.saved_datagrams.is_empty(),
            "Always process all inbound datagrams first."
        );
        let mut callback = None;

        // Reused across connections; no output leaves the buffer empty.
        for connection in &mut self.connections {
            let batch = connection.borrow_mut().process_multiple_output(
                now,
                &mut *send_buffer,
                max_datagrams,
            );
            // Metadata only, so the borrow ends here.
            let Some(meta) = batch.meta() else {
                if let OutputBatch::Callback(next) = batch {
                    callback = Some(callback.map_or(next, |previous| min(previous, next)));
                }
                continue;
            };
            return OutputBatch::rebuild(Some(&meta), send_buffer);
        }

        callback.map_or(OutputBatch::None, OutputBatch::Callback)
    }

    /// Short-hand for [`Server::process`] without an input datagram.
    #[must_use]
    pub fn process_output(&mut self, now: Instant) -> Output {
        self.process(None::<Datagram>, now)
    }

    /// Wrapper around [`Server::process_multiple`] that processes a single output
    /// datagram only.
    #[must_use]
    pub fn process<A: AsRef<[u8]> + AsMut<[u8]>, I: IntoIterator<Item = Datagram<A>>>(
        &mut self,
        dgrams: I,
        now: Instant,
    ) -> Output {
        Output::owned(|b, max| self.process_multiple(dgrams, now, b, max))
    }

    pub fn process_multiple<
        'b,
        A: AsRef<[u8]> + AsMut<[u8]>,
        I: IntoIterator<Item = Datagram<A>>,
    >(
        &mut self,
        dgrams: I,
        now: Instant,
        send_buffer: &'b mut Vec<u8>,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch<'b> {
        // Metadata only, so the borrow ends here.
        let written = self
            .process_multiple_input(dgrams, now, &mut *send_buffer)
            .meta();
        if written.is_some() {
            // Return immediately. Do any maintenance on next call.
            return OutputBatch::rebuild(written.as_ref(), send_buffer);
        }

        // Process output datagrams.
        let maybe_callback = match self.process_next_output(now, send_buffer, max_datagrams) {
            // Return immediately. Do any maintenance on next call.
            o @ OutputBatch::DatagramBatch(_) => return o,
            o @ (OutputBatch::Callback(_) | OutputBatch::None) => o,
        };

        // Clean-up closed connections.
        self.connections
            .retain(|c| !matches!(c.borrow().state(), State::Closed(_)));

        maybe_callback
    }

    /// This lists the connections that have received new events
    /// as a result of calling `process()`.
    #[expect(
        clippy::mutable_key_type,
        reason = "ActiveConnectionRef::Hash doesn't access any of the interior mutable types."
    )]
    #[must_use]
    pub fn active_connections(&self) -> HashSet<ConnectionRef> {
        self.connections
            .iter()
            .filter(|c| c.borrow().has_events())
            .map(|c| ConnectionRef { c: Rc::clone(c) })
            .collect()
    }

    /// Whether any connections have received new events as a result of calling
    /// `process()`.
    #[must_use]
    pub fn has_active_connections(&self) -> bool {
        self.connections.iter().any(|c| c.borrow().has_events())
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionRef {
    c: Rc<RefCell<Connection>>,
}

impl ConnectionRef {
    #[must_use]
    pub fn borrow(&self) -> impl Deref<Target = Connection> + '_ {
        self.c.borrow()
    }

    #[must_use]
    pub fn borrow_mut(&self) -> impl DerefMut<Target = Connection> + '_ {
        self.c.borrow_mut()
    }

    #[must_use]
    pub fn connection(&self) -> Rc<RefCell<Connection>> {
        Rc::clone(&self.c)
    }
}

impl std::hash::Hash for ConnectionRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let ptr: *const _ = self.c.as_ref();
        ptr.hash(state);
    }
}

impl PartialEq for ConnectionRef {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.c, &other.c)
    }
}

impl Eq for ConnectionRef {}

impl Display for Server {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Server")
    }
}
