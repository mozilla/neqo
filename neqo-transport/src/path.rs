// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::cell::RefCell;
use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::cid::{ConnectionId, ConnectionIdRef, RemoteConnectionIdEntry};
use crate::frame::{
    FRAME_TYPE_PATH_CHALLENGE, FRAME_TYPE_PATH_RESPONSE, FRAME_TYPE_RETIRE_CONNECTION_ID,
};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::stats::FrameStats;

use neqo_common::{hex, qdebug, qinfo, qtrace, Datagram, Encoder};
use neqo_crypto::random;

/// This is the MTU that we assume when using IPv6.
/// We use this size for Initial packets, so we don't need to worry about probing for support.
/// If the path doesn't support this MTU, we will assume that it doesn't support QUIC.
///
/// This is a multiple of 16 greater than the largest possible short header (1 + 20 + 4).
pub const PATH_MTU_V6: usize = 1337;
/// The path MTU for IPv4 can be 20 bytes larger than for v6.
pub const PATH_MTU_V4: usize = PATH_MTU_V6 + 20;
/// The number of times that a path will be probed before it is considered failed.
const MAX_PATH_PROBES: usize = 3;
/// The maximum number of paths that `Paths` will track.
const MAX_PATHS: usize = 15;

pub type PathRef = Rc<RefCell<Path>>;

/// A collection for network paths.
/// This holds a collection of paths that have been used for sending or
/// receiving, plus an additional "temporary" path that is held only while
/// processing a packet.
/// This structure limits its storage and will forget about paths if it
/// is exposed to too many paths.
#[derive(Debug, Default)]
pub struct Paths {
    /// All of the paths.
    paths: Vec<PathRef>,
    /// This is the primary path.  This will only be `None` initially, so
    /// care needs to be taken regarding that only during the handshake.
    /// This path will also be in `paths`.
    primary: Option<PathRef>,

    /// The path that we would prefer to migrate to.
    migration_target: Option<PathRef>,

    /// Connection IDs that need to be retired.
    to_retire: Vec<u64>,
}

impl Paths {
    /// Find the path for the given addresses.
    /// This might be a temporary path.
    pub fn path_or_temporary(&self, local: SocketAddr, remote: SocketAddr) -> PathRef {
        self.paths
            .iter()
            .find_map(|p| {
                if p.borrow().received_on(local, remote) {
                    Some(Rc::clone(p))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| Rc::new(RefCell::new(Path::temporary(local, remote))))
    }

    /// Get a reference to the primary path.  This will assert if there is no primary
    /// path, which happens at a server prior to receiving a valid Initial packet
    /// from a client.  So be careful using this method.
    pub fn primary(&self) -> PathRef {
        self.primary_fallible().unwrap()
    }

    /// Get a reference to the primary path.
    pub fn primary_fallible(&self) -> Option<PathRef> {
        self.primary.as_ref().map(Rc::clone)
    }

    /// Returns true if the path is not permanent.
    pub fn is_temporary(&self, path: &PathRef) -> bool {
        // Ask the path first, which is simpler.
        path.borrow().is_temporary() || !self.paths.iter().any(|p| Rc::ptr_eq(p, path))
    }

    fn retire(to_retire: &mut Vec<u64>, retired: &PathRef) {
        let seqno = retired
            .borrow()
            .remote_cid
            .as_ref()
            .unwrap()
            .sequence_number();
        to_retire.push(seqno);
    }

    /// Adopt a temporary path as permanent.
    /// The first path that is made permanent is made primary.
    pub fn make_permanent(
        &mut self,
        path: &PathRef,
        local_cid: Option<ConnectionId>,
        remote_cid: RemoteConnectionIdEntry,
    ) {
        debug_assert!(self.is_temporary(&path));

        // Make sure not to track too many paths.
        // This protects index 0, which contains the primary path.
        if self.paths.len() >= MAX_PATHS {
            debug_assert_eq!(self.paths.len(), MAX_PATHS);
            let removed = self.paths.remove(1);
            Self::retire(&mut self.to_retire, &removed);
            debug_assert_eq!(Rc::strong_count(&removed), 1);
        }

        qdebug!([path.borrow()], "Make permanent");
        path.borrow_mut().make_permanent(local_cid, remote_cid);
        self.paths.push(Rc::clone(&path));
        if self.primary.is_none() {
            self.set_primary(&path, false);
        }
    }

    fn set_primary(&mut self, path: &PathRef, probe: bool) {
        qinfo!([path.borrow()], "set as primary, probe={}", probe);
        if let Some(old) = self.primary.replace(Rc::clone(path)) {
            old.borrow_mut().set_primary(false);
            if probe {
                // When migrating to a new path, send a probe on the old one first.
                old.borrow_mut().probe();
            }
        }

        // Swap the primary path into slot 0, so that it is protected from eviction.
        let idx = self
            .paths
            .iter()
            .enumerate()
            .find_map(|(i, p)| if Rc::ptr_eq(p, path) { Some(i) } else { None })
            .expect("migration target should be permanent");
        self.paths.swap(0, idx);

        path.borrow_mut().set_primary(true);
        if probe {
            path.borrow_mut().probe();
        }
    }

    /// Migrate to the identified path.  If `force` is true, the path
    /// is forcibly marked as valid and the path is used immediately.
    /// Otherwise, migration will occur after probing succeeds.
    /// The path is always probed and will be abandoned if probing fails.
    pub fn migrate(&mut self, path: &PathRef, force: bool, now: Instant) {
        debug_assert!(!self.is_temporary(path));
        if force || path.borrow().is_valid() {
            path.borrow_mut().set_valid(now);
            self.set_primary(path, false);
        } else {
            self.migration_target = Some(Rc::clone(path));
        }
        path.borrow_mut().probe();
    }

    /// Process elapsed time for active paths.
    /// Returns an true if there are viable paths remaining after tidying up.
    ///
    /// TODO(mt) - the paths should own the RTT estimator, so they can find the PTO
    /// for themselves.
    pub fn process_timeout(&mut self, now: Instant, pto: Duration) -> bool {
        let to_retire = &mut self.to_retire;
        let mut primary_failed = false;
        self.paths.retain(|p| {
            if p.borrow_mut().process_timeout(now, pto) {
                true
            } else {
                qdebug!([p.borrow()], "Retiring path");
                if p.borrow().is_primary() {
                    primary_failed = true;
                }
                Self::retire(to_retire, p);
                false
            }
        });

        if primary_failed {
            self.primary = None;
            // Find a valid path to fall back to.
            if let Some(fallback) = self
                .paths
                .iter()
                .rev() // More recent paths are toward the end.
                .find(|p| p.borrow().is_valid())
            {
                // Need a clone as `fallback` is borrowed from `self`.
                let path = Rc::clone(fallback);
                qinfo!([path.borrow()], "Failing over after primary path failed");
                self.set_primary(&path, false);
                true
            } else {
                false
            }
        } else {
            true
        }
    }

    /// Get when the next call to `process_timeout()` should be scheduled.
    pub fn next_timeout(&self, pto: Duration) -> Option<Instant> {
        self.paths
            .iter()
            .filter_map(|p| p.borrow().next_timeout(pto))
            .min()
    }

    /// Set the identified path to be primary.
    /// This panics if `make_permanent` hasn't been called.
    pub fn handle_migration(&mut self, path: &PathRef, remote: SocketAddr, now: Instant) {
        qtrace!([self.primary().borrow()], "handle_migration");
        for p in &self.paths {
            qtrace!("Path {}", p.borrow());
        }
        // The update here needs to match the checks in `Path::received_on`.
        // Here, we update the remote port number to match the source port on the
        // datagram that was received.  This ensures that we send subsequent
        // packets back to the right place.
        path.borrow_mut().update_port(remote.port());

        if path.borrow().is_primary() {
            // Update when the path was last regarded as valid.
            path.borrow_mut().update(now);
            return;
        }

        self.set_primary(path, true);
    }

    /// Select a path to send on.  This will select the first path that has
    /// probes to send, then fall back to the primary path.
    pub fn select_path(&self) -> Option<PathRef> {
        self.paths
            .iter()
            .find_map(|p| {
                if p.borrow().has_probe() {
                    Some(Rc::clone(p))
                } else {
                    None
                }
            })
            .or_else(|| self.primary.as_ref().map(Rc::clone))
    }

    pub fn path_response(&mut self, response: [u8; 8], now: Instant) {
        for p in &self.paths {
            if p.borrow_mut().path_response(response, now) {
                if self
                    .migration_target
                    .as_ref()
                    .map_or(false, |target| Rc::ptr_eq(target, p))
                {
                    let primary = self.migration_target.take();
                    self.set_primary(&primary.unwrap(), false);
                }
                break;
            }
        }
    }

    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        while let Some(seqno) = self.to_retire.pop() {
            if builder.remaining() < 1 + Encoder::varint_len(seqno) {
                self.to_retire.push(seqno);
                break;
            }
            builder.encode_varint(FRAME_TYPE_RETIRE_CONNECTION_ID);
            builder.encode_varint(seqno);
            tokens.push(RecoveryToken::RetireConnectionId(seqno));
            stats.retire_connection_id += 1;
        }
    }

    pub fn lost_retire_cid(&mut self, lost: u64) {
        self.to_retire.push(lost);
    }

    pub fn acked_retire_cid(&mut self, acked: u64) {
        self.to_retire.retain(|&seqno| seqno != acked);
    }
}

/// The state of a path with respect to address validation.
#[derive(Debug)]
enum ProbeState {
    /// The path was last valid at the indicated time.
    Valid,
    /// The path was previously valid, but a new probe is needed.
    ProbeNeeded { probe_count: usize },
    /// The path hasn't been validated, but a probe has been sent.
    Probing {
        /// The number of probes that have been sent.
        probe_count: usize,
        /// The probe that was last sent.
        data: [u8; 8],
        /// Whether the probe was sent in a datagram padded to the path MTU.
        mtu: bool,
        /// When the probe was sent.
        sent: Instant,
    },
    /// Validation failed the last time it was attempted.
    Failed,
}

impl ProbeState {
    ///  Determine whether the current state requires probing.
    fn probe_needed(&self) -> bool {
        matches!(self, Self::ProbeNeeded { .. })
    }
}

/// A network path.
///
/// Paths are used a little bit strangely by connections:
/// they need to encapsulate all the state for a path (which
/// is normal), but that information is not propagated to the
/// `Paths` instance that holds them.  This is because the packet
/// processing where changes occur can't hold a reference to the
/// `Paths` instance that owns the `Path`.  Any changes to the
/// path are communicated to `Paths` afterwards.
#[derive(Debug)]
pub struct Path {
    /// A local socket address.
    local: SocketAddr,
    /// A remote socket address.
    remote: SocketAddr,
    /// The connection IDs that we use when sending on this path.
    /// This is only needed during the handshake.
    local_cid: Option<ConnectionId>,
    /// The current connection ID that we are using and its details.
    remote_cid: Option<RemoteConnectionIdEntry>,

    /// Whether this is the primary path.
    primary: bool,
    /// Whether the current path is considered valid.
    state: ProbeState,
    /// For a path that is not validated, this is `None`.  For a validated
    /// path, the time that the path was last valid.
    validated: Option<Instant>,
    /// A path challenge was received and PATH_RESPONSE has not been sent.
    challenge: Option<[u8; 8]>,

    /// The number of bytes received on this path.
    /// Note that this value might saturate on a long-lived connection,
    /// but we only use it before the path is validated.
    received_bytes: usize,
    /// The number of bytes sent on this path.
    sent_bytes: usize,
}

impl Path {
    /// Create a path from addresses and a remote connection ID.
    /// This is used for migration and for new datagrams.
    pub fn temporary(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            local,
            remote,
            local_cid: None,
            remote_cid: None,
            primary: false,
            state: ProbeState::ProbeNeeded { probe_count: 0 },
            validated: None,
            challenge: None,
            received_bytes: 0,
            sent_bytes: 0,
        }
    }

    /// Whether this path is the primary or current path for the connection.
    pub fn is_primary(&self) -> bool {
        self.primary
    }

    /// Whether this path is a temporary one.
    pub fn is_temporary(&self) -> bool {
        self.remote_cid.is_none()
    }

    /// By adding a remote connection ID, we make the path permanent
    /// and one that we will later send packets on.
    /// If `local_cid` is `None`, the existing value will be kept.
    fn make_permanent(
        &mut self,
        local_cid: Option<ConnectionId>,
        remote_cid: RemoteConnectionIdEntry,
    ) {
        if self.local_cid.is_none() {
            self.local_cid = local_cid;
        }
        self.remote_cid.replace(remote_cid);
    }

    /// Determine if this path was the one that the provided datagram was received on.
    /// This uses the full local socket address, but ignores the port number on the peer.
    /// NAT rebinding to the same IP address and a different port is thereby ignored.
    fn received_on(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        self.local == local && self.remote.ip() == remote.ip()
    }

    /// Update the remote port number.  Any flexibility we allow in `received_on`
    /// need to be adjusted at this point.
    fn update_port(&mut self, port: u16) {
        self.remote.set_port(port);
    }

    /// Set whether this path is primary.
    fn set_primary(&mut self, primary: bool) {
        qdebug!([self], "Make primary {}", primary);
        self.primary = primary;
    }

    /// Set the current path as valid.  This updates the time that the path was
    /// last validated and cancels any path validation.
    pub fn set_valid(&mut self, now: Instant) {
        qdebug!([self], "Path validated {:?}", now);
        self.state = ProbeState::Valid;
        self.validated = Some(now);
    }

    /// Update the last use of this path, if it is valid.
    /// This will keep the path active slightly longer.
    pub fn update(&mut self, now: Instant) {
        if self.validated.is_some() {
            self.validated = Some(now);
        }
    }

    pub fn mtu(&self) -> usize {
        if self.local.is_ipv4() {
            PATH_MTU_V4
        } else {
            PATH_MTU_V6 // IPv6
        }
    }

    /// Get the first local connection ID.
    /// Only do this for the primary path during the handshake.
    pub fn local_cid(&self) -> &ConnectionId {
        self.local_cid.as_ref().unwrap()
    }

    /// Set the remote connection ID based on the peer's choice.
    /// This is only valid during the handshake.
    pub fn set_remote_cid(&mut self, cid: &ConnectionIdRef) {
        self.remote_cid
            .as_mut()
            .unwrap()
            .update_cid(ConnectionId::from(cid));
    }

    /// Access the remote connection ID.
    pub fn remote_cid(&self) -> &ConnectionId {
        self.remote_cid.as_ref().unwrap().connection_id()
    }

    /// Set the stateless reset token for the connection ID that is currently in use.
    /// Panics if the sequence number is non-zero as this is only necessary during
    /// the handshake; all other connection IDs are initialized with a token.
    pub fn set_reset_token(&mut self, token: [u8; 16]) {
        self.remote_cid
            .as_mut()
            .unwrap()
            .set_stateless_reset_token(token);
    }

    /// Determine if the provided token is a stateless reset token.
    pub fn is_stateless_reset(&self, token: &[u8; 16]) -> bool {
        self.remote_cid
            .as_ref()
            .map_or(false, |rcid| rcid.is_stateless_reset(token))
    }

    /// Make a datagram.
    pub fn datagram<V: Into<Vec<u8>>>(&self, payload: V) -> Datagram {
        Datagram::new(self.local, self.remote, payload)
    }

    /// Get local address as `SocketAddr`
    pub fn local_address(&self) -> SocketAddr {
        self.local
    }

    /// Get remote address as `SocketAddr`
    pub fn remote_address(&self) -> SocketAddr {
        self.remote
    }

    /// Whether the path has been validated.
    pub fn is_valid(&self) -> bool {
        self.validated.is_some()
    }

    /// Handle a `PATH_RESPONSE` frame. Returns true if the response was accepted.
    pub fn path_response(&mut self, response: [u8; 8], now: Instant) -> bool {
        if let ProbeState::Probing { data, mtu, .. } = &mut self.state {
            if response == *data {
                let need_full_probe = !*mtu;
                self.set_valid(now);
                if need_full_probe {
                    qdebug!([self], "Sub-MTU probe successful, reset probe count");
                    self.probe();
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// The path has been challenged.  This generates a response.
    /// This only generates a single response at a time.
    pub fn challenged(&mut self, challenge: [u8; 8]) {
        self.challenge = Some(challenge.to_owned());
        if !self.is_valid() {
            self.probe();
        }
    }

    /// At the next opportunity, send a probe.
    /// Unless the probe count has been exhausted already.
    fn probe(&mut self) {
        let probe_count = match &self.state {
            ProbeState::Probing { probe_count, .. } => *probe_count + 1,
            ProbeState::ProbeNeeded { probe_count, .. } => *probe_count,
            _ => 0,
        };
        self.state = if probe_count >= MAX_PATH_PROBES {
            qinfo!([self], "Probing failed");
            ProbeState::Failed
        } else {
            qdebug!([self], "Initiating probe");
            ProbeState::ProbeNeeded { probe_count }
        };
    }

    /// Returns true if this path have any probing frames to send.
    pub fn has_probe(&self) -> bool {
        self.challenge.is_some() || self.state.probe_needed()
    }

    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        stats: &mut FrameStats,
        mtu: bool, // Whether the packet we're writing into will be a full MTU.
        now: Instant,
    ) -> bool {
        if builder.remaining() < 9 {
            return false;
        }

        // Send PATH_RESPONSE.
        let resp_sent = if let Some(challenge) = self.challenge.take() {
            qtrace!([self], "Responding to path challenge {}", hex(&challenge));
            builder.encode_varint(FRAME_TYPE_PATH_RESPONSE);
            builder.encode(&challenge[..]);

            // These frames are not retransmitted in the usual fashion.
            // There is no token, therefore we need to count `all` specially.
            stats.path_response += 1;
            stats.all += 1;

            if builder.remaining() < 9 {
                return true;
            }
            true
        } else {
            false
        };

        // Send PATH_CHALLENGE.
        if let ProbeState::ProbeNeeded { probe_count } = self.state {
            qtrace!([self], "Initiating path challenge {}", probe_count);
            let data = <[u8; 8]>::try_from(&random(8)[..]).unwrap();
            builder.encode_varint(FRAME_TYPE_PATH_CHALLENGE);
            builder.encode(&data);

            // As above, no recovery token.
            stats.path_challenge += 1;
            stats.all += 1;

            self.state = ProbeState::Probing {
                probe_count,
                data,
                mtu,
                sent: now,
            };
            true
        } else {
            resp_sent
        }
    }

    /// Process a timer for this path.
    /// This returns true if the path is viable and can be kept alive.
    pub fn process_timeout(&mut self, now: Instant, pto: Duration) -> bool {
        if let ProbeState::Probing { sent, .. } = &self.state {
            if now >= *sent + pto {
                self.probe();
            }
        }
        if let ProbeState::Failed = self.state {
            // Retire failed paths immediately.
            false
        } else if self.primary {
            // Keep valid primary paths otherwise.
            true
        } else if let ProbeState::Valid = self.state {
            // Retire validated, non-primary paths.
            // Allow more than `MAX_PATH_PROBES` times the PTO so that an old
            // path remains around until after a previous path fails.
            let count = u32::try_from(MAX_PATH_PROBES + 1).unwrap();
            self.validated.unwrap() + (pto * count) > now
        } else {
            // Keep paths that are being actively probed.
            true
        }
    }

    /// Return the next time that this path needs servicing.
    /// This only considers retransmissions of probes, not cleanup of the path.
    /// If there is no other activity, then there is no real need to schedule a
    /// timer to cleanup old paths.
    pub fn next_timeout(&self, pto: Duration) -> Option<Instant> {
        if let ProbeState::Probing { sent, .. } = &self.state {
            Some(*sent + pto)
        } else {
            None
        }
    }

    /// Record received bytes for the path.
    pub fn add_received(&mut self, count: usize) {
        self.received_bytes = self.received_bytes.saturating_add(count);
    }

    /// Record sent bytes for the path.
    pub fn add_sent(&mut self, count: usize) {
        self.sent_bytes = self.sent_bytes.saturating_add(count);
    }

    /// Get the number of bytes that can be written to this path.
    pub fn amplification_limit(&self) -> usize {
        if matches!(self.state, ProbeState::Failed) {
            0
        } else if self.is_valid() {
            usize::MAX
        } else if let Some(limit) = self.received_bytes.checked_mul(3) {
            limit.saturating_sub(self.sent_bytes)
        } else {
            usize::MAX
        }
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_primary() {
            write!(f, "pri-")?; // primary
        }
        if !self.is_valid() {
            write!(f, "unv-")?; // unvalidated
        }
        write!(f, "path")?;
        if let Some(entry) = self.remote_cid.as_ref() {
            write!(f, ":{}", entry.connection_id())?;
        }
        write!(f, " {}->{}", self.local, self.remote,)?;
        Ok(())
    }
}
