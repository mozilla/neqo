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
use std::time::Instant;

use crate::cid::{ConnectionId, ConnectionIdRef, RemoteConnectionIdEntry};
use crate::frame::{FRAME_TYPE_PATH_CHALLENGE, FRAME_TYPE_PATH_RESPONSE};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::stats::FrameStats;

use neqo_common::{hex, qdebug, qinfo, qtrace, Datagram};
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
}

impl Paths {
    /// Find the path that the provided `Datagram` was received on.
    /// This might be a temporary path.
    pub fn path_or_temporary(&self, d: &Datagram) -> PathRef {
        self.paths
            .iter()
            .find_map(|p| {
                if p.borrow().received_on(d) {
                    Some(Rc::clone(p))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| Rc::new(RefCell::new(Path::temporary(d.destination(), d.source()))))
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

    /// Adopt a temporary path as permanent.
    /// The first path that is made permanent is made primary.
    pub fn make_permanent(
        &mut self,
        path: PathRef,
        local_cid: Option<ConnectionId>,
        remote_cid: RemoteConnectionIdEntry,
    ) {
        debug_assert!(self.is_temporary(&path));

        // Make sure not to track too many paths.
        // This protects index 0, which contains the primary path.
        if self.paths.len() >= MAX_PATHS {
            self.paths.remove(1);
            debug_assert!(self.paths.len() < MAX_PATHS);
        }

        qdebug!([path.borrow()], "Make permanent");
        path.borrow_mut().make_permanent(local_cid, remote_cid);
        if self.primary.is_none() {
            self.primary = Some(Rc::clone(&path));
            path.borrow_mut().primary = true;
        }
        self.paths.push(path);
    }

    /// Set the identified path to be primary.
    /// This panics if `make_permanent` hasn't been called.
    pub fn migrate(&mut self, path: &PathRef, d: &Datagram) {
        // The update here needs to match the checks in `Path::received_on`.
        // Here, we update the remote port number to match the source port on the
        // datagram that was received.  This ensures that we send subsequent
        // packets back to the right place.
        path.borrow_mut().update_port(d.source().port());

        if path.borrow().is_primary() {
            return;
        }

        qinfo!([path.borrow()], "migrating to a new path");

        if let Some(old) = self.primary.replace(Rc::clone(path)) {
            // When migrating to a new path, send a probe on the old one first.
            old.borrow_mut().primary = false;
            old.borrow_mut().probe();
        }

        // Swap the primary path into slot 0, so that it is protected from eviction.
        let idx = self
            .paths
            .iter()
            .enumerate()
            .find_map(|(i, p)| if Rc::ptr_eq(p, path) { Some(i) } else { None })
            .expect("migrating to a temporary path");
        self.paths.swap(0, idx);

        path.borrow_mut().primary = true;
        path.borrow_mut().probe();
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
            p.borrow_mut().path_response(response, now);
        }
    }

    pub fn lost(&mut self, lost: [u8; 8]) {
        for p in &self.paths {
            p.borrow_mut().lost(lost);
        }
    }
}

/// The state of a path with respect to address validation.
#[derive(Debug)]
enum PathState {
    /// The path was validated at the indicated time.
    Valid,
    /// The path was previously valid, but a new probe is needed.
    ProbeNeeded { probe_count: usize },
    /// The path hasn't been validated, but a probe has been sent.
    Probing { probe_count: usize, data: [u8; 8] },
    /// Validation failed the last time it was attempted.
    Failed,
}

impl PathState {
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
    state: PathState,
    /// The last time the path was validated.
    last_valid: Option<Instant>,
    /// A path challenge was received and PATH_RESPONSE has not been sent.
    challenge: Option<[u8; 8]>,
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
            state: PathState::ProbeNeeded { probe_count: 0 },
            last_valid: None,
            challenge: None,
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
    fn received_on(&self, d: &Datagram) -> bool {
        self.local == d.destination() && self.remote.ip() == d.source().ip()
    }

    /// Update the remote port number.  Any flexibility we allow in `received_on`
    /// need to be adjusted at this point.
    fn update_port(&mut self, port: u16) {
        self.remote.set_port(port);
    }

    /// Set the current path as valid.  This updates the time that the path was
    /// last validated and cancels any path validation.
    pub fn set_valid(&mut self, now: Instant) {
        qdebug!([self], "Path validated");
        self.state = PathState::Valid;
        self.last_valid = Some(now);
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
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        self.last_valid.is_some()
    }

    /// Handle a `PATH_RESPONSE` frame.
    pub fn path_response(&mut self, response: [u8; 8], now: Instant) {
        if let PathState::Probing { data, .. } = &self.state {
            if response == *data {
                self.set_valid(now);
            }
        }
    }

    /// The path has been challenged.  This generates a response.
    /// This only generates a single response at a time.
    pub fn challenged(&mut self, challenge: [u8; 8], probe_back: bool) {
        self.challenge = Some(challenge.to_owned());
        if probe_back {
            self.probe();
        }
    }

    /// At the next opportunity, send a probe.
    /// Unless the probe count has been exhausted already.
    fn probe(&mut self) {
        let probe_count = match &self.state {
            PathState::Probing { probe_count, .. } => *probe_count + 1,
            PathState::ProbeNeeded { probe_count, .. } => *probe_count,
            _ => 0,
        };
        self.state = if probe_count >= MAX_PATH_PROBES {
            qinfo!([self], "Probing failed");
            PathState::Failed
        } else {
            qdebug!([self], "Initiating probe");
            PathState::ProbeNeeded { probe_count }
        };
    }

    /// Returns true if this path have any probing frames to send.
    pub fn has_probe(&self) -> bool {
        self.challenge.is_some() || self.state.probe_needed()
    }

    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        if builder.remaining() < 9 {
            return;
        }

        // Send PATH_RESPONSE.
        if let Some(challenge) = self.challenge.take() {
            qtrace!([self], "Responding to path challenge {}", hex(&challenge));
            builder.encode_varint(FRAME_TYPE_PATH_RESPONSE);
            builder.encode(&challenge[..]);
            stats.path_response += 1;
            stats.all += 1; // This doesn't add a token, so it needs to count all itself.

            if builder.remaining() < 9 {
                return;
            }
        }

        // Send PATH_CHALLENGE.
        if let PathState::ProbeNeeded { probe_count } = self.state {
            qtrace!([self], "Initiating path challenge {}", probe_count);
            let data = <[u8; 8]>::try_from(&random(8)[..]).unwrap();
            builder.encode_varint(FRAME_TYPE_PATH_CHALLENGE);
            builder.encode(&data);

            stats.path_challenge += 1;
            tokens.push(RecoveryToken::PathProbe(data));

            self.state = PathState::Probing { probe_count, data };
        }
    }

    pub fn lost(&mut self, lost: [u8; 8]) {
        if let PathState::Probing { data, .. } = &self.state {
            if lost == *data {
                self.probe();
            }
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
