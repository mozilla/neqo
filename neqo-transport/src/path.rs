// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::ops::{Index, IndexMut};
use std::time::Instant;

use crate::cid::{ConnectionId, ConnectionIdRef, RemoteConnectionIdEntry};
use crate::frame::{FRAME_TYPE_PATH_CHALLENGE, FRAME_TYPE_PATH_RESPONSE};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::stats::FrameStats;
use crate::{Error, Res};

use neqo_common::{qdebug, Datagram};
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PathId {
    Primary,
    Temporary,
    Id(u32),
}

/// A collection for network paths.
/// This holds a collection of paths that have been used for sending or
/// receiving, plus an additional "temporary" path that is held only while
/// processing a packet.
/// This structure limits its storage and will forget about paths if it
/// is exposed to too many paths.
#[derive(Debug, Default)]
pub struct Paths {
    paths: Vec<Path>,
    temp: Option<Path>,
    next_id: u32,
}

impl Paths {
    /// Make a temporary path.
    pub fn make_temporary(&mut self, local: SocketAddr, remote: SocketAddr) -> Res<PathId> {
        debug_assert!(self.temp.is_none());
        let path = Path::temporary(self.next_id, local, remote);
        let id = path.id();
        self.temp = Some(path);
        self.next_id = self.next_id.checked_add(1).ok_or(Error::IntegerOverflow)?;
        Ok(id)
    }

    /// Find the path that the provided `Datagram` was received on.
    pub fn path_or_temporary(&mut self, d: &Datagram) -> Res<PathId> {
        self.paths
            .iter()
            .find_map(|p| {
                if p.received_on(d) {
                    Some(Ok(p.id()))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| self.make_temporary(d.destination(), d.source()))
    }

    /// Does this path ID refer to the current temporary path.
    pub fn is_temporary(&self, path: PathId) -> bool {
        path == PathId::Temporary || self.temp.as_ref().map_or(false, |p| p.id() == path)
    }

    /// Discard the temporary path.
    pub fn discard_temporary(&mut self) {
        self.temp = None;
    }

    /// Make the temporary path permanent.
    /// This returns the canonical ID that is assigned to the path.
    #[must_use]
    pub fn ensure_permanent(
        &mut self,
        path: PathId,
        local_cid: Option<ConnectionId>,
        remote_cid: RemoteConnectionIdEntry,
    ) -> PathId {
        if !self.is_temporary(path) {
            // This does not refer to the current temporary path.
            return path;
        }

        // Make sure not to track too many paths.
        if self.paths.len() >= MAX_PATHS {
            self.paths.remove(1);
            debug_assert!(self.paths.len() < MAX_PATHS);
        }

        let mut path = self.temp.take().unwrap();
        let id = path.id();
        qdebug!([path], "Make permanent");
        path.make_permanent(local_cid, remote_cid);
        self.paths.push(path);
        id
    }

    /// Set the identified path to be primary.
    pub fn migrate(&mut self, idx: PathId, d: &Datagram) {
        match idx {
            PathId::Primary => (),
            PathId::Temporary => panic!("a temporary path can't be made primary"),
            PathId::Id(id) => {
                let index_of = self
                    .paths
                    .iter()
                    .enumerate()
                    .find_map(|(i, p)| if p.id == id { Some(i) } else { None })
                    .unwrap();
                self.paths.swap(0, index_of);
            }
        }
        // The updates here need to match the checks in `Path::received_on`.
        // Here, we update the remote port number to ensure that we send
        // packets back to the right place.
        self.paths[0].update_port(d.source().port());
    }

    pub fn get(&self, idx: PathId) -> Option<&Path> {
        match idx {
            PathId::Temporary => self.temp.as_ref(),
            PathId::Primary => self.paths.get(0),
            PathId::Id(id) => self
                .temp
                .as_ref()
                .into_iter()
                .chain(&self.paths)
                .find(|p| p.id == id),
        }
    }

    pub fn get_mut(&mut self, idx: PathId) -> Option<&mut Path> {
        match idx {
            PathId::Temporary => self.temp.as_mut(),
            PathId::Primary => self.paths.get_mut(0),
            PathId::Id(id) => self
                .temp
                .as_mut()
                .into_iter()
                .chain(&mut self.paths)
                .find(|p| p.id == id),
        }
    }

    /// Determine whether any non-primary path has a probe to send.
    pub fn has_probes(&self) -> Option<PathId> {
        self.paths
            .iter()
            .skip(1)
            .find_map(|p| if p.has_probe() { Some(p.id()) } else { None })
    }

    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        for p in &mut self.paths {
            p.write_frames(builder, tokens, stats);
        }
    }

    pub fn path_response(&mut self, response: &[u8; 8], now: Instant) {
        for p in &mut self.paths {
            p.path_response(response, now);
        }
    }

    pub fn lost(&mut self, lost: &[u8; 8]) {
        for p in &mut self.paths {
            p.lost(lost);
        }
    }
}

impl Index<PathId> for Paths {
    type Output = Path;
    fn index(&self, idx: PathId) -> &Path {
        self.get(idx).unwrap()
    }
}

impl IndexMut<PathId> for Paths {
    fn index_mut(&mut self, idx: PathId) -> &mut Path {
        self.get_mut(idx).unwrap()
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
        matches!(self, PathState::ProbeNeeded { .. })
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
    /// A stable identifier for the path.
    id: u32,

    /// A local socket address.
    local: SocketAddr,
    /// A remote socket address.
    remote: SocketAddr,
    /// The connection IDs that we use when sending on this path.
    /// This is only needed during the handshake.
    local_cid: Option<ConnectionId>,
    /// The current connection ID that we are using and its details.
    remote_cid: Option<RemoteConnectionIdEntry>,

    /// Whether the current path is considered valid.
    state: PathState,
    /// The last time the path was validated.
    last_valid: Option<Instant>,
    /// A path challenge was received and is not yet sent.
    challenge: Option<[u8; 8]>,
}

impl Path {
    /// Create a path from addresses and a remote connection ID.
    /// This is used for migration.
    fn temporary(id: u32, local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            id,
            local,
            remote,
            local_cid: None,
            remote_cid: None,
            state: PathState::ProbeNeeded { probe_count: 0 },
            last_valid: None,
            challenge: None,
        }
    }

    /// Get the canonical path ID for this path.
    pub fn id(&self) -> PathId {
        PathId::Id(self.id)
    }

    /// The first path is the one used for the handshake and it's special.
    pub fn is_handshake(&self) -> bool {
        self.id == 0
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
    pub fn path_response(&mut self, response: &[u8; 8], now: Instant) {
        if let PathState::Probing { data, .. } = &self.state {
            if response == data {
                self.set_valid(now);
            }
        }
    }

    /// The path has been challenged.  This generates a response.
    /// This only generates a single response at a time.
    pub fn challenged(&mut self, challenge: [u8; 8]) {
        self.challenge = Some(challenge.to_owned())
    }

    /// At the next opportunity, send a probe.
    /// Unless the probe count has been exhausted already.
    pub fn probe(&mut self) {
        let probe_count = match &self.state {
            PathState::Probing { probe_count, .. } => *probe_count + 1,
            PathState::ProbeNeeded { probe_count, .. } => *probe_count,
            _ => 0,
        };
        self.state = if probe_count >= MAX_PATH_PROBES {
            PathState::Failed
        } else {
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
            let data = <[u8; 8]>::try_from(&random(8)[..]).unwrap();
            builder.encode_varint(FRAME_TYPE_PATH_CHALLENGE);
            builder.encode(&data);

            stats.path_challenge += 1;
            tokens.push(RecoveryToken::PathProbe(data.clone()));

            self.state = PathState::Probing { probe_count, data };
        }
    }

    pub fn lost(&mut self, lost: &[u8; 8]) {
        if let PathState::Probing { data, .. } = &self.state {
            if data == lost {
                self.probe();
            }
        }
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "path{} {}->{} {:?}",
            self.id,
            self.local,
            self.remote,
            self.remote_cid.as_ref().map(|r| r.connection_id())
        )
    }
}
