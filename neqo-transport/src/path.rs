// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

use std::net::SocketAddr;

use crate::cid::{ConnectionId, ConnectionIdRef, RemoteConnectionIdEntry};

use neqo_common::Datagram;

/// This is the MTU that we assume when using IPv6.
/// We use this size for Initial packets, so we don't need to worry about probing for support.
/// If the path doesn't support this MTU, we will assume that it doesn't support QUIC.
///
/// This is a multiple of 16 greater than the largest possible short header (1 + 20 + 4).
pub const PATH_MTU_V6: usize = 1337;
/// The path MTU for IPv4 can be 20 bytes larger than for v6.
pub const PATH_MTU_V4: usize = PATH_MTU_V6 + 20;

#[derive(Debug, Default)]
pub struct Paths {
    paths: Vec<Path>,
}

impl Paths {
    pub fn new(p: Option<Path>) -> Self {
        Self {
            paths: p.into_iter().collect(),
        }
    }

    /// Get the primary path for sending.
    pub fn primary(&self) -> Option<&Path> {
        self.paths.get(0)
    }

    /// Get the primary path for sending.  Mutable version.
    pub fn primary_mut(&mut self) -> Option<&mut Path> {
        self.paths.get_mut(0)
    }

    /// Find the path that the provided `Datagram` was received on.
    pub fn received_on(&self, d: &Datagram) -> Option<&Path> {
        self.paths.iter().find(|p| p.received_on(d))
    }

    /// If there are no paths; this should only occur for a new server connection
    /// that hasn't handled a valid Initial packet yet.
    pub fn no_paths(&self) -> bool {
        self.paths.is_empty()
    }

    /// Add a path.
    pub fn add(&mut self, p: Path) {
        self.paths.push(p);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Path {
    /// A local socket address.
    local: SocketAddr,
    /// A remote socket address.
    remote: SocketAddr,
    /// The connection IDs that we use when sending on this path.
    /// This is only needed during the handshake.
    local_cid: Option<ConnectionId>,
    /// The current connection ID that we are using and its details.
    remote_cid: RemoteConnectionIdEntry,
    /// Whether the current path is considered valid.
    valid: bool,
}

impl Path {
    /// Create a path from addresses and a remote connection ID.
    /// This is used for migration.
    pub fn new(local: SocketAddr, remote: SocketAddr, remote_cid: RemoteConnectionIdEntry) -> Self {
        Self {
            local,
            remote,
            local_cid: None,
            remote_cid,
            valid: false,
        }
    }

    /// Create a path from addresses and local and remote connection IDs for use
    /// during the handshake.
    pub fn new_handshake(
        local: SocketAddr,
        remote: SocketAddr,
        local_cid: ConnectionId,
        remote_cid: RemoteConnectionIdEntry,
    ) -> Self {
        Self {
            local,
            remote,
            local_cid: Some(local_cid),
            remote_cid,
            valid: true,
        }
    }

    /// Determine if this path was the one that the provided datagram was received on.
    pub fn received_on(&self, d: &Datagram) -> bool {
        self.local == d.destination() && self.remote == d.source()
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
        self.remote_cid.update_cid(ConnectionId::from(cid));
    }

    /// Access the remote connection ID.
    pub fn remote_cid(&self) -> &ConnectionId {
        self.remote_cid.connection_id()
    }

    /// Set the stateless reset token for the connection ID that is currently in use.
    /// Panics if the sequence number is non-zero as this is only necessary during
    /// the handshake; all other connection IDs are initialized with a token.
    pub fn set_reset_token(&mut self, token: [u8; 16]) {
        self.remote_cid.set_stateless_reset_token(token);
    }

    /// Determine if the provided token is a stateless reset token.
    pub fn is_stateless_reset(&self, token: &[u8; 16]) -> bool {
        self.remote_cid.is_stateless_reset(token)
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

    // /// Whether the path is validated.
    // pub fn is_valid(&self) -> bool {
    //     self.valid
    // }

    // /// Set the path as validated.
    // pub fn validated(&mut self) {
    //     self.valid = true;
    // }
}
