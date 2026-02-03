# Neqo WebTransport Spec Compliance Implementation Plan

This document outlines the implementation plan for adding WebTransport spec features to neqo to support the Firefox DOM/necko WebTransport implementation.

## Overview

The following features need to be implemented in neqo:

1. **TLS Keying Material Export** - `exportKeyingMaterial()`
2. **Draining State Notification** - `draining` promise support
3. **Protocol Negotiation Attribute** - `protocol` attribute
4. **Send Groups** - `createSendGroup()` and stream association
5. **Session-Level Statistics** - `getStats()`

All phases are equal priority as they are part of the same WebTransport spec update.

---

## Phase 1: TLS Keying Material Export

### Goal
Enable applications to export keying material from the TLS connection for use in application-level security protocols (RFC 5705/8446).

### 1.1 Add SSL_ExportKeyingMaterial Binding

**File: `neqo-crypto/src/exp.rs`**

Add the NSS experimental API binding:
```rust
experimental_api!(SSL_ExportKeyingMaterial(
    fd: *mut PRFileDesc,
    label: *const c_char,
    label_len: c_uint,
    has_context: PRBool,
    context: *const u8,
    context_len: c_uint,
    out: *mut u8,
    out_len: c_uint,
));
```

### 1.2 Add Export Method to Agent

**File: `neqo-crypto/src/agent.rs`**

```rust
const DEFAULT_EXPORT_LENGTH: usize = 32;

impl SecretAgentInfo {
    /// Export keying material per RFC 5705/8446.
    ///
    /// # Arguments
    /// * `label` - The exporter label (e.g., "EXPORTER-WebTransport")
    /// * `context` - Optional context data
    /// * `out_len` - Length of output keying material (default 32 bytes)
    ///
    /// # Errors
    /// Returns error if handshake is not complete or export fails.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        out_len: usize,
    ) -> Res<Vec<u8>> {
        let mut out = vec![0u8; out_len];
        let (has_context, ctx_ptr, ctx_len) = match context {
            Some(ctx) => (ssl::PRBool::from(true), ctx.as_ptr(), ctx.len()),
            None => (ssl::PRBool::from(false), std::ptr::null(), 0),
        };

        unsafe {
            SSL_ExportKeyingMaterial(
                self.fd,
                label.as_ptr().cast(),
                c_uint::try_from(label.len())?,
                has_context,
                ctx_ptr,
                c_uint::try_from(ctx_len)?,
                out.as_mut_ptr(),
                c_uint::try_from(out_len)?,
            )?;
        }
        Ok(out)
    }
}
```

### 1.3 Expose via neqo-transport Connection

**File: `neqo-transport/src/connection/mod.rs`**

```rust
impl Connection {
    /// Export keying material from the TLS connection.
    ///
    /// # Errors
    /// Returns error if handshake is not complete.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        out_len: usize,
    ) -> Res<Vec<u8>> {
        if !matches!(self.state(), State::Connected | State::Confirmed) {
            return Err(Error::InvalidState);
        }
        self.crypto
            .tls
            .borrow()
            .info()
            .ok_or(Error::InvalidState)?
            .export_keying_material(label, context, out_len)
            .map_err(|_| Error::CryptoError)
    }
}
```

### 1.4 Expose via neqo-http3 Http3Client

**File: `neqo-http3/src/connection_client.rs`**

```rust
impl Http3Client {
    /// Export keying material for a WebTransport session.
    ///
    /// # Errors
    /// Returns error if session doesn't exist or connection not ready.
    pub fn webtransport_export_keying_material(
        &self,
        session_id: StreamId,
        label: &[u8],
        context: Option<&[u8]>,
        out_len: usize,
    ) -> Res<Vec<u8>> {
        // Verify session exists
        self.base_handler
            .webtransport_session_exists(session_id)?;
        self.conn.export_keying_material(label, context, out_len)
    }
}
```

### 1.5 FFI Bindings

**File: `netwerk/socket/neqo_glue/src/lib.rs`**

```rust
#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_export_keying_material(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    label: *const u8,
    label_len: u32,
    context: *const u8,
    context_len: u32,
    out: *mut u8,
    out_len: u32,
) -> nsresult {
    let label_slice = unsafe {
        std::slice::from_raw_parts(label, label_len as usize)
    };
    let context_opt = if context.is_null() || context_len == 0 {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(context, context_len as usize) })
    };

    match conn.conn.webtransport_export_keying_material(
        StreamId::from(session_id),
        label_slice,
        context_opt,
        out_len as usize,
    ) {
        Ok(material) => {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    material.as_ptr(),
                    out,
                    material.len(),
                );
            }
            NS_OK
        }
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}
```

### 1.6 Testing

**File: `neqo-crypto/tests/export.rs` (new)**

```rust
#[test]
fn test_export_keying_material_basic() {
    // Setup client/server handshake
    // After handshake complete:
    let material = client.export_keying_material(b"test-label", None, 32).unwrap();
    assert_eq!(material.len(), 32);
}

#[test]
fn test_export_keying_material_with_context() {
    let material = client.export_keying_material(
        b"test-label",
        Some(b"test-context"),
        32
    ).unwrap();
    assert_eq!(material.len(), 32);
}

#[test]
fn test_export_different_labels_differ() {
    let m1 = client.export_keying_material(b"label1", None, 32).unwrap();
    let m2 = client.export_keying_material(b"label2", None, 32).unwrap();
    assert_ne!(m1, m2);
}

#[test]
fn test_export_before_handshake_fails() {
    // Before handshake complete, should return error
}
```

**File: `neqo-http3/src/features/extended_connect/tests/webtransport/keying.rs` (new)**

---

## Phase 2: Draining State Notification

### Goal
Notify the application when a WebTransport session is draining (server sent GOAWAY or close is imminent).

### 2.1 Add Draining Event

**File: `neqo-http3/src/features/extended_connect/mod.rs`**

```rust
#[derive(Debug, PartialEq, Clone)]
pub enum WebTransportEvent {
    // Existing variants...

    /// Session is draining - no new streams should be created.
    /// The session will close after existing streams complete.
    Draining { session_id: StreamId },
}
```

### 2.2 Emit Draining Event on GOAWAY

**File: `neqo-http3/src/connection_client.rs`**

Modify `handle_goaway` to emit draining events for affected WebTransport sessions:

```rust
fn handle_goaway(&mut self, goaway_stream_id: StreamId) -> Res<()> {
    // Existing GOAWAY handling...

    // Emit draining events for WebTransport sessions
    for session_id in self.base_handler.webtransport_session_ids() {
        if session_id >= goaway_stream_id {
            self.events.webtransport_event(WebTransportEvent::Draining {
                session_id,
            });
        }
    }

    // Continue with existing logic...
}
```

### 2.3 Add Session Draining State

**File: `neqo-http3/src/features/extended_connect/webtransport_session.rs`**

```rust
impl Session {
    /// Mark session as draining
    pub fn set_draining(&mut self) {
        // Update internal state
    }

    /// Check if session is draining
    pub fn is_draining(&self) -> bool {
        // Return draining state
    }
}
```

### 2.4 FFI Event Handling

**File: `netwerk/socket/neqo_glue/src/lib.rs`**

Add draining event to the event enum and handling in `neqo_http3conn_event`.

### 2.5 Testing

**File: `neqo-http3/src/features/extended_connect/tests/webtransport/draining.rs` (new)**

```rust
#[test]
fn test_draining_event_on_goaway() {
    // Create session
    // Server sends GOAWAY
    // Verify Draining event is emitted
}

#[test]
fn test_no_new_streams_while_draining() {
    // Create session, trigger draining
    // Attempt to create stream should fail or be rejected
}
```

---

## Phase 3: Protocol Negotiation Attribute

### Goal
Expose the negotiated subprotocol from the WebTransport session establishment.

### 3.1 Store Protocol in Session

**File: `neqo-http3/src/features/extended_connect/webtransport_session.rs`**

```rust
#[derive(Debug)]
pub struct Session {
    // Existing fields...

    /// The negotiated protocol from server response headers
    negotiated_protocol: Option<String>,
}

impl Session {
    pub fn set_protocol(&mut self, protocol: Option<String>) {
        self.negotiated_protocol = protocol;
    }

    pub fn protocol(&self) -> Option<&str> {
        self.negotiated_protocol.as_deref()
    }
}
```

### 3.2 Extract Protocol from Response Headers

**File: `neqo-http3/src/features/extended_connect/session.rs`**

In `maybe_check_headers`, extract the `sec-webtransport-http3-draft` or protocol header:

```rust
fn extract_protocol_from_headers(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case("sec-webtransport-http3-draft"))
        .map(|h| String::from_utf8_lossy(h.value()).into_owned())
}
```

### 3.3 Add Accessor to Http3Client

**File: `neqo-http3/src/connection_client.rs`**

```rust
impl Http3Client {
    /// Get the negotiated protocol for a WebTransport session.
    ///
    /// Returns None if no protocol was negotiated or session doesn't exist.
    pub fn webtransport_session_protocol(&self, session_id: StreamId) -> Res<Option<String>> {
        self.base_handler.webtransport_session_protocol(session_id)
    }
}
```

### 3.4 FFI Bindings

```rust
#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_session_protocol(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    protocol: &mut nsACString,
) -> nsresult {
    match conn.conn.webtransport_session_protocol(StreamId::from(session_id)) {
        Ok(Some(p)) => {
            protocol.assign(&p);
            NS_OK
        }
        Ok(None) => {
            protocol.truncate();
            NS_OK
        }
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}
```

### 3.5 Testing

```rust
#[test]
fn test_protocol_empty_when_not_specified() {
    // Create session without protocols
    // Verify protocol() returns None or empty
}

#[test]
fn test_protocol_from_server_response() {
    // Create session with protocols
    // Server responds with selected protocol
    // Verify protocol() returns the selected one
}
```

---

## Phase 4: Send Groups

### Goal
Implement send groups for stream prioritization within a WebTransport session.

### 4.1 Define SendGroup Types

**File: `neqo-http3/src/features/extended_connect/send_group.rs` (new)**

```rust
use std::sync::atomic::{AtomicU64, Ordering};

use neqo_transport::StreamId;

static NEXT_SEND_GROUP_ID: AtomicU64 = AtomicU64::new(1);

/// Unique identifier for a send group within a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendGroupId(u64);

impl SendGroupId {
    pub fn new() -> Self {
        Self(NEXT_SEND_GROUP_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for SendGroupId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

/// A send group for organizing streams with shared prioritization
#[derive(Debug)]
pub struct SendGroup {
    id: SendGroupId,
    session_id: StreamId,
}

impl SendGroup {
    pub fn new(session_id: StreamId) -> Self {
        Self {
            id: SendGroupId::new(),
            session_id,
        }
    }

    pub fn id(&self) -> SendGroupId {
        self.id
    }

    pub fn session_id(&self) -> StreamId {
        self.session_id
    }
}
```

### 4.2 Add Send Group Management to Session

**File: `neqo-http3/src/features/extended_connect/webtransport_session.rs`**

```rust
use std::collections::HashMap;
use super::send_group::{SendGroup, SendGroupId};

impl Session {
    // Add field:
    // send_groups: HashMap<SendGroupId, SendGroup>,

    /// Create a new send group for this session
    pub fn create_send_group(&mut self) -> SendGroupId {
        let group = SendGroup::new(self.id);
        let id = group.id();
        self.send_groups.insert(id, group);
        id
    }

    /// Validate that a send group belongs to this session
    pub fn validate_send_group(&self, group_id: SendGroupId) -> bool {
        self.send_groups.contains_key(&group_id)
    }

    /// Get the session ID for a send group (for cross-session validation)
    pub fn send_group_session(&self, group_id: SendGroupId) -> Option<StreamId> {
        self.send_groups.get(&group_id).map(|g| g.session_id())
    }
}
```

### 4.3 Modify Stream Creation to Accept Send Group

**File: `neqo-http3/src/connection_client.rs`**

```rust
/// Options for creating a WebTransport stream
#[derive(Debug, Default)]
pub struct WebTransportStreamOptions {
    pub send_group: Option<SendGroupId>,
    pub send_order: Option<i64>,
}

impl Http3Client {
    /// Create a WebTransport stream with options
    pub fn webtransport_create_stream_with_options(
        &mut self,
        session_id: StreamId,
        stream_type: StreamType,
        options: WebTransportStreamOptions,
    ) -> Res<StreamId> {
        // Validate send_group if provided
        if let Some(group_id) = options.send_group {
            if !self.base_handler.validate_send_group(session_id, group_id)? {
                return Err(Error::InvalidState);
            }
        }

        let stream_id = self.webtransport_create_stream(session_id, stream_type)?;

        // Apply send order if specified
        if let Some(order) = options.send_order {
            self.webtransport_set_sendorder(stream_id, Some(order))?;
        }

        Ok(stream_id)
    }
}
```

### 4.4 FFI Bindings

```rust
#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_create_send_group(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    group_id: &mut u64,
) -> nsresult {
    match conn.conn.webtransport_create_send_group(StreamId::from(session_id)) {
        Ok(id) => {
            *group_id = id.as_u64();
            NS_OK
        }
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_create_stream_with_options(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    stream_type: WebTransportStreamType,
    send_group: u64,  // 0 = no group
    send_order: *const i64,  // null = no order
    stream_id: &mut u64,
) -> nsresult {
    let options = WebTransportStreamOptions {
        send_group: if send_group == 0 {
            None
        } else {
            Some(SendGroupId::from(send_group))
        },
        send_order: unsafe { send_order.as_ref().copied() },
    };

    match conn.conn.webtransport_create_stream_with_options(
        StreamId::from(session_id),
        stream_type.into(),
        options,
    ) {
        Ok(id) => {
            *stream_id = id.as_u64();
            NS_OK
        }
        Err(Http3Error::InvalidState) => NS_ERROR_DOM_INVALID_STATE_ERR,
        Err(Http3Error::StreamLimit) => NS_BASE_STREAM_WOULD_BLOCK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}
```

### 4.5 Testing

```rust
#[test]
fn test_create_send_group() {
    // Create session
    let group = wt.create_send_group(session_id).unwrap();
    assert!(group.as_u64() > 0);
}

#[test]
fn test_create_stream_with_send_group() {
    let group = wt.create_send_group(session_id).unwrap();
    let stream = wt.create_stream_with_options(session_id, StreamType::UniDi,
        WebTransportStreamOptions { send_group: Some(group), ..Default::default() }
    ).unwrap();
}

#[test]
fn test_cross_session_send_group_rejected() {
    // Create two sessions
    let group1 = wt.create_send_group(session1).unwrap();
    // Try to use group1 with session2 - should fail with InvalidState
    let result = wt.create_stream_with_options(session2, StreamType::UniDi,
        WebTransportStreamOptions { send_group: Some(group1), ..Default::default() }
    );
    assert!(matches!(result, Err(Error::InvalidState)));
}
```

---

## Phase 5: Session-Level Statistics

### Goal
Provide session-level statistics for WebTransport connections.

### 5.1 Define Session Stats Structure

**File: `neqo-http3/src/features/extended_connect/stats.rs` (new)**

```rust
use std::time::Instant;

/// Statistics for a WebTransport session
#[derive(Debug, Clone, Default)]
pub struct WebTransportSessionStats {
    /// When these stats were collected
    pub timestamp: Option<Instant>,
    /// Total bytes sent on this session (streams + datagrams)
    pub bytes_sent: u64,
    /// Total bytes received on this session
    pub bytes_received: u64,
    /// Number of datagrams sent
    pub datagrams_sent: u64,
    /// Number of datagrams received
    pub datagrams_received: u64,
    /// Number of streams opened locally
    pub streams_opened_local: u64,
    /// Number of streams opened by remote
    pub streams_opened_remote: u64,
}

impl WebTransportSessionStats {
    pub fn new() -> Self {
        Self {
            timestamp: Some(Instant::now()),
            ..Default::default()
        }
    }
}
```

### 5.2 Track Stats in Session

**File: `neqo-http3/src/features/extended_connect/webtransport_session.rs`**

```rust
impl Session {
    // Add field: stats: WebTransportSessionStats

    pub fn record_bytes_sent(&mut self, bytes: u64) {
        self.stats.bytes_sent += bytes;
    }

    pub fn record_bytes_received(&mut self, bytes: u64) {
        self.stats.bytes_received += bytes;
    }

    pub fn record_datagram_sent(&mut self) {
        self.stats.datagrams_sent += 1;
    }

    pub fn record_datagram_received(&mut self) {
        self.stats.datagrams_received += 1;
    }

    pub fn record_stream_opened(&mut self, local: bool) {
        if local {
            self.stats.streams_opened_local += 1;
        } else {
            self.stats.streams_opened_remote += 1;
        }
    }

    pub fn stats(&self) -> WebTransportSessionStats {
        let mut stats = self.stats.clone();
        stats.timestamp = Some(Instant::now());
        stats
    }
}
```

### 5.3 Integrate Stats Tracking

Update the following to call stats recording methods:
- `webtransport_send_datagram` - record datagram sent + bytes
- `webtransport_create_stream` - record stream opened
- Stream data send/receive - record bytes
- Datagram receive events - record datagram received

### 5.4 Add Accessor to Http3Client

**File: `neqo-http3/src/connection_client.rs`**

```rust
impl Http3Client {
    /// Get statistics for a WebTransport session
    pub fn webtransport_session_stats(
        &self,
        session_id: StreamId
    ) -> Res<WebTransportSessionStats> {
        self.base_handler.webtransport_session_stats(session_id)
    }
}
```

### 5.5 FFI Bindings

```rust
#[repr(C)]
pub struct WebTransportStats {
    pub timestamp_ms: u64,  // milliseconds since some epoch
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub streams_opened_local: u64,
    pub streams_opened_remote: u64,
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_session_stats(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    stats: &mut WebTransportStats,
) -> nsresult {
    match conn.conn.webtransport_session_stats(StreamId::from(session_id)) {
        Ok(s) => {
            stats.timestamp_ms = s.timestamp
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);
            stats.bytes_sent = s.bytes_sent;
            stats.bytes_received = s.bytes_received;
            stats.datagrams_sent = s.datagrams_sent;
            stats.datagrams_received = s.datagrams_received;
            stats.streams_opened_local = s.streams_opened_local;
            stats.streams_opened_remote = s.streams_opened_remote;
            NS_OK
        }
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}
```

### 5.6 Testing

```rust
#[test]
fn test_stats_initial_zero() {
    let stats = wt.session_stats(session_id).unwrap();
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
}

#[test]
fn test_stats_bytes_sent_increments() {
    wt.send_datagram(session_id, &[1, 2, 3, 4], 0).unwrap();
    exchange_packets(&mut client, &mut server);
    let stats = wt.session_stats(session_id).unwrap();
    assert!(stats.bytes_sent >= 4);
    assert_eq!(stats.datagrams_sent, 1);
}

#[test]
fn test_stats_streams_counted() {
    wt.create_stream(session_id, StreamType::UniDi).unwrap();
    let stats = wt.session_stats(session_id).unwrap();
    assert_eq!(stats.streams_opened_local, 1);
}
```

---

## Implementation Schedule

All phases can be implemented in parallel as they are independent:

```
Week 1-2:
├── Phase 1: TLS Keying Material Export (neqo-crypto focused)
├── Phase 2: Draining State (event system focused)
└── Phase 3: Protocol Attribute (header parsing focused)

Week 2-3:
├── Phase 4: Send Groups (builds on existing SendOrder)
└── Phase 5: Session Statistics (tracking focused)

Week 3-4:
├── Integration testing across all features
├── FFI bindings completion
└── Documentation
```

---

## File Summary

### New Files
- `neqo-crypto/tests/export.rs` - Keying material export tests
- `neqo-http3/src/features/extended_connect/send_group.rs` - Send group types
- `neqo-http3/src/features/extended_connect/stats.rs` - Session stats types
- `neqo-http3/src/features/extended_connect/tests/webtransport/keying.rs` - Keying tests
- `neqo-http3/src/features/extended_connect/tests/webtransport/draining.rs` - Draining tests

### Modified Files
- `neqo-crypto/src/exp.rs` - Add SSL_ExportKeyingMaterial binding
- `neqo-crypto/src/agent.rs` - Add export_keying_material method
- `neqo-transport/src/connection/mod.rs` - Expose keying material export
- `neqo-http3/src/connection_client.rs` - Add all new public APIs
- `neqo-http3/src/features/extended_connect/mod.rs` - Add Draining event, exports
- `neqo-http3/src/features/extended_connect/session.rs` - Protocol extraction
- `neqo-http3/src/features/extended_connect/webtransport_session.rs` - Stats, send groups, protocol
- `netwerk/socket/neqo_glue/src/lib.rs` - All FFI bindings
- `netwerk/socket/neqo_glue/NeqoHttp3Conn.h` - C++ header updates

---

## Testing Strategy

1. **Unit Tests**: Each phase includes unit tests in the relevant crate
2. **Integration Tests**: Use existing WebTransport test infrastructure in `neqo-http3/src/features/extended_connect/tests/webtransport/`
3. **Firefox Integration**: xpcshell tests in `dom/webtransport/test/xpcshell/test_new_features.js`

---

## Notes

- Default keying material export length: 32 bytes
- Send Groups build on existing SendOrder infrastructure in `neqo-transport/src/streams.rs`
- Existing WebTransport test server infrastructure can be extended for new features
- FFI stability is not a concern; API can be changed as needed
