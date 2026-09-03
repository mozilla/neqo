// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub(crate) mod connect_udp_session;
pub(crate) mod datagram_queue;
pub mod send_group;
pub mod session;
pub mod stats;
pub(crate) mod webtransport_session;
pub(crate) mod webtransport_streams;

// Re-export DatagramOutcome for FFI access
pub use datagram_queue::{DatagramId, DatagramOutcome, DatagramQueueOutcome};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::{cell::RefCell, fmt::Debug, mem, rc::Rc};

use neqo_common::{Bytes, Header, Role, qdebug};
use neqo_transport::{StreamId, StreamType};

use crate::{
    Http3StreamInfo, HttpRecvStreamEvents, RecvStreamEvents, Res, SendStreamEvents,
    client_events::Http3ClientEvents,
    features::{
        NegotiationState, WebTransportVersion,
        extended_connect::session::{CloseReason, Protocol},
    },
    settings::{HSettingType, HSettings},
};

pub(crate) trait ExtendedConnectEvents: Debug {
    fn session_start(
        &self,
        connect_type: ExtendedConnectType,
        stream_id: StreamId,
        status: u16,
        headers: Vec<Header>,
    );
    fn session_end(
        &self,
        connect_type: ExtendedConnectType,
        stream_id: StreamId,
        reason: CloseReason,
        headers: Option<Vec<Header>>,
    );
    fn session_draining(&self, connect_type: ExtendedConnectType, stream_id: StreamId);
    /// The peer raised this session's stream limit, so a caller that was blocked
    /// on it (e.g. `waitUntilAvailable`) can retry.
    fn session_stream_creatable(&self, stream_type: StreamType);
    fn extended_connect_new_stream(
        &self,
        stream_info: Http3StreamInfo,
        emit_readable: bool,
    ) -> Res<()>;
    fn new_datagram(
        &self,
        session_id: StreamId,
        datagram: Bytes,
        connect_type: ExtendedConnectType,
    );
    fn datagram_outcome(
        &self,
        session_id: StreamId,
        outcome: DatagramOutcome,
        connect_type: ExtendedConnectType,
    );
}

#[derive(Debug, PartialEq, Copy, Clone, Eq, strum::Display)]
pub(crate) enum ExtendedConnectType {
    #[strum(to_string = "webtransport")]
    WebTransport,
    #[strum(to_string = "connect-udp")]
    ConnectUdp,
}

impl ExtendedConnectType {
    pub(crate) fn new_protocol(self, session_id: StreamId, role: Role) -> Box<dyn Protocol> {
        match self {
            Self::WebTransport => Box::new(webtransport_session::Session::new(session_id, role)),
            Self::ConnectUdp => Box::new(connect_udp_session::Session::new(session_id)),
        }
    }
}

impl From<ExtendedConnectType> for HSettingType {
    fn from(from: ExtendedConnectType) -> Self {
        match from {
            ExtendedConnectType::WebTransport => Self::EnableWebTransportDraft15,
            ExtendedConnectType::ConnectUdp => Self::EnableConnect,
        }
    }
}

pub(crate) struct TransportPrerequisites {
    datagrams: bool,
    reliable_reset: bool,
}

impl TransportPrerequisites {
    #[must_use]
    pub const fn new(datagrams: bool, reliable_reset: bool) -> Self {
        Self {
            datagrams,
            reliable_reset,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExtendedConnectFeature {
    feature_negotiation: NegotiationState,
    connect_type: ExtendedConnectType,
    role: Role,
    /// Negotiated WebTransport version; `None` for non-WebTransport features or before
    /// negotiation.
    version: Option<WebTransportVersion>,
}

impl ExtendedConnectFeature {
    #[must_use]
    pub fn new(connect_type: ExtendedConnectType, role: Role, enable: bool) -> Self {
        Self {
            feature_negotiation: NegotiationState::new(enable, HSettingType::from(connect_type)),
            connect_type,
            role,
            version: None,
        }
    }

    pub fn set_listener(&mut self, new_listener: Http3ClientEvents) {
        self.feature_negotiation.set_listener(new_listener);
    }

    /// `transport_prereqs` captures the state of transport-level features that might be needed.
    pub fn handle_settings(
        &mut self,
        settings: &HSettings,
        transport_prereqs: &TransportPrerequisites,
    ) {
        // reset_stream_at is also required (draft Section 4.4), but too few servers support it
        // yet, so we don't gate on it for now (falls back to RESET_STREAM). See #3917.
        let conditions_met = match self.connect_type {
            ExtendedConnectType::WebTransport => {
                // Two draft versions are accepted, preferring draft-15. draft-07's setting is
                // SETTINGS_WEBTRANSPORT_MAX_SESSIONS, a session count rather than a boolean,
                // so any value > 0 signals support.
                let draft15 = settings.get(HSettingType::EnableWebTransportDraft15) == 1;
                let draft07 = settings.get(HSettingType::EnableWebTransportDraft07) > 0;
                self.version = if draft15 {
                    Some(WebTransportVersion::Draft15)
                } else if draft07 {
                    Some(WebTransportVersion::Draft07)
                } else {
                    None
                };
                transport_prereqs.datagrams
                    && settings.get(HSettingType::EnableH3Datagram) == 1
                    && (self.role == Role::Server
                        || (settings.get(HSettingType::EnableConnect) == 1 && (draft15 || draft07)))
            }
            ExtendedConnectType::ConnectUdp => {
                self.role == Role::Server || settings.get(HSettingType::EnableConnect) == 1
            }
        };
        self.feature_negotiation.negotiate(conditions_met);
        if self.connect_type == ExtendedConnectType::WebTransport
            && self.enabled()
            && !transport_prereqs.reliable_reset
        {
            qdebug!(
                "WebTransport negotiated without peer reliable reset; stream resets use RESET_STREAM"
            );
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.feature_negotiation.enabled()
    }

    /// Returns the negotiated WebTransport version, or `None` if not yet negotiated
    /// or if this feature is not WebTransport.
    #[must_use]
    pub const fn version(&self) -> Option<WebTransportVersion> {
        self.version
    }
}

#[expect(
    clippy::struct_field_names,
    reason = "wrapper type, providing additional info"
)]
#[derive(Debug, Default)]
struct Headers {
    headers: Vec<Header>,
    interim: bool,
    fin: bool,
}

/// Implementation of [`HttpRecvStreamEvents`]. Registered with the underlying
/// [`RecvMessage`] stream. Listening for [`RecvMessage`] to read
/// incoming headers.
///
/// [`RecvMessage`]: crate::recv_message::RecvMessage
#[derive(Debug, Default)]
struct HeaderListener {
    headers: Option<Headers>,
}

impl HeaderListener {
    fn set_headers(&mut self, headers: Vec<Header>, interim: bool, fin: bool) {
        self.headers = Some(Headers {
            headers,
            interim,
            fin,
        });
    }

    pub fn get_headers(&mut self) -> Option<Headers> {
        mem::take(&mut self.headers)
    }
}

impl RecvStreamEvents for Rc<RefCell<HeaderListener>> {}

impl HttpRecvStreamEvents for Rc<RefCell<HeaderListener>> {
    fn header_ready(
        &self,
        _stream_info: &Http3StreamInfo,
        headers: Vec<Header>,
        interim: bool,
        fin: bool,
    ) {
        if !interim || fin {
            self.borrow_mut().set_headers(headers, interim, fin);
        }
    }
}

impl SendStreamEvents for Rc<RefCell<HeaderListener>> {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod version_tests {
    use neqo_common::Role;

    use super::{
        ExtendedConnectFeature, ExtendedConnectType, TransportPrerequisites, WebTransportVersion,
    };
    use crate::settings::{HSetting, HSettingType, HSettings};

    fn negotiate(peer: &[(HSettingType, u64)]) -> ExtendedConnectFeature {
        let mut feature =
            ExtendedConnectFeature::new(ExtendedConnectType::WebTransport, Role::Client, true);
        // Everything other than the WebTransport setting that a client needs from the server.
        let mut settings = vec![
            HSetting::new(HSettingType::EnableH3Datagram, 1),
            HSetting::new(HSettingType::EnableConnect, 1),
        ];
        settings.extend(peer.iter().map(|&(t, v)| HSetting::new(t, v)));
        feature.handle_settings(
            &HSettings::new(&settings),
            &TransportPrerequisites::new(true, true),
        );
        feature
    }

    #[test]
    fn draft15_peer_negotiates_draft15() {
        let feature = negotiate(&[(HSettingType::EnableWebTransportDraft15, 1)]);
        assert!(feature.enabled());
        assert_eq!(feature.version(), Some(WebTransportVersion::Draft15));
    }

    /// A peer that only speaks draft-07 advertises `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`,
    /// a session count rather than a boolean. Any non-zero value means it supports
    /// WebTransport, and we then have to use the draft-07 `:protocol` token.
    #[test]
    fn draft07_only_peer_negotiates_draft07() {
        let feature = negotiate(&[(HSettingType::EnableWebTransportDraft07, 5)]);
        assert!(feature.enabled());
        assert_eq!(feature.version(), Some(WebTransportVersion::Draft07));
    }

    #[test]
    fn draft15_wins_when_the_peer_advertises_both() {
        let feature = negotiate(&[
            (HSettingType::EnableWebTransportDraft07, 5),
            (HSettingType::EnableWebTransportDraft15, 1),
        ]);
        assert_eq!(feature.version(), Some(WebTransportVersion::Draft15));
    }

    /// The `:protocol` token sent on the CONNECT request is derived from the
    /// negotiated version, so the two must not drift apart.
    #[test]
    fn protocol_token_matches_the_negotiated_version() {
        for (version, expected) in [
            (Some(WebTransportVersion::Draft15), "webtransport-h3"),
            (Some(WebTransportVersion::Draft07), "webtransport"),
            (None, "webtransport-h3"),
        ] {
            assert_eq!(WebTransportVersion::protocol_token(version), expected);
        }
    }

    #[test]
    fn peer_without_webtransport_negotiates_nothing() {
        let feature = negotiate(&[(HSettingType::EnableWebTransportDraft07, 0)]);
        assert!(!feature.enabled());
        assert_eq!(feature.version(), None);
    }
}
