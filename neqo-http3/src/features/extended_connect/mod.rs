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
pub use datagram_queue::DatagramOutcome;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::{cell::RefCell, fmt::Debug, mem, rc::Rc};

use neqo_common::{Bytes, Header, Role};
use neqo_transport::StreamId;

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

#[derive(Debug)]
pub(crate) struct ExtendedConnectFeature {
    feature_negotiation: NegotiationState,
    /// Negotiated WebTransport version; `None` for non-WebTransport features or before
    /// negotiation.
    version: Option<WebTransportVersion>,
}

impl ExtendedConnectFeature {
    #[must_use]
    pub fn new(connect_type: ExtendedConnectType, enable: bool) -> Self {
        Self {
            feature_negotiation: NegotiationState::new(enable, HSettingType::from(connect_type)),
            version: None,
        }
    }

    pub fn set_listener(&mut self, new_listener: Http3ClientEvents) {
        self.feature_negotiation.set_listener(new_listener);
    }

    pub fn handle_settings(&mut self, settings: &HSettings) {
        // WebTransport supports two draft versions; check draft-15 first, fall back to draft-07.
        if matches!(
            &self.feature_negotiation,
            NegotiationState::Negotiating {
                feature_type: HSettingType::EnableWebTransportDraft15,
                ..
            }
        ) {
            let draft15 = settings.get(HSettingType::EnableWebTransportDraft15) == 1;
            // draft-07's setting is SETTINGS_WEBTRANSPORT_MAX_SESSIONS, a count, not a
            // boolean: any value > 0 signals support.
            let draft07 = settings.get(HSettingType::EnableWebTransportDraft07) > 0;
            self.version = if draft15 {
                Some(WebTransportVersion::Draft15)
            } else if draft07 {
                Some(WebTransportVersion::Draft07)
            } else {
                None
            };
            // Report whichever draft setting actually enabled the feature, so
            // listeners inspecting the setting type see the real one negotiated.
            let negotiated_type = if draft15 {
                HSettingType::EnableWebTransportDraft15
            } else {
                HSettingType::EnableWebTransportDraft07
            };
            self.feature_negotiation
                .handle_settings_with_enabled(negotiated_type, draft15 || draft07);
        } else {
            self.feature_negotiation.handle_settings(settings);
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
    use super::{ExtendedConnectFeature, ExtendedConnectType, WebTransportVersion};
    use crate::settings::{HSetting, HSettingType, HSettings};

    fn negotiate(peer: &[(HSettingType, u64)]) -> ExtendedConnectFeature {
        let mut feature = ExtendedConnectFeature::new(ExtendedConnectType::WebTransport, true);
        let settings = HSettings::new(
            &peer
                .iter()
                .map(|&(t, v)| HSetting::new(t, v))
                .collect::<Vec<_>>(),
        );
        feature.handle_settings(&settings);
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
