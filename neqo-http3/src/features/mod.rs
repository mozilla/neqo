// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{fmt::Debug, mem};

use neqo_common::qtrace;

use crate::{
    client_events::Http3ClientEvents,
    features::extended_connect::ExtendedConnectType,
    settings::{HSettingType, HSettings},
};

pub mod extended_connect;

/// The WebTransport protocol version negotiated with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebTransportVersion {
    /// draft-ietf-webtrans-http3-07 (`:protocol: webtransport`)
    Draft07,
    /// draft-ietf-webtrans-http3-15 (`:protocol: webtransport-h3`)
    Draft15,
}

/// States:
/// - `Disable` - it is not turned on for this connection.
/// - `Negotiating` - the feature is enabled locally, but settings from the peer have not been
///   received yet.
/// - `Negotiated` - the settings have been received and both sides support the feature.
/// - `NegotiationFailed` - the settings have been received and the peer does not support the
///   feature.
#[derive(Debug)]
pub enum NegotiationState {
    Disabled,
    Negotiating {
        feature_type: HSettingType,
        listener: Option<Http3ClientEvents>,
    },
    Negotiated,
    Failed,
}

impl NegotiationState {
    #[must_use]
    pub const fn new(enable: bool, feature_type: HSettingType) -> Self {
        if enable {
            Self::Negotiating {
                feature_type,
                listener: None,
            }
        } else {
            Self::Disabled
        }
    }

    pub fn set_listener(&mut self, new_listener: Http3ClientEvents) {
        if let Self::Negotiating { listener, .. } = self {
            *listener = Some(new_listener);
        }
    }

    pub fn handle_settings(&mut self, settings: &HSettings) {
        if !self.locally_enabled() {
            return;
        }

        if let Self::Negotiating {
            feature_type,
            listener,
        } = self
        {
            qtrace!(
                "set_negotiated {feature_type:?} to {}",
                settings.get(*feature_type)
            );
            let cb = mem::take(listener);
            let ft = *feature_type;
            *self = if settings.get(ft) == 1 {
                Self::Negotiated
            } else {
                Self::Failed
            };
            if let Some(l) = cb {
                l.negotiation_done(ft, self.enabled());
            }
        }
    }

    /// Transition using a pre-computed `enabled` value rather than querying settings.
    /// Used by `ExtendedConnectFeature` when checking multiple setting types (e.g. WebTransport).
    pub fn handle_settings_with_enabled(&mut self, feature_type: HSettingType, enabled: bool) {
        if !self.locally_enabled() {
            return;
        }
        if let Self::Negotiating { listener, .. } = self {
            let cb = mem::take(listener);
            *self = if enabled {
                Self::Negotiated
            } else {
                Self::Failed
            };
            if let Some(l) = cb {
                l.negotiation_done(feature_type, enabled);
            }
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        matches!(self, &Self::Negotiated)
    }

    #[must_use]
    pub const fn locally_enabled(&self) -> bool {
        !matches!(self, &Self::Disabled)
    }
}

/// The type of an HTTP CONNECT.
#[derive(Debug, PartialEq, Copy, Clone, Eq)]
pub(crate) enum ConnectType {
    /// Classic HTTP CONNECT see
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-the-connect-method>.
    Classic,
    /// Extended CONNECT see <https://www.rfc-editor.org/rfc/rfc9220>.
    /// The second field is the `:protocol` header value to send.
    Extended(ExtendedConnectType, &'static str),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::{features::NegotiationState, settings::HSettingType};

    #[test]
    fn negotiation_state_locally_enabled() {
        let disabled = NegotiationState::new(false, HSettingType::EnableWebTransportDraft15);
        assert!(!disabled.locally_enabled());

        let negotiating = NegotiationState::new(true, HSettingType::EnableWebTransportDraft15);
        assert!(negotiating.locally_enabled());

        assert!(NegotiationState::Negotiated.locally_enabled());
        assert!(NegotiationState::Failed.locally_enabled());
    }

    #[test]
    fn handle_settings_with_enabled_transitions() {
        // A disabled feature stays disabled regardless of the peer.
        let mut disabled = NegotiationState::new(false, HSettingType::EnableWebTransportDraft15);
        disabled.handle_settings_with_enabled(HSettingType::EnableWebTransportDraft15, true);
        assert!(!disabled.locally_enabled());
        assert!(!disabled.enabled());

        // Negotiating + peer enabled => Negotiated.
        let mut negotiated = NegotiationState::new(true, HSettingType::EnableWebTransportDraft15);
        negotiated.handle_settings_with_enabled(HSettingType::EnableWebTransportDraft15, true);
        assert!(negotiated.enabled());

        // Negotiating + peer not enabled => Failed.
        let mut failed = NegotiationState::new(true, HSettingType::EnableWebTransportDraft15);
        failed.handle_settings_with_enabled(HSettingType::EnableWebTransportDraft15, false);
        assert!(failed.locally_enabled());
        assert!(!failed.enabled());
    }
}
