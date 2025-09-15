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
    Extended(ExtendedConnectType),
}
