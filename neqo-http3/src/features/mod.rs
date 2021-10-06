// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::settings::{HSettingType, HSettings};
use neqo_common::qtrace;
use std::fmt::Debug;
use std::mem;

pub trait NegotiationListener: Debug {
    fn negotiation_done(&self, feature_type: HSettingType, negotiated: bool);
}

#[derive(Debug)]
pub enum NegotiationState {
    Disabled,
    Negotiating {
        feature_type: HSettingType,
        listener: Option<Box<dyn NegotiationListener>>,
    },
    Negotiated,
    NegotiationFailed,
}

impl NegotiationState {
    #[must_use]
    pub fn new(
        enable: bool,
        feature_type: HSettingType,
        listener: Option<Box<dyn NegotiationListener>>,
    ) -> Self {
        if enable {
            Self::Negotiating {
                feature_type,
                listener,
            }
        } else {
            Self::Disabled
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
                "set_negotiated {:?} to {}",
                feature_type,
                settings.get(*feature_type)
            );
            let cb = mem::take(listener);
            let ft = *feature_type;
            *self = if settings.get(ft) == 1 {
                Self::Negotiated
            } else {
                Self::NegotiationFailed
            };
            if let Some(l) = cb {
                l.negotiation_done(ft, self.enabled());
            }
        }
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        matches!(self, &Self::Negotiated)
    }

    #[must_use]
    pub fn locally_enabled(&self) -> bool {
        !matches!(self, &Self::Disabled)
    }
}
