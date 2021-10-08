// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod session;

use crate::client_events::Http3ClientEvents;
use crate::features::NegotiationState;
use crate::settings::{HSettingType, HSettings};
use neqo_transport::{AppError, StreamId};
pub use session::ExtendedConnectSession;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::rc::Rc;

pub trait ExtendedConnectEvents: Debug {
    fn extended_connect_session_established(
        &self,
        connect_type: ExtendedConnectType,
        stream_id: StreamId,
    );
    fn extended_connect_session_closed(
        &self,
        connect_type: ExtendedConnectType,
        stream_id: StreamId,
        error: Option<AppError>,
    );
}

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
pub enum ExtendedConnectType {
    WebTransport,
}

impl ExtendedConnectType {
    pub fn string(&self) -> &str {
        "webtransport"
    }

    pub fn setting_type(&self) -> HSettingType {
        HSettingType::EnableWebTransport
    }
}

#[derive(Debug)]
pub struct ExtendedConnectFeature {
    connect_type: ExtendedConnectType,
    feature_negotiation: NegotiationState,
    sessions: HashMap<StreamId, Rc<RefCell<ExtendedConnectSession>>>,
}

impl ExtendedConnectFeature {
    pub fn new(connect_type: ExtendedConnectType, enable: bool) -> Self {
        Self {
            feature_negotiation: NegotiationState::new(enable, connect_type.setting_type()),
            connect_type,
            sessions: HashMap::new(),
        }
    }

    pub fn set_listener(&mut self, new_listener: Http3ClientEvents) {
        self.feature_negotiation.set_listener(new_listener);
    }

    pub fn insert(&mut self, stream_id: StreamId, session: Rc<RefCell<ExtendedConnectSession>>) {
        self.sessions.insert(stream_id, session);
    }

    pub fn handle_settings(&mut self, settings: &HSettings) {
        self.feature_negotiation.handle_settings(settings);
    }

    pub fn enabled(&self) -> bool {
        self.feature_negotiation.enabled()
    }
}
