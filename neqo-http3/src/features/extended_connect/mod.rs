// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub(crate) mod connect_udp_session;
pub mod session;
pub(crate) mod webtransport_session;
pub(crate) mod webtransport_streams;

#[cfg(test)]
mod tests;

use std::{cell::RefCell, fmt::Debug, mem, rc::Rc};

use neqo_common::{Header, Role};
use neqo_transport::StreamId;

use crate::{
    client_events::Http3ClientEvents,
    features::{
        extended_connect::session::{CloseReason, Protocol},
        NegotiationState,
    },
    settings::{HSettingType, HSettings},
    Http3StreamInfo, HttpRecvStreamEvents, RecvStreamEvents, Res, SendStreamEvents,
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
    fn extended_connect_new_stream(
        &self,
        stream_info: Http3StreamInfo,
        emit_readable: bool,
    ) -> Res<()>;
    fn new_datagram(
        &self,
        session_id: StreamId,
        datagram: Vec<u8>,
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
            ExtendedConnectType::WebTransport => Self::EnableWebTransport,
            ExtendedConnectType::ConnectUdp => Self::EnableConnect,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExtendedConnectFeature {
    feature_negotiation: NegotiationState,
}

impl ExtendedConnectFeature {
    #[must_use]
    pub fn new(connect_type: ExtendedConnectType, enable: bool) -> Self {
        Self {
            feature_negotiation: NegotiationState::new(enable, HSettingType::from(connect_type)),
        }
    }

    pub fn set_listener(&mut self, new_listener: Http3ClientEvents) {
        self.feature_negotiation.set_listener(new_listener);
    }

    pub fn handle_settings(&mut self, settings: &HSettings) {
        self.feature_negotiation.handle_settings(settings);
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.feature_negotiation.enabled()
    }
}

#[derive(Debug, Default)]
struct Listener {
    headers: Option<(Vec<Header>, bool, bool)>,
}

impl Listener {
    fn set_headers(&mut self, headers: Vec<Header>, interim: bool, fin: bool) {
        self.headers = Some((headers, interim, fin));
    }

    pub fn get_headers(&mut self) -> Option<(Vec<Header>, bool, bool)> {
        mem::take(&mut self.headers)
    }
}

impl RecvStreamEvents for Rc<RefCell<Listener>> {}

impl HttpRecvStreamEvents for Rc<RefCell<Listener>> {
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

impl SendStreamEvents for Rc<RefCell<Listener>> {}
