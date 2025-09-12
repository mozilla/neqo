// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use neqo_common::{header::HeadersExt as _, Header};
use neqo_transport::{AppError, StreamId};

use crate::{
    connection::Http3State,
    features::extended_connect::{self, ExtendedConnectEvents, ExtendedConnectType},
    CloseType, Http3StreamInfo, HttpRecvStreamEvents, Priority, RecvStreamEvents, Res,
    SendStreamEvents,
};

/// Server events for a single connection.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Http3ServerConnEvent {
    /// Headers are ready.
    Headers {
        stream_info: Http3StreamInfo,
        headers: Vec<Header>,
        fin: bool,
    },
    PriorityUpdate {
        stream_id: StreamId,
        priority: Priority,
    },
    /// Request data is ready.
    DataReadable {
        stream_info: Http3StreamInfo,
    },
    DataWritable {
        stream_info: Http3StreamInfo,
    },
    StreamReset {
        stream_info: Http3StreamInfo,
        error: AppError,
    },
    StreamStopSending {
        stream_info: Http3StreamInfo,
        error: AppError,
    },
    /// Connection state change.
    StateChange(Http3State),
    WebTransport(WebTransportEvent),
    ConnectUdp(ConnectUdpEvent),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WebTransportEvent {
    Session {
        stream_id: StreamId,
        headers: Vec<Header>,
    },
    SessionClosed {
        stream_id: StreamId,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    },
    NewStream(Http3StreamInfo),
    Datagram {
        session_id: StreamId,
        datagram: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConnectUdpEvent {
    Session {
        stream_id: StreamId,
        headers: Vec<Header>,
    },
    SessionClosed {
        stream_id: StreamId,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    },
    Datagram {
        session_id: StreamId,
        datagram: Vec<u8>,
    },
}

#[derive(Debug, Default, Clone)]
pub struct Http3ServerConnEvents {
    events: Rc<RefCell<VecDeque<Http3ServerConnEvent>>>,
}

impl SendStreamEvents for Http3ServerConnEvents {
    fn send_closed(&self, stream_info: &Http3StreamInfo, close_type: CloseType) {
        if close_type != CloseType::Done {
            if let Some(error) = close_type.error() {
                self.insert(Http3ServerConnEvent::StreamStopSending {
                    stream_info: *stream_info,
                    error,
                });
            }
        }
    }

    fn data_writable(&self, stream_info: &Http3StreamInfo) {
        self.insert(Http3ServerConnEvent::DataWritable {
            stream_info: *stream_info,
        });
    }
}

impl RecvStreamEvents for Http3ServerConnEvents {
    /// Add a new `DataReadable` event
    fn data_readable(&self, stream_info: &Http3StreamInfo) {
        self.insert(Http3ServerConnEvent::DataReadable {
            stream_info: *stream_info,
        });
    }

    fn recv_closed(&self, stream_info: &Http3StreamInfo, close_type: CloseType) {
        if close_type != CloseType::Done {
            self.remove_events_for_stream_id(stream_info);
            if let Some(error) = close_type.error() {
                self.insert(Http3ServerConnEvent::StreamReset {
                    stream_info: *stream_info,
                    error,
                });
            }
        }
    }
}

impl HttpRecvStreamEvents for Http3ServerConnEvents {
    /// Add a new `HeaderReady` event.
    fn header_ready(
        &self,
        stream_info: &Http3StreamInfo,
        headers: Vec<Header>,
        _interim: bool,
        fin: bool,
    ) {
        self.insert(Http3ServerConnEvent::Headers {
            stream_info: *stream_info,
            headers,
            fin,
        });
    }

    fn extended_connect_new_session(&self, stream_id: StreamId, headers: Vec<Header>) {
        match headers.find_header(":protocol").map(Header::value) {
            Some("webtransport") => {
                self.insert(Http3ServerConnEvent::WebTransport(
                    WebTransportEvent::Session { stream_id, headers },
                ));
            }
            Some("connect-udp") => {
                self.insert(Http3ServerConnEvent::ConnectUdp(ConnectUdpEvent::Session {
                    stream_id,
                    headers,
                }));
            }
            Some(_) => {
                unimplemented!("Extended connect other than webtransport or connect-udp")
            }
            None => {
                unimplemented!("connect without :protocol header");
            }
        }
    }
}

impl ExtendedConnectEvents for Http3ServerConnEvents {
    fn session_start(
        &self,
        _connect_type: ExtendedConnectType,
        _stream_id: StreamId,
        _status: u16,
        _headers: Vec<Header>,
    ) {
    }

    fn session_end(
        &self,
        connect_type: ExtendedConnectType,
        stream_id: StreamId,
        reason: extended_connect::session::CloseReason,
        headers: Option<Vec<Header>>,
    ) {
        let event = match connect_type {
            ExtendedConnectType::WebTransport => {
                Http3ServerConnEvent::WebTransport(WebTransportEvent::SessionClosed {
                    stream_id,
                    reason,
                    headers,
                })
            }
            ExtendedConnectType::ConnectUdp => {
                Http3ServerConnEvent::ConnectUdp(ConnectUdpEvent::SessionClosed {
                    stream_id,
                    reason,
                    headers,
                })
            }
        };
        self.insert(event);
    }

    fn extended_connect_new_stream(
        &self,
        stream_info: Http3StreamInfo,
        emit_readable: bool,
    ) -> Res<()> {
        debug_assert!(!emit_readable, "only set by client");
        self.insert(Http3ServerConnEvent::WebTransport(
            WebTransportEvent::NewStream(stream_info),
        ));
        Ok(())
    }

    fn new_datagram(
        &self,
        session_id: StreamId,
        datagram: Vec<u8>,
        connect_type: ExtendedConnectType,
    ) {
        let event = match connect_type {
            ExtendedConnectType::WebTransport => {
                Http3ServerConnEvent::WebTransport(WebTransportEvent::Datagram {
                    session_id,
                    datagram,
                })
            }
            ExtendedConnectType::ConnectUdp => {
                Http3ServerConnEvent::ConnectUdp(ConnectUdpEvent::Datagram {
                    session_id,
                    datagram,
                })
            }
        };
        self.insert(event);
    }
}

impl Http3ServerConnEvents {
    fn insert(&self, event: Http3ServerConnEvent) {
        self.events.borrow_mut().push_back(event);
    }

    fn remove<F>(&self, f: F)
    where
        F: Fn(&Http3ServerConnEvent) -> bool,
    {
        self.events.borrow_mut().retain(|evt| !f(evt));
    }

    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }

    pub fn next_event(&self) -> Option<Http3ServerConnEvent> {
        self.events.borrow_mut().pop_front()
    }

    pub fn connection_state_change(&self, state: Http3State) {
        self.insert(Http3ServerConnEvent::StateChange(state));
    }

    pub fn priority_update(&self, stream_id: StreamId, priority: Priority) {
        self.insert(Http3ServerConnEvent::PriorityUpdate {
            stream_id,
            priority,
        });
    }

    fn remove_events_for_stream_id(&self, stream_info: &Http3StreamInfo) {
        self.remove(|evt| {
            matches!(evt,
                Http3ServerConnEvent::Headers { stream_info: x, .. } | Http3ServerConnEvent::DataReadable { stream_info: x, .. } if x == stream_info)
        });
    }
}
