// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is example code.")]

//! An HTTP/3 MASQUE connect-udp proxy client.
//!
//! Wraps an [`Http3Client`] and [`super::http3::Handler`] and proxies their UDP
//! datagrams via an HTTP/3 MASQUE connect-udp proxy.

use std::{cmp::min, fmt::Display, net::SocketAddr, num::NonZeroUsize, time::Instant};

use neqo_common::{event::Provider, Datagram, Tos};
use neqo_crypto::{AuthenticationStatus, ResumptionToken};
use neqo_http3::{ConnectUdpEvent, Header, Http3Client, Http3ClientEvent, Http3State};
use neqo_transport::{AppError, CloseReason, DatagramTracking, OutputBatch, StreamId};
use url::Url;

use super::{Client, CloseState, Res};

pub struct Handler {}

impl Handler {
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

impl super::Handler for Handler {
    type Client = ProxiedHttp3;

    fn handle(&mut self, client: &mut ProxiedHttp3) -> Res<bool> {
        let done = client.handler.handle(&mut client.proxied_conn)?;

        if matches!(client.proxied_conn.is_closed()?, CloseState::Closed) {
            if let Some(stream_id) = client.session_id.take() {
                client
                    .proxy_conn
                    .connect_udp_close_session(stream_id, 0, "kthxbye!")?;
                client.proxy_conn.close(Instant::now(), 0, "kthxbye!");
            }

            return Ok(true);
        }

        if client.session_id.is_none() {
            return Ok(false);
        }

        Ok(done)
    }

    fn take_token(&mut self) -> Option<ResumptionToken> {
        None
    }
}

pub struct ProxiedHttp3 {
    proxied_conn: Http3Client,
    handler: super::http3::Handler,
    proxy_conn: Http3Client,
    url: Url,
    /// The MASQUE connect-udp session ID, i.e. the HTTP EXTENDED CONNECT stream ID.
    session_id: Option<StreamId>,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    headers: Vec<Header>,
}
impl ProxiedHttp3 {
    pub(crate) const fn new(
        proxied_conn: Http3Client,
        handler: super::http3::Handler,
        proxy: Http3Client,
        url: Url,
        headers: Vec<Header>,
    ) -> Self {
        Self {
            proxied_conn,
            handler,
            proxy_conn: proxy,
            url,
            session_id: None,
            local: None,
            remote: None,
            headers,
        }
    }
}

impl Client for ProxiedHttp3 {
    fn process_multiple_output(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        // First, if the proxy session is established already, service the proxied connection first.
        let maybe_proxied_conn_callback = loop {
            let Some(stream_id) = self.session_id else {
                // If we don't have a stream ID, the proxy session isn't
                // established yet, and we can't send anything.
                break None;
            };
            match self.proxied_conn.process_output(now) {
                neqo_http3::Output::None => break None,
                neqo_http3::Output::Callback(duration) => break Some(duration),
                neqo_http3::Output::Datagram(datagram) => {
                    self.local = Some(datagram.source());
                    self.remote = Some(datagram.destination());
                    self.proxy_conn
                        .connect_udp_send_datagram(
                            stream_id,
                            datagram.as_ref(),
                            DatagramTracking::None,
                        )
                        .unwrap();
                }
            }
        };

        // Second, service the proxy connection.
        let maybe_proxy_conn_callback =
            match self.proxy_conn.process_multiple_output(now, max_datagrams) {
                OutputBatch::None => None,
                o @ OutputBatch::DatagramBatch(_) => return o,
                OutputBatch::Callback(duration) => Some(duration),
            };

        // No datagram to send. Return the earlier callback, if any.
        match (maybe_proxied_conn_callback, maybe_proxy_conn_callback) {
            (None, None) => OutputBatch::None,
            (Some(duration), None) | (None, Some(duration)) => OutputBatch::Callback(duration),
            (Some(d1), Some(d2)) => OutputBatch::Callback(min(d1, d2)),
        }
    }

    fn process_multiple_input<'a>(
        &mut self,
        dgrams: impl IntoIterator<Item = Datagram<&'a mut [u8]>>,
        now: Instant,
    ) {
        // Process the input datagrams.
        self.proxy_conn.process_multiple_input(dgrams, now);

        // See whether as a result we have any datagrams for the proxied connection.
        while let Some(event) = self.proxy_conn.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    self.proxy_conn
                        .authenticated(AuthenticationStatus::Ok, Instant::now());
                }
                Http3ClientEvent::ConnectUdp(event) => match event {
                    ConnectUdpEvent::Negotiated(success) => {
                        assert!(success);
                        assert!(self.proxy_conn.state().active());
                        self.proxy_conn
                            .connect_udp_create_session(Instant::now(), &self.url, &self.headers)
                            .unwrap();
                    }
                    ConnectUdpEvent::NewSession { stream_id, .. } => {
                        self.session_id = Some(stream_id);
                    }
                    ConnectUdpEvent::Datagram {
                        session_id,
                        datagram,
                    } => {
                        assert_eq!(session_id, self.session_id.unwrap());
                        let tos = Tos::default();
                        let datagram = Datagram::new(
                            *self.remote.as_ref().unwrap(),
                            *self.local.as_ref().unwrap(),
                            tos,
                            datagram,
                        );
                        self.proxied_conn.process_input(datagram, now);
                    }
                    ConnectUdpEvent::SessionClosed { .. } => {}
                },
                Http3ClientEvent::RequestsCreatable
                | Http3ClientEvent::StateChange(Http3State::Connected)
                | Http3ClientEvent::ResumptionToken(_) => {}
                _ => {
                    panic!("Unhandled event {event:?}");
                }
            }
        }
    }

    fn close<S>(&mut self, now: Instant, app_error: AppError, msg: S)
    where
        S: AsRef<str> + Display,
    {
        self.proxied_conn
            .close(now, app_error, msg.as_ref().to_string());
    }

    fn is_closed(&self) -> Result<CloseState, CloseReason> {
        match self.proxied_conn.is_closed()? {
            CloseState::NotClosing => return Ok(CloseState::NotClosing),
            CloseState::Closing => return Ok(CloseState::Closing),
            CloseState::Closed => {}
        }

        match self.proxy_conn.is_closed()? {
            CloseState::Closed => Ok(CloseState::Closed),
            CloseState::NotClosing | CloseState::Closing => Ok(CloseState::Closing),
        }
    }

    fn stats(&self) -> neqo_transport::Stats {
        self.proxied_conn.transport_stats()
    }

    fn has_events(&self) -> bool {
        Provider::has_events(&self.proxied_conn)
    }
}
