// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An HTTP/3 MASQUE connect-udp proxy client.
//!
//! Wraps an [`Http3Client`] and [`super::http3::Handler`] and proxies their UDP
//! datagrams via an HTTP/3 MASQUE connect-udp proxy.

use std::{
    cell::RefCell, cmp::min, fmt::Display, net::SocketAddr, num::NonZeroUsize, rc::Rc,
    time::Instant,
};

use neqo_common::{event::Provider, Datagram, Tos};
use neqo_crypto::{AuthenticationStatus, ResumptionToken};
use neqo_http3::{
    ConnectUdpEvent, Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3State,
};
use neqo_transport::{
    AppError, CloseReason, ConnectionParameters, DatagramTracking, EmptyConnectionIdGenerator,
    OutputBatch, StreamId,
};
use url::Url;

use super::{Client, CloseState, Res};

#[derive(Default)]
pub struct Handler {}

impl super::Handler for Handler {
    type Client = ProxiedHttp3;

    fn handle(&mut self, client: &mut ProxiedHttp3) -> Res<bool> {
        let done = client.handler.handle(&mut client.inner_conn)?;

        if matches!(client.inner_conn.is_closed()?, CloseState::Closed) {
            if let Some(stream_id) = client.session_id.take() {
                client
                    .outer_conn
                    .connect_udp_close_session(stream_id, 0, "kthxbye!")?;
                client.outer_conn.close(Instant::now(), 0, "kthxbye!");
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
    /// HTTP/3 connection to the origin, proxied through
    /// [`ProxiedHttp3::proxy_conn`].
    inner_conn: Http3Client,
    handler: super::http3::Handler,
    /// HTTP/3 connection to the proxy server, providing a MASQUE connect-udp
    /// session.
    outer_conn: Http3Client,
    url: Url,
    /// The MASQUE connect-udp session ID, i.e., the HTTP EXTENDED CONNECT stream ID.
    session_id: Option<StreamId>,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    headers: Vec<Header>,
}

impl ProxiedHttp3 {
    pub(crate) fn new(
        proxied_conn: Http3Client,
        handler: super::http3::Handler,
        url: Url,
        headers: Vec<Header>,
        hostname: &str,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Res<Self> {
        let proxy_conn = Http3Client::new(
            hostname,
            Rc::new(RefCell::new(EmptyConnectionIdGenerator::default())),
            local_addr,
            remote_addr,
            Http3Parameters::default()
                .connection_parameters(
                    ConnectionParameters::default()
                        .datagram_size(1500)
                        .pmtud(true),
                )
                .connect(true)
                .http3_datagram(true),
            Instant::now(),
        )?;
        Ok(Self {
            inner_conn: proxied_conn,
            handler,
            outer_conn: proxy_conn,
            url,
            session_id: None,
            local: None,
            remote: None,
            headers,
        })
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
            match self.inner_conn.process_output(now) {
                neqo_http3::Output::None => break None,
                neqo_http3::Output::Callback(duration) => break Some(duration),
                neqo_http3::Output::Datagram(datagram) => {
                    self.local = Some(datagram.source());
                    self.remote = Some(datagram.destination());
                    self.outer_conn
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
            match self.outer_conn.process_multiple_output(now, max_datagrams) {
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
        self.outer_conn.process_multiple_input(dgrams, now);

        // See whether as a result we have any datagrams for the proxied connection.
        while let Some(event) = self.outer_conn.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    self.outer_conn
                        .authenticated(AuthenticationStatus::Ok, Instant::now());
                }
                Http3ClientEvent::ConnectUdp(event) => match event {
                    ConnectUdpEvent::Negotiated(success) => {
                        assert!(success);
                        assert!(self.outer_conn.state().active());
                        self.outer_conn
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
                        self.inner_conn.process_input(datagram, now);
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
        self.inner_conn
            .close(now, app_error, msg.as_ref().to_string());
    }

    fn is_closed(&self) -> Result<CloseState, CloseReason> {
        match self.inner_conn.is_closed()? {
            CloseState::NotClosing => return Ok(CloseState::NotClosing),
            CloseState::Closing => return Ok(CloseState::Closing),
            CloseState::Closed => {}
        }

        match self.outer_conn.is_closed()? {
            CloseState::Closed => Ok(CloseState::Closed),
            CloseState::NotClosing | CloseState::Closing => Ok(CloseState::Closing),
        }
    }

    fn stats(&self) -> neqo_transport::Stats {
        self.inner_conn.transport_stats()
    }

    fn has_events(&self) -> bool {
        Provider::has_events(&self.inner_conn)
    }
}
