// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is example code.")]

//! An HTTP 3 client implementation.

use std::{fmt::Display, net::SocketAddr, num::NonZeroUsize, time::Instant};

use neqo_common::{event::Provider, qwarn, Datagram, Tos};
use neqo_crypto::{AuthenticationStatus, ResumptionToken};
use neqo_http3::{ConnectUdpEvent, Http3Client, Http3ClientEvent, Http3State};
use neqo_transport::{AppError, CloseReason, DatagramTracking, OutputBatch, StreamId};
use url::Url;

use super::{Client, CloseState, Res};

pub struct Handler {}

impl Handler {
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

pub struct Proxy {
    client: Http3Client,
    handler: super::http3::Handler,
    proxy_conn: Http3Client,
    url: Url,
    stream_id: Option<StreamId>,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
}
impl Proxy {
    pub(crate) const fn new(
        client: Http3Client,
        handler: super::http3::Handler,
        proxy: Http3Client,
        url: Url,
    ) -> Self {
        Self {
            client,
            handler,
            proxy_conn: proxy,
            url,
            stream_id: None,
            local: None,
            remote: None,
        }
    }
}

impl Client for Proxy {
    fn process_multiple_output(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        let maybe_callback = loop {
            let Some(stream_id) = self.stream_id else {
                // If we don't have a stream ID, we can't send anything.
                break None;
            };
            match self.client.process_output(now) {
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

        let maybe_callback_2 = match self.proxy_conn.process_multiple_output(now, max_datagrams) {
            OutputBatch::None => None,
            o @ OutputBatch::DatagramBatch(_) => return o,
            OutputBatch::Callback(duration) => Some(duration),
        };

        match (maybe_callback, maybe_callback_2) {
            (None, None) => OutputBatch::None,
            (Some(duration), None) | (None, Some(duration)) => OutputBatch::Callback(duration),
            (Some(d1), Some(d2)) => {
                if d1 < d2 {
                    OutputBatch::Callback(d1)
                } else {
                    OutputBatch::Callback(d2)
                }
            }
        }
    }

    fn process_multiple_input<'a>(
        &mut self,
        dgrams: impl IntoIterator<Item = Datagram<&'a mut [u8]>>,
        now: Instant,
    ) {
        self.proxy_conn.process_multiple_input(dgrams, now);

        while let Some(event) = self.proxy_conn.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    self.proxy_conn
                        .authenticated(AuthenticationStatus::Ok, Instant::now());
                }
                Http3ClientEvent::HeaderReady { headers, .. } => {
                    panic!("{headers:?}");
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    panic!("{stream_id} is readable");
                }
                Http3ClientEvent::DataWritable { stream_id } => {
                    panic!("{stream_id} is writable");
                }
                Http3ClientEvent::RequestsCreatable => {}
                Http3ClientEvent::StateChange(Http3State::Connected) => {
                    assert!(self.proxy_conn.state().active());
                    self.proxy_conn
                        .connect_udp_create_session(Instant::now(), &self.url, &[])
                        .unwrap();
                }
                Http3ClientEvent::ZeroRttRejected => {
                    panic!("Zero RTT rejected");
                }
                Http3ClientEvent::ResumptionToken(_) => {}
                Http3ClientEvent::ConnectUdp(event) => match event {
                    ConnectUdpEvent::Negotiated(_) => todo!(),
                    ConnectUdpEvent::Session {
                        stream_id,
                        status: _,
                        headers: _,
                    } => {
                        self.stream_id = Some(stream_id);
                    }
                    ConnectUdpEvent::SessionClosed {
                        stream_id: _,
                        reason: _,
                        headers: _,
                    } => {
                    }
                    ConnectUdpEvent::Datagram {
                        session_id,
                        datagram,
                    } => {
                        assert_eq!(session_id, self.stream_id.unwrap());
                        let tos = Tos::default();
                        let datagram = Datagram::new(
                            *self.remote.as_ref().unwrap(),
                            *self.local.as_ref().unwrap(),
                            tos,
                            datagram,
                        );
                        self.client.process_input(datagram, now);
                    }
                },
                _ => {
                    qwarn!("Unhandled event {event:?}");
                }
            }
        }
    }

    fn close<S>(&mut self, now: Instant, app_error: AppError, msg: S)
    where
        S: AsRef<str> + Display,
    {
        self.client.close(now, app_error, msg.as_ref().to_string());
    }

    fn is_closed(&self) -> Result<CloseState, CloseReason> {
        match self.client.is_closed()? {
            CloseState::NotClosing => return Ok(CloseState::NotClosing),
            CloseState::Closing => return Ok(CloseState::Closing),
            CloseState::Closed => {}
        }

        match self.proxy_conn.is_closed()? {
            CloseState::NotClosing => Ok(CloseState::Closing),
            CloseState::Closing => Ok(CloseState::Closing),
            CloseState::Closed => Ok(CloseState::Closed),
        }
    }

    fn stats(&self) -> neqo_transport::Stats {
        // TODO: This is the inner conn.
        self.client.transport_stats()
    }

    fn has_events(&self) -> bool {
        Provider::has_events(&self.client)
    }
}

impl super::Handler for Handler {
    type Client = Proxy;

    fn handle(&mut self, client: &mut Proxy) -> Res<bool> {

        let done = client.handler.handle(&mut client.client)?;

        if matches!(client.client.is_closed()?, CloseState::Closed) {
            if let Some(stream_id) = client.stream_id.take() {
                client
                    .proxy_conn
                    .connect_udp_close_session(stream_id, 0, "kthxbye!")
                    .unwrap();
                client.proxy_conn.close(Instant::now(), 0, "kthxbye!");
            }

            return Ok(true);
        }

        if client.stream_id.is_none() {
            return Ok(false);
        }

        Ok(done)
    }

    fn take_token(&mut self) -> Option<ResumptionToken> {
        None
    }
}
