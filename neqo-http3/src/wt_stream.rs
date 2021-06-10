// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::wt::WebTransportSession;
use crate::{
    AppError, Http3StreamType, HttpRecvStream, HttpSendStream, ReceiveOutput, RecvStream, Res,
    ResetType, SendStream, WtEvents, WtRecvStream, WtSendStream,
};
use neqo_common::Encoder;
use neqo_transport::{Connection, StreamId};
use std::cell::RefCell;
use std::rc::Rc;

pub const WEBTRANSPORT_UNI_STREAM: u64 = 0x54;
pub const WEBTRANSPORT_STREAM: u64 = 0x41;

#[derive(Debug)]
pub struct WebTransportRecvStream {
    stream_id: u64,
    session: Rc<RefCell<WebTransportSession>>,
    events: Box<dyn WtEvents>,
    fin: bool,
}

impl WebTransportRecvStream {
    pub fn new(
        stream_id: u64,
        session: Rc<RefCell<WebTransportSession>>,
        events: Box<dyn WtEvents>,
    ) -> Self {
        Self {
            stream_id,
            session,
            events,
            fin: false,
        }
    }
}

impl RecvStream for WebTransportRecvStream {
    fn stream_reset(&mut self, error: AppError, reset_type: ResetType) -> Res<()> {
        if reset_type != ResetType::App {
            self.events
                .web_transport_stream_reset(self.stream_id, error);
        }
        self.session.borrow_mut().remove_stream(self.stream_id);
        Ok(())
    }

    fn receive(&mut self, _conn: &mut Connection) -> Res<ReceiveOutput> {
        self.events.web_transport_data_readable(self.stream_id);
        Ok(ReceiveOutput::NoOutput)
    }

    fn done(&self) -> bool {
        self.fin
    }

    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::WebTransportStream
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        None
    }

    fn wt_stream(&mut self) -> Option<&mut dyn WtRecvStream> {
        Some(self)
    }
}

impl WtRecvStream for WebTransportRecvStream {
    fn read_data(&mut self, conn: &mut Connection, buf: &mut [u8]) -> Res<(usize, bool)> {
        let (amount, fin) = conn.stream_recv(self.stream_id, buf)?;
        self.fin = fin;
        Ok((amount, fin))
    }
}

#[derive(Debug, PartialEq)]
enum WebTransportSenderStreamState {
    SendingInit { buf: Vec<u8>, fin: bool },
    SendingData,
    Done,
}

#[derive(Debug)]
pub struct WebTransportSendStream {
    stream_id: u64,
    state: WebTransportSenderStreamState,
    session: Rc<RefCell<WebTransportSession>>,
    events: Box<dyn WtEvents>,
}

impl WebTransportSendStream {
    pub fn new(
        stream_id: u64,
        session: Rc<RefCell<WebTransportSession>>,
        events: Box<dyn WtEvents>,
        local: bool,
    ) -> Self {
        Self {
            stream_id,
            state: if local {
                let mut d = Encoder::default();
                if StreamId::new(stream_id).is_uni() {
                    d.encode_varint(WEBTRANSPORT_UNI_STREAM);
                } else {
                    d.encode_varint(WEBTRANSPORT_STREAM);
                }
                d.encode_varint(session.borrow().stream_id());
                WebTransportSenderStreamState::SendingInit {
                    buf: d.into(),
                    fin: false,
                }
            } else {
                WebTransportSenderStreamState::SendingData
            },
            session,
            events,
        }
    }
}

impl SendStream for WebTransportSendStream {
    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        if let WebTransportSenderStreamState::SendingInit { ref mut buf, fin } = self.state {
            let sent = conn.stream_send(self.stream_id, &buf[..])?;
            if sent == buf.len() {
                if fin {
                    conn.stream_close_send(self.stream_id)?;
                    self.state = WebTransportSenderStreamState::Done;
                } else {
                    self.state = WebTransportSenderStreamState::SendingData;
                }
            } else {
                let b = buf.split_off(sent);
                *buf = b;
            }
        }
        Ok(())
    }

    fn has_data_to_send(&self) -> bool {
        matches!(
            self.state,
            WebTransportSenderStreamState::SendingInit { .. }
        )
    }

    fn stream_writable(&self) {
        self.events.web_transport_data_writable(self.stream_id);
    }

    fn done(&self) -> bool {
        self.state == WebTransportSenderStreamState::Done
    }

    fn stop_sending(&mut self, error: AppError) {
        self.events
            .web_transport_stream_stop_sending(self.stream_id, error);
        self.session.borrow_mut().remove_stream(self.stream_id);
        self.state = WebTransportSenderStreamState::Done;
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpSendStream> {
        None
    }

    fn get_wt_session(&self) -> Option<Rc<RefCell<WebTransportSession>>> {
        None
    }

    fn wt_stream(&mut self) -> Option<&mut dyn WtSendStream> {
        Some(self)
    }
}

impl WtSendStream for WebTransportSendStream {
    fn send_data(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        self.send(conn)?;
        if self.state == WebTransportSenderStreamState::SendingData {
            let sent = conn.stream_send(self.stream_id, &buf)?;
            Ok(sent)
        } else {
            Ok(0)
        }
    }

    fn close(&mut self, conn: &mut Connection) -> Res<()> {
        if let WebTransportSenderStreamState::SendingInit { ref mut fin, .. } = self.state {
            *fin = true;
        } else {
            self.state = WebTransportSenderStreamState::Done;
            conn.stream_close_send(self.stream_id)?;
        }
        Ok(())
    }
}
