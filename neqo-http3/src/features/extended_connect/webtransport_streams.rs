// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::WebTransportSession;
use crate::{
    CloseType, Http3StreamInfo, Http3StreamType, ReceiveOutput, RecvStream, RecvStreamEvents, Res,
    SendStream, SendStreamEvents, SendStreamStats, Stream,
};
use neqo_common::Encoder;
use neqo_transport::{Connection, StreamId};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const WEBTRANSPORT_UNI_STREAM: u64 = 0x54;
pub const WEBTRANSPORT_STREAM: u64 = 0x41;

#[derive(Debug)]
pub(crate) struct WebTransportRecvStream {
    stream_id: StreamId,
    events: Box<dyn RecvStreamEvents>,
    session: Rc<RefCell<WebTransportSession>>,
    session_id: StreamId,
    fin: bool,
}

impl WebTransportRecvStream {
    pub fn new(
        stream_id: StreamId,
        session_id: StreamId,
        events: Box<dyn RecvStreamEvents>,
        session: Rc<RefCell<WebTransportSession>>,
    ) -> Self {
        Self {
            stream_id,
            events,
            session_id,
            session,
            fin: false,
        }
    }

    fn get_info(&self) -> Http3StreamInfo {
        Http3StreamInfo::new(self.stream_id, self.stream_type())
    }
}

impl Stream for WebTransportRecvStream {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::WebTransport(self.session_id)
    }
}

impl RecvStream for WebTransportRecvStream {
    fn receive(&mut self, _conn: &mut Connection) -> Res<(ReceiveOutput, bool)> {
        self.events.data_readable(self.get_info());
        Ok((ReceiveOutput::NoOutput, false))
    }

    fn reset(&mut self, close_type: CloseType) -> Res<()> {
        if !matches!(close_type, CloseType::ResetApp(_)) {
            self.events.recv_closed(self.get_info(), close_type);
        }
        self.session.borrow_mut().remove_recv_stream(self.stream_id);
        Ok(())
    }

    fn read_data(&mut self, conn: &mut Connection, buf: &mut [u8]) -> Res<(usize, bool)> {
        let (amount, fin) = conn.stream_recv(self.stream_id, buf)?;
        self.fin = fin;
        if fin {
            self.session.borrow_mut().remove_recv_stream(self.stream_id);
        }
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
pub(crate) struct WebTransportSendStream {
    stream_id: StreamId,
    state: WebTransportSenderStreamState,
    events: Box<dyn SendStreamEvents>,
    session: Rc<RefCell<WebTransportSession>>,
    session_id: StreamId,
    bytes_written: u64,
    bytes_sent: u64,
    bytes_non_app_data: u64,
}

impl WebTransportSendStream {
    pub fn new(
        stream_id: StreamId,
        session_id: StreamId,
        events: Box<dyn SendStreamEvents>,
        session: Rc<RefCell<WebTransportSession>>,
        local: bool,
    ) -> Self {
        Self {
            stream_id,
            state: if local {
                let mut d = Encoder::default();
                if stream_id.is_uni() {
                    d.encode_varint(WEBTRANSPORT_UNI_STREAM);
                } else {
                    d.encode_varint(WEBTRANSPORT_STREAM);
                }
                d.encode_varint(session_id.as_u64());
                WebTransportSenderStreamState::SendingInit {
                    buf: d.into(),
                    fin: false,
                }
            } else {
                WebTransportSenderStreamState::SendingData
            },
            events,
            session_id,
            session,
            bytes_written: 0,
            bytes_sent: 0,
            bytes_non_app_data: 0,
        }
    }

    fn set_done(&mut self, close_type: CloseType) {
        self.state = WebTransportSenderStreamState::Done;
        self.events.send_closed(self.get_info(), close_type);
        self.session.borrow_mut().remove_send_stream(self.stream_id);
    }

    fn get_info(&self) -> Http3StreamInfo {
        Http3StreamInfo::new(self.stream_id, self.stream_type())
    }
}

impl Stream for WebTransportSendStream {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::WebTransport(self.session_id)
    }
}

impl SendStream for WebTransportSendStream {
    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        if let WebTransportSenderStreamState::SendingInit { ref mut buf, fin } = self.state {
            let sent = conn.stream_send(self.stream_id, &buf[..])?;
            // We only want to count bytes when the state is SendingData.
            // However, the underlying connection is not aware of the state
            // here. That's why we need to count the bytes sent before
            // SendingData state.
            self.bytes_non_app_data += sent as u64;
            if sent == buf.len() {
                if fin {
                    conn.stream_close_send(self.stream_id)?;
                    self.set_done(CloseType::Done);
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
        self.events.data_writable(self.get_info());
    }

    fn done(&self) -> bool {
        self.state == WebTransportSenderStreamState::Done
    }

    fn send_data(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        self.send(conn)?;
        if self.state == WebTransportSenderStreamState::SendingData {
            self.bytes_written += buf.len() as u64;
            let sent = conn.stream_send(self.stream_id, buf)?;
            self.bytes_sent += sent as u64;
            Ok(sent)
        } else {
            Ok(0)
        }
    }

    fn handle_stop_sending(&mut self, close_type: CloseType) {
        self.set_done(close_type);
    }

    fn close(&mut self, conn: &mut Connection) -> Res<()> {
        if let WebTransportSenderStreamState::SendingInit { ref mut fin, .. } = self.state {
            *fin = true;
        } else {
            self.state = WebTransportSenderStreamState::Done;
            conn.stream_close_send(self.stream_id)?;
            self.set_done(CloseType::Done);
        }
        Ok(())
    }

    fn stats(&mut self, conn: &mut Connection) -> Res<SendStreamStats> {
        let mut acked = conn.stream_bytes_acked(self.stream_id)?;
        acked -= self.bytes_non_app_data;
        let stats = SendStreamStats::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("SystemTime before UNIX EPOCH!"),
            self.bytes_written,
            self.bytes_sent,
            acked,
        );
        Ok(stats)
    }
}
