// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::{self, Display, Formatter};

use neqo_common::{qtrace, Encoder};
use neqo_transport::{Connection, StreamId};

use crate::{
    features::extended_connect::{
        ExtendedConnectEvents, ExtendedConnectType, SessionCloseReason, SessionState,
    }, frames::{FrameReader, StreamReaderRecvStreamWrapper, WebTransportFrame}, Error, RecvStream, Res
};

#[derive(Debug)]
pub(crate) struct WebTransportSession {
    frame_reader: FrameReader,
    session_id: StreamId,
}

impl Display for WebTransportSession {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "WebTransportSession")
    }
}

impl WebTransportSession {
    #[must_use]
    pub(crate) fn new(session_id: StreamId) -> Self {
        Self {
            session_id,
            frame_reader: FrameReader::new(),
        }
    }

    pub(crate) fn close_frame(&self, error: u32, message: &str) -> Option<Vec<u8>> {
        let close_frame = WebTransportFrame::CloseSession {
            error,
            message: message.to_string(),
        };
        let mut encoder = Encoder::default();
        close_frame.encode(&mut encoder);
        Some(encoder.into())
    }

    pub(crate) fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
    ) -> Res<Option<SessionState>> {
        let (f, fin) = self
            .frame_reader
            .receive::<WebTransportFrame>(&mut StreamReaderRecvStreamWrapper::new(
                conn,
                control_stream_recv,
            ))
            .map_err(|_| Error::HttpGeneralProtocolStream)?;
        qtrace!("[{self}] Received frame: {f:?} fin={fin}");
        if let Some(WebTransportFrame::CloseSession { error, message }) = f {
            events.session_end(
                ExtendedConnectType::WebTransport,
                self.session_id,
                SessionCloseReason::Clean { error, message },
                None,
            );
            if fin {
                Ok(Some(SessionState::Done))
            } else {
                Ok(Some(SessionState::FinPending))
            }
        } else if fin {
            events.session_end(
                ExtendedConnectType::WebTransport,
                self.session_id,
                SessionCloseReason::Clean {
                    error: 0,
                    message: String::new(),
                },
                None,
            );
            Ok(Some(SessionState::Done))
        } else {
            Ok(None)
        }
    }
}
