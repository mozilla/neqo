// TODO: Rename to connect_udp_session.rs to be consistent with webtransport_session.rs?
use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

use neqo_transport::{Connection, StreamId};

use crate::{
    features::extended_connect::{
        ExtendedConnectEvents, ExtendedConnectType, SessionCloseReason, SessionState,
    },
    frames::{ConnectUdpFrame, FrameReader, StreamReaderRecvStreamWrapper},
    Error, RecvStream, Res,
};

#[derive(Debug)]
pub struct ConnectUdpSession {
    frame_reader: FrameReader,
    session_id: StreamId,
}

impl Display for ConnectUdpSession {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConnectUdpSession",)
    }
}

impl ConnectUdpSession {
    #[must_use]
    pub(crate) fn new(session_id: StreamId) -> Self {
        Self {
            session_id,
            frame_reader: FrameReader::new(),
        }
    }

    pub(crate) fn close_frame(&self, _error: u32, _message: &str) -> Option<Vec<u8>> {
        // TODO: WebTransport sends a message. needed here as well?
        None
    }

    // TODO: De-duplicate further with webtransport_session.rs?
    pub(crate) fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
    ) -> Res<Option<SessionState>> {
        let (f, fin) = self
            .frame_reader
            .receive::<ConnectUdpFrame>(&mut StreamReaderRecvStreamWrapper::new(
                conn,
                control_stream_recv,
            ))
            .map_err(|_| Error::HttpGeneralProtocolStream)?;

        match f {
            // TODO: Implement HTTP Datagram <https://github.com/mozilla/neqo/issues/2843>.
            None => {}
        }

        if fin {
            events.session_end(
                ExtendedConnectType::ConnectUdp,
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

    // TODO: Faking it to simplify implementation in connection.rs. Can we do better?
    pub fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        (HashSet::default(), HashSet::default())
    }
}
