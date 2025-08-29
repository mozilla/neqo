// TODO: Rename to connect_udp_session.rs to be consistent with webtransport_session.rs?
use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

use neqo_common::{qdebug, Encoder};
use neqo_transport::{Connection, StreamId};

use crate::{
    features::extended_connect::{
        ExtendedConnectEvents, ExtendedConnectType, Protocol, SessionCloseReason, SessionState,
    },
    frames::{ConnectUdpFrame, FrameReader, StreamReaderRecvStreamWrapper},
    Error, RecvStream, Res,
};

#[derive(Debug)]
pub struct Session {
    frame_reader: FrameReader,
    session_id: StreamId,
}

impl Session {
    #[must_use]
    pub(crate) fn new(session_id: StreamId) -> Self {
        Self {
            session_id,
            frame_reader: FrameReader::new(),
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConnectUdpSession",)
    }
}

impl Protocol for Session {
    fn connect_type(&self) -> ExtendedConnectType {
        ExtendedConnectType::ConnectUdp
    }

    fn close_frame(&self, _error: u32, _message: &str) -> Option<Vec<u8>> {
        // ConnectUdp does not have a close frame.
        None
    }

    // TODO: De-duplicate further with webtransport_session.rs?
    fn read_control_stream(
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

    fn add_stream(
        &mut self,
        _stream_id: StreamId,
        _events: &mut Box<dyn ExtendedConnectEvents>,
    ) -> Res<()> {
        // ConnectUdp does not support adding streams.
        let msg = "ConnectUdp does not support adding streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
        Ok(())
    }

    fn remove_recv_stream(&mut self, _stream_id: StreamId) {
        // ConnectUdp does not support removing recv streams.
        let msg = "ConnectUdp does not support removing recv streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
    }

    fn remove_send_stream(&mut self, _stream_id: StreamId) {
        // ConnectUdp does not support removing send streams.
        let msg = "ConnectUdp does not support removing send streams";
        qdebug!("{msg}");
        debug_assert!(false, "{msg}");
    }

    // TODO: Faking it to simplify implementation in connection.rs. Can we do better?
    fn take_sub_streams(&mut self) -> (HashSet<StreamId>, HashSet<StreamId>) {
        (HashSet::default(), HashSet::default())
    }

    fn write_datagram_prefix(&self, encoder: &mut Encoder) {
        encoder.encode_varint(0u64);
    }

    fn read_datagram_prefix<'a>(&self, datagram: &'a [u8]) -> &'a [u8] {
        let Some((context_id, remainder)) = datagram.split_first() else {
            // TODO: Return error instead? Is datagram without context ID allowed?
            return datagram; // emtpy
        };

        debug_assert_eq!(*context_id, 0, "only supports context_id 0");

        remainder
    }
}
