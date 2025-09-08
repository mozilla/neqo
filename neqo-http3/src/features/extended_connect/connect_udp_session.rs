// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::{self, Display, Formatter};

use neqo_common::Encoder;
use neqo_transport::{Connection, StreamId};

use crate::{
    features::extended_connect::{
        session::{DgramContextIdError, State},
        CloseReason, ExtendedConnectEvents, ExtendedConnectType, Protocol,
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

    fn read_control_stream(
        &mut self,
        conn: &mut Connection,
        events: &mut Box<dyn ExtendedConnectEvents>,
        control_stream_recv: &mut Box<dyn RecvStream>,
    ) -> Res<Option<State>> {
        let (f, fin) = self
            .frame_reader
            .receive::<ConnectUdpFrame>(&mut StreamReaderRecvStreamWrapper::new(
                conn,
                control_stream_recv,
            ))
            .map_err(|_| Error::HttpGeneralProtocolStream)?;

        if let Some(f) = f {
            // TODO: Implement HTTP Datagram <https://github.com/mozilla/neqo/issues/2843>.
            match f {}
        }

        if fin {
            events.session_end(
                ExtendedConnectType::ConnectUdp,
                self.session_id,
                CloseReason::Clean {
                    error: 0,
                    message: String::new(),
                },
                None,
            );
            Ok(Some(State::Done))
        } else {
            Ok(None)
        }
    }

    fn write_datagram_prefix(&self, encoder: &mut Encoder) {
        encoder.encode_varint(0u64);
    }

    fn dgram_context_id<'a>(&self, datagram: &'a [u8]) -> Result<&'a [u8], DgramContextIdError> {
        match datagram.split_first() {
            Some((0, remainder)) => Ok(remainder),
            Some((context_id, _)) => Err(DgramContextIdError::UnknownIdentifier(*context_id)),
            None => {
                // > all HTTP Datagrams associated with UDP Proxying request streams start with a Context ID field;
                //
                // <https://datatracker.ietf.org/doc/html/rfc9298#name-context-identifiers>
                Err(DgramContextIdError::MissingIdentifier)
            }
        }
    }
}
