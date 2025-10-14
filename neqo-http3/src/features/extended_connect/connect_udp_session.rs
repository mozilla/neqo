// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    time::Instant,
};

use neqo_common::{Bytes, Decoder, Encoder};
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
        now: Instant,
    ) -> Res<Option<State>> {
        let (f, fin) = self
            .frame_reader
            .receive::<ConnectUdpFrame>(
                &mut StreamReaderRecvStreamWrapper::new(conn, control_stream_recv),
                now,
            )
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

    fn dgram_context_id(&self, datagram: Bytes) -> Result<Bytes, DgramContextIdError> {
        let (context_id, offset) = {
            let mut decoder = Decoder::new(datagram.as_ref());
            (decoder.decode_varint(), decoder.offset())
        };
        match context_id {
            Some(0) => Ok(datagram.skip(offset)),
            Some(context_id) => Err(DgramContextIdError::UnknownIdentifier(context_id)),
            None => {
                // > all HTTP Datagrams associated with UDP Proxying request streams start with a Context ID field;
                //
                // <https://datatracker.ietf.org/doc/html/rfc9298#name-context-identifiers>
                Err(DgramContextIdError::MissingIdentifier)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use neqo_common::Bytes;
    use neqo_transport::StreamId;

    use super::Session;
    use crate::features::extended_connect::session::Protocol as _;

    #[test]
    fn varint_0_context_id() {
        let session = Session::new(StreamId::new(42));
        // Varint [0x00] is 0, i.e. a supported connect-udp context ID.
        assert_eq!(
            session
                .dgram_context_id(Bytes::from(vec![0x00, 0x00, 0x00]))
                .unwrap(),
            Bytes::from(vec![0x00, 0x00])
        );
        // Varint [0x40 0x00] is 0 as well, thus a supported connect-udp context ID, too.
        assert_eq!(
            session
                .dgram_context_id(Bytes::from(vec![0x40, 0x00, 0x00, 0x00]))
                .unwrap(),
            Bytes::from(vec![0x00, 0x00])
        );
    }
}
