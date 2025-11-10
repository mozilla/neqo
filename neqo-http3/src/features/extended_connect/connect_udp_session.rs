// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    time::Instant,
};

use neqo_common::{qdebug, qtrace, Bytes, Decoder, Encoder};
use neqo_transport::{Connection, StreamId};

use crate::{
    features::extended_connect::{
        session::{DgramContextIdError, State},
        CloseReason, ExtendedConnectEvents, ExtendedConnectType, Protocol,
    },
    frames::{capsule::Capsule, FrameReader, StreamReaderRecvStreamWrapper},
    Error, RecvStream, Res, SendStream,
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
        loop {
            let (capsule, fin) = self
                .frame_reader
                .receive::<Capsule>(
                    &mut StreamReaderRecvStreamWrapper::new(conn, control_stream_recv),
                    now,
                )
                .map_err(|_| Error::HttpGeneralProtocolStream)?;

            let capsule_is_some = capsule.is_some();

            match capsule {
                Some(Capsule::Datagram { payload }) => match self.dgram_context_id(payload) {
                    Ok(slice) => {
                        events.new_datagram(self.session_id, slice, self.connect_type());
                    }
                    Err(e) => {
                        qdebug!("[{self}]: received capsule with invalid context identifier: {e}");
                    }
                },
                None => {}
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
                return Ok(Some(State::Done));
            }

            if !capsule_is_some {
                return Ok(None);
            }
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

    fn write_datagram_capsule(
        &self,
        control_stream_send: &mut Box<dyn SendStream>,
        conn: &mut Connection,
        buf: &[u8],
        now: Instant,
    ) -> Res<()> {
        let mut dgram_data = Encoder::default();
        self.write_datagram_prefix(&mut dgram_data);
        dgram_data.encode(buf);

        if conn.stream_avail_send_space(self.session_id)? < dgram_data.len() {
            qdebug!("Not enough space to send datagram capsule, dropping it.");
            return Ok(());
        }
        // TODO: Make Capsule abstract over either an owned (Bytes) or borrowed (&[u8]) type
        // to avoid this allocation.
        let capsule = Capsule::Datagram {
            payload: Bytes::from(Vec::from(dgram_data)),
        };
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);
        control_stream_send.send_data_atomic(conn, enc.as_ref(), now)?;
        qtrace!("[{self}] sent datagram via HTTP DATAGRAM Capsule");
        Ok(())
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
