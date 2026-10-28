// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    num::NonZeroUsize,
    time::Instant,
};

use neqo_common::{Bytes, Decoder, Encoder};
use neqo_transport::{Connection, StreamId};
use tracing::{debug, trace};

use crate::{
    Error, RecvStream, Res, SendStream,
    features::extended_connect::{
        CloseReason, ExtendedConnectEvents, ExtendedConnectType, Protocol,
        session::{DgramContextIdError, State},
    },
    frames::{FrameReader, StreamReaderRecvStreamWrapper, capsule::Capsule},
    send_message::SendMessage,
};

/// The only context ID RFC 9298 defines: the payload is a UDP packet.
const CONTEXT_ID: u64 = 0;

/// Datagram bytes one control stream read may queue as events (RFC 9298 Section 5).
const MAX_DATAGRAM_BYTES_PER_READ: usize = 256 * 1024;

/// Per-event bookkeeping charge, as `PER_DATAGRAM_OVERHEAD` in neqo-transport's datagram queue.
const PER_DATAGRAM_OVERHEAD: usize = 64;

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
        write!(f, "ConnectUdpSession")
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
        let mut budget = MAX_DATAGRAM_BYTES_PER_READ;
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
                        let cost = slice.len().saturating_add(PER_DATAGRAM_OVERHEAD);
                        if let Some(rest) = budget.checked_sub(cost) {
                            budget = rest;
                            events.new_datagram(self.session_id, slice, self.connect_type());
                        } else {
                            // RFC 9221 Section 5.3 lets the receiver drop datagrams.
                            debug!("[{self}]: dropped datagram over the per-read budget");
                        }
                    }
                    Err(e) => {
                        debug!("[{self}]: received capsule with invalid context identifier: {e}");
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

    fn datagram_prefix(&self) -> Option<u64> {
        Some(CONTEXT_ID)
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

    fn datagram_capsule_support(&self) -> bool {
        true
    }

    fn write_datagram_capsule(
        &self,
        control_stream_send: &mut Box<dyn SendStream>,
        conn: &mut Connection,
        buf: &[u8],
        now: Instant,
    ) -> Res<()> {
        let mut dgram_data = Encoder::with_capacity(Encoder::varint_len(CONTEXT_ID) + buf.len());
        dgram_data.encode_varint(CONTEXT_ID);
        dgram_data.encode(buf);
        // TODO: Make Capsule abstract over either an owned (Bytes) or borrowed (&[u8]) type
        // to avoid this allocation.
        let capsule = Capsule::Datagram {
            payload: Bytes::from(Vec::from(dgram_data)),
        };

        // The capsule goes on the control stream wrapped in an HTTP/3 DATA frame, so the
        // flow-control window has to hold both wrappers, not just the payload.
        let needed = SendMessage::data_frame_len(capsule.encoded_len());
        if conn.stream_avail_send_space(self.session_id)? < needed {
            debug!("[{self}] datagram capsule exceeds control-stream flow-control space");
            // Ask to be told when the stream can hold a capsule this size again.
            // Repeated refusals overwrite this, so the event tracks the most recent
            // size rather than the largest; the sender retries and re-arms.
            if let Some(watermark) = NonZeroUsize::new(needed) {
                conn.stream_set_writable_event_low_watermark(self.session_id, watermark)?;
            }
            return Err(Error::FlowControlLimit);
        }
        let mut enc = Encoder::default();
        capsule.encode(&mut enc);
        control_stream_send.send_data_atomic(conn, enc.as_ref(), now)?;
        // Drop the watermark a previous refusal raised, so neqo-transport stops
        // suppressing writable events for other users of the control stream.
        conn.stream_set_writable_event_low_watermark(self.session_id, NonZeroUsize::MIN)?;
        trace!("[{self}] sent datagram via HTTP DATAGRAM Capsule");
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::iter;

    use neqo_common::{Bytes, Datagram, event::Provider as _};
    use neqo_transport::{ConnectionParameters, DatagramQueueOutcome, StreamId};
    use test_fixture::now;

    use super::{MAX_DATAGRAM_BYTES_PER_READ, PER_DATAGRAM_OVERHEAD, Session};
    use crate::{
        ConnectUdpEvent, Http3Client, Http3ClientEvent, Http3Parameters, Http3Server,
        Http3ServerEvent, Res, SessionAcceptAction,
        connect_udp::{ClientSession as _, ServerEvent, ServerSession},
        features::extended_connect::{session::Protocol as _, tests::webtransport::connect},
    };

    trait Peer {
        /// Processes `dgrams` in one batch and returns everything sent in response.
        fn exchange(&mut self, dgrams: Vec<Datagram>) -> Vec<Datagram>;
        fn datagram_events(&mut self) -> usize;
    }

    impl Peer for Http3Client {
        fn exchange(&mut self, dgrams: Vec<Datagram>) -> Vec<Datagram> {
            self.process_multiple_input(dgrams, now());
            iter::from_fn(|| self.process_output(now()).dgram()).collect()
        }

        fn datagram_events(&mut self) -> usize {
            self.events()
                .filter(|e| {
                    matches!(
                        e,
                        Http3ClientEvent::ConnectUdp(ConnectUdpEvent::Datagram { .. })
                    )
                })
                .count()
        }
    }

    impl Peer for Http3Server {
        fn exchange(&mut self, dgrams: Vec<Datagram>) -> Vec<Datagram> {
            let first = self.process(dgrams, now()).dgram();
            first
                .into_iter()
                .chain(iter::from_fn(|| {
                    self.process(None::<Datagram>, now()).dgram()
                }))
                .collect()
        }

        fn datagram_events(&mut self) -> usize {
            self.events()
                .filter(|e| {
                    matches!(
                        e,
                        Http3ServerEvent::ConnectUdp(ServerEvent::Datagram { .. })
                    )
                })
                .count()
        }
    }

    /// Runs both peers until `sender` is idle. With `hold_first`, the first datagram of every
    /// flight is held back, so the receiver cannot read past the stream data it carries.
    fn exchange_all(
        sender: &mut impl Peer,
        receiver: &mut impl Peer,
        to_sender: Vec<Datagram>,
        hold_first: bool,
    ) -> Vec<Datagram> {
        let mut held = Vec::new();
        let mut flight = sender.exchange(to_sender);
        while !flight.is_empty() {
            if hold_first {
                held.push(flight.remove(0));
            }
            flight = sender.exchange(receiver.exchange(flight));
        }
        held
    }

    /// Establishes a session that carries datagrams in capsules.
    fn capsule_session() -> (Http3Client, Http3Server, ServerSession) {
        let params = Http3Parameters::default()
            .connect(true)
            .connection_parameters(ConnectionParameters::default().datagram_size(0));
        let (mut client, mut server) = connect(params.clone(), params);
        let session_id = client
            .connect_udp_create_session(now(), ("https", "something.com", "/"), &[])
            .unwrap();
        exchange_all(&mut client, &mut server, Vec::new(), false);
        let session = server
            .events()
            .find_map(|e| match e {
                Http3ServerEvent::ConnectUdp(ServerEvent::NewSession { session, .. }) => {
                    Some(session)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(session.stream_id(), session_id);
        session
            .response(&SessionAcceptAction::Accept, now())
            .unwrap();
        exchange_all(&mut server, &mut client, Vec::new(), false);
        (client, server, session)
    }

    /// Makes more empty datagram capsules than the per-read budget readable at once, then
    /// checks that the session still delivers a later datagram.
    fn flood<S: Peer>(
        sender: &mut S,
        receiver: &mut impl Peer,
        send: impl Fn(&mut S) -> Res<DatagramQueueOutcome>,
    ) {
        let budgeted = MAX_DATAGRAM_BYTES_PER_READ / PER_DATAGRAM_OVERHEAD;
        for _ in 0..=budgeted {
            assert_eq!(send(sender), Ok(DatagramQueueOutcome::Ok));
        }
        let held = exchange_all(sender, receiver, Vec::new(), true);
        assert_eq!(receiver.datagram_events(), 0);
        let acks = receiver.exchange(held);
        assert_eq!(receiver.datagram_events(), budgeted);
        assert_eq!(send(sender), Ok(DatagramQueueOutcome::Ok));
        exchange_all(sender, receiver, acks, false);
        assert_eq!(receiver.datagram_events(), 1);
    }

    #[test]
    fn proxy_capsule_flood_is_bounded_per_read() {
        let (mut client, mut server, session) = capsule_session();
        flood(&mut server, &mut client, |_| {
            session.send_datagram(&[], None, now())
        });
    }

    #[test]
    fn client_capsule_flood_is_bounded_per_read() {
        let (mut client, mut server, session) = capsule_session();
        let session_id = session.stream_id();
        flood(&mut client, &mut server, |client| {
            client.connect_udp_send_datagram(session_id, &[], None, now())
        });
    }

    #[test]
    fn datagram_one_byte_over_remaining_budget_is_dropped() {
        let (mut client, mut server, session) = capsule_session();
        let send = |payload: &[u8]| session.send_datagram(payload, None, now());
        let budgeted = MAX_DATAGRAM_BYTES_PER_READ / PER_DATAGRAM_OVERHEAD;
        for _ in 1..budgeted {
            assert_eq!(send(&[]), Ok(DatagramQueueOutcome::Ok));
        }
        // Costs one byte more than the remaining `PER_DATAGRAM_OVERHEAD`.
        assert_eq!(send(&[0]), Ok(DatagramQueueOutcome::Ok));
        let held = exchange_all(&mut server, &mut client, Vec::new(), true);
        _ = client.exchange(held);
        assert_eq!(client.datagram_events(), budgeted - 1);
    }

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
