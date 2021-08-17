// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use crate::{
    AppError, Error, Http3StreamType, HttpRecvStream, NewStreamType, ReceiveOutput, RecvStream,
    Res, ResetType,
};
use neqo_common::{qtrace, Decoder, IncrementalDecoderUint};
use neqo_transport::Connection;

#[derive(Debug)]
pub enum NewStreamTypeReader {
    ReadType {
        push_stream_allowed: bool,
        reader: IncrementalDecoderUint,
        stream_id: u64,
    },
    ReadSessionId {
        reader: IncrementalDecoderUint,
        stream_id: u64,
    },
    Done,
}

impl NewStreamTypeReader {
    pub fn new(stream_id: u64, push_stream_allowed: bool) -> Self {
        NewStreamTypeReader::ReadType {
            push_stream_allowed,
            reader: IncrementalDecoderUint::default(),
            stream_id,
        }
    }

    fn read(&mut self, conn: &mut Connection) -> Res<(Option<u64>, bool)> {
        match self {
            NewStreamTypeReader::ReadType {
                reader, stream_id, ..
            }
            | NewStreamTypeReader::ReadSessionId { reader, stream_id } => loop {
                let to_read = reader.min_remaining();
                let mut buf = vec![0; to_read];
                match conn.stream_recv(*stream_id, &mut buf[..])? {
                    (0, f) => break Ok((None, f)),
                    (amount, f) => {
                        let res = reader.consume(&mut Decoder::from(&buf[..amount]));
                        if res.is_some() || f {
                            break Ok((res, f));
                        }
                    }
                }
            },
            _ => Ok((None, false)),
        }
    }

    pub fn get_type(&mut self, conn: &mut Connection) -> Res<Option<NewStreamType>> {
        loop {
            let (output, fin) = self.read(conn)?;
            if output.is_none() {
                if fin {
                    *self = NewStreamTypeReader::Done;
                    break Err(Error::HttpStreamCreation);
                }
                break Ok(None);
            }
            let output = output.unwrap();
            qtrace!("Decoded uint {}", output);
            match self {
                NewStreamTypeReader::ReadType {
                    push_stream_allowed,
                    stream_id,
                    ..
                } => {
                    let res = NewStreamType::decode_stream_type(output, *push_stream_allowed);
                    if res.is_err() {
                        *self = NewStreamTypeReader::Done;
                        return res;
                    }
                    let res = res.unwrap();
                    if fin {
                        *self = NewStreamTypeReader::Done;
                        return self.map_stream_fin(res);
                    }
                    qtrace!("Decoded stream type {:?}", res);
                    if res.is_some() {
                        *self = NewStreamTypeReader::Done;
                        break Ok(res);
                    }
                    // This is a WebTransportStream stream and it needs more data to be decoded.
                    *self = NewStreamTypeReader::ReadSessionId {
                        reader: IncrementalDecoderUint::default(),
                        stream_id: *stream_id,
                    };
                }
                NewStreamTypeReader::ReadSessionId { .. } => {
                    *self = NewStreamTypeReader::Done;
                    qtrace!("New Stream stream push_id={}", output);
                    if fin {
                        break Err(Error::HttpGeneralProtocol);
                    }
                    break Ok(Some(NewStreamType::Push(output)));
                }
                _ => unreachable!("Cannot be in state NewStreamTypeReader::Done"),
            }
        }
    }

    fn map_stream_fin(&self, decoded: Option<NewStreamType>) -> Res<Option<NewStreamType>> {
        match decoded {
            Some(NewStreamType::Control)
            | Some(NewStreamType::Encoder)
            | Some(NewStreamType::Decoder) => Err(Error::HttpClosedCriticalStream),
            None => Err(Error::HttpStreamCreation),
            Some(NewStreamType::Unknown) => Ok(decoded),
            _ => unreachable!("PushStream is mapped to None at this stage."),
        }
    }
}

impl RecvStream for NewStreamTypeReader {
    fn stream_reset(&mut self, _error: AppError, _reset_type: ResetType) -> Res<()> {
        *self = NewStreamTypeReader::Done;
        Ok(())
    }

    fn receive(&mut self, conn: &mut Connection) -> Res<ReceiveOutput> {
        Ok(self
            .get_type(conn)?
            .map_or(ReceiveOutput::NoOutput, |t| ReceiveOutput::NewStream(t)))
    }

    fn done(&self) -> bool {
        matches!(self, NewStreamTypeReader::Done)
    }

    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::NewStream
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpRecvStream> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::NewStreamTypeReader;
    use neqo_transport::{Connection, StreamType};
    use std::mem;
    use test_fixture::{connect, now};

    use crate::control_stream_local::HTTP3_UNI_STREAM_TYPE_CONTROL;
    use crate::{
        Error, NewStreamType, ReceiveOutput, RecvStream, Res, ResetType, HTTP3_UNI_STREAM_TYPE_PUSH,
    };
    use neqo_common::Encoder;
    use neqo_qpack::decoder::QPACK_UNI_STREAM_TYPE_DECODER;
    use neqo_qpack::encoder::QPACK_UNI_STREAM_TYPE_ENCODER;

    struct Test {
        conn_c: Connection,
        conn_s: Connection,
        stream_id: u64,
        decoder: NewStreamTypeReader,
    }

    impl Test {
        fn new(push_allowed: bool) -> Self {
            let (mut conn_c, mut conn_s) = connect();
            // create a stream
            let stream_id = conn_s.stream_create(StreamType::UniDi).unwrap();
            let out = conn_s.process(None, now());
            mem::drop(conn_c.process(out.dgram(), now()));

            Self {
                conn_c,
                conn_s,
                stream_id,
                decoder: NewStreamTypeReader::new(stream_id, push_allowed),
            }
        }

        fn decode_buffer(
            &mut self,
            enc: &[u8],
            fin: bool,
            outcome: Res<ReceiveOutput>,
            done: bool,
        ) {
            let len = enc.len() - 1;
            for i in 0..len {
                self.conn_s
                    .stream_send(self.stream_id, &enc[i..=i])
                    .unwrap();
                let out = self.conn_s.process(None, now());
                mem::drop(self.conn_c.process(out.dgram(), now()));
                assert_eq!(
                    self.decoder.receive(&mut self.conn_c).unwrap(),
                    ReceiveOutput::NoOutput
                );
                assert!(!self.decoder.done());
            }
            self.conn_s
                .stream_send(self.stream_id, &enc[enc.len() - 1..])
                .unwrap();
            if fin {
                self.conn_s.stream_close_send(self.stream_id).unwrap();
            }
            let out = self.conn_s.process(None, now());
            mem::drop(self.conn_c.process(out.dgram(), now()));
            assert_eq!(self.decoder.receive(&mut self.conn_c), outcome);
            assert_eq!(self.decoder.done(), done);
        }

        fn decode(
            &mut self,
            to_encode: &[u64],
            fin: bool,
            outcome: Res<ReceiveOutput>,
            done: bool,
        ) {
            let mut enc = Encoder::default();
            for i in to_encode {
                enc.encode_varint(*i);
            }
            self.decode_buffer(&enc[..], fin, outcome, done);
        }
    }

    #[test]
    fn decode_streams() {
        let mut t = Test::new(false);
        t.decode(
            &[QPACK_UNI_STREAM_TYPE_DECODER],
            false,
            Ok(ReceiveOutput::NewStream(NewStreamType::Encoder)),
            true,
        );

        let mut t = Test::new(false);
        t.decode(
            &[QPACK_UNI_STREAM_TYPE_ENCODER],
            false,
            Ok(ReceiveOutput::NewStream(NewStreamType::Decoder)),
            true,
        );

        let mut t = Test::new(false);
        t.decode(
            &[HTTP3_UNI_STREAM_TYPE_CONTROL],
            false,
            Ok(ReceiveOutput::NewStream(NewStreamType::Control)),
            true,
        );

        let mut t = Test::new(true);
        t.decode(
            &[HTTP3_UNI_STREAM_TYPE_PUSH, 0xaaaa_aaaa],
            false,
            Ok(ReceiveOutput::NewStream(NewStreamType::Push(0xaaaa_aaaa))),
            true,
        );

        let mut t = Test::new(false);
        t.decode(
            &[HTTP3_UNI_STREAM_TYPE_PUSH],
            false,
            Err(Error::HttpStreamCreation),
            true,
        );

        let mut t = Test::new(true);
        t.decode(
            &[0x3fff_ffff_ffff_ffff],
            false,
            Ok(ReceiveOutput::NewStream(NewStreamType::Unknown)),
            true,
        );
    }

    #[test]
    fn done_decoding() {
        let mut t = Test::new(true);
        t.decode(
            &[0x3fff],
            false,
            Ok(ReceiveOutput::NewStream(NewStreamType::Unknown)),
            true,
        );
        // NewStreamTypeReader is done, it will not continue reading from the stream.
        t.decode(
            &[QPACK_UNI_STREAM_TYPE_DECODER],
            false,
            Ok(ReceiveOutput::NoOutput),
            true,
        );
    }

    #[test]
    fn decoding_truncate() {
        let mut t = Test::new(false);
        t.decode_buffer(&[0xff], false, Ok(ReceiveOutput::NoOutput), false);
    }

    #[test]
    fn reset() {
        let mut t = Test::new(true);
        t.decoder.stream_reset(0x100, ResetType::Remote).unwrap();
        // after a reset NewStreamTypeReader will not read more data.
        t.decode(
            &[QPACK_UNI_STREAM_TYPE_DECODER],
            false,
            Ok(ReceiveOutput::NoOutput),
            true,
        );
    }

    #[test]
    fn stream_fin() {
        let mut t = Test::new(false);
        t.decode(
            &[QPACK_UNI_STREAM_TYPE_DECODER],
            true,
            Err(Error::HttpClosedCriticalStream),
            true,
        );

        let mut t = Test::new(false);
        t.decode(
            &[QPACK_UNI_STREAM_TYPE_ENCODER],
            true,
            Err(Error::HttpClosedCriticalStream),
            true,
        );

        let mut t = Test::new(false);
        t.decode(
            &[HTTP3_UNI_STREAM_TYPE_CONTROL],
            true,
            Err(Error::HttpClosedCriticalStream),
            true,
        );

        let mut t = Test::new(true);
        t.decode(
            &[HTTP3_UNI_STREAM_TYPE_PUSH, 0xaaaa_aaaa],
            true,
            Err(Error::HttpGeneralProtocol),
            true,
        );

        let mut t = Test::new(false);
        t.decode(
            &[HTTP3_UNI_STREAM_TYPE_PUSH],
            true,
            Err(Error::HttpStreamCreation),
            true,
        );

        let mut t = Test::new(true);
        t.decode(
            &[0x3fff_ffff_ffff_ffff],
            true,
            Ok(ReceiveOutput::NewStream(NewStreamType::Unknown)),
            true,
        );

        let mut t = Test::new(true);
        // stream_id 0x3fff_ffff_ffff_ffff is encoded into [0xff, 8].
        // For this test the last byte is no delivered before a fin.
        // This should cause aan error.
        t.decode_buffer(&[0xff; 7], true, Err(Error::HttpStreamCreation), true);
    }
}
