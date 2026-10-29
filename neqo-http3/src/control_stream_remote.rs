// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    time::Instant,
};

use neqo_transport::{Connection, StreamId};
use tracing::debug;

use crate::{
    CloseType, Error, Http3StreamType, ReceiveOutput, RecvStream, Res, Stream,
    frames::{FrameReader, HFrame, StreamReaderConnectionWrapper},
};

/// The remote control stream is responsible only for reading frames. The frames are handled by
/// `Http3Connection`.
#[derive(Debug)]
pub struct ControlStreamRemote {
    stream_id: StreamId,
    frame_reader: FrameReader,
}

impl Display for ControlStreamRemote {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Http3 remote control stream {:?}", self.stream_id)
    }
}

impl ControlStreamRemote {
    pub fn new(stream_id: StreamId) -> Self {
        Self {
            stream_id,
            frame_reader: FrameReader::new(),
        }
    }

    /// Check if a stream is the control stream and read received data.
    pub fn receive_single(&mut self, conn: &mut Connection, now: Instant) -> Res<Option<HFrame>> {
        debug!("[{self}] Receiving data");
        match self.frame_reader.receive(
            &mut StreamReaderConnectionWrapper::new(conn, self.stream_id),
            now,
        )? {
            (_, true) => Err(Error::HttpClosedCriticalStream),
            (s, false) => {
                debug!("[{self}] received {s:?}");
                Ok(s)
            }
        }
    }
}

impl Stream for ControlStreamRemote {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::Control
    }
}

impl RecvStream for ControlStreamRemote {
    fn reset(&mut self, _close_type: CloseType) -> Res<()> {
        Err(Error::HttpClosedCriticalStream)
    }

    fn receive(&mut self, conn: &mut Connection, now: Instant) -> Res<(ReceiveOutput, bool)> {
        let output = self
            .receive_single(conn, now)?
            .map_or(ReceiveOutput::NoOutput, |f| {
                ReceiveOutput::ControlFrames(vec![f])
            });
        Ok((output, false))
    }
}

#[test]
fn control_stream_remote_display() {
    let stream = ControlStreamRemote::new(StreamId::new(2));
    assert_eq!(
        stream.to_string(),
        "Http3 remote control stream StreamId(2)"
    );
}

#[test]
fn control_stream_remote_receive_one_frame_at_a_time() {
    use neqo_common::Encoder;
    use neqo_transport::StreamType;
    use test_fixture::{connect, now};

    let (mut client, mut server) = connect();
    let stream_id = server.stream_create(StreamType::UniDi).unwrap();
    let frames = [8, 4].map(|id| HFrame::Goaway {
        stream_id: StreamId::new(id),
    });
    let mut enc = Encoder::default();
    for f in &frames {
        f.encode(&mut enc);
    }
    let sent = server.stream_send(stream_id, enc.as_ref()).unwrap();
    assert_eq!(sent, enc.len());
    let out = server.process_output(now());
    client.process_input(out.dgram().unwrap(), now());

    let mut stream = ControlStreamRemote::new(stream_id);
    for f in frames {
        let output = ReceiveOutput::ControlFrames(vec![f]);
        assert_eq!(stream.receive(&mut client, now()), Ok((output, false)));
    }
    let output = ReceiveOutput::NoOutput;
    assert_eq!(stream.receive(&mut client, now()), Ok((output, false)));
}
