// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::hframe::HFrame;
use crate::{
    qlog, BufferedStream, CloseType, Error, Header, Headers, Http3StreamType, HttpSendStream, Res,
    SendStream, SendStreamEvents, Stream,
};

use neqo_common::{qdebug, qinfo, qtrace, Encoder};
use neqo_qpack::encoder::QPackEncoder;
use neqo_transport::{Connection, StreamId};
use std::cell::RefCell;
use std::cmp::min;
use std::fmt::Debug;
use std::rc::Rc;

const MAX_DATA_HEADER_SIZE_2: usize = (1 << 6) - 1; // Maximal amount of data with DATA frame header size 2
const MAX_DATA_HEADER_SIZE_2_LIMIT: usize = MAX_DATA_HEADER_SIZE_2 + 3; // 63 + 3 (size of the next buffer data frame header)
const MAX_DATA_HEADER_SIZE_3: usize = (1 << 14) - 1; // Maximal amount of data with DATA frame header size 3
const MAX_DATA_HEADER_SIZE_3_LIMIT: usize = MAX_DATA_HEADER_SIZE_3 + 5; // 16383 + 5 (size of the next buffer data frame header)
const MAX_DATA_HEADER_SIZE_5: usize = (1 << 30) - 1; // Maximal amount of data with DATA frame header size 3
const MAX_DATA_HEADER_SIZE_5_LIMIT: usize = MAX_DATA_HEADER_SIZE_5 + 9; // 1073741823 + 9 (size of the next buffer data frame header)

#[derive(Debug)]
pub(crate) struct SendMessage {
    stream: BufferedStream,
    fin: bool,
    encoder: Rc<RefCell<QPackEncoder>>,
    conn_events: Box<dyn SendStreamEvents>,
}

impl SendMessage {
    pub fn new(
        stream_id: StreamId,
        encoder: Rc<RefCell<QPackEncoder>>,
        conn_events: Box<dyn SendStreamEvents>,
    ) -> Self {
        qinfo!("Create a request stream_id={}", stream_id);
        Self {
            stream: BufferedStream::new(stream_id),
            fin: false,
            encoder,
            conn_events,
        }
    }

    /// # Errors
    /// `ClosedCriticalStream` if the encoder stream is closed.
    /// `InternalError` if an unexpected error occurred.
    fn encode(
        encoder: &mut QPackEncoder,
        headers: &[Header],
        conn: &mut Connection,
        stream_id: StreamId,
    ) -> Vec<u8> {
        qdebug!("Encoding headers");
        let header_block = encoder.encode_header_block(conn, headers, stream_id);
        let hframe = HFrame::Headers {
            header_block: header_block.to_vec(),
        };
        let mut d = Encoder::default();
        hframe.encode(&mut d);
        d.into()
    }

    fn stream_id(&self) -> StreamId {
        Option::<StreamId>::from(&self.stream).unwrap()
    }
}

impl Stream for SendMessage {
    fn stream_type(&self) -> Http3StreamType {
        Http3StreamType::Http
    }
}
impl SendStream for SendMessage {
    fn send_data(&mut self, conn: &mut Connection, buf: &[u8]) -> Res<usize> {
        qtrace!([self], "send_body: len={}", buf.len());
        if self.fin {
            return Err(Error::AlreadyClosed);
        }
        self.stream.send_buffer(conn)?;
        if self.stream.has_buffered_data() {
            return Ok(0);
        }
        let available = conn
            .stream_avail_send_space(self.stream_id())
            .map_err(|e| Error::map_stream_send_errors(&e.into()))?;
        if available <= 2 {
            return Ok(0);
        }
        let to_send = if available <= MAX_DATA_HEADER_SIZE_2_LIMIT {
            // 63 + 3
            min(min(buf.len(), available - 2), MAX_DATA_HEADER_SIZE_2)
        } else if available <= MAX_DATA_HEADER_SIZE_3_LIMIT {
            // 16383 + 5
            min(min(buf.len(), available - 3), MAX_DATA_HEADER_SIZE_3)
        } else if available <= MAX_DATA_HEADER_SIZE_5 {
            // 1073741823 + 9
            min(min(buf.len(), available - 5), MAX_DATA_HEADER_SIZE_5_LIMIT)
        } else {
            min(buf.len(), available - 9)
        };

        qinfo!(
            [self],
            "send_request_body: available={} to_send={}.",
            available,
            to_send
        );

        let data_frame = HFrame::Data {
            len: to_send as u64,
        };
        let mut enc = Encoder::default();
        data_frame.encode(&mut enc);
        let sent_fh = self
            .stream
            .send_atomic(conn, &enc)
            .map_err(|e| Error::map_stream_send_errors(&e))?;
        debug_assert!(sent_fh);

        let sent = self
            .stream
            .send_atomic(conn, &buf[..to_send])
            .map_err(|e| Error::map_stream_send_errors(&e))?;
        debug_assert!(sent);
        qlog::h3_data_moved_down(&mut conn.qlog_mut(), self.stream_id(), to_send);
        Ok(to_send)
    }

    fn done(&self) -> bool {
        !self.stream.has_buffered_data() && self.fin
    }

    fn stream_writable(&self) {
        if !self.stream.has_buffered_data() && !self.fin {
            self.conn_events.data_writable(self.stream_id());
        }
    }

    /// # Errors
    /// `InternalError` if an unexpected error occurred.
    /// `InvalidStreamId` if the stream does not exist,
    /// `AlreadyClosed` if the stream has already been closed.
    /// `TransportStreamDoesNotExist` if the transport stream does not exist (this may happen if `process_output`
    /// has not been called when needed, and HTTP3 layer has not picked up the info that the stream has been closed.)
    fn send(&mut self, conn: &mut Connection) -> Res<()> {
        let sent = Error::map_error(self.stream.send_buffer(conn), Error::HttpInternal(5))?;
        qlog::h3_data_moved_down(&mut conn.qlog_mut(), self.stream_id(), sent);

        qtrace!([self], "{} bytes sent", sent);

        if !self.stream.has_buffered_data() {
            if self.fin {
                Error::map_error(
                    conn.stream_close_send(self.stream_id()),
                    Error::HttpInternal(6),
                )?;
                qtrace!([self], "done sending request");
            } else {
                self.conn_events.data_writable(self.stream_id());
            }
        }
        Ok(())
    }

    // SendMessage owns headers and sends them. It may also own data for the server side.
    // This method returns if they're still being sent. Request body (if any) is sent by
    // http client afterwards using `send_request_body` after receiving DataWritable event.
    fn has_data_to_send(&self) -> bool {
        self.stream.has_buffered_data()
    }

    fn close(&mut self, conn: &mut Connection) -> Res<()> {
        self.fin = true;
        if !self.stream.has_buffered_data() {
            conn.stream_close_send(self.stream_id())?;
        }

        self.conn_events
            .send_closed(self.stream_id(), CloseType::Done);
        Ok(())
    }

    fn stop_sending(&mut self, close_type: CloseType) {
        if !self.fin {
            self.conn_events.send_closed(self.stream_id(), close_type);
        }
    }

    fn http_stream(&mut self) -> Option<&mut dyn HttpSendStream> {
        Some(self)
    }
}

impl HttpSendStream for SendMessage {
    fn send_headers(&mut self, headers: Headers, conn: &mut Connection) {
        let buf = SendMessage::encode(
            &mut self.encoder.borrow_mut(),
            &headers,
            conn,
            self.stream_id(),
        );
        self.stream.buffer(&buf);
    }
}

impl ::std::fmt::Display for SendMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "SendMesage {}", self.stream_id())
    }
}
