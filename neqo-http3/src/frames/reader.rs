// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::frames::hframe::{
    HFrame, H3_FRAME_TYPE_CANCEL_PUSH, H3_FRAME_TYPE_DATA, H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_HEADERS, H3_FRAME_TYPE_MAX_PUSH_ID, H3_FRAME_TYPE_PRIORITY_UPDATE_PUSH,
    H3_FRAME_TYPE_PRIORITY_UPDATE_REQUEST, H3_FRAME_TYPE_PUSH_PROMISE, H3_FRAME_TYPE_SETTINGS,
    H3_RESERVED_FRAME_TYPES,
};
use crate::settings::HSettings;
use neqo_common::{
    hex_with_len, qtrace, Decoder, IncrementalDecoderBuffer, IncrementalDecoderIgnore,
    IncrementalDecoderUint,
};
use neqo_transport::{Connection, StreamId};
use std::convert::TryFrom;
use std::mem;

use crate::{Error, Priority, Res};

const MAX_READ_SIZE: usize = 4096;

#[derive(Clone, Debug)]
enum FrameReaderState {
    GetType { decoder: IncrementalDecoderUint },
    GetLength { decoder: IncrementalDecoderUint },
    GetData { decoder: IncrementalDecoderBuffer },
    UnknownFrameDischargeData { decoder: IncrementalDecoderIgnore },
}

#[derive(Debug)]
pub struct FrameReader {
    state: FrameReaderState,
    hframe_type: u64,
    hframe_len: u64,
    payload: Vec<u8>,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: FrameReaderState::GetType {
                decoder: IncrementalDecoderUint::default(),
            },
            hframe_type: 0,
            hframe_len: 0,
            payload: Vec::new(),
        }
    }

    #[must_use]
    pub fn new_with_type(hframe_type: u64) -> Self {
        Self {
            state: FrameReaderState::GetLength {
                decoder: IncrementalDecoderUint::default(),
            },
            hframe_type,
            hframe_len: 0,
            payload: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.state = FrameReaderState::GetType {
            decoder: IncrementalDecoderUint::default(),
        };
    }

    fn min_remaining(&self) -> usize {
        match &self.state {
            FrameReaderState::GetType { decoder } | FrameReaderState::GetLength { decoder } => {
                decoder.min_remaining()
            }
            FrameReaderState::GetData { decoder } => decoder.min_remaining(),
            FrameReaderState::UnknownFrameDischargeData { decoder } => decoder.min_remaining(),
        }
    }

    fn decoding_in_progress(&self) -> bool {
        if let FrameReaderState::GetType { decoder } = &self.state {
            decoder.decoding_in_progress()
        } else {
            true
        }
    }

    /// returns true if quic stream was closed.
    /// # Errors
    /// May return `HttpFrame` if a frame cannot be decoded.
    /// and `TransportStreamDoesNotExist` if `stream_recv` fails.
    pub fn receive(
        &mut self,
        conn: &mut Connection,
        stream_id: StreamId,
    ) -> Res<(Option<HFrame>, bool)> {
        loop {
            let to_read = std::cmp::min(self.min_remaining(), MAX_READ_SIZE);
            let mut buf = vec![0; to_read];
            let (output, read, fin) = match conn
                .stream_recv(stream_id, &mut buf)
                .map_err(|e| Error::map_stream_recv_errors(&e))?
            {
                (0, f) => (None, false, f),
                (amount, f) => {
                    qtrace!(
                        [conn],
                        "FrameReader::receive: reading {} byte, fin={}",
                        amount,
                        f
                    );
                    (self.consume(Decoder::from(&buf[..amount]))?, true, f)
                }
            };

            if output.is_some() {
                break Ok((output, fin));
            }

            if fin {
                if self.decoding_in_progress() {
                    break Err(Error::HttpFrame);
                }
                break Ok((None, fin));
            }

            if !read {
                // There was no new data, exit the loop.
                break Ok((None, false));
            }
        }
    }

    /// # Errors
    /// May return `HttpFrame` if a frame cannot be decoded.
    fn consume(&mut self, mut input: Decoder) -> Res<Option<HFrame>> {
        match &mut self.state {
            FrameReaderState::GetType { decoder } => {
                if let Some(v) = decoder.consume(&mut input) {
                    qtrace!("FrameReader::receive: read frame type {}", v);
                    self.hframe_type = v;
                    if H3_RESERVED_FRAME_TYPES.contains(&self.hframe_type) {
                        return Err(Error::HttpFrameUnexpected);
                    }
                    self.state = FrameReaderState::GetLength {
                        decoder: IncrementalDecoderUint::default(),
                    };
                }
            }

            FrameReaderState::GetLength { decoder } => {
                if let Some(len) = decoder.consume(&mut input) {
                    qtrace!(
                        "FrameReader::receive: frame type {} length {}",
                        self.hframe_type,
                        len
                    );
                    self.hframe_len = len;
                    self.state = match self.hframe_type {
                        // DATA payload are left on the quic stream and picked up separately
                        H3_FRAME_TYPE_DATA => {
                            return Ok(Some(self.get_frame()?));
                        }

                        // for other frames get all data before decoding.
                        H3_FRAME_TYPE_CANCEL_PUSH
                        | H3_FRAME_TYPE_SETTINGS
                        | H3_FRAME_TYPE_GOAWAY
                        | H3_FRAME_TYPE_MAX_PUSH_ID
                        | H3_FRAME_TYPE_PUSH_PROMISE
                        | H3_FRAME_TYPE_HEADERS
                        | H3_FRAME_TYPE_PRIORITY_UPDATE_REQUEST
                        | H3_FRAME_TYPE_PRIORITY_UPDATE_PUSH => {
                            if len == 0 {
                                return Ok(Some(self.get_frame()?));
                            }
                            FrameReaderState::GetData {
                                decoder: IncrementalDecoderBuffer::new(
                                    usize::try_from(len).or(Err(Error::HttpFrame))?,
                                ),
                            }
                        }
                        _ => {
                            if len == 0 {
                                FrameReaderState::GetType {
                                    decoder: IncrementalDecoderUint::default(),
                                }
                            } else {
                                FrameReaderState::UnknownFrameDischargeData {
                                    decoder: IncrementalDecoderIgnore::new(
                                        usize::try_from(len).or(Err(Error::HttpFrame))?,
                                    ),
                                }
                            }
                        }
                    };
                }
            }
            FrameReaderState::GetData { decoder } => {
                if let Some(data) = decoder.consume(&mut input) {
                    qtrace!(
                        "received frame {}: {}",
                        self.hframe_type,
                        hex_with_len(&data[..])
                    );
                    self.payload = data;
                    return Ok(Some(self.get_frame()?));
                }
            }
            FrameReaderState::UnknownFrameDischargeData { decoder } => {
                if decoder.consume(&mut input) {
                    self.reset();
                }
            }
        }
        Ok(None)
    }

    /// # Errors
    /// May return `HttpFrame` if a frame cannot be decoded.
    fn get_frame(&mut self) -> Res<HFrame> {
        let payload = mem::take(&mut self.payload);
        let mut dec = Decoder::from(&payload[..]);
        let f = match self.hframe_type {
            H3_FRAME_TYPE_DATA => HFrame::Data {
                len: self.hframe_len,
            },
            H3_FRAME_TYPE_HEADERS => HFrame::Headers {
                header_block: dec.decode_remainder().to_vec(),
            },
            H3_FRAME_TYPE_CANCEL_PUSH => HFrame::CancelPush {
                push_id: dec.decode_varint().ok_or(Error::HttpFrame)?,
            },
            H3_FRAME_TYPE_SETTINGS => {
                let mut settings = HSettings::default();
                settings.decode_frame_contents(&mut dec).map_err(|e| {
                    if e == Error::HttpSettings {
                        e
                    } else {
                        Error::HttpFrame
                    }
                })?;
                HFrame::Settings { settings }
            }
            H3_FRAME_TYPE_PUSH_PROMISE => HFrame::PushPromise {
                push_id: dec.decode_varint().ok_or(Error::HttpFrame)?,
                header_block: dec.decode_remainder().to_vec(),
            },
            H3_FRAME_TYPE_GOAWAY => HFrame::Goaway {
                stream_id: StreamId::new(dec.decode_varint().ok_or(Error::HttpFrame)?),
            },
            H3_FRAME_TYPE_MAX_PUSH_ID => HFrame::MaxPushId {
                push_id: dec.decode_varint().ok_or(Error::HttpFrame)?,
            },
            H3_FRAME_TYPE_PRIORITY_UPDATE_REQUEST | H3_FRAME_TYPE_PRIORITY_UPDATE_PUSH => {
                let element_id = dec.decode_varint().ok_or(Error::HttpFrame)?;
                let priority = dec.decode_remainder();
                let priority = Priority::from_bytes(priority)?;
                if self.hframe_type == H3_FRAME_TYPE_PRIORITY_UPDATE_REQUEST {
                    HFrame::PriorityUpdateRequest {
                        element_id,
                        priority,
                    }
                } else {
                    HFrame::PriorityUpdatePush {
                        element_id,
                        priority,
                    }
                }
            }
            _ => panic!("We should not be calling this function with unknown frame type!"),
        };
        self.reset();
        Ok(f)
    }
}
