// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracks possibly-redundant flow control signals from other code and converts
// into flow control frames needing to be sent to the remote.

use std::collections::HashMap;
use std::mem;

use neqo_common::qwarn;
use smallvec::{smallvec, SmallVec};

use crate::frame::{write_varint_frame, Frame};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::stats::FrameStats;
use crate::stream_id::{StreamId, StreamIndex, StreamIndexes, StreamType};
use crate::{AppError, Res};

type FlowFrame = Frame<'static>;
pub type FlowControlRecoveryToken = FlowFrame;

#[derive(Debug, Default)]
pub struct FlowMgr {
    // (id, discriminant) as key ensures only 1 of every frame type per stream
    // will be queued.
    from_streams: HashMap<(StreamId, mem::Discriminant<FlowFrame>), FlowFrame>,

    // (stream_type, discriminant) as key ensures only 1 of every frame type
    // per stream type will be queued.
    from_stream_types: HashMap<(StreamType, mem::Discriminant<FlowFrame>), FlowFrame>,
}

impl FlowMgr {
    // -- frames scoped on stream --

    /// Indicate to sending remote we are no longer interested in the stream
    pub fn stop_sending(&mut self, stream_id: StreamId, application_error_code: AppError) {
        let frame = Frame::StopSending {
            stream_id,
            application_error_code,
        };
        self.from_streams
            .insert((stream_id, mem::discriminant(&frame)), frame);
    }

    // -- frames scoped on stream type --

    pub fn max_streams(&mut self, stream_limit: StreamIndex, stream_type: StreamType) {
        let frame = Frame::MaxStreams {
            stream_type,
            maximum_streams: stream_limit,
        };
        self.from_stream_types
            .insert((stream_type, mem::discriminant(&frame)), frame);
    }

    pub fn streams_blocked(&mut self, stream_limit: StreamIndex, stream_type: StreamType) {
        let frame = Frame::StreamsBlocked {
            stream_type,
            stream_limit,
        };
        self.from_stream_types
            .insert((stream_type, mem::discriminant(&frame)), frame);
    }

    pub fn peek(&self) -> Option<&Frame> {
        if let Some(key) = self.from_streams.keys().next() {
            self.from_streams.get(key)
        } else if let Some(key) = self.from_stream_types.keys().next() {
            self.from_stream_types.get(key)
        } else {
            None
        }
    }

    pub(crate) fn lost(&mut self, token: &FlowControlRecoveryToken, indexes: &mut StreamIndexes) {
        match *token {
            // Resend MaxStreams if lost (with updated value)
            Frame::MaxStreams { stream_type, .. } => {
                let local_max = match stream_type {
                    StreamType::BiDi => &mut indexes.local_max_stream_bidi,
                    StreamType::UniDi => &mut indexes.local_max_stream_uni,
                };

                self.max_streams(*local_max, stream_type)
            }
            // Only resend "*Blocked" frames if still blocked
            Frame::StreamsBlocked { stream_type, .. } => match stream_type {
                StreamType::UniDi => {
                    if indexes.remote_next_stream_uni >= indexes.remote_max_stream_uni {
                        self.streams_blocked(indexes.remote_max_stream_uni, StreamType::UniDi);
                    }
                }
                StreamType::BiDi => {
                    if indexes.remote_next_stream_bidi >= indexes.remote_max_stream_bidi {
                        self.streams_blocked(indexes.remote_max_stream_bidi, StreamType::BiDi);
                    }
                }
            },
            // Resend StopSending
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => self.stop_sending(stream_id, application_error_code),
            _ => qwarn!("Unexpected Flow frame {:?} lost, not re-sent", token),
        }
    }

    pub(crate) fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        while let Some(frame) = self.peek() {
            // All these frames are bags of varints, so we can just extract the
            // varints and use common code for writing.
            let (mut values, stat): (SmallVec<[_; 3]>, _) = match frame {
                Frame::StopSending {
                    stream_id,
                    application_error_code,
                } => (
                    smallvec![stream_id.as_u64(), *application_error_code],
                    &mut stats.stop_sending,
                ),
                Frame::MaxStreams {
                    maximum_streams, ..
                } => (smallvec![maximum_streams.as_u64()], &mut stats.max_streams),
                Frame::StreamsBlocked { stream_limit, .. } => {
                    (smallvec![stream_limit.as_u64()], &mut stats.streams_blocked)
                }
                Frame::MaxStreamData {
                    stream_id,
                    maximum_stream_data,
                } => (
                    smallvec![stream_id.as_u64(), *maximum_stream_data],
                    &mut stats.max_stream_data,
                ),
                _ => unreachable!("{:?}", frame),
            };
            values.insert(0, frame.get_type());
            debug_assert!(!values.spilled());

            if write_varint_frame(builder, &values)? {
                tokens.push(RecoveryToken::Flow(self.next().unwrap()));
                *stat += 1;
            } else {
                return Ok(());
            }
        }
        Ok(())
    }
}

impl Iterator for FlowMgr {
    type Item = FlowFrame;

    /// Used by generator to get a flow control frame.
    fn next(&mut self) -> Option<Self::Item> {
        let first_key = self.from_streams.keys().next();
        if let Some(&first_key) = first_key {
            return self.from_streams.remove(&first_key);
        }

        let first_key = self.from_stream_types.keys().next();
        if let Some(&first_key) = first_key {
            return self.from_stream_types.remove(&first_key);
        }

        None
    }
}
