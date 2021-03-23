// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracks possibly-redundant flow control signals from other code and converts
// into flow control frames needing to be sent to the remote.

use crate::frame::{
    write_varint_frame, FRAME_TYPE_DATA_BLOCKED, FRAME_TYPE_MAX_DATA, FRAME_TYPE_MAX_STREAMS_BIDI,
    FRAME_TYPE_MAX_STREAMS_UNIDI, FRAME_TYPE_MAX_STREAM_DATA, FRAME_TYPE_STREAMS_BLOCKED_BIDI,
    FRAME_TYPE_STREAMS_BLOCKED_UNIDI, FRAME_TYPE_STREAM_DATA_BLOCKED,
};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::stats::FrameStats;
use crate::stream_id::{StreamId, StreamType};
use crate::{Error, Res};
use neqo_common::Role;

use std::convert::TryFrom;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::ops::{Index, IndexMut};

#[derive(Debug)]
pub struct SenderFlowControl<T>
where
    T: Debug + Sized,
{
    /// The thing that we're counting for.
    subject: T,
    /// The limit.
    limit: u64,
    /// How much of that limit we've used.
    used: u64,
    /// The point at which blocking occurred.  This is updated each time
    /// the sender decides that it is blocked.  It only ever changes
    /// when blocking occurs.  This ensures that blocking at any given limit
    /// is only reported once.
    /// Note: All values are one greater than the corresponding `limit` to
    /// allow distinguishing between blocking at a limit of 0 and no blocking.
    blocked_at: u64,
    /// Whether a blocked frame should be sent.
    blocked_frame: bool,
}

impl<T> SenderFlowControl<T>
where
    T: Debug + Sized,
{
    /// Make a new instance with the initial value and subject.
    pub fn new(subject: T, initial: u64) -> Self {
        Self {
            subject,
            limit: initial,
            used: 0,
            blocked_at: 0,
            blocked_frame: false,
        }
    }

    /// Update the maximum.  Returns `true` if the change was an increase.
    pub fn update(&mut self, limit: u64) -> bool {
        debug_assert!(limit < u64::MAX);
        if limit > self.limit {
            self.limit = limit;
            self.blocked_frame = false;
            true
        } else {
            false
        }
    }

    /// Consume flow control.
    pub fn consume(&mut self, count: usize) {
        let amt = u64::try_from(count).unwrap();
        debug_assert!(self.used + amt <= self.limit);
        self.used += amt;
    }

    /// Get available flow control.
    pub fn available(&self) -> usize {
        usize::try_from(self.limit - self.used).unwrap_or(usize::MAX)
    }

    /// How much data has been written.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Mark flow control as blocked.
    /// This only does something if the current limit exceeds the last reported blocking limit.
    pub fn blocked(&mut self) {
        if self.limit >= self.blocked_at {
            self.blocked_at = self.limit + 1;
            self.blocked_frame = true;
        }
    }

    /// Return whether a blocking frame needs to be sent.
    /// This is `Some` with the active limit if `blocked` has been called,
    /// if a blocking frame has not been sent (or it has been lost), and
    /// if the blocking condition remains.
    fn blocked_needed(&self) -> Option<u64> {
        if self.blocked_frame && self.limit < self.blocked_at {
            Some(self.blocked_at - 1)
        } else {
            None
        }
    }

    /// Clear the need to send a blocked frame.
    fn blocked_sent(&mut self) {
        self.blocked_frame = false;
    }

    /// Mark a blocked frame as having been lost.
    /// Only send again if value of `self.blocked_at` hasn't increased since sending.
    /// That would imply that the limit has since increased.
    pub fn lost(&mut self, limit: u64) {
        if self.blocked_at == limit + 1 {
            self.blocked_frame = true;
        }
    }
}

impl SenderFlowControl<()> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if let Some(limit) = self.blocked_needed() {
            if write_varint_frame(builder, &[FRAME_TYPE_DATA_BLOCKED, limit])? {
                stats.data_blocked += 1;
                tokens.push(RecoveryToken::DataBlocked(limit));
                self.blocked_sent();
            }
        }
        Ok(())
    }
}

impl SenderFlowControl<StreamId> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if let Some(limit) = self.blocked_needed() {
            if write_varint_frame(
                builder,
                &[FRAME_TYPE_STREAM_DATA_BLOCKED, self.subject.as_u64(), limit],
            )? {
                stats.stream_data_blocked += 1;
                tokens.push(RecoveryToken::StreamDataBlocked {
                    stream_id: self.subject,
                    limit,
                });
                self.blocked_sent();
            }
        }
        Ok(())
    }
}

impl SenderFlowControl<StreamType> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if let Some(limit) = self.blocked_needed() {
            let frame = if self.subject == StreamType::BiDi {
                FRAME_TYPE_STREAMS_BLOCKED_BIDI
            } else {
                FRAME_TYPE_STREAMS_BLOCKED_UNIDI
            };
            if write_varint_frame(builder, &[frame, limit])? {
                stats.streams_blocked += 1;
                tokens.push(RecoveryToken::StreamsBlocked {
                    stream_type: self.subject,
                    limit,
                });
                self.blocked_sent();
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReceiverFlowControl<T>
where
    T: Debug + Sized,
{
    /// The thing that we're counting for.
    subject: T,
    /// The maximum amount of items that can be active (e.g., the size of the receive buffer).
    max_active: u64,
    // Last max data sent.
    max_data: u64,
    // Retired bytes.
    retired: u64,
    frame_pending: bool,
}

impl<T> ReceiverFlowControl<T>
where
    T: Debug + Sized,
{
    /// Make a new instance with the initial value and subject.
    pub fn new(subject: T, max_bytes: u64) -> Self {
        Self {
            subject,
            max_active: max_bytes,
            max_data: max_bytes,
            retired: 0,
            frame_pending: false,
        }
    }

    /// Check if received data exceeds the allowed flow control limit.
    pub fn check_allowed(&self, new_end: u64) -> bool {
        new_end < self.max_data
    }

    /// Some data has been read, retired them and maybe send flow control
    /// update.
    pub fn retired(&mut self, retired: u64) {
        if retired <= self.retired {
            return;
        }

        self.retired = retired;
        if self.retired + self.max_active / 2 > self.max_data {
            self.frame_pending = true;
        }
    }

    /// Retire given amount of additional data.
    /// This function will sen flow updates immediately.
    pub fn add_retired(&mut self, count: u64) {
        self.retired += count;
        if count > 0 {
            self.send_flowc_update();
        }
    }

    /// This function is called when STREAM_DATA_BLOCKED frame is received.
    /// The flow control willl try to send an update if possible.
    pub fn send_flowc_update(&mut self) {
        if self.retired + self.max_active > self.max_data {
            self.frame_pending = true;
        }
    }

    pub fn max_data_needed(&self) -> Option<u64> {
        if self.frame_pending {
            Some(self.retired + self.max_active)
        } else {
            None
        }
    }

    pub fn lost(&mut self, maximum_data: u64) {
        if maximum_data == self.max_data {
            self.frame_pending = true;
        }
    }

    fn max_data_sent(&mut self, new_max: u64) {
        self.max_data = new_max;
        self.frame_pending = false;
    }

    pub fn set_max_active(&mut self, max: u64) {
        // If max_active has been increased, send an update immediately.
        self.frame_pending |= self.max_active < max;
        self.max_active = max;
    }
}

impl ReceiverFlowControl<()> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if let Some(max_data) = self.max_data_needed() {
            if write_varint_frame(builder, &[FRAME_TYPE_MAX_DATA, max_data])? {
                stats.max_data += 1;
                tokens.push(RecoveryToken::MaxData(max_data));
                self.max_data_sent(max_data);
            }
        }
        Ok(())
    }
}

impl ReceiverFlowControl<StreamId> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if let Some(max_data) = self.max_data_needed() {
            if write_varint_frame(
                builder,
                &[FRAME_TYPE_MAX_STREAM_DATA, self.subject.as_u64(), max_data],
            )? {
                stats.max_stream_data += 1;
                tokens.push(RecoveryToken::MaxStreamData {
                    stream_id: self.subject,
                    max_data,
                });
                self.max_data_sent(max_data);
            }
        }
        Ok(())
    }
}

impl ReceiverFlowControl<StreamType> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if let Some(max_streams) = self.max_data_needed() {
            let frame = if self.subject == StreamType::BiDi {
                FRAME_TYPE_MAX_STREAMS_BIDI
            } else {
                FRAME_TYPE_MAX_STREAMS_UNIDI
            };
            if write_varint_frame(builder, &[frame, max_streams])? {
                stats.max_streams += 1;
                tokens.push(RecoveryToken::MaxStreams {
                    stream_type: self.subject,
                    max_streams,
                });
                self.max_data_sent(max_streams);
            }
        }
        Ok(())
    }
}

pub struct RemoteStreamLimit {
    streams_fc: ReceiverFlowControl<StreamType>,
    next_stream: StreamId,
}

impl RemoteStreamLimit {
    pub fn new(stream_type: StreamType, max_streams: u64, role: Role) -> Self {
        Self {
            streams_fc: ReceiverFlowControl::new(stream_type, max_streams),
            // // This is for a stream created by a peer, therefore we use role.remote().
            next_stream: StreamId::init(stream_type, role.remote()),
        }
    }

    pub fn is_new_stream(&mut self, stream_id: StreamId) -> Res<bool> {
        let stream_idx = stream_id.as_u64() >> 2;
        if !self.streams_fc.check_allowed(stream_idx) {
            return Err(Error::StreamLimitError);
        }
        Ok(stream_id >= self.next_stream)
    }

    pub fn take_stream_id(&mut self) -> StreamId {
        let new_stream = self.next_stream;
        self.next_stream.next();
        assert!(self.streams_fc.check_allowed(new_stream.as_u64() >> 2));
        new_stream
    }
}

impl Deref for RemoteStreamLimit {
    type Target = ReceiverFlowControl<StreamType>;
    fn deref(&self) -> &Self::Target {
        &self.streams_fc
    }
}

impl DerefMut for RemoteStreamLimit {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.streams_fc
    }
}

pub struct RemoteStreamLimits([RemoteStreamLimit; 2]);

impl RemoteStreamLimits {
    pub fn new(local_max_stream_bidi: u64, local_max_stream_uni: u64, role: Role) -> Self {
        Self([
            RemoteStreamLimit::new(StreamType::BiDi, local_max_stream_bidi, role),
            RemoteStreamLimit::new(StreamType::UniDi, local_max_stream_uni, role),
        ])
    }
}

impl Index<StreamType> for RemoteStreamLimits {
    type Output = RemoteStreamLimit;

    fn index(&self, idx: StreamType) -> &Self::Output {
        match idx {
            StreamType::BiDi => &self.0[0],
            StreamType::UniDi => &self.0[1],
        }
    }
}

impl IndexMut<StreamType> for RemoteStreamLimits {
    fn index_mut(&mut self, idx: StreamType) -> &mut Self::Output {
        match idx {
            StreamType::BiDi => &mut self.0[0],
            StreamType::UniDi => &mut self.0[1],
        }
    }
}

pub struct LocalStreamsFlowControls {
    fc: [SenderFlowControl<StreamType>; 2],
    role_bit: u64,
}

impl LocalStreamsFlowControls {
    pub fn new(role: Role) -> Self {
        Self {
            fc: [
                SenderFlowControl::new(StreamType::BiDi, 0),
                SenderFlowControl::new(StreamType::UniDi, 0),
            ],
            role_bit: StreamId::role_bit(role),
        }
    }

    pub fn take_stream_id(&mut self, stream_type: StreamType) -> Option<StreamId> {
        let fc = match stream_type {
            StreamType::BiDi => &mut self.fc[0],
            StreamType::UniDi => &mut self.fc[1],
        };
        if fc.available() > 0 {
            let new_stream = fc.used();
            fc.consume(1);
            let type_bit = match stream_type {
                StreamType::BiDi => 0,
                StreamType::UniDi => 2,
            };
            Some(StreamId::from((new_stream << 2) + type_bit + self.role_bit))
        } else {
            fc.blocked();
            None
        }
    }
}

impl Index<StreamType> for LocalStreamsFlowControls {
    type Output = SenderFlowControl<StreamType>;

    fn index(&self, idx: StreamType) -> &Self::Output {
        match idx {
            StreamType::BiDi => &self.fc[0],
            StreamType::UniDi => &self.fc[1],
        }
    }
}

impl IndexMut<StreamType> for LocalStreamsFlowControls {
    fn index_mut(&mut self, idx: StreamType) -> &mut Self::Output {
        match idx {
            StreamType::BiDi => &mut self.fc[0],
            StreamType::UniDi => &mut self.fc[1],
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        LocalStreamsFlowControls, ReceiverFlowControl, RemoteStreamLimits, SenderFlowControl,
    };
    use crate::packet::PacketBuilder;
    use crate::stats::FrameStats;
    use crate::stream_id::{StreamId, StreamType};
    use crate::Error;
    use neqo_common::{Encoder, Role};

    #[test]
    fn blocked_at_zero() {
        let mut fc = SenderFlowControl::new((), 0);
        fc.blocked();
        assert_eq!(fc.blocked_needed(), Some(0));
    }

    #[test]
    fn blocked() {
        let mut fc = SenderFlowControl::new((), 10);
        fc.blocked();
        assert_eq!(fc.blocked_needed(), Some(10));
    }

    #[test]
    fn update_consume() {
        let mut fc = SenderFlowControl::new((), 10);
        fc.consume(10);
        assert_eq!(fc.available(), 0);
        fc.update(5); // An update lower than the current limit does nothing.
        assert_eq!(fc.available(), 0);
        fc.update(15);
        assert_eq!(fc.available(), 5);
        fc.consume(3);
        assert_eq!(fc.available(), 2);
    }

    #[test]
    fn update_clears_blocked() {
        let mut fc = SenderFlowControl::new((), 10);
        fc.blocked();
        assert_eq!(fc.blocked_needed(), Some(10));
        fc.update(5); // An update lower than the current limit does nothing.
        assert_eq!(fc.blocked_needed(), Some(10));
        fc.update(11);
        assert_eq!(fc.blocked_needed(), None);
    }

    #[test]
    fn lost_blocked_resent() {
        let mut fc = SenderFlowControl::new((), 10);
        fc.blocked();
        fc.blocked_sent();
        assert_eq!(fc.blocked_needed(), None);
        fc.lost(10);
        assert_eq!(fc.blocked_needed(), Some(10));
    }

    #[test]
    fn lost_after_increase() {
        let mut fc = SenderFlowControl::new((), 10);
        fc.blocked();
        fc.blocked_sent();
        assert_eq!(fc.blocked_needed(), None);
        fc.update(11);
        fc.lost(10);
        assert_eq!(fc.blocked_needed(), None);
    }

    #[test]
    fn lost_after_higher_blocked() {
        let mut fc = SenderFlowControl::new((), 10);
        fc.blocked();
        fc.blocked_sent();
        fc.update(11);
        fc.blocked();
        assert_eq!(fc.blocked_needed(), Some(11));
        fc.blocked_sent();
        fc.lost(10);
        assert_eq!(fc.blocked_needed(), None);
    }

    #[test]
    fn do_no_need_max_data_frame_at_start() {
        let fc = ReceiverFlowControl::new((), 0);
        assert_eq!(fc.max_data_needed(), None);
    }

    #[test]
    fn max_data_after_bytes_retired() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retired(49);
        assert_eq!(fc.max_data_needed(), None);
        fc.retired(51);
        assert_eq!(fc.max_data_needed(), Some(151));
    }

    #[test]
    fn need_max_data_frame_after_loss() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retired(100);
        assert_eq!(fc.max_data_needed(), Some(200));
        fc.max_data_sent(200);
        assert_eq!(fc.max_data_needed(), None);
        fc.lost(200);
        assert_eq!(fc.max_data_needed(), Some(200));
    }

    #[test]
    fn no_max_data_frame_after_old_loss() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retired(51);
        assert_eq!(fc.max_data_needed(), Some(151));
        fc.max_data_sent(151);
        assert_eq!(fc.max_data_needed(), None);
        fc.retired(102);
        assert_eq!(fc.max_data_needed(), Some(202));
        fc.max_data_sent(202);
        assert_eq!(fc.max_data_needed(), None);
        fc.lost(151);
        assert_eq!(fc.max_data_needed(), None);
    }

    #[test]
    fn force_send_max_data() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retired(10);
        assert_eq!(fc.max_data_needed(), None);
    }

    #[test]
    fn multiple_retries_after_frame_pending_is_set() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retired(51);
        assert_eq!(fc.max_data_needed(), Some(151));
        fc.retired(61);
        assert_eq!(fc.max_data_needed(), Some(161));
        fc.retired(88);
        assert_eq!(fc.max_data_needed(), Some(188));
        fc.retired(90);
        assert_eq!(fc.max_data_needed(), Some(190));
        fc.max_data_sent(190);
        assert_eq!(fc.max_data_needed(), None);
        fc.retired(141);
        assert_eq!(fc.max_data_needed(), Some(241));
        fc.max_data_sent(241);
        assert_eq!(fc.max_data_needed(), None);
    }

    #[test]
    fn new_retired_before_loss() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retired(51);
        assert_eq!(fc.max_data_needed(), Some(151));
        fc.max_data_sent(151);
        assert_eq!(fc.max_data_needed(), None);
        fc.retired(62);
        assert_eq!(fc.max_data_needed(), None);
        fc.lost(151);
        assert_eq!(fc.max_data_needed(), Some(162));
    }

    #[test]
    fn changing_max_active() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.set_max_active(50);
        // There is no MAX_STREAM_DATA frame needed.
        assert_eq!(fc.max_data_needed(), None);
        // We can still retire more than 50.
        fc.retired(60);
        // There is no MAX_STREAM_DATA fame needed yet.
        assert_eq!(fc.max_data_needed(), None);
        fc.retired(76);
        assert_eq!(fc.max_data_needed(), Some(126));

        // Increase max_active.
        fc.set_max_active(60);
        assert_eq!(fc.max_data_needed(), Some(136));

        // We can retire more than 60.
        fc.retired(136);
        assert_eq!(fc.max_data_needed(), Some(196));
    }

    #[test]
    fn local_streams_flow_control_new_stream_client() {
        let mut fc = RemoteStreamLimits::new(2, 1, Role::Client);
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(1))
            .unwrap());
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(5))
            .unwrap());
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(3))
            .unwrap());

        // Exeed limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(9)),
            Err(Error::StreamLimitError)
        );
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(7)),
            Err(Error::StreamLimitError)
        );

        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(1));
        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(5));
        assert_eq!(fc[StreamType::UniDi].take_stream_id(), StreamId::from(3));

        fc[StreamType::BiDi].add_retired(1);
        fc[StreamType::BiDi].send_flowc_update();
        // consume the frame
        let mut builder = PacketBuilder::short(Encoder::new(), false, &[]);
        let mut token = Vec::new();
        fc[StreamType::BiDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();
        // Now 9 can be a new StreamId.
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(9))
            .unwrap());
        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(9));
        // 13 exeeds limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(13)),
            Err(Error::StreamLimitError)
        );

        fc[StreamType::UniDi].add_retired(1);
        fc[StreamType::UniDi].send_flowc_update();
        // consume the frame
        fc[StreamType::UniDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();

        // Now 7 can be a new StreamId.
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(7))
            .unwrap());
        assert_eq!(fc[StreamType::UniDi].take_stream_id(), StreamId::from(7));
        // 11 exeeds limits
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(11)),
            Err(Error::StreamLimitError)
        );
    }

    #[test]
    fn local_streams_flow_control_new_stream_server() {
        let mut fc = RemoteStreamLimits::new(2, 1, Role::Server);
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(0))
            .unwrap());
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(4))
            .unwrap());
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(2))
            .unwrap());

        // Exeed limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(8)),
            Err(Error::StreamLimitError)
        );
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(6)),
            Err(Error::StreamLimitError)
        );

        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(0));
        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(4));
        assert_eq!(fc[StreamType::UniDi].take_stream_id(), StreamId::from(2));

        fc[StreamType::BiDi].add_retired(1);
        fc[StreamType::BiDi].send_flowc_update();
        // consume the frame
        let mut builder = PacketBuilder::short(Encoder::new(), false, &[]);
        let mut token = Vec::new();
        fc[StreamType::BiDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();
        // Now 8 can be a new StreamId.
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(8))
            .unwrap());
        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(8));
        // 12 exeeds limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(12)),
            Err(Error::StreamLimitError)
        );

        fc[StreamType::UniDi].add_retired(1);
        fc[StreamType::UniDi].send_flowc_update();
        // consume the frame
        fc[StreamType::UniDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();
        // Now 6 can be a new StreamId.
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(6))
            .unwrap());
        assert_eq!(fc[StreamType::UniDi].take_stream_id(), StreamId::from(6));
        // 10 exeeds limits
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(10)),
            Err(Error::StreamLimitError)
        );
    }

    #[test]
    fn remote_streams_flow_control_new_stream_client() {
        let mut fc = LocalStreamsFlowControls::new(Role::Client);

        fc[StreamType::BiDi].update(2);
        fc[StreamType::UniDi].update(1);

        // Add streams
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(0)
        );
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(4)
        );
        assert_eq!(fc.take_stream_id(StreamType::BiDi), None);
        assert_eq!(
            fc.take_stream_id(StreamType::UniDi).unwrap(),
            StreamId::from(2)
        );
        assert_eq!(fc.take_stream_id(StreamType::UniDi), None);

        // Increase limit
        fc[StreamType::BiDi].update(3);
        fc[StreamType::UniDi].update(2);
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(8)
        );
        assert_eq!(fc.take_stream_id(StreamType::BiDi), None);
        assert_eq!(
            fc.take_stream_id(StreamType::UniDi).unwrap(),
            StreamId::from(6)
        );
        assert_eq!(fc.take_stream_id(StreamType::UniDi), None);
    }

    #[test]
    fn remote_streams_flow_control_new_stream_server() {
        let mut fc = LocalStreamsFlowControls::new(Role::Server);

        fc[StreamType::BiDi].update(2);
        fc[StreamType::UniDi].update(1);

        // Add streams
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(1)
        );
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(5)
        );
        assert_eq!(fc.take_stream_id(StreamType::BiDi), None);
        assert_eq!(
            fc.take_stream_id(StreamType::UniDi).unwrap(),
            StreamId::from(3)
        );
        assert_eq!(fc.take_stream_id(StreamType::UniDi), None);

        // Increase limit
        fc[StreamType::BiDi].update(3);
        fc[StreamType::UniDi].update(2);
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(9)
        );
        assert_eq!(fc.take_stream_id(StreamType::BiDi), None);
        assert_eq!(
            fc.take_stream_id(StreamType::UniDi).unwrap(),
            StreamId::from(7)
        );
        assert_eq!(fc.take_stream_id(StreamType::UniDi), None);
    }
}
