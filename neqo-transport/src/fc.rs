// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracks possibly-redundant flow control signals from other code and converts
// into flow control frames needing to be sent to the remote.

use std::{
    cmp::min,
    fmt::Debug,
    ops::{Deref, DerefMut, Index, IndexMut},
    time::{Duration, Instant},
};

use neqo_common::{qdebug, qtrace, Role};

use crate::{
    frame::{
        FRAME_TYPE_DATA_BLOCKED, FRAME_TYPE_MAX_DATA, FRAME_TYPE_MAX_STREAMS_BIDI,
        FRAME_TYPE_MAX_STREAMS_UNIDI, FRAME_TYPE_MAX_STREAM_DATA, FRAME_TYPE_STREAMS_BLOCKED_BIDI,
        FRAME_TYPE_STREAMS_BLOCKED_UNIDI, FRAME_TYPE_STREAM_DATA_BLOCKED,
    },
    packet::PacketBuilder,
    recovery::{RecoveryToken, StreamRecoveryToken},
    recv_stream::MAX_RECV_WINDOW_SIZE,
    stats::FrameStats,
    stream_id::{StreamId, StreamType},
    Error, Res,
};

/// Fraction of a flow control window after which a receiver sends a window
/// update.
///
/// In steady-state and max utilization, a value of 4 leads to 4 window updates
/// per RTT.
///
/// Value aligns with [`crate::connection::params::DEFAULT_ACK_RATIO`].
pub const WINDOW_UPDATE_FRACTION: u64 = 4;

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
    pub const fn new(subject: T, initial: u64) -> Self {
        Self {
            subject,
            limit: initial,
            used: 0,
            blocked_at: 0,
            blocked_frame: false,
        }
    }

    /// Update the maximum. Returns `Some` with the updated available flow
    /// control if the change was an increase and `None` otherwise.
    pub fn update(&mut self, limit: u64) -> Option<usize> {
        debug_assert!(limit < u64::MAX);
        (limit > self.limit).then(|| {
            self.limit = limit;
            self.blocked_frame = false;
            self.available()
        })
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
    pub const fn used(&self) -> u64 {
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
    const fn blocked_needed(&self) -> Option<u64> {
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
    pub fn frame_lost(&mut self, limit: u64) {
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
    ) {
        if let Some(limit) = self.blocked_needed() {
            if builder.write_varint_frame(&[FRAME_TYPE_DATA_BLOCKED, limit]) {
                stats.data_blocked += 1;
                tokens.push(RecoveryToken::Stream(StreamRecoveryToken::DataBlocked(
                    limit,
                )));
                self.blocked_sent();
            }
        }
    }
}

impl SenderFlowControl<StreamId> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        if let Some(limit) = self.blocked_needed() {
            if builder.write_varint_frame(&[
                FRAME_TYPE_STREAM_DATA_BLOCKED,
                self.subject.as_u64(),
                limit,
            ]) {
                stats.stream_data_blocked += 1;
                tokens.push(RecoveryToken::Stream(
                    StreamRecoveryToken::StreamDataBlocked {
                        stream_id: self.subject,
                        limit,
                    },
                ));
                self.blocked_sent();
            }
        }
    }
}

impl SenderFlowControl<StreamType> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        if let Some(limit) = self.blocked_needed() {
            let frame = match self.subject {
                StreamType::BiDi => FRAME_TYPE_STREAMS_BLOCKED_BIDI,
                StreamType::UniDi => FRAME_TYPE_STREAMS_BLOCKED_UNIDI,
            };
            if builder.write_varint_frame(&[frame, limit]) {
                stats.streams_blocked += 1;
                tokens.push(RecoveryToken::Stream(StreamRecoveryToken::StreamsBlocked {
                    stream_type: self.subject,
                    limit,
                }));
                self.blocked_sent();
            }
        }
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
    /// Last max allowed sent.
    max_allowed: u64,
    /// Last time a flow control update was sent.
    ///
    /// Only used in [`ReceiverFlowControl<StreamId>`] implementation for
    /// receive window auto-tuning.
    max_allowed_sent_at: Option<Instant>,
    /// Item received, but not retired yet.
    /// This will be used for byte flow control: each stream will remember its largest byte
    /// offset received and session flow control will remember the sum of all bytes consumed
    /// by all streams.
    consumed: u64,
    /// Retired items.
    retired: u64,
    frame_pending: bool,
}

impl<T> ReceiverFlowControl<T>
where
    T: Debug + Sized,
{
    /// Make a new instance with the initial value and subject.
    pub const fn new(subject: T, max: u64) -> Self {
        Self {
            subject,
            max_active: max,
            max_allowed: max,
            max_allowed_sent_at: None,
            consumed: 0,
            retired: 0,
            frame_pending: false,
        }
    }

    /// Retire some items and maybe send flow control
    /// update.
    pub fn retire(&mut self, retired: u64) {
        if retired <= self.retired {
            return;
        }

        self.retired = retired;
        if self.should_send_flowc_update() {
            self.frame_pending = true;
        }
    }

    /// This function is called when `STREAM_DATA_BLOCKED` frame is received.
    /// The flow control will try to send an update if possible.
    pub fn send_flowc_update(&mut self) {
        if self.retired + self.max_active > self.max_allowed {
            self.frame_pending = true;
        }
    }

    const fn should_send_flowc_update(&self) -> bool {
        let window_bytes_unused = self.max_allowed.saturating_sub(self.retired);
        window_bytes_unused < self.max_active - self.max_active / WINDOW_UPDATE_FRACTION
    }

    pub const fn frame_needed(&self) -> bool {
        self.frame_pending
    }

    pub const fn next_limit(&self) -> u64 {
        self.retired + self.max_active
    }

    pub const fn max_active(&self) -> u64 {
        self.max_active
    }

    pub fn frame_lost(&mut self, maximum_data: u64) {
        if maximum_data == self.max_allowed {
            self.frame_pending = true;
        }
    }

    fn frame_sent(&mut self, new_max: u64) {
        self.max_allowed = new_max;
        self.frame_pending = false;
    }

    pub fn set_max_active(&mut self, max: u64) {
        // If max_active has been increased, send an update immediately.
        self.frame_pending |= self.max_active < max;
        self.max_active = max;
    }

    pub const fn retired(&self) -> u64 {
        self.retired
    }

    pub const fn consumed(&self) -> u64 {
        self.consumed
    }
}

impl ReceiverFlowControl<()> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        if !self.frame_needed() {
            return;
        }
        let max_allowed = self.next_limit();
        if builder.write_varint_frame(&[FRAME_TYPE_MAX_DATA, max_allowed]) {
            stats.max_data += 1;
            tokens.push(RecoveryToken::Stream(StreamRecoveryToken::MaxData(
                max_allowed,
            )));
            self.frame_sent(max_allowed);
        }
    }

    pub fn add_retired(&mut self, count: u64) {
        debug_assert!(self.retired + count <= self.consumed);
        self.retired += count;
        if self.should_send_flowc_update() {
            self.frame_pending = true;
        }
    }

    pub fn consume(&mut self, count: u64) -> Res<()> {
        if self.consumed + count > self.max_allowed {
            qtrace!(
                "Session RX window exceeded: consumed:{} new:{count} limit:{}",
                self.consumed,
                self.max_allowed
            );
            return Err(Error::FlowControlError);
        }
        self.consumed += count;
        Ok(())
    }
}

impl Default for ReceiverFlowControl<()> {
    fn default() -> Self {
        Self::new((), 0)
    }
}

impl ReceiverFlowControl<StreamId> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
        now: Instant,
        rtt: Duration,
    ) {
        if !self.frame_needed() {
            return;
        }

        // Auto-tune max_active, i.e. the flow control window.
        //
        // If the sending rate ( window_bytes used / elapsed ) exceeds the rate
        // allowed by the maximum flow control window and the current rtt (
        // max_active / rtt ), try to increase the maximum flow control window (
        // max_active ).
        if let Some(max_allowed_sent_at) = self.max_allowed_sent_at {
            let elapsed = now.duration_since(max_allowed_sent_at);
            let window_bytes_used = self.max_active - (self.max_allowed - self.retired);

            // Same as `elapsed / rtt < window_bytes_used / max_active`
            // without floating point division.
            if elapsed.as_micros() * u128::from(self.max_active)
                < rtt.as_micros() * u128::from(window_bytes_used)
            {
                let prev_max_active = self.max_active;
                // Try doubling the flow control window.
                //
                // Note that the flow control window should grow at least as
                // fast as the congestion control window, in order to not
                // unnecessarily limit throughput.
                self.max_active = min(2 * self.max_active, MAX_RECV_WINDOW_SIZE);
                qdebug!(
                    "Increasing max stream receive window: previous max_active: {} MiB new max_active: {} MiB last update: {:?} rtt: {rtt:?} stream_id: {}",
                    prev_max_active / 1024 / 1024, self.max_active / 1024 / 1024,  now-self.max_allowed_sent_at.unwrap(), self.subject,
                );
            }
        }

        let max_allowed = self.next_limit();
        if builder.write_varint_frame(&[
            FRAME_TYPE_MAX_STREAM_DATA,
            self.subject.as_u64(),
            max_allowed,
        ]) {
            stats.max_stream_data += 1;
            tokens.push(RecoveryToken::Stream(StreamRecoveryToken::MaxStreamData {
                stream_id: self.subject,
                max_data: max_allowed,
            }));
            self.frame_sent(max_allowed);
            self.max_allowed_sent_at = Some(now);
        }
    }

    pub fn add_retired(&mut self, count: u64) {
        debug_assert!(self.retired + count <= self.consumed);
        self.retired += count;
        if self.should_send_flowc_update() {
            self.frame_pending = true;
        }
    }

    pub fn set_consumed(&mut self, consumed: u64) -> Res<u64> {
        if consumed <= self.consumed {
            return Ok(0);
        }

        if consumed > self.max_allowed {
            qtrace!("Stream RX window exceeded: {consumed}");
            return Err(Error::FlowControlError);
        }
        let new_consumed = consumed - self.consumed;
        self.consumed = consumed;
        Ok(new_consumed)
    }
}

impl Default for ReceiverFlowControl<StreamId> {
    fn default() -> Self {
        Self::new(StreamId::new(0), 0)
    }
}

impl ReceiverFlowControl<StreamType> {
    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) {
        if !self.frame_needed() {
            return;
        }
        let max_streams = self.next_limit();
        let frame = match self.subject {
            StreamType::BiDi => FRAME_TYPE_MAX_STREAMS_BIDI,
            StreamType::UniDi => FRAME_TYPE_MAX_STREAMS_UNIDI,
        };
        if builder.write_varint_frame(&[frame, max_streams]) {
            stats.max_streams += 1;
            tokens.push(RecoveryToken::Stream(StreamRecoveryToken::MaxStreams {
                stream_type: self.subject,
                max_streams,
            }));
            self.frame_sent(max_streams);
        }
    }

    /// Check if received item exceeds the allowed flow control limit.
    pub const fn check_allowed(&self, new_end: u64) -> bool {
        new_end < self.max_allowed
    }

    /// Retire given amount of additional data.
    /// This function will send flow updates immediately.
    pub fn add_retired(&mut self, count: u64) {
        self.retired += count;
        if count > 0 {
            self.send_flowc_update();
        }
    }
}

pub struct RemoteStreamLimit {
    streams_fc: ReceiverFlowControl<StreamType>,
    next_stream: StreamId,
}

impl RemoteStreamLimit {
    pub const fn new(stream_type: StreamType, max_streams: u64, role: Role) -> Self {
        Self {
            streams_fc: ReceiverFlowControl::new(stream_type, max_streams),
            // // This is for a stream created by a peer, therefore we use role.remote().
            next_stream: StreamId::init(stream_type, role.remote()),
        }
    }

    pub const fn is_allowed(&self, stream_id: StreamId) -> bool {
        let stream_idx = stream_id.as_u64() >> 2;
        self.streams_fc.check_allowed(stream_idx)
    }

    pub fn is_new_stream(&self, stream_id: StreamId) -> Res<bool> {
        if !self.is_allowed(stream_id) {
            return Err(Error::StreamLimitError);
        }
        Ok(stream_id >= self.next_stream)
    }

    pub fn take_stream_id(&mut self) -> StreamId {
        let new_stream = self.next_stream;
        self.next_stream.next();
        assert!(self.is_allowed(new_stream));
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

pub struct RemoteStreamLimits {
    bidirectional: RemoteStreamLimit,
    unidirectional: RemoteStreamLimit,
}

impl RemoteStreamLimits {
    pub const fn new(local_max_stream_bidi: u64, local_max_stream_uni: u64, role: Role) -> Self {
        Self {
            bidirectional: RemoteStreamLimit::new(StreamType::BiDi, local_max_stream_bidi, role),
            unidirectional: RemoteStreamLimit::new(StreamType::UniDi, local_max_stream_uni, role),
        }
    }
}

impl Index<StreamType> for RemoteStreamLimits {
    type Output = RemoteStreamLimit;

    fn index(&self, index: StreamType) -> &Self::Output {
        match index {
            StreamType::BiDi => &self.bidirectional,
            StreamType::UniDi => &self.unidirectional,
        }
    }
}

impl IndexMut<StreamType> for RemoteStreamLimits {
    fn index_mut(&mut self, index: StreamType) -> &mut Self::Output {
        match index {
            StreamType::BiDi => &mut self.bidirectional,
            StreamType::UniDi => &mut self.unidirectional,
        }
    }
}

pub struct LocalStreamLimits {
    bidirectional: SenderFlowControl<StreamType>,
    unidirectional: SenderFlowControl<StreamType>,
    role_bit: u64,
}

impl LocalStreamLimits {
    pub const fn new(role: Role) -> Self {
        Self {
            bidirectional: SenderFlowControl::new(StreamType::BiDi, 0),
            unidirectional: SenderFlowControl::new(StreamType::UniDi, 0),
            role_bit: StreamId::role_bit(role),
        }
    }

    pub fn take_stream_id(&mut self, stream_type: StreamType) -> Option<StreamId> {
        let fc = match stream_type {
            StreamType::BiDi => &mut self.bidirectional,
            StreamType::UniDi => &mut self.unidirectional,
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

impl Index<StreamType> for LocalStreamLimits {
    type Output = SenderFlowControl<StreamType>;

    fn index(&self, index: StreamType) -> &Self::Output {
        match index {
            StreamType::BiDi => &self.bidirectional,
            StreamType::UniDi => &self.unidirectional,
        }
    }
}

impl IndexMut<StreamType> for LocalStreamLimits {
    fn index_mut(&mut self, index: StreamType) -> &mut Self::Output {
        match index {
            StreamType::BiDi => &mut self.bidirectional,
            StreamType::UniDi => &mut self.unidirectional,
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        cmp::min,
        collections::VecDeque,
        time::{Duration, Instant},
    };

    use neqo_common::{qdebug, Encoder, Role};
    use neqo_crypto::random;

    use super::{LocalStreamLimits, ReceiverFlowControl, RemoteStreamLimits, SenderFlowControl};
    use crate::{
        fc::WINDOW_UPDATE_FRACTION,
        packet::PacketBuilder,
        recv_stream::MAX_RECV_WINDOW_SIZE,
        stats::FrameStats,
        stream_id::{StreamId, StreamType},
        Error, Res, INITIAL_RECV_WINDOW_SIZE,
    };

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
        fc.frame_lost(10);
        assert_eq!(fc.blocked_needed(), Some(10));
    }

    #[test]
    fn lost_after_increase() {
        let mut fc = SenderFlowControl::new((), 10);
        fc.blocked();
        fc.blocked_sent();
        assert_eq!(fc.blocked_needed(), None);
        fc.update(11);
        fc.frame_lost(10);
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
        fc.frame_lost(10);
        assert_eq!(fc.blocked_needed(), None);
    }

    #[test]
    fn do_no_need_max_allowed_frame_at_start() {
        let fc = ReceiverFlowControl::new((), 0);
        assert!(!fc.frame_needed());
    }

    #[test]
    fn max_allowed_after_items_retired() {
        let window = 100;
        let trigger = window / WINDOW_UPDATE_FRACTION;
        let mut fc = ReceiverFlowControl::new((), window);
        fc.retire(trigger);
        assert!(!fc.frame_needed());
        fc.retire(trigger + 1);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), window + trigger + 1);
    }

    #[test]
    fn need_max_allowed_frame_after_loss() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retire(100);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 200);
        fc.frame_sent(200);
        assert!(!fc.frame_needed());
        fc.frame_lost(200);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 200);
    }

    #[test]
    fn no_max_allowed_frame_after_old_loss() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retire(51);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 151);
        fc.frame_sent(151);
        assert!(!fc.frame_needed());
        fc.retire(102);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 202);
        fc.frame_sent(202);
        assert!(!fc.frame_needed());
        fc.frame_lost(151);
        assert!(!fc.frame_needed());
    }

    #[test]
    fn force_send_max_allowed() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retire(10);
        assert!(!fc.frame_needed());
    }

    #[test]
    fn multiple_retries_after_frame_pending_is_set() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retire(51);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 151);
        fc.retire(61);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 161);
        fc.retire(88);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 188);
        fc.retire(90);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 190);
        fc.frame_sent(190);
        assert!(!fc.frame_needed());
        fc.retire(141);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 241);
        fc.frame_sent(241);
        assert!(!fc.frame_needed());
    }

    #[test]
    fn new_retired_before_loss() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.retire(51);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 151);
        fc.frame_sent(151);
        assert!(!fc.frame_needed());
        fc.retire(62);
        assert!(!fc.frame_needed());
        fc.frame_lost(151);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 162);
    }

    #[test]
    fn changing_max_active() {
        let mut fc = ReceiverFlowControl::new((), 100);
        fc.set_max_active(50);
        // There is no MAX_STREAM_DATA frame needed.
        assert!(!fc.frame_needed());
        // We can still retire more than 50.
        fc.retire(60);
        // There is no MAX_STREAM_DATA frame needed yet.
        assert!(!fc.frame_needed());
        fc.retire(76);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 126);

        // Increase max_active.
        fc.set_max_active(60);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 136);

        // We can retire more than 60.
        fc.retire(136);
        assert!(fc.frame_needed());
        assert_eq!(fc.next_limit(), 196);
    }

    fn remote_stream_limits(role: Role, bidi: u64, unidi: u64) {
        let mut fc = RemoteStreamLimits::new(2, 1, role);
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(bidi))
            .unwrap());
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(bidi + 4))
            .unwrap());
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(unidi))
            .unwrap());

        // Exceed limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(bidi + 8)),
            Err(Error::StreamLimitError)
        );
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(unidi + 4)),
            Err(Error::StreamLimitError)
        );

        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(bidi));
        assert_eq!(
            fc[StreamType::BiDi].take_stream_id(),
            StreamId::from(bidi + 4)
        );
        assert_eq!(
            fc[StreamType::UniDi].take_stream_id(),
            StreamId::from(unidi)
        );

        fc[StreamType::BiDi].add_retired(1);
        fc[StreamType::BiDi].send_flowc_update();
        // consume the frame
        let mut builder = PacketBuilder::short(Encoder::new(), false, None::<&[u8]>);
        let mut tokens = Vec::new();
        fc[StreamType::BiDi].write_frames(&mut builder, &mut tokens, &mut FrameStats::default());
        assert_eq!(tokens.len(), 1);

        // Now 9 can be a new StreamId.
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(bidi + 8))
            .unwrap());
        assert_eq!(
            fc[StreamType::BiDi].take_stream_id(),
            StreamId::from(bidi + 8)
        );
        // 13 still exceeds limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(bidi + 12)),
            Err(Error::StreamLimitError)
        );

        fc[StreamType::UniDi].add_retired(1);
        fc[StreamType::UniDi].send_flowc_update();
        // consume the frame
        fc[StreamType::UniDi].write_frames(&mut builder, &mut tokens, &mut FrameStats::default());
        assert_eq!(tokens.len(), 2);

        // Now 7 can be a new StreamId.
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(unidi + 4))
            .unwrap());
        assert_eq!(
            fc[StreamType::UniDi].take_stream_id(),
            StreamId::from(unidi + 4)
        );
        // 11 exceeds limits
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(unidi + 8)),
            Err(Error::StreamLimitError)
        );
    }

    #[test]
    fn remote_stream_limits_new_stream_client() {
        remote_stream_limits(Role::Client, 1, 3);
    }

    #[test]
    fn remote_stream_limits_new_stream_server() {
        remote_stream_limits(Role::Server, 0, 2);
    }

    #[should_panic(expected = ".is_allowed")]
    #[test]
    fn remote_stream_limits_asserts_if_limit_exceeded() {
        let mut fc = RemoteStreamLimits::new(2, 1, Role::Client);
        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(1));
        assert_eq!(fc[StreamType::BiDi].take_stream_id(), StreamId::from(5));
        _ = fc[StreamType::BiDi].take_stream_id();
    }

    fn local_stream_limits(role: Role, bidi: u64, unidi: u64) {
        let mut fc = LocalStreamLimits::new(role);

        fc[StreamType::BiDi].update(2);
        fc[StreamType::UniDi].update(1);

        // Add streams
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(bidi)
        );
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(bidi + 4)
        );
        assert_eq!(fc.take_stream_id(StreamType::BiDi), None);
        assert_eq!(
            fc.take_stream_id(StreamType::UniDi).unwrap(),
            StreamId::from(unidi)
        );
        assert_eq!(fc.take_stream_id(StreamType::UniDi), None);

        // Increase limit
        fc[StreamType::BiDi].update(3);
        fc[StreamType::UniDi].update(2);
        assert_eq!(
            fc.take_stream_id(StreamType::BiDi).unwrap(),
            StreamId::from(bidi + 8)
        );
        assert_eq!(fc.take_stream_id(StreamType::BiDi), None);
        assert_eq!(
            fc.take_stream_id(StreamType::UniDi).unwrap(),
            StreamId::from(unidi + 4)
        );
        assert_eq!(fc.take_stream_id(StreamType::UniDi), None);
    }

    #[test]
    fn local_stream_limits_new_stream_client() {
        local_stream_limits(Role::Client, 0, 2);
    }

    #[test]
    fn local_stream_limits_new_stream_server() {
        local_stream_limits(Role::Server, 1, 3);
    }

    fn write_frames(fc: &mut ReceiverFlowControl<StreamId>, rtt: Duration, now: Instant) -> usize {
        let mut builder = PacketBuilder::short(Encoder::new(), false, None::<&[u8]>);
        let mut tokens = Vec::new();
        fc.write_frames(
            &mut builder,
            &mut tokens,
            &mut FrameStats::default(),
            now,
            rtt,
        );
        tokens.len()
    }

    #[test]
    fn trigger_factor() -> Res<()> {
        let rtt = Duration::from_millis(40);
        let now = Instant::now();
        let mut fc = ReceiverFlowControl::new(StreamId::new(0), INITIAL_RECV_WINDOW_SIZE as u64);

        let fraction = INITIAL_RECV_WINDOW_SIZE as u64 / WINDOW_UPDATE_FRACTION;

        let consumed = fc.set_consumed(fraction)?;
        fc.add_retired(consumed);
        assert_eq!(write_frames(&mut fc, rtt, now), 0);

        let consumed = fc.set_consumed(fraction + 1)?;
        assert_eq!(write_frames(&mut fc, rtt, now), 0);

        fc.add_retired(consumed);
        assert_eq!(write_frames(&mut fc, rtt, now), 1);

        Ok(())
    }

    #[test]
    fn auto_tuning_increase_no_decrease() -> Res<()> {
        let rtt = Duration::from_millis(40);
        let mut now = Instant::now();
        let mut fc = ReceiverFlowControl::new(StreamId::new(0), INITIAL_RECV_WINDOW_SIZE as u64);
        let initial_max_active = fc.max_active();

        // Consume and retire multiple receive windows without increasing time.
        for _ in 1..11 {
            let consumed = fc.set_consumed(fc.next_limit())?;
            fc.add_retired(consumed);
            write_frames(&mut fc, rtt, now);
        }
        let increased_max_active = fc.max_active();

        assert!(
            initial_max_active < increased_max_active,
            "expect receive window auto-tuning to increase max_active on 0 latency connection"
        );

        // Huge idle time.
        now += Duration::from_secs(60 * 60); // 1h
        let consumed = fc.set_consumed(fc.next_limit()).unwrap();
        fc.add_retired(consumed);

        assert_eq!(write_frames(&mut fc, rtt, now), 1);
        assert_eq!(
            increased_max_active,
            fc.max_active(),
            "expect receive window auto-tuning never to decrease max_active"
        );

        Ok(())
    }

    #[test]
    fn stream_data_blocked_triggers_auto_tuning() -> Res<()> {
        let rtt = Duration::from_millis(40);
        let now = Instant::now();
        let mut fc = ReceiverFlowControl::new(StreamId::new(0), INITIAL_RECV_WINDOW_SIZE as u64);

        // Send first window update to give auto-tuning algorithm a baseline.
        let consumed = fc.set_consumed(fc.next_limit())?;
        fc.add_retired(consumed);
        assert_eq!(write_frames(&mut fc, rtt, now), 1);

        // Use up a single byte only, i.e. way below WINDOW_UPDATE_FRACTION.
        let consumed = fc.set_consumed(fc.retired + 1)?;
        fc.add_retired(consumed);
        assert_eq!(
            write_frames(&mut fc, rtt, now),
            0,
            "expect receiver to not send window update unprompted"
        );

        // Receive STREAM_DATA_BLOCKED frame.
        fc.send_flowc_update();
        let previous_max_active = fc.max_active();
        assert_eq!(
            write_frames(&mut fc, rtt, now),
            1,
            "expect receiver to send window update"
        );
        assert!(
            previous_max_active < fc.max_active(),
            "expect receiver to auto-tune (i.e. increase) max_active"
        );

        Ok(())
    }

    #[allow(clippy::cast_precision_loss)]
    #[test]
    fn auto_tuning_approximates_bandwidth_delay_product() -> Res<()> {
        const DATA_FRAME_SIZE: u64 = 1_500;

        test_fixture::fixture_init();

        // Run multiple iterations with randomized bandwidth and rtt.
        for _ in 0..1_000 {
            // Random bandwidth between 1 Mbit/s and 1 Gbit/s.
            let bandwidth = u64::from(u16::from_be_bytes(random::<2>()) % 1_000 + 1) * 1024 * 1024;
            // Random delay between 1 ms and 256 ms.
            let rtt = Duration::from_millis(u64::from(random::<1>()[0]) + 1);
            let bdp = bandwidth * u64::try_from(rtt.as_millis()).unwrap() / 1_000 / 8;

            let mut now = Instant::now();

            let mut send_to_recv = VecDeque::new();
            let mut recv_to_send = VecDeque::new();

            let mut last_max_active = INITIAL_RECV_WINDOW_SIZE as u64;
            let mut last_max_active_changed = now;

            let mut sender_window = INITIAL_RECV_WINDOW_SIZE as u64;
            let mut fc =
                ReceiverFlowControl::new(StreamId::new(0), INITIAL_RECV_WINDOW_SIZE as u64);

            loop {
                // Sender receives window updates.
                if recv_to_send.front().is_some_and(|(at, _)| *at <= now) {
                    let (_, update) = recv_to_send.pop_front().unwrap();
                    sender_window += update;
                }

                // Sender sends data frames.
                let sender_progressed = if sender_window > 0 {
                    let to_send = min(DATA_FRAME_SIZE, sender_window);
                    send_to_recv.push_back((now, to_send));
                    sender_window -= to_send;
                    now += Duration::from_secs_f64(to_send as f64 * 8.0 / bandwidth as f64);
                    true
                } else {
                    false
                };

                // Receiver receives data frames.
                let mut receiver_progressed = false;
                if send_to_recv.front().is_some_and(|(at, _)| *at <= now) {
                    let (_, data) = send_to_recv.pop_front().unwrap();
                    let consumed = fc.set_consumed(fc.retired() + data)?;
                    fc.add_retired(consumed);

                    // Receiver sends window updates.
                    let prev_max_allowed = fc.max_allowed;
                    if write_frames(&mut fc, rtt, now) == 1 {
                        recv_to_send.push_front((now, fc.max_allowed - prev_max_allowed));
                        receiver_progressed = true;
                        if last_max_active < fc.max_active() {
                            last_max_active = fc.max_active();
                            last_max_active_changed = now;
                        }
                    }
                }

                // When idle, travel in (simulated) time.
                if !sender_progressed && !receiver_progressed {
                    now = [recv_to_send.front(), send_to_recv.front()]
                        .into_iter()
                        .flatten()
                        .map(|(at, _)| *at)
                        .min()
                        .expect("both are None");
                }

                // Consider auto-tuning done once receive window hasn't changed for 4 RTT.
                if now.duration_since(last_max_active_changed) > 4 * rtt {
                    break;
                }
            }

            let summary = format!(
                "Got receive window of {} MiB on connection with bandwidth {} MBit/s ({bandwidth} Bit/s), delay {rtt:?}, bdp {} MiB.",
                fc.max_active() / 1024 / 1024,
                bandwidth / 1_000 / 1_000,
                bdp / 1024 / 1024,
            );

            assert!(
                fc.max_active() >= bdp || fc.max_active() == MAX_RECV_WINDOW_SIZE,
                "{summary} Receive window is smaller than the bdp."
            );
            assert!(
                fc.max_active <= 2 * bdp || fc.max_active == INITIAL_RECV_WINDOW_SIZE as u64,
                "{summary} Receive window is more than twice the bdp."
            );

            qdebug!("{summary}");
        }

        Ok(())
    }
}
