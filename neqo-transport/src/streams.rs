// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Stream ID and stream index handling.

use crate::fc::{
    LocalStreamsFlowControls, ReceiverFlowControl, RemoteStreamLimits, SenderFlowControl,
};
use crate::frame::Frame;
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::recv_stream::{RecvStream, RecvStreams};
use crate::send_stream::{SendStream, SendStreams, TransmissionPriority};
use crate::stats::FrameStats;
use crate::stream_id::{StreamId, StreamType};
use crate::tparams::{self, TransportParametersHandler};
use crate::ConnectionEvents;
use crate::{Error, Res};
use neqo_common::{qtrace, qwarn, Role};
use std::cell::RefCell;
use std::rc::Rc;

pub struct Streams {
    role: Role,
    tps: Rc<RefCell<TransportParametersHandler>>,
    events: ConnectionEvents,
    flow_control_sender: Rc<RefCell<SenderFlowControl<()>>>,
    flow_control_receiver: Rc<RefCell<ReceiverFlowControl<()>>>,
    remote_streams_fc: RemoteStreamLimits,
    local_streams_fc: LocalStreamsFlowControls,
    pub(crate) send_streams: SendStreams,
    pub(crate) recv_streams: RecvStreams,
}

impl Streams {
    pub fn new(
        tps: Rc<RefCell<TransportParametersHandler>>,
        role: Role,
        events: ConnectionEvents,
    ) -> Self {
        let limit_bidi = tps
            .borrow()
            .local
            .get_integer(tparams::INITIAL_MAX_STREAMS_BIDI);
        let limit_uni = tps
            .borrow()
            .local
            .get_integer(tparams::INITIAL_MAX_STREAMS_UNI);
        let max_data = tps.borrow().local.get_integer(tparams::INITIAL_MAX_DATA);
        Self {
            role,
            tps,
            events,
            flow_control_sender: Rc::new(RefCell::new(SenderFlowControl::new((), 0))),
            flow_control_receiver: Rc::new(RefCell::new(ReceiverFlowControl::new((), max_data))),
            remote_streams_fc: RemoteStreamLimits::new(limit_bidi, limit_uni, role),
            local_streams_fc: LocalStreamsFlowControls::new(role),
            send_streams: SendStreams::default(),
            recv_streams: RecvStreams::default(),
        }
    }

    pub fn client_0rtt_rejected(&mut self) {
        self.send_streams.clear();
        self.recv_streams.clear();
        self.remote_streams_fc = RemoteStreamLimits::new(
            self.tps
                .borrow()
                .local
                .get_integer(tparams::INITIAL_MAX_STREAMS_BIDI),
            self.tps
                .borrow()
                .local
                .get_integer(tparams::INITIAL_MAX_STREAMS_UNI),
            self.role,
        );
        self.local_streams_fc = LocalStreamsFlowControls::new(self.role);
    }

    pub fn input_frame(&mut self, frame: Frame, stats: &mut FrameStats) -> Res<()> {
        match frame {
            Frame::ResetStream {
                stream_id,
                application_error_code,
                ..
            } => {
                // TODO(agrover@mozilla.com): use final_size for connection MaxData calc
                stats.reset_stream += 1;
                if let (_, Some(rs)) = self.obtain_stream(stream_id)? {
                    rs.reset(application_error_code);
                }
            }
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => {
                stats.stop_sending += 1;
                self.events
                    .send_stream_stop_sending(stream_id, application_error_code);
                if let (Some(ss), _) = self.obtain_stream(stream_id)? {
                    ss.reset(application_error_code);
                }
            }
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
                ..
            } => {
                stats.stream += 1;
                if let (_, Some(rs)) = self.obtain_stream(stream_id)? {
                    rs.inbound_stream_frame(fin, offset, data)?;
                }
            }
            Frame::MaxData { maximum_data } => {
                stats.max_data += 1;
                self.handle_max_data(maximum_data);
            }
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                qtrace!(
                    "Stream {} Received MaxStreamData {}",
                    stream_id,
                    maximum_stream_data
                );
                stats.max_stream_data += 1;
                if let (Some(ss), _) = self.obtain_stream(stream_id)? {
                    ss.set_max_stream_data(maximum_stream_data);
                }
            }
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {
                stats.max_streams += 1;
                self.handle_max_streams(stream_type, maximum_streams);
            }
            Frame::DataBlocked { data_limit } => {
                // Should never happen since we set data limit to max
                qwarn!("Received DataBlocked with data limit {}", data_limit);
                stats.data_blocked += 1;
                self.handle_data_blocked();
            }
            Frame::StreamDataBlocked { stream_id, .. } => {
                qtrace!("Received StreamDataBlocked");
                stats.stream_data_blocked += 1;
                // Terminate connection with STREAM_STATE_ERROR if send-only
                // stream (-transport 19.13)
                if stream_id.is_send_only(self.role) {
                    return Err(Error::StreamStateError);
                }

                if let (_, Some(rs)) = self.obtain_stream(stream_id)? {
                    rs.send_flowc_update();
                }
            }
            Frame::StreamsBlocked { .. } => {
                stats.streams_blocked += 1;
                // We send an update evry time we retire a stream. There is no need to
                // trigger flow updates here.
            }
            _ => unreachable!("This is not a stream RecoveryToken"),
        }
        Ok(())
    }

    pub fn write_frames(
        &mut self,
        priority: TransmissionPriority,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if priority == TransmissionPriority::Important {
            // Send `DATA_BLOCKED` as necessary.
            self.flow_control_sender
                .borrow_mut()
                .write_frames(builder, tokens, stats)?;
            if builder.remaining() < 2 {
                return Ok(());
            }

            // Send `MAX_DATA` as necessary.
            self.flow_control_receiver
                .borrow_mut()
                .write_frames(builder, tokens, stats)?;
            if builder.remaining() < 2 {
                return Ok(());
            }

            self.recv_streams.write_frames(builder, tokens, stats)?;

            self.remote_streams_fc[StreamType::BiDi].write_frames(builder, tokens, stats)?;
            if builder.remaining() < 2 {
                return Ok(());
            }
            self.remote_streams_fc[StreamType::UniDi].write_frames(builder, tokens, stats)?;
            if builder.remaining() < 2 {
                return Ok(());
            }

            self.local_streams_fc[StreamType::BiDi].write_frames(builder, tokens, stats)?;
            if builder.remaining() < 2 {
                return Ok(());
            }

            self.local_streams_fc[StreamType::UniDi].write_frames(builder, tokens, stats)?;
            if builder.remaining() < 2 {
                return Ok(());
            }
        }

        self.send_streams
            .write_frames(priority, builder, tokens, stats)
    }

    pub fn lost(&mut self, token: &RecoveryToken) {
        match token {
            RecoveryToken::Stream(st) => self.send_streams.lost(&st),
            RecoveryToken::ResetStream { stream_id } => self.send_streams.reset_lost(*stream_id),
            RecoveryToken::StreamDataBlocked { stream_id, limit } => {
                self.send_streams.blocked_lost(*stream_id, *limit)
            }
            RecoveryToken::MaxStreamData {
                stream_id,
                max_data,
            } => {
                if let Ok((_, Some(rs))) = self.obtain_stream(*stream_id) {
                    rs.max_stream_data_lost(*max_data);
                }
            }
            RecoveryToken::StopSending { stream_id } => {
                if let Ok((_, Some(rs))) = self.obtain_stream(*stream_id) {
                    rs.stop_sending_lost();
                }
            }
            RecoveryToken::StreamsBlocked { stream_type, limit } => {
                self.local_streams_fc[*stream_type].lost(*limit);
            }
            RecoveryToken::MaxStreams {
                stream_type,
                max_streams,
            } => {
                self.remote_streams_fc[*stream_type].lost(*max_streams);
            }
            RecoveryToken::DataBlocked(limit) => self.flow_control_sender.borrow_mut().lost(*limit),
            RecoveryToken::MaxData(maximum_data) => {
                self.flow_control_receiver.borrow_mut().lost(*maximum_data)
            }
            _ => unreachable!("This is not a stream RecoveryToken"),
        }
    }

    pub fn acked(&mut self, token: &RecoveryToken) {
        match token {
            RecoveryToken::Stream(st) => self.send_streams.acked(st),
            RecoveryToken::ResetStream { stream_id } => self.send_streams.reset_acked(*stream_id),
            RecoveryToken::StopSending { stream_id } => {
                if let Ok((_, Some(rs))) = self.obtain_stream(*stream_id) {
                    rs.stop_sending_acked();
                }
            }
            _ => unreachable!("This is not a stream RecoveryToken"),
        }
    }

    pub fn clear_streams(&mut self) {
        self.send_streams.clear();
        self.recv_streams.clear();
    }

    pub fn cleanup_closed_streams(&mut self) {
        self.send_streams.clear_terminal();
        let send_streams = &self.send_streams;
        let (removed_bidi, removed_uni) = self.recv_streams.clear_terminal(send_streams, self.role);

        // Send max_streams updates if we removed remote-initiated recv streams.
        // The updates will be send if any steams has been removed.
        self.remote_streams_fc[StreamType::BiDi].add_retired(removed_bidi);
        self.remote_streams_fc[StreamType::UniDi].add_retired(removed_uni);
    }

    /// Get or make a stream, and implicitly open additional streams as
    /// indicated by its stream id.
    pub fn obtain_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Res<(Option<&mut SendStream>, Option<&mut RecvStream>)> {
        // May require creating new stream(s)
        if stream_id.is_remote_initiated(self.role) {
            if self.remote_streams_fc[stream_id.stream_type()].is_new_stream(stream_id)? {
                let recv_initial_max_stream_data = if stream_id.is_bidi() {
                    // From the local perspective, this is a remote- originated BiDi stream. From
                    // the remote perspective, this is a local-originated BiDi stream. Therefore,
                    // look at the local transport parameters for the
                    // INITIAL_MAX_STREAM_DATA_BIDI_REMOTE value to decide how much this endpoint
                    // will allow its peer to send.
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
                } else {
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tparams::INITIAL_MAX_STREAM_DATA_UNI)
                };

                while self.remote_streams_fc[stream_id.stream_type()].is_new_stream(stream_id)? {
                    let next_stream_id =
                        self.remote_streams_fc[stream_id.stream_type()].take_stream_id();
                    self.events.new_stream(next_stream_id);

                    self.recv_streams.insert(
                        next_stream_id,
                        RecvStream::new(
                            next_stream_id,
                            recv_initial_max_stream_data,
                            self.events.clone(),
                        ),
                    );

                    if next_stream_id.is_bidi() {
                        // From the local perspective, this is a remote- originated BiDi stream.
                        // From the remote perspective, this is a local-originated BiDi stream.
                        // Therefore, look at the remote's transport parameters for the
                        // INITIAL_MAX_STREAM_DATA_BIDI_LOCAL value to decide how much this endpoint
                        // is allowed to send its peer.
                        let send_initial_max_stream_data = self
                            .tps
                            .borrow()
                            .remote()
                            .get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
                        self.send_streams.insert(
                            next_stream_id,
                            SendStream::new(
                                next_stream_id,
                                send_initial_max_stream_data,
                                Rc::clone(&self.flow_control_sender),
                                self.events.clone(),
                            ),
                        );
                    }
                }
            }
        }

        Ok((
            self.send_streams.get_mut(stream_id).ok(),
            self.recv_streams.get_mut(stream_id).ok(),
        ))
    }

    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        match self.local_streams_fc.take_stream_id(st) {
            None => Err(Error::StreamLimitError),
            Some(new_id) => {
                let send_limit_tp = match st {
                    StreamType::UniDi => tparams::INITIAL_MAX_STREAM_DATA_UNI,
                    StreamType::BiDi => tparams::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                };
                let send_limit = self.tps.borrow().remote().get_integer(send_limit_tp);
                self.send_streams.insert(
                    new_id,
                    SendStream::new(
                        new_id,
                        send_limit,
                        Rc::clone(&self.flow_control_sender),
                        self.events.clone(),
                    ),
                );
                if st == StreamType::BiDi {
                    // From the local perspective, this is a local- originated BiDi stream. From the
                    // remote perspective, this is a remote-originated BiDi stream. Therefore, look at
                    // the local transport parameters for the INITIAL_MAX_STREAM_DATA_BIDI_LOCAL value
                    // to decide how much this endpoint will allow its peer to send.
                    let recv_initial_max_stream_data = self
                        .tps
                        .borrow()
                        .local
                        .get_integer(tparams::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);

                    self.recv_streams.insert(
                        new_id,
                        RecvStream::new(new_id, recv_initial_max_stream_data, self.events.clone()),
                    );
                }
                Ok(new_id.as_u64())
            }
        }
    }

    pub fn handle_max_data(&mut self, maximum_data: u64) {
        let conn_was_blocked = self.flow_control_sender.borrow().available() == 0;
        let conn_credit_increased = self.flow_control_sender.borrow_mut().update(maximum_data);

        if conn_was_blocked && conn_credit_increased {
            for (id, ss) in &mut self.send_streams {
                if ss.avail() > 0 {
                    // These may not actually all be writable if one
                    // uses up all the conn credit. Not our fault.
                    self.events.send_stream_writable(*id);
                }
            }
        }
    }

    pub fn handle_data_blocked(&mut self) {
        self.flow_control_receiver.borrow_mut().send_flowc_update();
    }

    pub fn set_initial_limits(&mut self) {
        let _ = self.local_streams_fc[StreamType::BiDi].update(
            self.tps
                .borrow()
                .remote()
                .get_integer(tparams::INITIAL_MAX_STREAMS_BIDI),
        );
        let _ = self.local_streams_fc[StreamType::UniDi].update(
            self.tps
                .borrow()
                .remote()
                .get_integer(tparams::INITIAL_MAX_STREAMS_UNI),
        );

        // As a client, there are two sets of initial limits for sending stream data.
        // If the second limit is higher and streams have been created, then
        // ensure that streams are not blocked on the lower limit.
        if self.role == Role::Client {
            self.send_streams
                .update_initial_limit(self.tps.borrow().remote());
        }

        self.flow_control_sender.borrow_mut().update(
            self.tps
                .borrow()
                .remote()
                .get_integer(tparams::INITIAL_MAX_DATA),
        );
    }

    pub fn handle_max_streams(&mut self, stream_type: StreamType, maximum_streams: u64) {
        if self.local_streams_fc[stream_type].update(maximum_streams) {
            self.events.send_stream_creatable(stream_type);
        }
    }

    pub fn get_send_stream_mut(&mut self, stream_id: StreamId) -> Res<&mut SendStream> {
        self.send_streams.get_mut(stream_id)
    }

    pub fn get_send_stream(&self, stream_id: StreamId) -> Res<&SendStream> {
        self.send_streams.get(stream_id)
    }

    pub fn get_recv_stream_mut(&mut self, stream_id: StreamId) -> Res<&mut RecvStream> {
        self.recv_streams.get_mut(stream_id)
    }
}
