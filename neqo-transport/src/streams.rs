// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Stream ID and stream index handling.

use crate::fc::{LocalStreamsFlowControls, RemoteStreamLimits, SenderFlowControl};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::recv_stream::{RecvStream, RecvStreams};
use crate::send_stream::{SendStream, SendStreams, TransmissionPriority};
use crate::stats::FrameStats;
use crate::stream_id::{StreamId, StreamType};
use crate::tparams::{self, TransportParametersHandler};
use crate::ConnectionEvents;
use crate::{Error, Res};
use neqo_common::Role;
use std::cell::RefCell;
use std::rc::Rc;

pub struct Streams {
    role: Role,
    tps: Rc<RefCell<TransportParametersHandler>>,
    events: ConnectionEvents,
    flow_control_sender: Rc<RefCell<SenderFlowControl<()>>>,
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
        flow_control_sender: Rc<RefCell<SenderFlowControl<()>>>,
    ) -> Self {
        let limit_bidi = tps
            .borrow()
            .local
            .get_integer(tparams::INITIAL_MAX_STREAMS_BIDI);
        let limit_uni = tps
            .borrow()
            .local
            .get_integer(tparams::INITIAL_MAX_STREAMS_UNI);
        Self {
            role,
            tps,
            events,
            flow_control_sender,
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

    pub fn write_frames(
        &mut self,
        priority: TransmissionPriority,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        if priority == TransmissionPriority::Important {
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

    pub fn send_stream_writable(&mut self) {
        for (id, ss) in &mut self.send_streams {
            if ss.avail() > 0 {
                // These may not actually all be writable if one
                // uses up all the conn credit. Not our fault.
                self.events.send_stream_writable(*id)
            }
        }
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
