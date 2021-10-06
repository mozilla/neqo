// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use crate::control_stream_local::ControlStreamLocal;
use crate::control_stream_remote::ControlStreamRemote;
use crate::hframe::HFrame;
use crate::qpack_decoder_receiver::DecoderRecvStream;
use crate::qpack_encoder_receiver::EncoderRecvStream;
use crate::settings::{HSetting, HSettingType, HSettings, HttpZeroRttChecker};
use crate::stream_type_reader::NewStreamHeadReader;
use crate::{
    CloseType, Http3StreamType, NewStreamType, Priority, ReceiveOutput, RecvStream, SendStream,
};
use neqo_common::{qdebug, qerror, qinfo, qtrace, qwarn, Role};
use neqo_qpack::decoder::QPackDecoder;
use neqo_qpack::encoder::QPackEncoder;
use neqo_qpack::QpackSettings;
use neqo_transport::{AppError, Connection, ConnectionError, State, StreamType};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::mem;
use std::rc::Rc;

use crate::{Error, Res};

const QPACK_TABLE_SIZE_LIMIT: u64 = 1 << 30;

#[derive(Debug)]
enum Http3RemoteSettingsState {
    NotReceived,
    Received(HSettings),
    ZeroRtt(HSettings),
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub enum Http3State {
    Initializing,
    ZeroRtt,
    Connected,
    GoingAway(u64),
    Closing(ConnectionError),
    Closed(ConnectionError),
}

impl Http3State {
    #[must_use]
    pub fn active(&self) -> bool {
        matches!(
            self,
            Http3State::Connected | Http3State::GoingAway(_) | Http3State::ZeroRtt
        )
    }
}

#[derive(Debug)]
pub(crate) struct Http3Connection {
    pub state: Http3State,
    local_qpack_settings: QpackSettings,
    control_stream_local: ControlStreamLocal,
    pub qpack_encoder: Rc<RefCell<QPackEncoder>>,
    pub qpack_decoder: Rc<RefCell<QPackDecoder>>,
    settings_state: Http3RemoteSettingsState,
    streams_with_pending_data: BTreeSet<u64>,
    pub send_streams: HashMap<u64, Box<dyn SendStream>>,
    pub recv_streams: HashMap<u64, Box<dyn RecvStream>>,
}

impl ::std::fmt::Display for Http3Connection {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http3 connection")
    }
}

impl Http3Connection {
    /// Create a new connection.
    pub fn new(local_qpack_settings: QpackSettings) -> Self {
        if (local_qpack_settings.max_table_size_encoder >= QPACK_TABLE_SIZE_LIMIT)
            || (local_qpack_settings.max_table_size_decoder >= QPACK_TABLE_SIZE_LIMIT)
        {
            panic!("Wrong max_table_size");
        }
        Self {
            state: Http3State::Initializing,
            local_qpack_settings,
            control_stream_local: ControlStreamLocal::new(),
            qpack_encoder: Rc::new(RefCell::new(QPackEncoder::new(local_qpack_settings, true))),
            qpack_decoder: Rc::new(RefCell::new(QPackDecoder::new(local_qpack_settings))),
            settings_state: Http3RemoteSettingsState::NotReceived,
            streams_with_pending_data: BTreeSet::new(),
            send_streams: HashMap::new(),
            recv_streams: HashMap::new(),
        }
    }

    fn initialize_http3_connection(&mut self, conn: &mut Connection) -> Res<()> {
        qinfo!([self], "Initialize the http3 connection.");
        self.control_stream_local.create(conn)?;

        self.send_settings();
        self.create_qpack_streams(conn)?;
        Ok(())
    }

    fn send_settings(&mut self) {
        qdebug!([self], "Send settings.");
        self.control_stream_local.queue_frame(&HFrame::Settings {
            settings: HSettings::new(&[
                HSetting {
                    setting_type: HSettingType::MaxTableCapacity,
                    value: self.qpack_decoder.borrow().get_max_table_size(),
                },
                HSetting {
                    setting_type: HSettingType::BlockedStreams,
                    value: self.qpack_decoder.borrow().get_blocked_streams().into(),
                },
            ]),
        });
        self.control_stream_local.queue_frame(&HFrame::Grease);
    }

    /// Save settings for adding to the session ticket.
    pub(crate) fn save_settings(&self) -> Vec<u8> {
        HttpZeroRttChecker::save(self.local_qpack_settings)
    }

    fn create_qpack_streams(&mut self, conn: &mut Connection) -> Res<()> {
        qdebug!([self], "create_qpack_streams.");
        self.qpack_encoder
            .borrow_mut()
            .add_send_stream(conn.stream_create(StreamType::UniDi)?);
        self.qpack_decoder
            .borrow_mut()
            .add_send_stream(conn.stream_create(StreamType::UniDi)?);
        Ok(())
    }

    /// Inform a `HttpConnection` that a stream has data to send and that `send` should be called for the stream.
    pub fn stream_has_pending_data(&mut self, stream_id: u64) {
        self.streams_with_pending_data.insert(stream_id);
    }

    /// Return true if there is a stream that needs to send data.
    pub fn has_data_to_send(&self) -> bool {
        !self.streams_with_pending_data.is_empty()
    }

    fn send_non_control_streams(&mut self, conn: &mut Connection) -> Res<()> {
        let to_send = mem::take(&mut self.streams_with_pending_data);
        for stream_id in to_send {
            let done = if let Some(s) = &mut self.send_streams.get_mut(&stream_id) {
                s.send(conn)?;
                if s.has_data_to_send() {
                    self.streams_with_pending_data.insert(stream_id);
                }
                s.done()
            } else {
                false
            };
            if done {
                self.send_streams.remove(&stream_id);
            }
        }
        Ok(())
    }

    /// Call `send` for all streams that need to send data.
    pub fn process_sending(&mut self, conn: &mut Connection) -> Res<()> {
        // check if control stream has data to send.
        self.control_stream_local
            .send(conn, &mut self.recv_streams)?;

        self.send_non_control_streams(conn)?;

        self.qpack_decoder.borrow_mut().send(conn)?;
        match self.qpack_encoder.borrow_mut().send(conn) {
            Ok(())
            | Err(neqo_qpack::Error::EncoderStreamBlocked)
            | Err(neqo_qpack::Error::DynamicTableFull) => {}
            Err(e) => return Err(Error::QpackError(e)),
        }
        Ok(())
    }

    /// We have a resumption token which remembers previous settings. Update the setting.
    pub fn set_0rtt_settings(&mut self, conn: &mut Connection, settings: HSettings) -> Res<()> {
        self.initialize_http3_connection(conn)?;
        self.set_qpack_settings(&settings)?;
        self.settings_state = Http3RemoteSettingsState::ZeroRtt(settings);
        self.state = Http3State::ZeroRtt;
        Ok(())
    }

    /// Returns the settings for a connection. This is used for creating a resumption token.
    pub fn get_settings(&self) -> Option<HSettings> {
        if let Http3RemoteSettingsState::Received(settings) = &self.settings_state {
            Some(settings.clone())
        } else {
            None
        }
    }

    pub fn add_new_stream(&mut self, stream_id: u64, role: Role) {
        qtrace!([self], "A new stream: {}.", stream_id);
        self.recv_streams.insert(
            stream_id,
            Box::new(NewStreamHeadReader::new(stream_id, role)),
        );
    }

    #[allow(clippy::option_if_let_else)] // False positive as borrow scope isn't lexical here.
    fn stream_receive(&mut self, conn: &mut Connection, stream_id: u64) -> Res<ReceiveOutput> {
        qtrace!([self], "Readable stream {}.", stream_id);

        if let Some(recv_stream) = self.recv_streams.get_mut(&stream_id) {
            let res = recv_stream.receive(conn);
            self.handle_stream_manipulation_output(res, stream_id, conn)
                .map(|(output, _)| output)
        } else {
            Ok(ReceiveOutput::NoOutput)
        }
    }

    fn handle_unblocked_streams(
        &mut self,
        unblocked_streams: Vec<u64>,
        conn: &mut Connection,
    ) -> Res<()> {
        for stream_id in unblocked_streams {
            qdebug!([self], "Stream {} is unblocked", stream_id);
            if let Some(r) = self.recv_streams.get_mut(&stream_id) {
                let res = r
                    .http_stream()
                    .ok_or(Error::HttpInternal(10))?
                    .header_unblocked(conn);
                debug_assert!(matches!(
                    self.handle_stream_manipulation_output(res, stream_id, conn)?,
                    (ReceiveOutput::NoOutput, _)
                ));
            }
        }
        Ok(())
    }

    /// This function handles reading from all streams, i.e. control, qpack, request/response
    /// stream and unidi stream that are still do not have a type.
    /// The function cannot handle:
    /// 1) a Push stream (if an unknown unidi stream is decoded to be a push stream)
    /// 2) frames `MaxPushId` or `Goaway` must be handled by `Http3Client`/`Server`.
    /// The function returns `ReceiveOutput`.
    pub fn handle_stream_readable(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Res<ReceiveOutput> {
        let mut output = self.stream_receive(conn, stream_id)?;

        if let ReceiveOutput::NewStream(stream_type) = output {
            output = self.handle_new_stream(conn, stream_type, stream_id)?;
        }

        #[allow(clippy::match_same_arms)] // clippy is being stupid here
        match output {
            ReceiveOutput::UnblockedStreams(unblocked_streams) => {
                self.handle_unblocked_streams(unblocked_streams, conn)?;
                Ok(ReceiveOutput::NoOutput)
            }
            ReceiveOutput::ControlFrames(mut control_frames) => {
                let mut rest = Vec::new();
                for cf in control_frames.drain(..) {
                    if let Some(not_handled) = self.handle_control_frame(cf)? {
                        rest.push(not_handled);
                    }
                }
                Ok(ReceiveOutput::ControlFrames(rest))
            }
            ReceiveOutput::NewStream(NewStreamType::Push(_))
            | ReceiveOutput::NewStream(NewStreamType::Http) => Ok(output),
            ReceiveOutput::NewStream(_) => {
                unreachable!("NewStream should have been handled already")
            }
            _ => Ok(output),
        }
    }

    /// This is called when a RESET frame has been received.
    pub fn handle_stream_reset(&mut self, stream_id: u64, app_error: AppError) -> Res<()> {
        qinfo!(
            [self],
            "Handle a stream reset stream_id={} app_err={}",
            stream_id,
            app_error
        );

        self.recv_streams
            .remove(&stream_id)
            .map_or(Ok(()), |mut s| s.reset(CloseType::ResetRemote(app_error)))
    }

    pub fn handle_stream_stop_sending(&mut self, stream_id: u64, app_error: AppError) -> Res<()> {
        qinfo!(
            [self],
            "Handle stream_stop_sending stream_id={} app_err={}",
            stream_id,
            app_error
        );

        if let Some(mut s) = self.send_streams.remove(&stream_id) {
            s.stop_sending(CloseType::ResetRemote(app_error));
            Ok(())
        } else if self.send_stream_is_critical(stream_id) {
            Err(Error::HttpClosedCriticalStream)
        } else {
            Ok(())
        }
    }

    /// This is called when `neqo_transport::Connection` state has been change to take proper actions in
    /// the HTTP3 layer.
    pub fn handle_state_change(&mut self, conn: &mut Connection, state: &State) -> Res<bool> {
        qdebug!([self], "Handle state change {:?}", state);
        match state {
            State::Connected => {
                debug_assert!(matches!(
                    self.state,
                    Http3State::Initializing | Http3State::ZeroRtt
                ));
                if self.state == Http3State::Initializing {
                    self.initialize_http3_connection(conn)?;
                }
                self.state = Http3State::Connected;
                Ok(true)
            }
            State::Closing { error, .. } | State::Draining { error, .. } => {
                if matches!(self.state, Http3State::Closing(_) | Http3State::Closed(_)) {
                    Ok(false)
                } else {
                    self.state = Http3State::Closing(error.clone());
                    Ok(true)
                }
            }
            State::Closed(error) => {
                if matches!(self.state, Http3State::Closed(_)) {
                    Ok(false)
                } else {
                    self.state = Http3State::Closed(error.clone());
                    Ok(true)
                }
            }
            _ => Ok(false),
        }
    }

    /// This is called when 0RTT has been reseted to clear `send_streams`, `recv_streams` and settings.
    pub fn handle_zero_rtt_rejected(&mut self) -> Res<()> {
        if self.state == Http3State::ZeroRtt {
            self.state = Http3State::Initializing;
            self.control_stream_local = ControlStreamLocal::new();
            self.qpack_encoder = Rc::new(RefCell::new(QPackEncoder::new(
                self.local_qpack_settings,
                true,
            )));
            self.qpack_decoder =
                Rc::new(RefCell::new(QPackDecoder::new(self.local_qpack_settings)));
            self.settings_state = Http3RemoteSettingsState::NotReceived;
            self.streams_with_pending_data.clear();
            // TODO: investigate whether this code can automatically retry failed transactions.
            self.send_streams.clear();
            self.recv_streams.clear();
            Ok(())
        } else {
            debug_assert!(false, "Zero rtt rejected in the wrong state.");
            Err(Error::HttpInternal(3))
        }
    }

    fn check_stream_exists(&self, stream_type: Http3StreamType) -> Res<()> {
        if self
            .recv_streams
            .values()
            .any(|c| c.stream_type() == stream_type)
        {
            Err(Error::HttpStreamCreation)
        } else {
            Ok(())
        }
    }

    /// If the new stream is a control stream, this function creates a proper handler
    /// and perform a read.
    /// if the new stream is a push stream, the function returns `ReceiveOutput::PushStream`
    /// and the caller will handle it.
    /// If the stream is of a unknown type the stream will be closed.
    fn handle_new_stream(
        &mut self,
        conn: &mut Connection,
        stream_type: NewStreamType,
        stream_id: u64,
    ) -> Res<ReceiveOutput> {
        match stream_type {
            NewStreamType::Control => {
                self.check_stream_exists(Http3StreamType::Control)?;
                self.recv_streams
                    .insert(stream_id, Box::new(ControlStreamRemote::new(stream_id)));
            }

            NewStreamType::Push(push_id) => {
                qinfo!(
                    [self],
                    "A new push stream {} push_id:{}.",
                    stream_id,
                    push_id
                );
            }
            NewStreamType::Decoder => {
                qinfo!([self], "A new remote qpack encoder stream {}", stream_id);
                self.check_stream_exists(Http3StreamType::Decoder)?;
                self.recv_streams.insert(
                    stream_id,
                    Box::new(DecoderRecvStream::new(
                        stream_id,
                        Rc::clone(&self.qpack_decoder),
                    )),
                );
            }
            NewStreamType::Encoder => {
                qinfo!([self], "A new remote qpack decoder stream {}", stream_id);
                self.check_stream_exists(Http3StreamType::Encoder)?;
                self.recv_streams.insert(
                    stream_id,
                    Box::new(EncoderRecvStream::new(
                        stream_id,
                        Rc::clone(&self.qpack_encoder),
                    )),
                );
            }
            NewStreamType::Http => {
                qinfo!([self], "A new http stream {}.", stream_id);
            }
            NewStreamType::WebTransportStream(_) | NewStreamType::Unknown => {
                conn.stream_stop_sending(stream_id, Error::HttpStreamCreation.code())?;
            }
        };

        match stream_type {
            NewStreamType::Control | NewStreamType::Decoder | NewStreamType::Encoder => {
                self.stream_receive(conn, stream_id)
            }
            NewStreamType::Push(_) | NewStreamType::Http => {
                Ok(ReceiveOutput::NewStream(stream_type))
            }
            NewStreamType::WebTransportStream(_) | NewStreamType::Unknown => {
                Ok(ReceiveOutput::NoOutput)
            }
        }
    }

    /// This is called when an application closes the connection.
    pub fn close(&mut self, error: AppError) {
        qinfo!([self], "Close connection error {:?}.", error);
        self.state = Http3State::Closing(ConnectionError::Application(error));
        if (!self.send_streams.is_empty() || !self.recv_streams.is_empty()) && (error == 0) {
            qwarn!("close(0) called when streams still active");
        }
        self.send_streams.clear();
        self.recv_streams.clear();
    }

    /// This function will not handle the output of the function completely, but only
    /// handle the indication that a stream is closed. There are 2 cases:
    ///  - an error occurred or
    ///  - the stream is done, i.e. the second value in `output` tuple is true if
    ///    the stream is done and can be removed from the `recv_streams`
    /// How it is handling `output`:
    ///  - if the stream is done, it removes the stream from `recv_streams`
    ///  - if the stream is not done and there is no error, return `output` and the caller will
    ///    handle it.
    ///  - in case of an error:
    ///    - if it is only a stream error and the stream is not critical, send STOP_SENDING
    ///      frame, remove the stream from `recv_streams` and inform the listener that the stream
    ///      has been reset.
    ///    - otherwise this is a connection error. In this case, propagate the error to the caller
    ///      that will handle it properly.
    fn handle_stream_manipulation_output<U>(
        &mut self,
        output: Res<(U, bool)>,
        stream_id: u64,
        conn: &mut Connection,
    ) -> Res<(U, bool)>
    where
        U: Default,
    {
        match &output {
            Ok((_, true)) => mem::drop(self.recv_streams.remove(&stream_id)),
            Ok((_, false)) => {}
            Err(e) => {
                if e.stream_reset_error() && !self.recv_stream_is_critical(stream_id) {
                    mem::drop(conn.stream_stop_sending(stream_id, e.code()));
                    if let Some(mut rs) = self.recv_streams.remove(&stream_id) {
                        rs.reset(CloseType::LocalError(e.code())).unwrap();
                    }
                    return Ok((U::default(), false));
                }
            }
        }
        output
    }

    /// Stream data are read directly into a buffer supplied as a parameter of this function to avoid copying
    /// data.
    /// # Errors
    /// It returns an error if a stream does not exist or an error happens while reading a stream, e.g.
    /// early close, protocol error, etc.
    pub fn read_data(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Res<(usize, bool)> {
        qinfo!([self], "read_data from stream {}.", stream_id);
        let res = self
            .recv_streams
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?
            .http_stream()
            .ok_or(Error::InvalidStreamId)?
            .read_data(conn, buf);
        self.handle_stream_manipulation_output(res, stream_id, conn)
    }

    /// This is called when an application resets a stream.
    /// The application reset will close both sides.
    pub fn stream_reset_send(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        error: AppError,
    ) -> Res<()> {
        qinfo!(
            [self],
            "Reset sending side of stream {} error={}.",
            stream_id,
            error
        );

        if self.send_stream_is_critical(stream_id) {
            return Err(Error::InvalidStreamId);
        }

        if let Some(mut s) = self.send_streams.remove(&stream_id) {
            s.stop_sending(CloseType::ResetApp(error));
        }
        conn.stream_reset_send(stream_id, error)?;
        Ok(())
    }

    pub fn stream_stop_sending(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        error: AppError,
    ) -> Res<()> {
        qinfo!(
            [self],
            "Send stop sending for stream {} error={}.",
            stream_id,
            error
        );
        if self.recv_stream_is_critical(stream_id) {
            return Err(Error::InvalidStreamId);
        }

        self.recv_streams
            .remove(&stream_id)
            .map_or(Ok(()), |mut s| s.reset(CloseType::ResetApp(error)))?;

        // Stream may be already be closed and we may get an error here, but we do not care.
        conn.stream_stop_sending(stream_id, error)?;
        Ok(())
    }

    pub fn cancel_fetch(
        &mut self,
        stream_id: u64,
        error: AppError,
        conn: &mut Connection,
    ) -> Res<()> {
        qinfo!([self], "reset_:stream {} error={}.", stream_id, error);
        let send_stream = self.send_streams.get(&stream_id);
        let recv_stream = self.recv_streams.get(&stream_id);
        match (send_stream, recv_stream) {
            (None, None) => return Err(Error::InvalidStreamId),
            (Some(s), None) => {
                if !matches!(s.stream_type(), Http3StreamType::Http) {
                    return Err(Error::InvalidStreamId);
                }
                // Stream may be already be closed and we may get an error here, but we do not care.
                mem::drop(self.stream_reset_send(conn, stream_id, error));
            }
            (None, Some(s)) => {
                if !matches!(
                    s.stream_type(),
                    Http3StreamType::Http | Http3StreamType::Push
                ) {
                    return Err(Error::InvalidStreamId);
                }

                // Stream may be already be closed and we may get an error here, but we do not care.
                mem::drop(self.stream_stop_sending(conn, stream_id, error));
            }
            (Some(s), Some(r)) => {
                debug_assert_eq!(s.stream_type(), r.stream_type());
                if !matches!(s.stream_type(), Http3StreamType::Http) {
                    return Err(Error::InvalidStreamId);
                }
                // Stream may be already be closed and we may get an error here, but we do not care.
                mem::drop(self.stream_reset_send(conn, stream_id, error));
                // Stream may be already be closed and we may get an error here, but we do not care.
                mem::drop(self.stream_stop_sending(conn, stream_id, error));
            }
        }
        Ok(())
    }

    /// This is called when an application wants to close the sending side of a stream.
    pub fn stream_close_send(&mut self, conn: &mut Connection, stream_id: u64) -> Res<()> {
        qinfo!([self], "Close the sending side for stream {}.", stream_id);
        debug_assert!(self.state.active());
        let send_stream = self
            .send_streams
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?;
        // The following function may return InvalidStreamId from the transport layer if the stream has been closed
        // already. It is ok to ignore it here.
        mem::drop(send_stream.close(conn));
        if send_stream.done() {
            self.send_streams.remove(&stream_id);
        }
        Ok(())
    }

    // If the control stream has received frames MaxPushId or Goaway which handling is specific to
    // the client and server, we must give them to the specific client/server handler.
    fn handle_control_frame(&mut self, f: HFrame) -> Res<Option<HFrame>> {
        qinfo!([self], "Handle a control frame {:?}", f);
        if !matches!(f, HFrame::Settings { .. })
            && !matches!(
                self.settings_state,
                Http3RemoteSettingsState::Received { .. }
            )
        {
            return Err(Error::HttpMissingSettings);
        }
        match f {
            HFrame::Settings { settings } => {
                self.handle_settings(settings)?;
                Ok(None)
            }
            HFrame::Goaway { .. }
            | HFrame::MaxPushId { .. }
            | HFrame::CancelPush { .. }
            | HFrame::PriorityUpdateRequest { .. }
            | HFrame::PriorityUpdatePush { .. } => Ok(Some(f)),
            _ => Err(Error::HttpFrameUnexpected),
        }
    }

    fn set_qpack_settings(&mut self, settings: &[HSetting]) -> Res<()> {
        for s in settings {
            qinfo!([self], " {:?} = {:?}", s.setting_type, s.value);
            match s.setting_type {
                HSettingType::MaxTableCapacity => {
                    self.qpack_encoder.borrow_mut().set_max_capacity(s.value)?;
                }
                HSettingType::BlockedStreams => self
                    .qpack_encoder
                    .borrow_mut()
                    .set_max_blocked_streams(s.value)?,
                HSettingType::MaxHeaderListSize => (),
            }
        }
        Ok(())
    }

    fn handle_settings(&mut self, new_settings: HSettings) -> Res<()> {
        qinfo!([self], "Handle SETTINGS frame.");
        match &self.settings_state {
            Http3RemoteSettingsState::NotReceived => {
                self.set_qpack_settings(&new_settings)?;
                self.settings_state = Http3RemoteSettingsState::Received(new_settings);
                Ok(())
            }
            Http3RemoteSettingsState::ZeroRtt(settings) => {
                let mut qpack_changed = false;
                for st in &[
                    HSettingType::MaxHeaderListSize,
                    HSettingType::MaxTableCapacity,
                    HSettingType::BlockedStreams,
                ] {
                    let zero_rtt_value = settings.get(*st);
                    let new_value = new_settings.get(*st);
                    if zero_rtt_value == new_value {
                        continue;
                    }
                    if zero_rtt_value > new_value {
                        qerror!(
                            [self],
                            "The new({}) and the old value({}) of setting {:?} do not match",
                            new_value,
                            zero_rtt_value,
                            st
                        );
                        return Err(Error::HttpSettings);
                    }

                    match st {
                        HSettingType::MaxTableCapacity => {
                            if zero_rtt_value != 0 {
                                return Err(Error::QpackError(neqo_qpack::Error::DecoderStream));
                            }
                            qpack_changed = true;
                        }
                        HSettingType::BlockedStreams => qpack_changed = true,
                        HSettingType::MaxHeaderListSize => (),
                    }
                }
                if qpack_changed {
                    qdebug!([self], "Settings after zero rtt differ.");
                    self.set_qpack_settings(&(new_settings))?;
                }
                self.settings_state = Http3RemoteSettingsState::Received(new_settings);
                Ok(())
            }
            Http3RemoteSettingsState::Received { .. } => Err(Error::HttpFrameUnexpected),
        }
    }

    /// Return the current state on `Http3Connection`.
    pub fn state(&self) -> Http3State {
        self.state.clone()
    }

    /// Adds a new send and receive stream.
    pub fn add_streams(
        &mut self,
        stream_id: u64,
        send_stream: Box<dyn SendStream>,
        recv_stream: Box<dyn RecvStream>,
    ) {
        if send_stream.has_data_to_send() {
            self.streams_with_pending_data.insert(stream_id);
        }
        self.send_streams.insert(stream_id, send_stream);
        self.recv_streams.insert(stream_id, recv_stream);
    }

    /// Add a new recv stream. This is used for push streams.
    pub fn add_recv_stream(&mut self, stream_id: u64, recv_stream: Box<dyn RecvStream>) {
        self.recv_streams.insert(stream_id, recv_stream);
    }

    pub fn queue_control_frame(&mut self, frame: &HFrame) {
        self.control_stream_local.queue_frame(frame);
    }

    pub fn queue_update_priority(&mut self, stream_id: u64, priority: Priority) -> Res<bool> {
        let stream = self
            .recv_streams
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?
            .http_stream()
            .ok_or(Error::InvalidStreamId)?;

        if stream
            .priority_handler_mut()
            .maybe_update_priority(priority)
        {
            self.control_stream_local.queue_update_priority(stream_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn recv_stream_is_critical(&self, stream_id: u64) -> bool {
        if let Some(r) = self.recv_streams.get(&stream_id) {
            matches!(
                r.stream_type(),
                Http3StreamType::Control | Http3StreamType::Encoder | Http3StreamType::Decoder
            )
        } else {
            false
        }
    }

    fn send_stream_is_critical(&self, stream_id: u64) -> bool {
        self.qpack_encoder
            .borrow()
            .local_stream_id()
            .iter()
            .chain(self.qpack_decoder.borrow().local_stream_id().iter())
            .chain(self.control_stream_local.stream_id().iter())
            .any(|id| stream_id == *id)
    }
}
