// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::control_stream_local::{ControlStreamLocal, HTTP3_UNI_STREAM_TYPE_CONTROL};
use crate::control_stream_remote::ControlStreamRemote;
use crate::hframe::{HFrame, HSettingType};
use crate::stream_type_reader::NewStreamTypeReader;
use neqo_common::{matches, qdebug, qerror, qinfo, qtrace, qwarn};
use neqo_qpack::decoder::{QPackDecoder, QPACK_UNI_STREAM_TYPE_DECODER};
use neqo_qpack::encoder::{QPackEncoder, QPACK_UNI_STREAM_TYPE_ENCODER};
use neqo_transport::{AppError, CloseError, Connection, State, StreamType};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::mem;

use crate::{Error, Res};

const HTTP3_UNI_STREAM_TYPE_PUSH: u64 = 0x1;

const MAX_HEADER_LIST_SIZE_DEFAULT: u64 = u64::max_value();

// handle_stream_readable will return:
// 1) is a push stream
// 2) vec of control frames
// 3) vec of unblocked_streams(streams are blocked by qpack)
// It can return only one of this.
pub struct HandleStreamReadableResult {
    pub push: bool,
    pub control_frames: Vec<HFrame>,
    pub unblocked_streams: Vec<u64>,
}

pub trait Http3Transaction: Debug {
    fn send(&mut self, conn: &mut Connection, encoder: &mut QPackEncoder) -> Res<()>;
    fn has_data_to_send(&self) -> bool;
    fn reset_receiving_side(&mut self);
    fn stop_sending(&mut self);
    fn done(&self) -> bool;
    fn close_send(&mut self, conn: &mut Connection) -> Res<()>;
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub enum Http3State {
    Initializing,
    Connected,
    GoingAway,
    Closing(CloseError),
    Closed(CloseError),
}

#[derive(Debug)]
pub struct Http3Connection<T: Http3Transaction> {
    pub state: Http3State,
    max_header_list_size: u64,
    control_stream_local: ControlStreamLocal,
    control_stream_remote: ControlStreamRemote,
    new_streams: HashMap<u64, NewStreamTypeReader>,
    pub qpack_encoder: QPackEncoder,
    pub qpack_decoder: QPackDecoder,
    settings_received: bool,
    streams_have_data_to_send: BTreeSet<u64>,
    pub transactions: HashMap<u64, T>,
}

impl<T: Http3Transaction> ::std::fmt::Display for Http3Connection<T> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Http3 connection")
    }
}

impl<T: Http3Transaction> Http3Connection<T> {
    pub fn new(max_table_size: u32, max_blocked_streams: u16) -> Self {
        if max_table_size > (1 << 30) - 1 {
            panic!("Wrong max_table_size");
        }
        Http3Connection {
            state: Http3State::Initializing,
            max_header_list_size: MAX_HEADER_LIST_SIZE_DEFAULT,
            control_stream_local: ControlStreamLocal::default(),
            control_stream_remote: ControlStreamRemote::new(),
            new_streams: HashMap::new(),
            qpack_encoder: QPackEncoder::new(true),
            qpack_decoder: QPackDecoder::new(max_table_size, max_blocked_streams),
            settings_received: false,
            streams_have_data_to_send: BTreeSet::new(),
            transactions: HashMap::new(),
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
        self.control_stream_local.queue_frame(HFrame::Settings {
            settings: vec![
                (
                    HSettingType::MaxTableSize,
                    self.qpack_decoder.get_max_table_size().into(),
                ),
                (
                    HSettingType::BlockedStreams,
                    self.qpack_decoder.get_blocked_streams().into(),
                ),
            ],
        });
    }

    fn create_qpack_streams(&mut self, conn: &mut Connection) -> Res<()> {
        qdebug!([self], "create_qpack_streams.");
        self.qpack_encoder
            .add_send_stream(conn.stream_create(StreamType::UniDi)?);
        self.qpack_decoder
            .add_send_stream(conn.stream_create(StreamType::UniDi)?);
        Ok(())
    }

    pub fn insert_streams_have_data_to_send(&mut self, stream_id: u64) {
        self.streams_have_data_to_send.insert(stream_id);
    }

    pub fn has_data_to_send(&self) -> bool {
        !self.streams_have_data_to_send.is_empty()
    }

    pub fn process_sending(&mut self, conn: &mut Connection) -> Res<()> {
        // check if control stream has data to send.
        self.control_stream_local.send(conn)?;

        let to_send = mem::replace(&mut self.streams_have_data_to_send, BTreeSet::new());
        for stream_id in to_send {
            if let Some(t) = &mut self.transactions.get_mut(&stream_id) {
                t.send(conn, &mut self.qpack_encoder)?;
                if t.has_data_to_send() {
                    self.streams_have_data_to_send.insert(stream_id);
                }
            }
        }
        self.qpack_decoder.send(conn)?;
        self.qpack_encoder.send(conn)?;
        Ok(())
    }

    pub fn handle_new_unidi_stream(&mut self, conn: &mut Connection, stream_id: u64) -> Res<bool> {
        qtrace!([self], "A new stream: {}.", stream_id);
        assert!(self.state_active());
        let stream_type;
        let fin;
        {
            let ns = &mut self
                .new_streams
                .entry(stream_id)
                .or_insert_with(NewStreamTypeReader::new);
            stream_type = ns.get_type(conn, stream_id);
            fin = ns.fin();
        }

        if fin {
            self.new_streams.remove(&stream_id);
            Ok(false)
        } else if let Some(t) = stream_type {
            self.new_streams.remove(&stream_id);
            self.decode_new_stream(conn, t, stream_id)
        } else {
            Ok(false)
        }
    }

    // There are 2 events that must be return to a client/server handler to properly consumes them:
    //   1) reading a new stream founds that is a push stream
    //   2) a control stream has received frames MaxPushId or Goaway which handling is specific to
    //      the client and server.
    pub fn handle_stream_readable(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Res<Option<HandleStreamReadableResult>> {
        qtrace!([self], "Readable stream {}.", stream_id);

        assert!(self.state_active());

        let mut unblocked_streams = Vec::new();
        let mut push = false;
        let mut control_frames = Vec::new();
        if self
            .control_stream_remote
            .receive_if_this_stream(conn, stream_id)?
        {
            qdebug!(
                [self],
                "The remote control stream ({}) is readable.",
                stream_id
            );
            while self.control_stream_remote.frame_reader_done()
                || self.control_stream_remote.recvd_fin()
            {
                if let Some(f) = self.handle_control_frame()? {
                    control_frames.push(f);
                }
                self.control_stream_remote
                    .receive_if_this_stream(conn, stream_id)?;
            }
        } else if self.qpack_encoder.recv_if_encoder_stream(conn, stream_id)? {
            qdebug!(
                [self],
                "The qpack encoder stream ({}) is readable.",
                stream_id
            );
        } else if self.qpack_decoder.is_recv_stream(stream_id) {
            qdebug!(
                [self],
                "The qpack decoder stream ({}) is readable.",
                stream_id
            );
            unblocked_streams = self.qpack_decoder.receive(conn, stream_id)?;
        } else if let Some(ns) = self.new_streams.get_mut(&stream_id) {
            let stream_type = ns.get_type(conn, stream_id);
            let fin = ns.fin();
            if fin {
                self.new_streams.remove(&stream_id);
            }
            if let Some(t) = stream_type {
                self.new_streams.remove(&stream_id);
                push = self.decode_new_stream(conn, t, stream_id)?;
            }
        } else {
            return Ok(None);
        }
        Ok(Some(HandleStreamReadableResult {
            push,
            control_frames,
            unblocked_streams,
        }))
    }

    pub fn handle_stream_reset(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        app_err: AppError,
    ) -> Res<Option<T>> {
        qinfo!(
            [self],
            "Handle a stream reset stream_id={} app_err={}",
            stream_id,
            app_err
        );

        assert!(self.state_active());

        if let Some(t) = self.transactions.get_mut(&stream_id) {
            // Close both sides of the transaction_client.
            t.reset_receiving_side();
            t.stop_sending();
            // close sending side of the transport stream as well. The server may have done
            // it se well, but just to be sure.
            let _ = conn.stream_reset_send(stream_id, app_err);
            // remove the stream
            Ok(self.transactions.remove(&stream_id))
        } else {
            Ok(None)
        }
    }

    pub fn handle_state_change(&mut self, conn: &mut Connection, state: &State) -> Res<bool> {
        match state {
            State::Connected => {
                assert_eq!(self.state, Http3State::Initializing);
                self.state = Http3State::Connected;
                self.initialize_http3_connection(conn)?;
                Ok(true)
            }
            State::Closing { error, .. } => {
                if !matches!(self.state, Http3State::Closing(_)| Http3State::Closed(_)) {
                    self.state = Http3State::Closing(error.clone().into());
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            State::Closed(error) => {
                if !matches!(self.state, Http3State::Closed(_)) {
                    self.state = Http3State::Closing(error.clone().into());
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false),
        }
    }

    // Returns true if it is a push stream.
    fn decode_new_stream(
        &mut self,
        conn: &mut Connection,
        stream_type: u64,
        stream_id: u64,
    ) -> Res<bool> {
        match stream_type {
            HTTP3_UNI_STREAM_TYPE_CONTROL => {
                self.control_stream_remote.add_remote_stream(stream_id)?;
                Ok(false)
            }

            HTTP3_UNI_STREAM_TYPE_PUSH => {
                qinfo!([self], "A new push stream {}.", stream_id);
                Ok(true)
            }
            QPACK_UNI_STREAM_TYPE_ENCODER => {
                qinfo!([self], "A new remote qpack encoder stream {}", stream_id);
                self.qpack_decoder
                    .add_recv_stream(stream_id)
                    .map_err(|_| Error::HttpStreamCreationError)?;
                Ok(false)
            }
            QPACK_UNI_STREAM_TYPE_DECODER => {
                qinfo!([self], "A new remote qpack decoder stream {}", stream_id);
                self.qpack_encoder
                    .add_recv_stream(stream_id)
                    .map_err(|_| Error::HttpStreamCreationError)?;
                Ok(false)
            }
            // TODO reserved stream types
            _ => {
                conn.stream_stop_sending(stream_id, Error::HttpStreamCreationError.code())?;
                Ok(false)
            }
        }
    }

    pub fn close(&mut self, error: AppError) {
        qinfo!([self], "Close connection error {:?}.", error);
        assert!(self.state_active());
        self.state = Http3State::Closing(CloseError::Application(error));
        if !self.transactions.is_empty() && (error == 0) {
            qwarn!("close() called when streams still active");
        }
        self.transactions.clear();
    }

    pub fn stream_reset(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        error: AppError,
    ) -> Res<()> {
        qinfo!([self], "Reset stream {} error={}.", stream_id, error);
        assert!(self.state_active());
        let mut transaction = self
            .transactions
            .remove(&stream_id)
            .ok_or(Error::InvalidStreamId)?;
        transaction.stop_sending();
        // Stream maybe already be closed and we may get an error here, but we do not care.
        let _ = conn.stream_reset_send(stream_id, error);
        transaction.reset_receiving_side();
        // Stream maybe already be closed and we may get an error here, but we do not care.
        conn.stream_stop_sending(stream_id, error)?;
        Ok(())
    }

    pub fn stream_close_send(&mut self, conn: &mut Connection, stream_id: u64) -> Res<()> {
        qinfo!([self], "Close sending side for stream {}.", stream_id);
        assert!(self.state_active());
        let transaction = self
            .transactions
            .get_mut(&stream_id)
            .ok_or(Error::InvalidStreamId)?;
        transaction.close_send(conn)?;
        if transaction.done() {
            self.transactions.remove(&stream_id);
        }
        Ok(())
    }

    // If the control stream has received frames MaxPushId or Goaway which handling is specific to
    // the client and server, we must give them to the specific client/server handler..
    fn handle_control_frame(&mut self) -> Res<Option<HFrame>> {
        if self.control_stream_remote.recvd_fin() {
            return Err(Error::HttpClosedCriticalStream);
        }
        if self.control_stream_remote.frame_reader_done() {
            let f = self.control_stream_remote.get_frame()?;
            qinfo!([self], "Handle a control frame {:?}", f);
            if let HFrame::Settings { .. } = f {
                if self.settings_received {
                    qerror!([self], "SETTINGS frame already received");
                    return Err(Error::HttpFrameUnexpected);
                }
                self.settings_received = true;
            } else if !self.settings_received {
                qerror!([self], "SETTINGS frame not received");
                return Err(Error::HttpMissingSettings);
            }
            return match f {
                HFrame::Settings { settings } => {
                    self.handle_settings(&settings)?;
                    Ok(None)
                }
                HFrame::CancelPush { .. } | HFrame::Goaway { .. } | HFrame::MaxPushId { .. } => {
                    Ok(Some(f))
                }
                _ => Err(Error::HttpFrameUnexpected),
            };
        }
        Ok(None)
    }

    fn handle_settings(&mut self, s: &[(HSettingType, u64)]) -> Res<()> {
        qinfo!([self], "Handle SETTINGS frame.");
        for (t, v) in s {
            qinfo!([self], " {:?} = {:?}", t, v);
            match t {
                HSettingType::MaxHeaderListSize => {
                    self.max_header_list_size = *v;
                }
                HSettingType::MaxTableSize => self.qpack_encoder.set_max_capacity(*v)?,
                HSettingType::BlockedStreams => self.qpack_encoder.set_max_blocked_streams(*v)?,

                _ => {}
            }
        }
        Ok(())
    }

    fn state_active(&self) -> bool {
        matches!(self.state, Http3State::Connected | Http3State::GoingAway)
    }

    pub fn state(&self) -> Http3State {
        self.state.clone()
    }

    pub fn add_transaction(&mut self, stream_id: u64, transaction: T) {
        if transaction.has_data_to_send() {
            self.streams_have_data_to_send.insert(stream_id);
        }
        self.transactions.insert(stream_id, transaction);
    }

    pub fn queue_control_frame(&mut self, frame: HFrame) {
        self.control_stream_local.queue_frame(frame);
    }
}
