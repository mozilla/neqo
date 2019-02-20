use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr};

use crate::data::Data;
use crate::frame::{decode_frame, Frame};
use crate::stream::Stream;
use crate::{Error, Res};
//use qinterface::{QInterface, StreamStateQuery, StateInfo, StreamInfo, ConnState, InterfaceError};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);


#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
    Client,
    Server
}

#[derive(Debug, PartialEq)]
enum State {
    Init,
    WaitInitial,
}

pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    d: Vec<u8>,
}

#[allow(unused_variables)]
#[derive(Debug)]
pub struct Connection {
    role: Role,
    state: State,
    deadline: u64,
    max_data: u64,
    max_streams: u64,
    highest_stream: Option<u64>,
    connection_ids: HashSet<(u64, Vec<u8>)>, // (sequence number, connection id)
    next_stream_id: u64,
    streams: HashMap<u64, Stream>, // stream id, stream
    outgoing_pkts: Vec<Packet>,    // (offset, data)
}

impl Connection {
    pub fn new(r: Role) -> Connection {
        Connection{
            role: r,
            state: match r { Role::Client => State::Init, Role::Server => State::WaitInitial },
            deadline: 0,
            max_data: 0,
            max_streams: 0,
            highest_stream: None,
            connection_ids: HashSet::new(),
            next_stream_id: 0,
            streams: HashMap::new(),
            outgoing_pkts: Vec::new()
        }
    }

    pub fn input(&mut self, _d: &Datagram, now: u64) -> Res<(&Datagram, u64)> {
        // TODO(ekr@rtfm.com): Process the incoming packets.
        
        if now > self.deadline {
            // Timer expired.
            match self.state {
                State::Init => { self.client_start()?;}
                _ => unimplemented!()
            }
        }

        Err(Error::ErrInternal)
    }

    fn client_start(&mut self) -> Res<(&Datagram, u64)> {
        Err(Error::ErrInternal)        
    }
    
    pub fn process_input_frame(&mut self, frame: &[u8]) -> Res<()> {
        let mut data = Data::from_slice(frame);
        let frame = decode_frame(&mut data)?;

        #[allow(unused_variables)]
        match frame {
            Frame::Padding => {
                println!("padding!");
            }
            Frame::Ping => {} // TODO generate ack
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
            } => {} // TODO remove acked ranges from list of in-flight packets
            Frame::ResetStream {
                stream_id,
                application_error_code,
                final_size,
            } => {} // TODO reset a stream
            Frame::StopSending {
                application_error_code,
            } => {} // TODO stop sending on a stream
            Frame::Crypto { offset, data } => {} // TODO pass to crypto handling code
            Frame::NewToken { token } => {} // TODO stick the new token somewhere
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
            } => {
                self.process_inbound_stream_frame(fin, stream_id, offset, data)?;
            }
            Frame::MaxData { maximum_data } => {} // TODO set self.max_data?
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {} // TODO lookup stream and modify its max_stream_data
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {} // TODO adjust self.max_streams?
            Frame::DataBlocked { data_limit } => {} // TODO use as input to flow control algorithms
            Frame::StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => {} // TODO do something
            Frame::StreamsBlocked {
                stream_type,
                stream_limit,
            } => {} // TODO do something
            Frame::NewConnectionId {
                sequence_number,
                connection_id,
                stateless_reset_token,
            } => {
                self.connection_ids.insert((sequence_number, connection_id));
            }
            Frame::RetireConnectionId { sequence_number } => {} // TODO remove from list of connection IDs
            Frame::PathChallenge { data } => {}                 // TODO generate PATH_RESPONSE
            Frame::PathResponse { data } => {}                  // TODO do something
            Frame::ConnectionClose {
                close_type,
                error_code,
                frame_type,
                reason_phrase,
            } => {} // TODO close the connection
        };

        Ok(())
    }

    pub fn process_inbound_stream_frame(
        &mut self,
        fin: bool,
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
    ) -> Res<()> {
        // TODO check against list of ooo frames and maybe make some data available
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| return Error::ErrInvalidStreamId)?;

        //let end_offset = offset + data.len() as u64;
        if offset == stream.next_rx_offset() {
            // in order!
            // TODO make data available to upper layers
            stream.data_ready(&data);
            // TODO generate ACK frames
        }
        if fin {
            println!("fin set!")
        }
        // TODO: handle ooo, fin
        Ok(())
    }

    // Returns new stream id
    pub fn stream_create(&mut self) -> u64 {
        let stream_id = self.next_stream_id;
        self.streams.insert(stream_id, Stream::new());
        self.next_stream_id += 1;
        stream_id
    }
}

/*
impl QInterface<Stream> for Connection {
  fn incoming_datagram(&mut self, path: SocketAddr, frame: &[u8], time: u64, streamStateQuery: StreamStateQuery) -> std::result::Result<StateInfo, InterfaceError> {
    Err(InterfaceError::NOT_IMPLEMENTED)
  }

  fn GetStream (&self, streamId: u64) -> Option<&Stream> {
     self.streams.get(&streamId)
  }
}
*/
