use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use crate::data::Data;
use crate::frame::{decode_frame, Frame};
use crate::nss_stub::*;
use crate::stream::{BidiStream, Recvable};

use crate::{Error, Res};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
    Client,
    Server,
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
    tls: Agent,
    deadline: u64,
    max_data: u64,
    max_streams: u64,
    highest_stream: Option<u64>,
    connection_ids: HashSet<(u64, Vec<u8>)>, // (sequence number, connection id)
    next_stream_id: u64,
    streams: HashMap<u64, BidiStream>, // stream id, stream
    outgoing_pkts: Vec<Packet>,        // (offset, data)
}

impl Connection {
    pub fn new_client(server_name: &str) -> Connection {
        Connection::new(
            Role::Client,
            Agent::Client(Client::new(server_name).unwrap()),
        )
    }

    pub fn new(r: Role, agent: Agent) -> Connection {
        Connection {
            role: r,
            state: match r {
                Role::Client => State::Init,
                Role::Server => State::WaitInitial,
            },
            tls: agent,
            deadline: 0,
            max_data: 0,
            max_streams: 0,
            highest_stream: None,
            connection_ids: HashSet::new(),
            next_stream_id: 0,
            streams: HashMap::new(),
            outgoing_pkts: Vec::new(),
        }
    }

    pub fn input(&mut self, _d: Option<Datagram>, now: u64) -> Res<(Option<Datagram>, u64)> {
        // TODO(ekr@rtfm.com): Process the incoming packets.
        if now >= self.deadline {
            // Timer expired.
            match self.state {
                State::Init => {
                    self.client_start()?;
                }
                _ => unimplemented!(),
            }
        }

        Ok((None, 0))
    }

    fn client_start(&mut self) -> Res<()> {
        self.handshake(1, 0, None)
    }

    fn handshake(&mut self, now: u64, epoch: u16, data: Option<&[u8]>) -> Res<()> {
        let mut recs = SslRecordList::default();
        if let Some(d) = data {
            recs.recs.push_back(SslRecord {
                epoch,
                data: d.to_vec(),
            });
        }
        
        let (_, msgs) = self.tls.handshake_raw(now, recs)?;
        debug!("Handshake emitted {} messages", msgs.recs.len());

        Ok(())
    }

    pub fn process_input_frame(&mut self, frame: &[u8]) -> Res<()> {
        let mut data = Data::from_slice(frame);
        let frame = decode_frame(&mut data)?;

        #[allow(unused_variables)]
        match frame {
            Frame::Padding => {
                println!("padding!");
            }
            Frame::Ping => {} // TODO(agrover@mozilla.com): generate ack
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
            } => {} // TODO(agrover@mozilla.com): remove acked ranges from list of in-flight packets
            Frame::ResetStream {
                stream_id,
                application_error_code,
                final_size,
            } => {} // TODO(agrover@mozilla.com): reset a stream
            Frame::StopSending {
                application_error_code,
            } => {} // TODO(agrover@mozilla.com): stop sending on a stream
            Frame::Crypto { offset, data } => {} // TODO(agrover@mozilla.com): pass to crypto handling code
            Frame::NewToken { token } => {} // TODO(agrover@mozilla.com): stick the new token somewhere
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
            } => {
                self.process_inbound_stream_frame(fin, stream_id, offset, data)?;
            }
            Frame::MaxData { maximum_data } => {} // TODO(agrover@mozilla.com): set self.max_data?
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {} // TODO(agrover@mozilla.com): lookup stream and modify its max_stream_data
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {} // TODO(agrover@mozilla.com): adjust self.max_streams?
            Frame::DataBlocked { data_limit } => {} // TODO(agrover@mozilla.com): use as input to flow control algorithms
            Frame::StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => {} // TODO(agrover@mozilla.com): do something
            Frame::StreamsBlocked {
                stream_type,
                stream_limit,
            } => {} // TODO(agrover@mozilla.com): do something
            Frame::NewConnectionId {
                sequence_number,
                connection_id,
                stateless_reset_token,
            } => {
                self.connection_ids.insert((sequence_number, connection_id));
            }
            Frame::RetireConnectionId { sequence_number } => {} // TODO(agrover@mozilla.com): remove from list of connection IDs
            Frame::PathChallenge { data } => {} // TODO(agrover@mozilla.com): generate PATH_RESPONSE
            Frame::PathResponse { data } => {}  // TODO(agrover@mozilla.com): do something
            Frame::ConnectionClose {
                close_type,
                error_code,
                frame_type,
                reason_phrase,
            } => {} // TODO(agrover@mozilla.com): close the connection
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
        // TODO(agrover@mozilla.com): check against list of ooo frames and maybe make some data available
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| return Error::ErrInvalidStreamId)?;

        let _new_bytes_available = stream.inbound_stream_frame(fin, offset, data)?;

        Ok(())
    }

    // Returns new stream id
    pub fn stream_create(&mut self) -> u64 {
        let stream_id = self.next_stream_id;
        self.streams.insert(stream_id, BidiStream::new());
        self.next_stream_id += 1;
        stream_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake() {
        let mut client = Connection::new_client(&"example.com");
        client.input(None, 0).unwrap();
    }

}
