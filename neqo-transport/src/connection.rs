#![allow(unused_variables)]

use crate::data::Data;
use crate::frame::{decode_frame, Frame};
use crate::nss_stub::*;
use crate::packet::*;
use crate::stream::{BidiStream, Recvable, TxBuffer};
use crate::{Error, Res};
use neqo_crypto::Epoch;

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug};
use std::net::SocketAddr;
use std::ops;

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

const QUIC_VERSION: u32 = 0xff000012;

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

#[derive(Debug, PartialEq)]
pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    d: Vec<u8>,
}

pub enum TxMode {
    Normal,
    Pto,
}

type FrameGeneratorFn = fn(&mut Connection, u64, TxMode, usize) -> Option<Frame>;
struct FrameGenerator(FrameGeneratorFn);

impl Debug for FrameGenerator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("<FrameGenerator Function>")
    }
}

impl ops::Deref for FrameGenerator {
    type Target = FrameGeneratorFn;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/*trait FrameGenerator: Debug {
    fn next_frame(&mut self, conn: &mut Connection, now: u64, mode: TxMode, left: usize) -> Option<Frame>;
}*/

#[allow(unused_variables)]
#[derive(Debug)]
pub struct Connection {
    version: Version,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
    role: Role,
    state: State,
    tls: Agent,
    scid: Vec<u8>,
    dcid: Vec<u8>,
    // TODO(ekr@rtfm.com): Prioritized generators, rather than a vec
    send_epoch: Epoch,
    recv_epoch: Epoch,
    crypto_stream_out: [TxBuffer; 4],
    generators: Vec<FrameGenerator>,
    deadline: u64,
    max_data: u64,
    max_streams: u64,
    highest_stream: Option<u64>,
    connection_ids: HashSet<(u64, Vec<u8>)>, // (sequence number, connection id)
    next_stream_id: u64,
    streams: HashMap<u64, BidiStream>, // stream id, stream
    outgoing_pkts: Vec<Packet>,        // (offset, data)
    pmtu: usize,
}

impl Connection {
    pub fn new_client(server_name: &str) -> Connection {
        let mut c = Connection::new(
            Role::Client,
            Agent::Client(Client::new(server_name).unwrap()),
        );
        c.local_addr = Some("127.0.0.1:0".parse().unwrap());
        c.remote_addr = Some("127.0.0.1:0".parse().unwrap());
        c
    }

    pub fn new(r: Role, agent: Agent) -> Connection {
        let mut c = Connection {
            version: QUIC_VERSION,
            local_addr: None,
            remote_addr: None,
            role: r,
            state: match r {
                Role::Client => State::Init,
                Role::Server => State::WaitInitial,
            },
            tls: agent,
            scid: Vec::new(),
            dcid: Vec::new(),
            send_epoch: 0,
            recv_epoch: 0,
            crypto_stream_out: [
                TxBuffer::default(),
                TxBuffer::default(),
                TxBuffer::default(),
                TxBuffer::default(),
            ],
            generators: vec![FrameGenerator(generate_crypto_frames)],
            deadline: 0,
            max_data: 0,
            max_streams: 0,
            highest_stream: None,
            connection_ids: HashSet::new(),
            next_stream_id: 0,
            streams: HashMap::new(),
            outgoing_pkts: Vec::new(),
            pmtu: 1280,
        };

        c.scid = c.generate_cid();
        if c.role == Role::Client {
            c.dcid = c.generate_cid();
        }

        c
    }

    pub fn process(&mut self, _d: Option<Datagram>, now: u64) -> Res<(Option<Datagram>, u64)> {
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

        let dgram = self.output(now)?;

        Ok((dgram, 0)) // TODO(ekr@rtfm.com): When to call back next.
    }

    // Iterate through all the generators, inserting as many frames as will
    // fit.
    fn output(&mut self, now: u64) -> Res<Option<Datagram>> {
        let mut d = Data::default();
        let len = self.generators.len();

        for epoch in 0..=self.send_epoch {
            for i in 0..len {
                {
                    // TODO(ekr@rtfm.com): Fix TxMode
                    if let Some(f) =
                        self.generators[i](self, now, TxMode::Normal, self.pmtu - d.remaining())
                    {
                        f.marshal(&mut d)?;
                    }
                }
            }

            if d.remaining() > 0 {
                debug!("Need to send a packet of size {}", d.remaining());

                let mut hdr = PacketHdr {
                    tbyte: 0,
                    tipe: PacketType::Initial(Vec::new()),
                    version: Some(self.version),
                    dcid: ConnectionId(self.dcid.clone()),
                    scid: Some(ConnectionId(self.scid.clone())),
                    pn: 0, // TODO(ekr@rtfm.com): Implement
                    epoch: epoch as u64,
                    hdr_len: 0,
                    body_len: 0,
                };

                let mut packet = encode_packet(self, &mut hdr, d.as_mut_vec())?;

                debug!("Packet length: {} {:0x?}", packet.len(), packet);
                return Ok(Some(Datagram {
                    src: self.local_addr.unwrap(),
                    dst: self.remote_addr.unwrap(),
                    d: packet.to_vec(),
                }));
            }
        }

        return Ok(None);
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

        for m in msgs.recs {
            self.crypto_stream_out[m.epoch as usize].send(&m.data);
        }

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

    fn generate_cid(&mut self) -> Vec<u8> {
        // TODO(ekr@rtfm.com): Implement.
        return vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    }
}

// Mock for the crypto pieces
const AEAD_MASK: u8 = 0;

fn auth_tag(_hdr: &[u8], _body: &[u8]) -> [u8; 16] {
    [0xaa; 16]
}

impl PacketCtx for Connection {
    fn pn_length(&self, _pn: PacketNumber) -> usize {
        3
    }

    fn compute_mask(&self, _sample: &[u8]) -> Res<[u8; 5]> {
        Ok([0xa5, 0xa5, 0xa5, 0xa5, 0xa5])
    }

    fn decode_pn(&self, pn: u64) -> Res<PacketNumber> {
        Ok(pn)
    }

    fn aead_decrypt(
        &self,
        _pn: PacketNumber,
        _epoch: u64,
        hdr: &[u8],
        body: &[u8],
    ) -> Res<Vec<u8>> {
        let mut pt = body.to_vec();

        for i in 0..pt.len() {
            pt[i] ^= AEAD_MASK;
        }
        let pt_len = pt.len() - 16;
        let at = auth_tag(hdr, &pt[0..pt_len]);
        for i in 0..16 {
            if at[i] != pt[pt_len + i] {
                return Err(Error::ErrDecryptError);
            }
        }
        Ok(pt[0..pt_len].to_vec())
    }

    fn aead_encrypt(
        &self,
        _pn: PacketNumber,
        _epoch: u64,
        hdr: &[u8],
        body: &[u8],
    ) -> Res<Vec<u8>> {
        let mut d = Data::from_slice(body);
        d.encode_vec(&auth_tag(hdr, body));
        let v = d.as_mut_vec();
        for i in 0..v.len() {
            v[i] ^= AEAD_MASK;
        }

        Ok(v.to_vec())
    }
}

impl PacketDecoder for Connection {
    fn get_cid_len(&self) -> usize {
        5
    }
}

fn generate_crypto_frames(
    conn: &mut Connection,
    _now: u64,
    mode: TxMode,
    remaining: usize,
) -> Option<Frame> {
    if let Some((offset, data)) = conn.crypto_stream_out[0].next_bytes(mode, remaining) {
        return Some(Frame::Crypto {
            offset,
            data: data.to_vec(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake() {
        let mut client = Connection::new_client(&"example.com");
        let res = client.process(None, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        debug!("Output={:?}", res.0);
    }

}
