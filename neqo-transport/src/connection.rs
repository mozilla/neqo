#![allow(unused_variables)]

use std::cmp::{max, min};
use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Debug};
use std::net::SocketAddr;
use std::ops;
use std::time::Instant;

use rand::prelude::*;

use crate::data::Data;
use crate::frame::{decode_frame, Frame, StreamType};
use crate::nss::*;
use crate::packet::*;
use crate::stream::{RecvStream, Recvable, RxStreamOrderer, SendStream, Sendable, TxBuffer};
use crate::varint::get_varint_len;

use crate::{CError, Error, HError, Res};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

const QUIC_VERSION: u32 = 0xff000012;

const NUM_EPOCHS: Epoch = 4;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum State {
    Init,
    WaitInitial,
    Handshaking,
    Connected,
    Closed,
}

#[derive(Debug, PartialEq)]
pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    d: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TxMode {
    Normal,
    Pto,
}

type FrameGeneratorFn = fn(&mut Connection, Epoch, TxMode, usize) -> Option<Frame>;
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

#[derive(Debug)]
pub struct CryptoState {
    pn: u64,
}

#[derive(Debug, Default)]
pub struct CryptoStream {
    tx: TxBuffer,
    rx: RxStreamOrderer,
}

#[allow(unused_variables)]
#[derive(Debug)]
pub struct Connection {
    version: crate::packet::Version,
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
    crypto_streams: [CryptoStream; 4],
    generators: Vec<FrameGenerator>,
    deadline: Instant,
    max_data: u64,
    max_streams: u64,
    highest_stream: Option<u64>,
    connection_ids: HashSet<(u64, Vec<u8>)>, // (sequence number, connection id)
    next_stream_id: u64,
    send_streams: BTreeMap<u64, SendStream>, // stream id, stream
    recv_streams: BTreeMap<u64, RecvStream>, // stream id, stream
    outgoing_pkts: Vec<Packet>,              // (offset, data)
    pmtu: usize,
}

impl Connection {
    pub fn new_client(server_name: &str) -> Connection {
        let mut c = Connection::new(
            Role::Client,
            Agent::Client(Client::new(server_name).unwrap()),
        );
        // TODO(ekr@rtfm.com): Need addresses.
        c.local_addr = Some("127.0.0.1:0".parse().unwrap());
        c.remote_addr = Some("127.0.0.1:0".parse().unwrap());
        c
    }

    pub fn new_server(certs: &[String]) -> Connection {
        let mut c = Connection::new(Role::Server, Agent::Server(Server::new(certs).unwrap()));
        // TODO(ekr@rtfm.com): Need addresses.
        c.local_addr = Some("127.0.0.1:0".parse().unwrap());
        c
    }

    pub fn new(r: Role, mut agent: Agent) -> Connection {
        agent
            .enable_ciphers(&[TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384])
            .unwrap();
        agent
            .set_version_range(TLS_VERSION_1_3, TLS_VERSION_1_3)
            .unwrap();

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
            crypto_streams: [
                CryptoStream::default(),
                CryptoStream::default(),
                CryptoStream::default(),
                CryptoStream::default(),
            ],
            generators: vec![
                FrameGenerator(generate_crypto_frames),
                FrameGenerator(generate_stream_frames),
            ],
            deadline: Instant::now(),
            max_data: 0,
            max_streams: 0,
            highest_stream: None,
            connection_ids: HashSet::new(),
            next_stream_id: 0,
            send_streams: BTreeMap::new(),
            recv_streams: BTreeMap::new(),
            outgoing_pkts: Vec::new(),
            pmtu: 1280,
        };

        c.scid = c.generate_cid();
        if c.role == Role::Client {
            c.dcid = c.generate_cid();
        }

        c
    }

    /// Call in to process activity on the connection. Either new packets have
    /// arrived or a timeout has expired (or both).
    pub fn process(&mut self, d: Vec<Datagram>) -> Res<Vec<Datagram>> {
        for dgram in d {
            self.input(dgram)?;
        }

        if Instant::now() >= self.deadline {
            // Timer expired.
            match self.state {
                State::Init => {
                    self.client_start()?;
                }
                State::Handshaking => {
                    // Nothing to do.
                }
                State::Connected => {
                    // Nothing to do.
                }
                _ => unimplemented!(),
            }
        }

        let out_dgrams = self.output()?;

        Ok(out_dgrams) // TODO(ekr@rtfm.com): When to call back next.
    }

    pub fn input(&mut self, d: Datagram) -> Res<()> {
        let mut slc = &d.d[..];

        // Handle each packet in the datagram
        while !slc.is_empty() {
            let mut hdr = decode_packet_hdr(self, slc)?;

            // TODO(ekr@rtfm.com): Check for bogus versions and reject.
            // TODO(ekr@rtfm.com): Set up masking.

            match self.state {
                State::Init => {
                    qinfo!(self, "Received message while in Init state");
                    return Err(Error::ErrUnexpectedMessage);
                }
                State::WaitInitial => {
                    let dcid = &hdr.scid.as_ref().unwrap().0;
                    if self.role == Role::Server {
                        if dcid.len() < 8 {
                            qwarn!(self, "Peer CID is too short");
                            return Err(Error::ErrInvalidPacket);
                        }
                        self.remote_addr = Some(d.src);
                    }

                    // Imprint on the remote parameters.
                    self.dcid = dcid.clone();
                }
                State::Handshaking => {
                    // No-op.
                }
                State::Connected => {
                    // No-op.
                }
                State::Closed => {
                    // TODO(agrover@mozilla.com): send STOP_SENDING?
                }
            }

            qdebug!(self, "Received unverified packet {:?}", hdr);

            let body = decrypt_packet(self, &mut hdr, slc)?;

            // OK, we have a valid packet.

            // TODO(ekr@rtfm.com): Check for duplicates.
            // TODO(ekr@rtfm.com): Mark this packet received.
            // TODO(ekr@rtfm.com): Filter for valid for this epoch.

            if matches!(self.state, State::WaitInitial) {
                self.set_state(State::Handshaking);
            }

            let mut d = Data::from_slice(&body);

            // Handle each frame in the packet
            while d.remaining() > 0 {
                let f = decode_frame(&mut d)?;
                self.process_input_frame(hdr.epoch, f)?;
            }

            slc = &slc[hdr.hdr_len + hdr.encrypted_body_len()..];
        }

        Ok(())
    }

    pub fn state(&self) -> State {
        self.state
    }

    // Iterate through all the generators, inserting as many frames as will
    // fit.
    fn output(&mut self) -> Res<Vec<Datagram>> {
        let mut out_packets = Vec::new();

        // TODO(ekr@rtfm.com): Be smarter about what epochs we actually have.

        // Frames for different epochs must go in different packets, but then these
        // packets can go in a single datagram
        for epoch in 0..NUM_EPOCHS {
            let mut d = Data::default();
            let mut ds = Vec::new();
            for i in 0..self.generators.len() {
                // TODO(ekr@rtfm.com): Fix TxMode

                let left = self.pmtu - d.remaining();
                while let Some(frame) = self.generators[i](self, epoch, TxMode::Normal, left) {
                    qtrace!("pmtu {} remaining {}", self.pmtu, d.remaining());
                    frame.marshal(&mut d)?;
                    assert!(d.remaining() <= self.pmtu);
                    if d.remaining() == self.pmtu {
                        // Filled this packet, get another one.
                        ds.push(d);
                        d = Data::default();
                    }
                }
            }
            if d.remaining() > 0 {
                ds.push(d)
            }

            for mut d in ds {
                qdebug!(self, "Need to send a packet");

                let mut hdr = PacketHdr::new(
                    0,
                    match epoch {
                        // TODO(ekr@rtfm.com): Retry token
                        0 => PacketType::Initial(Vec::new()),
                        1 => PacketType::ZeroRTT,
                        2 => PacketType::Handshake,
                        3 => PacketType::Short,
                        _ => unimplemented!(), // TODO(ekr@rtfm.com): Key Update.
                    },
                    Some(self.version),
                    ConnectionId(self.dcid.clone()),
                    Some(ConnectionId(self.scid.clone())),
                    0, // TODO(ekr@rtfm.com): Implement PN
                    epoch,
                    0,
                );

                let packet = encode_packet(self, &mut hdr, d.as_mut_vec())?;
                out_packets.push(packet);
                // TODO(ekr@rtfm.com): Pad the Client Initial.

                // TODO(ekr@rtfm.com): Update PN.
            }
        }

        // Put packets in UDP datagrams
        let out_dgrams = out_packets
            .into_iter()
            .inspect(|p| qdebug!(self, "Packet length: {} {:0x?}", p.len(), p))
            .fold(Vec::new(), |mut vec: Vec<Datagram>, packet| {
                let new_dgram: bool = vec
                    .last()
                    .map(|dgram| dgram.d.len() + packet.len() > self.pmtu)
                    .unwrap_or(true);
                if new_dgram {
                    vec.push(Datagram {
                        src: self.local_addr.unwrap(),
                        dst: self.remote_addr.unwrap(),
                        d: packet,
                    });
                } else {
                    vec.last_mut().unwrap().d.extend(packet);
                }
                vec
            });

        out_dgrams
            .iter()
            .for_each(|dgram| qdebug!(self, "Datagram length: {}", dgram.d.len()));

        return Ok(out_dgrams);
    }

    fn client_start(&mut self) -> Res<()> {
        self.handshake(0, None)?;
        self.set_state(State::WaitInitial);
        Ok(())
    }

    #[allow(dead_code, unused_variables)]
    pub fn close(&mut self, _error: HError) {
        unimplemented!()
    }

    fn handshake(&mut self, epoch: u16, data: Option<&[u8]>) -> Res<()> {
        qdebug!("Handshake epoch={} data={:0x?}", epoch, data);
        let mut rec: Option<Record> = None;

        if let Some(d) = data {
            qdebug!(self, "Handshake received {:0x?} ", d);
            rec = Some(Record {
                ct: 22, // TODO(ekr@rtfm.com): Symbolic constants for CT. This is handshake.
                epoch,
                data: d.to_vec(),
            });
        }

        let mut m = self.tls.handshake_raw(0, rec);

        if matches!(m, Ok((HandshakeState::AuthenticationPending, _))) {
            // TODO(ekr@rtfm.com): IMPORTANT: This overrides
            // authentication and so is fantastically dangerous.
            // Fix before shipping.
            qwarn!(self, "marking connection as authenticated without checking");
            self.tls.authenticated();
            m = self.tls.handshake_raw(0, None);
        }
        match m {
            Err(_) => {
                qwarn!(self, "Handshake failed");
                return Err(Error::ErrHandshakeFailed);
            }
            Ok((_, msgs)) => {
                for m in msgs {
                    qdebug!("Inserting message {:?}", m);
                    self.crypto_streams[m.epoch as usize].tx.send(&m.data);
                }
            }
        }
        if *self.tls.state() == HandshakeState::Complete {
            qinfo!(self, "TLS handshake completed");
            self.set_state(State::Connected);
        }
        Ok(())
    }

    pub fn process_input_frame(&mut self, epoch: Epoch, frame: Frame) -> Res<()> {
        #[allow(unused_variables)]
        match frame {
            Frame::Padding => {
                qdebug!(self, "padding!");
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
            Frame::Crypto { offset, data } => {
                qdebug!(
                    self,
                    "Crypto frame on epoch={} offset={}, data={:0x?}",
                    epoch,
                    offset,
                    &data
                );
                let rx = &mut self.crypto_streams[epoch as usize].rx;
                rx.inbound_frame(offset, data)?;
                let mut buf = [0; 4096];
                if rx.data_ready() {
                    // TODO(ekr@rtfm.com): This is a hack, let's just have
                    // a length parameter.
                    let read = rx.read(&mut buf)?;
                    qdebug!("Read {} bytes", read);
                    self.handshake(epoch, Some(&buf[0..(read as usize)]))?;
                }
            }
            Frame::NewToken { token } => {} // TODO(agrover@mozilla.com): stick the new token somewhere
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
            } => {
                self.process_inbound_stream_frame(fin, stream_id, offset, data)?;
            }
            Frame::MaxData { maximum_data } => self.max_data = max(self.max_data, maximum_data),
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
            } => {} // TODO(agrover@mozilla.com): generate MaxStreamData
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
            Frame::RetireConnectionId { sequence_number } => {
                //self.connection_ids.insert((sequence_number, connection_id));
            } // TODO(agrover@mozilla.com): remove from list of connection IDs
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

    fn set_state(&mut self, state: State) {
        if state != self.state {
            qinfo!(self, "State change from {:?} -> {:?}", self.state, state);
            self.state = state;
        }
    }

    pub fn process_inbound_stream_frame(
        &mut self,
        fin: bool,
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
    ) -> Res<()> {
        // TODO(agrover@mozilla.com): more checking here

        let stream_type = match stream_id & 0x1 == 0 {
            true => StreamType::BiDi,
            false => StreamType::UniDi,
        };

        // TODO(agrover@mozilla.com): May create a stream so check against streams_max
        let stream = self
            .recv_streams
            .entry(stream_id)
            .or_insert(RecvStream::new());

        let _new_bytes_available = stream.inbound_stream_frame(fin, offset, data)?;

        Ok(())
    }

    // Returns new stream id
    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        // TODO(agrover@mozilla.com): Check against max_stream_id
        let mut stream_id = self.next_stream_id << 2;
        if self.role == Role::Server {
            stream_id += 1;
        }
        if st == StreamType::UniDi {
            stream_id += 2;
            self.send_streams.insert(stream_id, SendStream::new());
        } else {
            self.send_streams.insert(stream_id, SendStream::new());
            self.recv_streams.insert(stream_id, RecvStream::new());
        }
        self.next_stream_id += 1;
        Ok(stream_id)
    }

    /// Send data on a stream.
    /// Returns how many bytes were successfully sent. Could be less
    /// than total, based on receiver credit space available, etc.
    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Res<usize> {
        let stream = self
            .send_streams
            .get_mut(&stream_id)
            .ok_or_else(|| return Error::ErrInvalidStreamId)?;

        stream.send(data)
    }

    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        let stream = self
            .send_streams
            .get_mut(&stream_id)
            .ok_or_else(|| return Error::ErrInvalidStreamId)?;

        Sendable::close(stream);
        Ok(())
    }

    fn generate_cid(&mut self) -> Vec<u8> {
        let mut v: [u8; 8] = [0; 8];
        rand::thread_rng().fill(&mut v);
        v.to_vec()
    }

    pub fn label(&self) -> String {
        String::from("Connection {id=xxx}")
    }
    pub fn get_state(&self) -> ConnState {
        ConnState {
            connected: self.state == State::Connected,
            error: CError::Error(Error::ErrNoError), // TODO
            closed: self.state == State::Closed,
        }
    }

    pub fn get_recv_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Recvable)> + 'a> {
        Box::new(
            self.recv_streams
                .iter_mut()
                .map(|(x, y)| (*x, y as &mut Recvable)),
        )
    }

    pub fn get_recvable_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Recvable)> + 'a> {
        Box::new(
            self.get_recv_streams()
                .filter(|(_, stream)| stream.recv_data_ready()),
        )
    }

    pub fn get_send_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Sendable)> + 'a> {
        Box::new(
            self.send_streams
                .iter_mut()
                .map(|(x, y)| (*x, y as &mut Sendable)),
        )
    }

    pub fn get_sendable_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Sendable)> + 'a> {
        Box::new(
            self.get_send_streams()
                .filter(|(_, stream)| stream.send_data_ready()),
        )
    }

    pub fn reset_stream(&mut self, _id: u64, _err: HError) {}
}

pub struct ConnState {
    pub connected: bool,
    pub error: CError,
    pub closed: bool,
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
        _epoch: Epoch,
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
        _epoch: Epoch,
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
        8
    }
}

fn generate_crypto_frames(
    conn: &mut Connection,
    epoch: u16,
    mode: TxMode,
    remaining: usize,
) -> Option<Frame> {
    if let Some((offset, data)) = conn.crypto_streams[epoch as usize]
        .tx
        .next_bytes(mode, false)
    {
        return Some(Frame::Crypto {
            offset,
            data: data.to_vec(),
        });
    }
    None
}

/// Calculate the frame header size so we know how much data we can fit
fn stream_frame_hdr_len(stream_id: u64, offset: u64, remaining: usize) -> usize {
    let mut hdr_len = 1; // for frame type
    hdr_len += get_varint_len(stream_id);
    if offset > 0 {
        hdr_len += get_varint_len(offset);
    }

    // We always specify length
    hdr_len as usize + get_varint_len(remaining as u64) as usize
}

fn generate_stream_frames(
    conn: &mut Connection,
    epoch: u16,
    mode: TxMode,
    remaining: usize,
) -> Option<Frame> {
    // only send in 1rtt epoch?
    if epoch != 3 {
        return None;
    }

    for (stream_id, stream) in &mut conn.get_sendable_streams() {
        if stream.send_data_ready() {
            let fin = Sendable::final_size(stream);
            if let Some((offset, data)) = stream.next_bytes(mode) {
                let fin = match fin {
                    None => false,
                    Some(fin) => {
                        if fin == offset + data.len() as u64 {
                            true
                        } else {
                            false
                        }
                    }
                };
                let frame_hdr_len = stream_frame_hdr_len(stream_id, offset, remaining);
                qtrace!(
                    "Stream {} sending bytes {}-{}, epoch {}, mode {:?}, remaining {}",
                    stream_id,
                    offset,
                    offset + data.len() as u64,
                    epoch,
                    mode,
                    remaining
                );
                let data_len = min(data.len(), remaining - frame_hdr_len);
                let frame = Some(Frame::Stream {
                    fin,
                    stream_id,
                    offset,
                    data: data[..data_len].to_vec(),
                });
                stream.mark_as_sent(offset, data_len);
                return frame;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::StreamType;

    #[test]
    fn test_conn_handshake() {
        init_db("./db");
        // 0 -> CH
        qdebug!("---- client");
        let mut client = Connection::new_client("example.com");
        let res = client.process(Vec::new()).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        // CH -> SH
        qdebug!("---- server");
        let mut server = Connection::new_server(&[String::from("key")]);
        let res = server.process(res).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        // SH -> 0
        qdebug!("---- client");
        let res = client.process(res).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        // 0 -> EE, CERT, CV, FIN
        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());
        qdebug!("Output={:0x?}", res);

        // EE, CERT, CV, FIN -> FIN
        qdebug!("---- client");
        let res = client.process(res).unwrap();
        assert!(res.is_empty());
        qdebug!("Output={:0x?}", res);

        // FIN -> 0
        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());

        assert_eq!(client.state(), State::Connected);
        assert_eq!(server.state(), State::Connected);
    }

    #[test]
    // tests stream send/recv after connection is established.
    // TODO(agrover@mozilla.com): Add a test that sends data before connection
    // is fully established.
    fn test_conn_stream() {
        init_db("./db");

        let mut client = Connection::new_client("example.com");
        let mut server = Connection::new_server(&[String::from("key")]);

        qdebug!("---- client");
        let res = client.process(Vec::new()).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[0]: CRYPTO[CH]

        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // TODO(agrover@mozilla.com): ACKs
        // <<-- Initial[0]: CRYPTO[SH] ACK[0]
        // <<-- Handshake[0]: CRYPTO[EE, CERT, CV, FIN]

        qdebug!("---- client");
        let res = client.process(res).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(client.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[1]: ACK[0]
        // -->> Handshake[0]: CRYPTO[FIN], ACK[0]

        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());
        assert_eq!(server.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // -->> nothing

        qdebug!("---- client");
        // Send
        let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
        client.stream_send(client_stream_id, &vec![6; 100]).unwrap();
        client.stream_send(client_stream_id, &vec![7; 40]).unwrap();
        client
            .stream_send(client_stream_id, &vec![8; 4000])
            .unwrap();

        // Send to another stream but some data after fin has been set
        let client_stream_id2 = client.stream_create(StreamType::UniDi).unwrap();
        client.stream_send(client_stream_id2, &vec![6; 60]).unwrap();
        client.stream_close_send(client_stream_id2).unwrap();
        client
            .stream_send(client_stream_id2, &vec![7; 50])
            .unwrap_err();
        let res = client.process(res).unwrap();
        assert_eq!(res.len(), 4);

        qdebug!("---- server");
        let res = server.process(res).unwrap();
        assert!(res.is_empty());
        assert_eq!(server.state(), State::Connected);
        qdebug!("Output={:0x?}", res);

        let mut buf = vec![0; 4000];

        let mut iter = server.get_recvable_streams();
        let (stream_id, stream) = iter.next().unwrap();
        let (received, fin) = stream.read(&mut buf).unwrap();
        assert_eq!(received, 4000);
        let (received, fin) = stream.read(&mut buf).unwrap();
        assert_eq!(received, 140);
        assert_eq!(fin, false);

        let (stream_id, stream) = iter.next().unwrap();
        let (received, fin) = stream.read(&mut buf).unwrap();
        assert_eq!(received, 60);
        assert_eq!(fin, true);
    }
}
