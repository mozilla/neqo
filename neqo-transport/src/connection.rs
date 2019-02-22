#![allow(unused_variables)]

use crate::data::Data;
use crate::frame::{decode_frame, Frame};
use crate::nss_stub::*;
use crate::packet::*;
use crate::{Error, Res};
use neqo_crypto::Epoch;

use crate::stream::{BidiStream, Recvable, RxStreamOrderer, TxBuffer};
use rand::prelude::*;
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

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum State {
    Init,
    WaitInitial,
    Handshaking,
    Connected,
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

type FrameGeneratorFn = fn(&mut Connection, u64, u16, TxMode, usize) -> Option<Frame>;
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
    version: Version,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
    role: Role,
    state: State,
    tls: Agent,
    scid: Vec<u8>,
    dcid: Vec<u8>,
    // TODO(ekr@rtfm.com): Prioritized generators, rather than a vec
    send_epoch: u16,
    recv_epoch: u16,
    crypto_streams: [CryptoStream; 4],
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
            crypto_streams: [
                CryptoStream::default(),
                CryptoStream::default(),
                CryptoStream::default(),
                CryptoStream::default(),
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

    pub fn process(&mut self, d: Option<Datagram>, now: u64) -> Res<(Option<Datagram>, u64)> {
        if let Some(dgram) = d {
            self.input(dgram, now)?;
        }

        if now >= self.deadline {
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

        let dgram = self.output(now)?;

        Ok((dgram, 0)) // TODO(ekr@rtfm.com): When to call back next.
    }

    pub fn input(&mut self, d: Datagram, now: u64) -> Res<()> {
        let mut hdr = decode_packet_hdr(self, &d.d)?;

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
            _ => unimplemented!(),
        }

        qdebug!(self, "Received unverified packet {:?}", hdr);

        let body = decrypt_packet(self, &mut hdr, &d.d)?;

        // OK, we have a valid packet.

        // TODO(ekr@rtfm.com): Check for duplicates.
        // TODO(ekr@rtfm.com): Mark this packet received.
        // TODO(ekr@rtfm.com): Filter for valid for this epoch.

        if matches!(self.state, State::WaitInitial) {
            self.set_state(State::Handshaking);
        }

        let mut d = Data::from_slice(&body);
        while d.remaining() > 0 {
            let f = decode_frame(&mut d)?;
            self.process_input_frame(hdr.epoch as u16, f)?;
        }

        Ok(())
    }

    pub fn state(&self) -> State {
        self.state
    }

    // Iterate through all the generators, inserting as many frames as will
    // fit.
    fn output(&mut self, now: u64) -> Res<Option<Datagram>> {
        let mut d = Data::default();
        let len = self.generators.len();

        // TOOD(ekr@rtfm.com): Be smarter about what epochs we actually have.
        for epoch in 0..4 {
            for i in 0..len {
                {
                    // TODO(ekr@rtfm.com): Fix TxMode
                    if let Some(f) = self.generators[i](
                        self,
                        now,
                        epoch as u16,
                        TxMode::Normal,
                        self.pmtu - d.remaining(),
                    ) {
                        f.marshal(&mut d)?;
                    }
                }
            }

            if d.remaining() > 0 {
                qdebug!(self, "Need to send a packet of size {}", d.remaining());

                let mut hdr = PacketHdr {
                    tbyte: 0,
                    tipe: match epoch {
                        // TODO(ekr@rtfm.com): Retry token
                        0 => PacketType::Initial(Vec::new()),
                        1 => PacketType::ZeroRTT,
                        2 => PacketType::Handshake,
                        3 => PacketType::Short,
                        _ => unimplemented!(), // TODO(ekr@rtfm.com): Key Update.
                    },
                    version: Some(self.version),
                    dcid: ConnectionId(self.dcid.clone()),
                    scid: Some(ConnectionId(self.scid.clone())),
                    pn: 0, // TODO(ekr@rtfm.com): Implement
                    epoch: epoch as u64,
                    hdr_len: 0,
                    body_len: 0,
                };

                let packet = encode_packet(self, &mut hdr, d.as_mut_vec())?;

                qdebug!(self, "Packet length: {} {:0x?}", packet.len(), packet);
                return Ok(Some(Datagram {
                    src: self.local_addr.unwrap(),
                    dst: self.remote_addr.unwrap(),
                    d: packet.to_vec(),
                }));
            }

            // TODO(ekr@rtfm.com): Pack >1 packet into a datagram.
            // TODO(ekr@rtfm.com): Pad the Client Initial.

            // TODO(ekr@rtfm.com): Update PN.
        }

        return Ok(None);
    }

    fn client_start(&mut self) -> Res<()> {
        self.handshake(1, 0, None)?;
        self.set_state(State::WaitInitial);
        Ok(())
    }

    fn handshake(&mut self, now: u64, epoch: u16, data: Option<&[u8]>) -> Res<()> {
        qdebug!("Handshake epoch={} data={:0x?}", epoch, data);
        let mut recs = SslRecordList::default();

        if let Some(d) = data {
            qdebug!(self, "Handshake received {:0x?} ", d.to_vec());
            recs.recs.push_back(SslRecord {
                epoch,
                data: d.to_vec(),
            });
        }

        let (_, msgs) = self.tls.handshake_raw(now, recs)?;
        qdebug!(self, "Handshake emitted {} messages", msgs.recs.len());

        for m in msgs.recs {
            qdebug!("Inserting message {:?}", m);
            self.crypto_streams[m.epoch as usize].tx.send(&m.data);
        }

        if self.tls.completed() {
            qinfo!(self, "TLS handshake completed");
            self.set_state(State::Connected);
        }
        Ok(())
    }

    pub fn process_input_frame(&mut self, epoch: u16, frame: Frame) -> Res<()> {
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
                let toread = rx.data_ready() as usize;
                if toread > 0 {
                    // TODO(ekr@rtfm.com): This is a hack, let's just have
                    // a length parameter.
                    let mut v = Vec::<u8>::with_capacity(toread);
                    v.resize(toread, 0);
                    let read = rx.read(&mut v)?;
                    qdebug!(self, "Read {} bytes", read);
                    assert_eq!(toread as u64, read);
                    self.handshake(0, epoch, Some(&v))?;
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
        let mut v: [u8; 8] = [0; 8];
        rand::thread_rng().fill(&mut v);
        v.to_vec()
    }

    pub fn label(&self) -> String {
        String::from("Connection {id=xxx}")
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
    now: u64,
    epoch: u16,
    mode: TxMode,
    remaining: usize,
) -> Option<Frame> {
    if let Some((offset, data)) = conn.crypto_streams[epoch as usize]
        .tx
        .next_bytes(mode, now, remaining)
    {
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
        // 0 -> CH
        let mut client = Connection::new_client(&"example.com");
        let res = client.process(None, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        qdebug!("Output={:?}", res.0);

        // CH -> SH
        let mut server = Connection::new_server(&[String::from("example.com")]);
        let res = server.process(res.0, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        qdebug!("Output={:?}", res.0);

        // SH -> 0
        let res = client.process(res.0, 0).unwrap();
        assert_eq!(None, res.0);

        // 0 -> EE.
        let res = server.process(None, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        qdebug!("Output={:?}", res.0);

        // EE -> 0
        let res = client.process(res.0, 0).unwrap();
        assert_eq!(None, res.0);

        // 0 -> CERT.
        let res = server.process(None, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        qdebug!("Output={:?}", res.0);

        // CERT -> 0
        let res = client.process(res.0, 0).unwrap();
        assert_eq!(None, res.0);

        // 0 -> CV.
        let res = server.process(None, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        qdebug!("Output={:?}", res.0);

        // CV -> 0
        let res = client.process(res.0, 0).unwrap();
        assert_eq!(None, res.0);

        // 0 -> FIN.
        let res = server.process(None, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        qdebug!("Output={:?}", res.0);

        // FIN -> FIN
        let res = client.process(res.0, 0).unwrap();
        assert_ne!(None, res.0);
        assert_eq!(0, res.1);
        qdebug!("Output={:?}", res.0);

        // FIN -> 0
        let res = server.process(res.0, 0).unwrap();
        assert_eq!(None, res.0);

        assert_eq!(client.state(), State::Connected);
        assert_eq!(server.state(), State::Connected);
    }

}
