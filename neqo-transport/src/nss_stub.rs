// TODO(ekr@rtfm.com): Remove this once I've implemented everything.
// Stub version of SSLRecord
#![allow(unused_variables, dead_code)]
use super::data::*;
//use super::packet::*;
use super::*;
use lazy_static::*;
use std::collections::linked_list::LinkedList;
use std::ops::{Deref, DerefMut};
use std::string::String;

#[derive(Debug, PartialEq)]
pub struct HandshakeMessage {
    name: String,
    epoch: u16,
    client: bool,
}

lazy_static! {
    pub static ref HANDSHAKE_MESSAGES: [HandshakeMessage; 7] = [
        HandshakeMessage {
            name: String::from("ClientHello"),
            epoch: 0,
            client: true
        },
        HandshakeMessage {
            name: String::from("ServerHello"),
            epoch: 0,
            client: false
        },
        HandshakeMessage {
            name: String::from("EncryptedExtensions"),
            epoch: 2,
            client: false
        },
        HandshakeMessage {
            name: String::from("Certificate"),
            epoch: 2,
            client: false
        },
        HandshakeMessage {
            name: String::from("CertificateVerify"),
            epoch: 2,
            client: false
        },
        HandshakeMessage {
            name: String::from("Finished"),
            epoch: 2,
            client: false,
        },
        HandshakeMessage {
            name: String::from("Finished"),
            epoch: 2,
            client: true
        }
    ];
}

#[derive(Debug)]
pub struct SslRecord {
    pub epoch: u16,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct SslRecordList {
    pub recs: LinkedList<SslRecord>,
}

#[derive(Default, Debug)]
pub struct SecretAgent {
    client: bool,
    next: usize,
}

#[derive(Default, Debug)]
pub struct HandshakeState {}

// This is a very bad simulation of the TLS handshake.
// Right now it just sends one message per record.
impl SecretAgent {
    pub fn handshake_raw(
        &mut self,
        _now: u64,
        input: SslRecordList,
    ) -> Res<(HandshakeState, SslRecordList)> {
        qdebug!(
            "handshake_raw self.next={} m={:?} client={}",
            self.next, HANDSHAKE_MESSAGES[self.next], self.client
        );
        let mut output = SslRecordList::default();
        // First read any input, but choke if we're not expecting it.
        for r in input.recs {
            if HANDSHAKE_MESSAGES[self.next].client == self.client {
                qwarn!("Receiving a handshake message when not expected");
                return Err(Error::ErrUnexpectedMessage);
            }
            let m = self.process_message(&r)?;
            if m != HANDSHAKE_MESSAGES[self.next] {
                qwarn!(
                    "Received message {:?} when expected {:?}",
                    &m, &HANDSHAKE_MESSAGES[self.next]
                );
                return Err(Error::ErrUnexpectedMessage);
            }
            self.next += 1;
        }

        // Now generate our output.
        while self.next < HANDSHAKE_MESSAGES.len() {
            let msg = &HANDSHAKE_MESSAGES[self.next];

            if msg.client != self.client {
                break;
            }
            let m = self.send_message(msg);
            qdebug!("Sending message: {:?}", msg);
            output.recs.push_back(SslRecord {
                data: m,
                epoch: msg.epoch,
            });
            self.next += 1;
        }

        qdebug!("handshake_raw() completed");

        if self.completed() {
            qinfo!("Handshake completed");
        }
        Ok((HandshakeState {}, output))
    }

    pub fn completed(&self) -> bool {
        self.next == HANDSHAKE_MESSAGES.len()
    }
    fn send_message(&mut self, m: &HandshakeMessage) -> Vec<u8> {
        let mut d = Data::default();
        d.encode_vec_and_len(&m.name.clone().into_bytes());
        d.as_mut_vec().to_vec()
    }

    fn process_message(&mut self, r: &SslRecord) -> Res<HandshakeMessage> {
        let mut d = Data::from_slice(&r.data);
        let v = d.decode_data_and_len()?;
        if d.remaining() > 0 {
            return Err(Error::ErrTooMuchData);
        }
        Ok(HandshakeMessage {
            name: String::from_utf8(v).unwrap(),
            epoch: r.epoch,
            client: !self.client,
        })
    }
}

#[derive(Debug)]
pub struct Client {
    agent: SecretAgent,
}

impl Client {
    pub fn new(server_name: &str) -> Res<Self> {
        let mut a = SecretAgent::default();
        a.client = true;
        Ok(Client { agent: a })
    }
}

impl Deref for Client {
    type Target = SecretAgent;
    fn deref(&self) -> &SecretAgent {
        &self.agent
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut SecretAgent {
        &mut self.agent
    }
}

#[derive(Debug)]
pub struct Server {
    agent: SecretAgent,
}

impl Server {
    pub fn new<T>(certificates: T) -> Res<Self>
    where
        T: IntoIterator,
        T::Item: ToString,
    {
        Ok(Server {
            agent: SecretAgent::default(),
        })
    }
}

impl Deref for Server {
    type Target = SecretAgent;
    fn deref(&self) -> &SecretAgent {
        &self.agent
    }
}

impl DerefMut for Server {
    fn deref_mut(&mut self) -> &mut SecretAgent {
        &mut self.agent
    }
}

/// A generic container for Client or Server.
#[derive(Debug)]
pub enum Agent {
    Client(Client),
    Server(Server),
}

impl Deref for Agent {
    type Target = SecretAgent;
    fn deref(&self) -> &SecretAgent {
        match self {
            Agent::Client(c) => c.deref(),
            Agent::Server(s) => s.deref(),
        }
    }
}

impl DerefMut for Agent {
    fn deref_mut(&mut self) -> &mut SecretAgent {
        match self {
            Agent::Client(c) => c.deref_mut(),
            Agent::Server(s) => s.deref_mut(),
        }
    }
}
