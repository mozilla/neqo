// TODO(ekr@rtfm.com): Remove this once I've implemented everything.
// Stub version of SSLRecord
#![allow(unused_variables, dead_code)]
//use super::data::*;
//use super::packet::*;
use super::*;
use std::collections::linked_list::{LinkedList};
use std::ops::{Deref, DerefMut};

struct SslRecord {
    epoch: u16,
    data: Vec<u8>,
}

struct SslRecordList {
    recs: LinkedList<SslRecord>,
}

#[derive(Default, Debug)]
struct SecretAgent {
}

struct Client {
    agent: SecretAgent,
}

impl Client {
    pub fn new(server_name: &str) -> Res<Self> {
        Ok(Client{
            agent: SecretAgent::default(),
        })
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

struct Server {
    agent: SecretAgent,
}

impl Server {
    pub fn new<T>(certificates: T) -> Res<Self>
    where
        T: IntoIterator,
        T::Item: ToString
    {
        Ok(Server{
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


/*
/// A generic container for Client or Server.
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
*/
