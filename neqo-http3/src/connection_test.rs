#![allow(unused_variables, dead_code)]

use crate::stream_test::{get_stream_type, Stream};
use neqo_transport::connection::{ConnState, Datagram, Role, State};
use neqo_transport::frame::StreamType;
use neqo_transport::stream::{as_recvable, as_sendable, Recvable, Sendable};
use neqo_transport::{Error, Res};
use std::collections::HashMap;

pub struct Connection {
    role: Role,
    agent: Agent,
    state: State,
    deadline: u64,
    next_stream_id: u64,
    pub streams: HashMap<u64, Stream>,
    pub closed_streams: Option<Vec<u64>>,
    error: Option<Error>,
}

pub struct Agent {}

impl Connection {
    pub fn new(r: Role, agent: Agent) -> Connection {
        Connection {
            role: r,
            agent: agent,
            state: State::Init,
            deadline: 0,
            next_stream_id: 0,
            streams: HashMap::new(),
            closed_streams: None,
            error: None,
        }
    }

    pub fn input(&mut self, _d: Option<Datagram>, _now: u64) -> Res<(Option<Datagram>, u64)> {
        self.state = State::Connected;
        Ok((None, self.deadline))
    }

    pub fn get_state(&self) -> ConnState {
        ConnState {
            connected: self.state == State::Connected,
            error: None,
            closed: self.state == State::Closed,
        }
    }

    pub fn stream_create(&mut self, st: StreamType) -> u64 {
        let stream_id = self.next_stream_id;
        self.streams
            .insert(stream_id, Stream::new(get_stream_type(self.role, st)));
        self.next_stream_id += 1;
        stream_id
    }

    pub fn get_readable_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Recvable)> + 'a> {
        Box::new(self.streams.iter_mut().map(|(x, y)| (*x, as_recvable(y))))
    }

    pub fn get_writable_streams<'a>(
        &'a mut self,
    ) -> Box<Iterator<Item = (u64, &mut dyn Sendable)> + 'a> {
        Box::new(self.streams.iter_mut().map(|(x, y)| (*x, as_sendable(y))))
    }

    pub fn get_closed_streams(&mut self) -> Option<Vec<u64>> {
        let r = self.closed_streams.clone();
        self.closed_streams = None;
        r
    }

    pub fn close_receive_side(&mut self, id: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.receive_close();
            if let None = self.closed_streams {
                self.closed_streams = Some(Vec::new());
            }
            if let Some(v) = &mut self.closed_streams {
                v.push(id);
            }
        }
    }

    pub fn reset_stream(&mut self, id: u64, err: Error) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.reset(err);
        }
    }

    pub fn close(&mut self, error: Option<Error>) {
        self.state = State::Closed;
        self.error = error;
    }
}
