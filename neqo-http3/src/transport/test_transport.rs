// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_variables, dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::test_stream::Stream;
use neqo_transport::connection::{Datagram, Role, State, StreamId};
use neqo_transport::frame::StreamType;
use neqo_transport::{AppError, ConnectionError, Res};
use neqo_transport::{ConnectionEvent, ConnectionEvents, Recvable, Sendable};

#[derive(Debug)]
pub struct Connection {
    role: Role,
    st: State,
    deadline: u64,
    next_stream_id: u64,
    pub streams: HashMap<u64, Stream>,
    events: Rc<RefCell<ConnectionEvents>>,
}

pub struct Agent {}

impl Connection {
    fn new(r: Role) -> Connection {
        Connection {
            role: r,
            st: State::Init,
            deadline: 0,
            next_stream_id: 0,
            streams: HashMap::new(),
            events: Rc::new(RefCell::new(ConnectionEvents::default())),
        }
    }

    /// Get the current role.
    pub fn role(&self) -> Role {
        self.role
    }

    pub fn new_client() -> Connection {
        Connection::new(Role::Client)
    }

    pub fn new_server() -> Connection {
        Connection::new(Role::Server)
    }
    pub fn process_input<I>(&mut self, in_dgrams: I, cur_time: u64)
    where
        I: IntoIterator<Item = Datagram>,
    {
        if self.st == State::Init {
            self.st = State::Connected;
        }
    }

    pub fn process_output(&mut self, cur_time: u64) -> (Vec<Datagram>, u64) {
        (Vec::new(), 0)
    }

    pub fn process<I>(&mut self, in_dgrams: I, cur_time: u64) -> (Vec<Datagram>, u64)
    where
        I: IntoIterator<Item = Datagram>,
    {
        self.process_input(in_dgrams, cur_time);
        self.process_output(cur_time)
    }

    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        let stream_id = self.next_stream_id;
        self.streams.insert(stream_id, Stream::new(self.role, st));
        self.next_stream_id += 1;
        Ok(stream_id)
    }

    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Res<usize> {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.send(data)
        } else {
            Ok(0)
        }
    }

    pub fn stream_recv(&mut self, stream_id: u64, data: &mut [u8]) -> Res<(usize, bool)> {
        let mut rb = (0, false);
        if let Some(s) = self.streams.get_mut(&stream_id) {
            rb = s.read(data)?;
        }
        Ok((rb.0 as usize, rb.1))
    }

    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            Sendable::close(s);
        }
        Ok(())
    }

    pub fn close_receive_side(&mut self, stream_id: u64) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.receive_close();
            self.events
                .borrow_mut()
                .recv_stream_readable(StreamId::from(stream_id));
        }
    }

    pub fn stream_reset(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.reset(err);
        }
        Ok(())
    }

    pub fn close<S: Into<String>>(&mut self, err: AppError, _msg: S) {
        self.st = State::Closed(ConnectionError::Application(err));
    }

    pub fn state(&self) -> &State {
        &self.st
    }

    pub fn events(&mut self) -> Vec<ConnectionEvent> {
        for (stream_id, s) in self.streams.iter_mut() {
            if s.role == self.role || s.stream_type == StreamType::BiDi {
                self.events
                    .borrow_mut()
                    .send_stream_writable(StreamId::from(*stream_id));
            }
            if s.recv_buf.len() > 0 {
                self.events
                    .borrow_mut()
                    .recv_stream_readable(StreamId::from(*stream_id));
            }
        }
        // Turn it into a vec for simplicity's sake
        self.events.borrow_mut().events().into_iter().collect()
    }

    pub fn get_recv_stream_mut(&mut self, stream_id: u64) -> Option<&mut Recvable> {
        self.streams
            .get_mut(&stream_id)
            .map(|rs| rs as &mut Recvable)
    }

    pub fn get_send_stream_mut(&mut self, stream_id: u64) -> Option<&mut Sendable> {
        self.streams
            .get_mut(&stream_id)
            .map(|rs| rs as &mut Sendable)
    }

    // For tests
    pub fn stream_recv_net(&mut self, stream_id: u64, data: &[u8]) {
        match self.streams.get_mut(&stream_id) {
            Some(s) => s.recv_buf.extend(data),
            None => assert!(false, "There must be a stream"),
        }
    }

    pub fn data_ready(&mut self, stream_id: u64) -> bool {
        match self.streams.get_mut(&stream_id) {
            Some(s) => s.data_ready(),
            None => {
                assert!(false, "There must be a stream");
                false
            }
        }
    }

    pub fn recv_data_ready_amount(&mut self, stream_id: u64) -> usize {
        match self.streams.get_mut(&stream_id) {
            Some(s) => s.recv_data_ready_amount(),
            None => {
                assert!(false, "There must be a stream");
                0
            }
        }
    }

    pub fn stream_create_net(&mut self, role: Role, st: StreamType) -> Res<u64> {
        let stream_id = self.next_stream_id;
        self.streams.insert(stream_id, Stream::new(role, st));
        self.next_stream_id += 1;
        self.events
            .borrow_mut()
            .new_stream(StreamId::from(stream_id), st);
        Ok(stream_id)
    }
}
