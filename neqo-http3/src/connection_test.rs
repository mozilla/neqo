use crate::stream_test::{Stream, get_stream_type};
use neqo_transport::connection::{Datagram, Role, State};
use neqo_transport::frame::StreamType;
use neqo_transport::{Error, Res};
use std::collections::HashMap;
//use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub struct ConnState {
    pub connected: bool,
    pub error: Option<Error>,
    pub closed: bool,
}

pub struct Connection {
    role: Role,
    state: State,
    deadline: u64,
    //    max_data: u64,
    //    max_streams: u64,
    next_stream_id: u64,
    streams: HashMap<u64, Stream>,
}

impl Connection {
    pub fn new(r: Role) -> Connection {
        Connection {
            role: r,
            state: State::Init,
            deadline: 0,
            next_stream_id: 0,
            streams: HashMap::new(),
        }
    }

    pub fn input(&mut self, _d: Option<&Datagram>, now: u64) -> Res<(Option<&Datagram>, u64)> {
        //   let d = Datagram { src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        //               dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080), d: vec![1,2,3] };
        Ok((None, self.deadline))
    }

    pub fn get_state(&self) -> ConnState {
        ConnState {
            connected: self.state == State::Connected,
            error: None,
            closed: self.state == State::Closed,
        }
    }

    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        let stream_id = self.next_stream_id;
        self.streams.insert(stream_id, Stream::new(get_stream_type(self.role, st)));
        self.next_stream_id += 1;
        Ok(stream_id)
    }

    pub fn get_readable_streams(&self) -> std::collections::hash_map::Iter<u64, Stream> {
        self.streams.iter()
    }

    pub fn get_writable_streams(&self) -> std::collections::hash_map::Iter<u64, Stream> {
        self.streams.iter()
    }
}
