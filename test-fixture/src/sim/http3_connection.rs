// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is test code.")]

use std::{cmp::min, collections::HashMap, fmt::Debug, time::Instant};

use neqo_common::{event::Provider as _, qdebug, qinfo, qtrace, Datagram};
use neqo_crypto::AuthenticationStatus;
use neqo_http3::{
    Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3Server, Http3ServerEvent,
    Http3State, Priority,
};
use neqo_transport::{ConnectionParameters, Output, StreamId};

use crate::{
    boxed, http3_client_with_params, http3_server_with_params, now,
    sim::{self, GoalStatus, Rng},
};

/// A goal for the connection.
/// Goals can be accomplished in any order.
pub trait Goal: Debug {
    fn init(&mut self, _c: &mut Endpoint, _now: Instant) {}
    /// Perform some processing.
    fn process(&mut self, _c: &mut Endpoint, _now: Instant) -> GoalStatus {
        GoalStatus::Waiting
    }
    /// Handle an event from the provided connection, returning `true` when the
    /// goal is achieved.
    fn handle_event(&mut self, c: &mut Endpoint, e: &Event, now: Instant) -> GoalStatus;
}

#[derive(derive_more::Debug)]
#[debug("{}", c)]
pub struct Node {
    c: Endpoint,
    setup_goals: Vec<Box<dyn Goal>>,
    goals: Vec<Box<dyn Goal>>,
}

#[expect(clippy::large_enum_variant, reason = "test code only")]
#[derive(strum::Display)]
pub enum Endpoint {
    #[strum(to_string = "{0}")]
    Client(Http3Client),
    #[strum(to_string = "{0}")]
    Server(Http3Server),
}

impl Endpoint {
    fn process(&mut self, take: Option<Datagram>, now: Instant) -> Output {
        match self {
            Self::Client(c) => c.process(take, now),
            Self::Server(s) => s.process(take, now),
        }
    }

    fn next_event(&mut self) -> Option<Event> {
        match self {
            Self::Client(c) => c.next_event().map(Event::Client),
            Self::Server(s) => s.next_event().map(Event::Server),
        }
    }
}

#[derive(Debug)]
pub enum Event {
    Client(Http3ClientEvent),
    Server(Http3ServerEvent),
}

impl Node {
    pub fn new_client<
        I: IntoIterator<Item = Box<dyn Goal>>,
        I1: IntoIterator<Item = Box<dyn Goal>>,
    >(
        params: Http3Parameters,
        setup: I,
        goals: I1,
    ) -> Self {
        Self {
            c: Endpoint::Client(http3_client_with_params(params)),
            setup_goals: setup.into_iter().collect(),
            goals: goals.into_iter().collect(),
        }
    }

    pub fn new_server<
        I: IntoIterator<Item = Box<dyn Goal>>,
        I1: IntoIterator<Item = Box<dyn Goal>>,
    >(
        params: Http3Parameters,
        setup: I,
        goals: I1,
    ) -> Self {
        Self {
            c: Endpoint::Server(http3_server_with_params(params)),
            setup_goals: setup.into_iter().collect(),
            goals: goals.into_iter().collect(),
        }
    }

    pub fn default_client<I: IntoIterator<Item = Box<dyn Goal>>>(goals: I) -> Self {
        Self::new_client(
            Http3Parameters::default().connection_parameters(
                // Simulator logic does not work with multi-packet MLKEM crypto flights.
                ConnectionParameters::default().mlkem(false),
            ),
            boxed![ReachState::new(Http3State::Connected)],
            goals,
        )
    }

    pub fn default_server<I: IntoIterator<Item = Box<dyn Goal>>>(goals: I) -> Self {
        Self::new_server(
            Http3Parameters::default().connection_parameters(
                // Simulator logic does not work with multi-packet MLKEM crypto flights.
                ConnectionParameters::default().mlkem(false),
            ),
            boxed![ReachState::new(Http3State::Connected)],
            goals,
        )
    }

    /// On the first call to this method, the setup goals will turn into the active goals.
    /// On the second call, they will be swapped back and the main goals will run.
    fn setup_goals(&mut self, now: Instant) {
        std::mem::swap(&mut self.goals, &mut self.setup_goals);
        for g in &mut self.goals {
            g.init(&mut self.c, now);
        }
    }

    /// Process all goals using the given closure and return whether any were active.
    fn process_goals<F>(&mut self, mut f: F) -> bool
    where
        F: FnMut(&mut Box<dyn Goal>, &mut Endpoint) -> GoalStatus,
    {
        let mut active = false;
        let mut i = 0;
        while i < self.goals.len() {
            let status = f(&mut self.goals[i], &mut self.c);
            if status == GoalStatus::Done {
                self.goals.remove(i);
                active = true;
            } else {
                active |= status == GoalStatus::Active;
                i += 1;
            }
        }
        active
    }
}

impl sim::Node for Node {
    fn init(&mut self, _rng: Rng, now: Instant) {
        self.setup_goals(now);
    }

    fn process(&mut self, mut d: Option<Datagram>, now: Instant) -> Output {
        _ = self.process_goals(|goal, c| goal.process(c, now));
        loop {
            let res = self.c.process(d.take(), now);

            let mut active = false;
            while let Some(e) = self.c.next_event() {
                qtrace!("[{}] received event {e:?}", self.c);

                // Perform authentication automatically.
                if matches!(e, Event::Client(Http3ClientEvent::AuthenticationNeeded)) {
                    match &mut self.c {
                        Endpoint::Client(http3_client) => {
                            http3_client.authenticated(AuthenticationStatus::Ok, now);
                        }
                        Endpoint::Server(_) => unreachable!(),
                    }
                }

                active |= self.process_goals(|goal, c| goal.handle_event(c, &e, now));
            }
            // Exit at this point if the connection produced a datagram.
            // We also exit if none of the goals were active, as there is
            // no point trying again if they did nothing.
            if matches!(res, Output::Datagram(_)) || !active {
                return res;
            }
            qdebug!("[{}] no datagram and goal activity, looping", self.c);
        }
    }

    fn prepare(&mut self, now: Instant) {
        assert!(self.done(), "ConnectionNode::prepare: setup not complete");
        self.setup_goals(now);
        assert!(!self.done(), "ConnectionNode::prepare: setup not complete");
    }

    fn done(&self) -> bool {
        self.goals.is_empty()
    }

    fn print_summary(&self, test_name: &str) {
        match &self.c {
            Endpoint::Client(c) => qinfo!("{test_name}: {:?}", c.transport_stats()),
            Endpoint::Server(_) => qinfo!("{test_name}: Server (no stats available on server)"),
        }
    }
}

/// A target for a connection that involves reaching a given connection state.
#[derive(Debug, Clone)]
pub struct ReachState {
    target: Http3State,
}

impl ReachState {
    /// Create a new instance that intends to reach the indicated state.
    #[must_use]
    pub const fn new(target: Http3State) -> Self {
        Self { target }
    }
}

impl Goal for ReachState {
    fn handle_event(&mut self, _c: &mut Endpoint, e: &Event, _now: Instant) -> GoalStatus {
        match e {
            Event::Client(Http3ClientEvent::StateChange(state))
            | Event::Server(Http3ServerEvent::StateChange { state, .. })
                if *state == self.target =>
            {
                GoalStatus::Done
            }
            _ => GoalStatus::Waiting,
        }
    }
}

/// A target for a connection that involves sending a given amount of data on the indicated stream.
#[derive(Debug, Clone)]
pub struct Requests {
    amount: usize,
    send_per_request: usize,
    remaining: HashMap<StreamId, usize>,
}

impl Requests {
    #[must_use]
    pub fn new(num_requests: usize, send_per_request: usize) -> Self {
        Self {
            amount: num_requests,
            send_per_request,
            remaining: HashMap::new(),
        }
    }

    fn fetch(&mut self, c: &mut Http3Client) {
        while self.amount > 0 {
            if self.amount == 0 {
                return;
            }
            let now = now();
            let stream_id = match c.fetch(
                now,
                "POST",
                ("https", "something.com", "/"),
                &[],
                Priority::default(),
            ) {
                Ok(stream_id) => stream_id,
                Err(neqo_http3::Error::StreamLimit) => {
                    break;
                }
                Err(e) => panic!("unexpected error from fetch: {e}"),
            };
            qdebug!("[{c}] made stream {stream_id} for sending");
            self.remaining.insert(stream_id, self.send_per_request);
            self.amount -= 1;
            self.send(c, stream_id, now);
        }
    }

    fn send(&mut self, c: &mut Http3Client, stream_id: StreamId, now: Instant) -> GoalStatus {
        const DATA: &[u8] = &[0; 4096];
        let mut status = GoalStatus::Waiting;
        loop {
            let remaining = self.remaining.get_mut(&stream_id).unwrap();
            let end = min(*remaining, DATA.len());
            let sent = c.send_data(stream_id, &DATA[..end], now).unwrap();
            if sent == 0 {
                return status;
            }
            status = GoalStatus::Active;
            *remaining -= sent;
            qtrace!("sent {sent} remaining {remaining}");
            if *remaining == 0 {
                c.stream_close_send(stream_id, now).unwrap();
                self.remaining.remove(&stream_id);
                return status;
            }
        }
    }

    fn is_done(&self) -> bool {
        self.amount == 0 && self.remaining.is_empty()
    }
}

impl Goal for Requests {
    fn init(&mut self, c: &mut Endpoint, _now: Instant) {
        let c = match c {
            Endpoint::Client(http3_client) => http3_client,
            Endpoint::Server(_) => unreachable!(),
        };
        self.fetch(c);
    }

    fn process(&mut self, _c: &mut Endpoint, _now: Instant) -> GoalStatus {
        if self.is_done() {
            return GoalStatus::Done;
        }

        GoalStatus::Waiting
    }

    fn handle_event(&mut self, c: &mut Endpoint, e: &Event, now: Instant) -> GoalStatus {
        let e = match e {
            Event::Client(http3_client_event) => http3_client_event,
            Event::Server(_) => unreachable!("only client can make a request"),
        };
        let c = match c {
            Endpoint::Client(http3_client) => http3_client,
            Endpoint::Server(_) => unreachable!("only client can make a request"),
        };
        match e {
            Http3ClientEvent::RequestsCreatable => {
                self.fetch(c);
                GoalStatus::Active
            }
            Http3ClientEvent::DataWritable { stream_id } => self.send(c, *stream_id, now),

            // If we sent data in 0-RTT, then we didn't track how much we should
            // have sent.  This is trivial to fix if 0-RTT testing is ever needed.
            Http3ClientEvent::ZeroRttRejected => panic!("not supported"),
            _ => GoalStatus::Waiting,
        }
    }
}

/// Receive a prescribed amount of data from any stream.
#[derive(Debug, Clone)]
pub struct Responses {
    amount: usize,
    receive_per_request: usize,
    remaining: HashMap<StreamId, usize>,
}

impl Responses {
    #[must_use]
    pub fn new(num_requests: usize, receive_per_request: usize) -> Self {
        Self {
            amount: num_requests,
            receive_per_request,
            remaining: HashMap::new(),
        }
    }

    fn is_done(&self) -> bool {
        self.amount == 0 && self.remaining.is_empty()
    }
}

impl Goal for Responses {
    fn handle_event(&mut self, _c: &mut Endpoint, e: &Event, now: Instant) -> GoalStatus {
        let e = match e {
            Event::Client(_) => unreachable!("only server can send a response"),
            Event::Server(http3_server_event) => http3_server_event,
        };

        match e {
            Http3ServerEvent::Headers { stream, fin, .. } => {
                assert_eq!(self.remaining.get(&stream.stream_id()), None);
                if !fin {
                    self.remaining
                        .insert(stream.stream_id(), self.receive_per_request);
                }
                self.amount -= 1;
                GoalStatus::Active
            }
            Http3ServerEvent::Data { stream, data, fin } => {
                let stream_id = stream.stream_id();
                let len = data.len();

                let remaining = self.remaining.get_mut(&stream_id).unwrap();

                *remaining -= len;
                qtrace!("received {len} remaining {remaining}");
                if *remaining == 0 {
                    assert!(fin);
                    stream
                        .send_headers(&[Header::new(":status", "200")])
                        .unwrap();
                    stream.stream_close_send(now).unwrap();
                    self.remaining.remove(&stream_id);
                }

                if self.is_done() {
                    return GoalStatus::Done;
                }

                GoalStatus::Active
            }
            _ => GoalStatus::Waiting,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::{
        boxed,
        sim::{
            http3_connection::{Node, Requests, Responses},
            network::TailDrop,
            Simulator,
        },
    };

    #[test]
    fn requests() {
        let nodes = boxed![
            Node::default_client(boxed![Requests::new(20, 1_000)]),
            TailDrop::dsl_uplink(),
            Node::default_server(boxed![Responses::new(20, 1_000)]),
            TailDrop::dsl_uplink(),
        ];
        let sim = Simulator::new("", nodes);
        sim.setup().run();
    }
}
