// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(clippy::module_name_repetitions)]

use std::{
    cmp::min,
    fmt::{self, Debug},
    time::Instant,
};

use neqo_common::{event::Provider, qdebug, qinfo, qtrace, Datagram};
use neqo_crypto::AuthenticationStatus;
use neqo_transport::{
    Connection, ConnectionEvent, ConnectionParameters, Output, State, StreamId, StreamType,
};

use crate::{
    boxed,
    sim::{Node, Rng},
};

/// The status of the processing of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalStatus {
    /// The event didn't result in doing anything; the goal is waiting for something.
    Waiting,
    /// An action was taken as a result of the event.
    Active,
    /// The goal was accomplished.
    Done,
}

/// A goal for the connection.
/// Goals can be accomplished in any order.
pub trait ConnectionGoal: Debug {
    fn init(&mut self, _c: &mut Connection, _now: Instant) {}
    /// Perform some processing.
    fn process(&mut self, _c: &mut Connection, _now: Instant) -> GoalStatus {
        GoalStatus::Waiting
    }
    /// Handle an event from the provided connection, returning `true` when the
    /// goal is achieved.
    fn handle_event(&mut self, c: &mut Connection, e: &ConnectionEvent, now: Instant)
        -> GoalStatus;
}

pub struct ConnectionNode {
    c: Connection,
    setup_goals: Vec<Box<dyn ConnectionGoal>>,
    goals: Vec<Box<dyn ConnectionGoal>>,
}

impl ConnectionNode {
    pub fn new_client(
        params: ConnectionParameters,
        setup: impl IntoIterator<Item = Box<dyn ConnectionGoal>>,
        goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>,
    ) -> Self {
        Self {
            c: crate::new_client(params),
            setup_goals: setup.into_iter().collect(),
            goals: goals.into_iter().collect(),
        }
    }

    pub fn new_server(
        params: ConnectionParameters,
        setup: impl IntoIterator<Item = Box<dyn ConnectionGoal>>,
        goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>,
    ) -> Self {
        Self {
            c: crate::new_server(crate::DEFAULT_ALPN, params),
            setup_goals: setup.into_iter().collect(),
            goals: goals.into_iter().collect(),
        }
    }

    pub fn default_client(goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>) -> Self {
        Self::new_client(
            ConnectionParameters::default(),
            boxed![ReachState::new(State::Confirmed)],
            goals,
        )
    }

    pub fn default_server(goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>) -> Self {
        Self::new_server(
            ConnectionParameters::default(),
            boxed![ReachState::new(State::Confirmed)],
            goals,
        )
    }

    #[allow(dead_code)]
    pub fn clear_goals(&mut self) {
        self.goals.clear();
    }

    #[allow(dead_code)]
    pub fn add_goal(&mut self, goal: Box<dyn ConnectionGoal>) {
        self.goals.push(goal);
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
        F: FnMut(&mut Box<dyn ConnectionGoal>, &mut Connection) -> GoalStatus,
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

impl Node for ConnectionNode {
    fn init(&mut self, _rng: Rng, now: Instant) {
        self.setup_goals(now);
    }

    fn process(&mut self, mut dgram: Option<Datagram>, now: Instant) -> Output {
        _ = self.process_goals(|goal, c| goal.process(c, now));
        loop {
            let res = self.c.process(dgram.take().as_ref(), now);

            let mut active = false;
            while let Some(e) = self.c.next_event() {
                qtrace!([self.c], "received event {:?}", e);

                // Perform authentication automatically.
                if matches!(e, ConnectionEvent::AuthenticationNeeded) {
                    self.c.authenticated(AuthenticationStatus::Ok, now);
                }

                active |= self.process_goals(|goal, c| goal.handle_event(c, &e, now));
            }
            // Exit at this point if the connection produced a datagram.
            // We also exit if none of the goals were active, as there is
            // no point trying again if they did nothing.
            if matches!(res, Output::Datagram(_)) || !active {
                return res;
            }
            qdebug!([self.c], "no datagram and goal activity, looping");
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
        qinfo!("{}: {:?}", test_name, self.c.stats());
    }
}

impl Debug for ConnectionNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.c, f)
    }
}

/// A target for a connection that involves reaching a given connection state.
#[derive(Debug, Clone)]
pub struct ReachState {
    target: State,
}

impl ReachState {
    /// Create a new instance that intends to reach the indicated state.
    #[must_use]
    pub fn new(target: State) -> Self {
        Self { target }
    }
}

impl ConnectionGoal for ReachState {
    fn handle_event(
        &mut self,
        _c: &mut Connection,
        e: &ConnectionEvent,
        _now: Instant,
    ) -> GoalStatus {
        if matches!(e, ConnectionEvent::StateChange(state) if *state == self.target) {
            GoalStatus::Done
        } else {
            GoalStatus::Waiting
        }
    }
}

/// A target for a connection that involves sending a given amount of data on the indicated stream.
#[derive(Debug, Clone)]
pub struct SendData {
    remaining: usize,
    stream_id: Option<StreamId>,
}

impl SendData {
    #[must_use]
    pub fn new(amount: usize) -> Self {
        Self {
            remaining: amount,
            stream_id: None,
        }
    }

    fn make_stream(&mut self, c: &mut Connection) {
        if self.stream_id.is_none() {
            if let Ok(stream_id) = c.stream_create(StreamType::UniDi) {
                qdebug!([c], "made stream {} for sending", stream_id);
                self.stream_id = Some(stream_id);
            }
        }
    }

    fn send(&mut self, c: &mut Connection, stream_id: StreamId) -> GoalStatus {
        const DATA: &[u8] = &[0; 4096];
        let mut status = GoalStatus::Waiting;
        loop {
            let end = min(self.remaining, DATA.len());
            let sent = c.stream_send(stream_id, &DATA[..end]).unwrap();
            if sent == 0 {
                return status;
            }
            self.remaining -= sent;
            qtrace!("sent {} remaining {}", sent, self.remaining);
            if self.remaining == 0 {
                c.stream_close_send(stream_id).unwrap();
                return GoalStatus::Done;
            }
            status = GoalStatus::Active;
        }
    }
}

impl ConnectionGoal for SendData {
    fn init(&mut self, c: &mut Connection, _now: Instant) {
        self.make_stream(c);
    }

    fn process(&mut self, c: &mut Connection, _now: Instant) -> GoalStatus {
        self.stream_id
            .map_or(GoalStatus::Waiting, |stream_id| self.send(c, stream_id))
    }

    fn handle_event(
        &mut self,
        c: &mut Connection,
        e: &ConnectionEvent,
        _now: Instant,
    ) -> GoalStatus {
        match e {
            ConnectionEvent::SendStreamCreatable {
                stream_type: StreamType::UniDi,
            } => {
                self.make_stream(c);
                GoalStatus::Active
            }

            ConnectionEvent::SendStreamWritable { stream_id }
                if Some(*stream_id) == self.stream_id =>
            {
                self.send(c, *stream_id)
            }

            // If we sent data in 0-RTT, then we didn't track how much we should
            // have sent.  This is trivial to fix if 0-RTT testing is ever needed.
            ConnectionEvent::ZeroRttRejected => panic!("not supported"),
            _ => GoalStatus::Waiting,
        }
    }
}

/// Receive a prescribed amount of data from any stream.
#[derive(Debug, Clone)]
pub struct ReceiveData {
    remaining: usize,
}

impl ReceiveData {
    #[must_use]
    pub fn new(amount: usize) -> Self {
        Self { remaining: amount }
    }

    fn recv(&mut self, c: &mut Connection, stream_id: StreamId) -> GoalStatus {
        let mut buf = vec![0; 4096];
        let mut status = GoalStatus::Waiting;
        loop {
            let end = min(self.remaining, buf.len());
            let (recvd, _) = c.stream_recv(stream_id, &mut buf[..end]).unwrap();
            qtrace!("received {} remaining {}", recvd, self.remaining);
            if recvd == 0 {
                return status;
            }
            self.remaining -= recvd;
            if self.remaining == 0 {
                return GoalStatus::Done;
            }
            status = GoalStatus::Active;
        }
    }
}

impl ConnectionGoal for ReceiveData {
    fn handle_event(
        &mut self,
        c: &mut Connection,
        e: &ConnectionEvent,
        _now: Instant,
    ) -> GoalStatus {
        if let ConnectionEvent::RecvStreamReadable { stream_id } = e {
            self.recv(c, *stream_id)
        } else {
            GoalStatus::Waiting
        }
    }
}
