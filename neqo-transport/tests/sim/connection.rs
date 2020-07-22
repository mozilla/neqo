// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::Node;
use neqo_common::{qdebug, Datagram};
use neqo_crypto::AuthenticationStatus;
use neqo_transport::{Connection, ConnectionEvent, Output, State, StreamId, StreamType};
use std::cmp::min;
use std::fmt::{self, Debug};
use std::time::Instant;

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

pub trait ConnectionGoal {
    fn init(&mut self, _c: &mut Connection, _now: Instant) {}
    /// Handle an event from the provided connection, returning `true` when the
    /// goal is achieved.
    fn handle_event(&mut self, c: &mut Connection, e: &ConnectionEvent, now: Instant)
        -> GoalStatus;
}

pub struct ConnectionNode {
    c: Connection,
    goals: Vec<Box<dyn ConnectionGoal>>,
}

impl ConnectionNode {
    pub fn new_client(goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>) -> Self {
        Self {
            c: test_fixture::default_client(),
            goals: goals.into_iter().collect(),
        }
    }

    pub fn new_server(goals: impl IntoIterator<Item = Box<dyn ConnectionGoal>>) -> Self {
        Self {
            c: test_fixture::default_server(),
            goals: goals.into_iter().collect(),
        }
    }

    #[allow(dead_code)]
    pub fn clear_goals(&mut self) {
        self.goals.clear();
    }

    #[allow(dead_code)]
    pub fn add_goal(&mut self, goal: Box<dyn ConnectionGoal>) {
        self.goals.push(goal);
    }
}

impl Node for ConnectionNode {
    fn init(&mut self, now: Instant) {
        for g in &mut self.goals {
            g.init(&mut self.c, now);
        }
    }

    fn process(&mut self, mut d: Option<Datagram>, now: Instant) -> Output {
        loop {
            let res = self.c.process(d.take(), now);
            let mut active = false;
            while let Some(e) = self.c.next_event() {
                qdebug!([self.c], "received event {:?}", e);

                // Perform authentication automatically.
                if matches!(e, ConnectionEvent::AuthenticationNeeded) {
                    self.c.authenticated(AuthenticationStatus::Ok, now);
                }

                // Waiting on drain_filter...
                // let _ = self.goals.drain_filter(|g| g.handle_event(&mut self.c, &e)).count();
                let mut i = 0;
                while i < self.goals.len() {
                    let status = self.goals[i].handle_event(&mut self.c, &e, now);
                    if status == GoalStatus::Done {
                        self.goals.remove(i);
                    } else {
                        active |= status == GoalStatus::Active;
                        i += 1;
                    }
                }
            }
            // Exit at this point if the connection produced a datagram.
            // OR if one of the goals acted.
            if matches!(res, Output::Datagram(_)) || !active {
                return res;
            }
            qdebug!([self.c], "no datagram and goal activity, looping");
        }
    }

    fn done(&self) -> bool {
        self.goals.is_empty()
    }
}

impl Debug for ConnectionNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.c, f)
    }
}

#[derive(Debug, Clone)]
pub struct ReachState {
    target: State,
}

impl ReachState {
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

#[derive(Debug)]
pub struct SendData {
    remaining: usize,
    stream_id: Option<StreamId>,
}

impl SendData {
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
                self.stream_id = Some(StreamId::new(stream_id));
            }
        }
    }
}

impl ConnectionGoal for SendData {
    fn init(&mut self, c: &mut Connection, _now: Instant) {
        self.make_stream(c);
    }

    fn handle_event(
        &mut self,
        c: &mut Connection,
        e: &ConnectionEvent,
        _now: Instant,
    ) -> GoalStatus {
        const DATA: &[u8] = &[0; 4096];
        match e {
            ConnectionEvent::SendStreamCreatable {
                stream_type: StreamType::UniDi,
            }
            // TODO(mt): remove the second condition when #842 is fixed.
            | ConnectionEvent::StateChange(_) => {
                self.make_stream(c);
                GoalStatus::Active
            }

            ConnectionEvent::SendStreamWritable { stream_id }
                if Some(*stream_id) == self.stream_id =>
            {
                let end = min(self.remaining, DATA.len());
                let sent = c.stream_send(stream_id.as_u64(), &DATA[..end]).unwrap();
                if self.remaining == sent {
                    GoalStatus::Done
                } else {
                    self.remaining -= sent;
                    GoalStatus::Active
                }
            }

            // If we sent data in 0-RTT, then we didn't track how much we should
            // have sent.  This is trivial to fix if 0-RTT testing is ever needed.
            ConnectionEvent::ZeroRttRejected => panic!("not supported"),
            _ => GoalStatus::Waiting,
        }
    }
}

/// Receive a prescribed amount of data from any stream.
#[derive(Debug)]
pub struct ReceiveData {
    remaining: usize,
}

impl ReceiveData {
    pub fn new(amount: usize) -> Self {
        Self { remaining: amount }
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
            let mut buf = vec![0; 4096];
            let end = min(self.remaining, buf.len());
            let (recvd, _) = c.stream_recv(*stream_id, &mut buf[..end]).unwrap();
            if recvd == self.remaining {
                GoalStatus::Done
            } else {
                self.remaining -= recvd;
                GoalStatus::Active
            }
        } else {
            GoalStatus::Waiting
        }
    }
}
