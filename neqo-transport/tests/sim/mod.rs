// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tests with simulated network
#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::pedantic)]

pub mod connection;
pub mod server;

use neqo_common::{qdebug, Datagram};
use neqo_transport::Output;
use std::cmp::min;
use std::fmt::Debug;
use std::time::{Duration, Instant};

use test_fixture::{self, now};

/// A macro that turns a list of values into boxed versions of the same.
#[macro_export]
macro_rules! boxed {
    [$($v:expr),+ $(,)?] => {
        vec![ $( Box::new($v) as _ ),+ ]
    };
}

pub trait Node: Debug {
    /// Perform processing.  This optionally takes a datagram and produces either
    /// another data, a time that the simulator needs to wait, or nothing.
    fn process(&mut self, d: Option<Datagram>, now: Instant) -> Output;
    /// An node can report when it considers itself "done".
    fn done(&self) -> bool {
        true
    }
}

#[derive(Debug, PartialEq)]
enum NodeState {
    /// The node just produced a datagram.  It should be activated again as soon as possible.
    Active,
    /// The node is waiting.
    Timeout(Instant),
    /// The node became idle; it will only activate if the previous node passes it a datagram.
    Idle,
}

#[derive(Debug)]
struct NodeHolder {
    node: Box<dyn Node>,
    state: NodeState,
}

pub struct Simulator {
    nodes: Vec<NodeHolder>,
}

impl Simulator {
    pub fn new(nodes: impl IntoIterator<Item = Box<dyn Node>>) -> Self {
        let mut it = nodes.into_iter();
        let nodes = it
            .next()
            .map(|node| NodeHolder {
                node,
                state: NodeState::Active,
            })
            .into_iter()
            .chain(it.map(|node| NodeHolder {
                node,
                state: NodeState::Idle,
            }))
            .collect::<Vec<_>>();
        Self { nodes }
    }

    fn next_time(&self, now: Instant) -> Instant {
        let mut next = None;
        for n in &self.nodes {
            match n.state {
                NodeState::Idle => continue,
                NodeState::Active => return now,
                NodeState::Timeout(a) => next = Some(next.map_or(a, |b| min(a, b))),
            }
        }
        next.expect("a node cannot be idle and not done")
    }

    /// Runs all the nodes,
    pub fn run(&mut self) -> Instant {
        let start = now();
        let mut now = start;
        let mut dgram = None;

        loop {
            for n in self.nodes.iter_mut() {
                if dgram.is_none() && n.state != NodeState::Active {
                    qdebug!(["sim"], "skipping {:?}", n);
                    continue;
                }

                qdebug!(["sim"], "processing {:?}", n.node);
                let res = n.node.process(dgram.take(), now);
                match res {
                    Output::Datagram(d) => {
                        dgram = Some(d);
                        n.state = NodeState::Active;
                    }
                    Output::Callback(delay) => {
                        assert_ne!(delay, Duration::new(0, 0));
                        n.state = NodeState::Timeout(now + delay);
                    }
                    Output::None => {
                        assert!(n.node.done(), "nodes have to be done when they go idle");
                        n.state = NodeState::Idle;
                    }
                }
            }

            if self.nodes.iter().all(|n| n.node.done()) {
                return now;
            }

            if dgram.is_none() {
                now = self.next_time(now);
            }
        }
    }
}
