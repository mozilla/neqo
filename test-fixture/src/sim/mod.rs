// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Tests with simulated network components.
pub mod connection;
mod delay;
mod drop;
pub mod rng;
mod taildrop;

use std::{
    cell::RefCell,
    cmp::min,
    fmt::Debug,
    ops::{Deref, DerefMut},
    rc::Rc,
    time::{Duration, Instant},
};

use neqo_common::{qdebug, qinfo, qtrace, Datagram, Encoder};
use neqo_transport::Output;
use rng::Random;
use NodeState::{Active, Idle, Waiting};

use crate::now;

pub mod network {
    pub use super::{delay::Delay, drop::Drop, taildrop::TailDrop};
}

type Rng = Rc<RefCell<Random>>;

/// A macro that turns a list of values into boxed versions of the same.
#[macro_export]
macro_rules! boxed {
    [$($v:expr),+ $(,)?] => {
        vec![ $( Box::new($v) as _ ),+ ]
    };
}

/// Create a simulation test case.  This takes either two or three arguments.
/// The two argument form takes a bare name (`ident`), a comma, and an array of
/// items that implement `Node`.
/// The three argument form adds a setup block that can be used to construct a
/// complex value that is then shared between all nodes.  The values in the
/// three-argument form have to be closures (or functions) that accept a reference
/// to the value returned by the setup.
#[macro_export]
macro_rules! simulate {
    ($n:ident, [ $($v:expr),+ $(,)? ] $(,)?) => {
        simulate!($n, (), [ $(|_| $v),+ ]);
    };
    ($n:ident, $setup:expr, [ $( $v:expr ),+ $(,)? ] $(,)?) => {
        #[test]
        fn $n() {
            let fixture = $setup;
            let mut nodes: Vec<Box<dyn $crate::sim::Node>> = Vec::new();
            $(
                let f: Box<dyn FnOnce(&_) -> _> = Box::new($v);
                nodes.push(Box::new(f(&fixture)));
            )*
            let mut sim = Simulator::new(stringify!($n), nodes);
            if let Ok(seed) = std::env::var("SIMULATION_SEED") {
                sim.seed_str(seed);
            }
            sim.run();
        }
    };
}

pub trait Node: Debug {
    fn init(&mut self, _rng: Rng, _now: Instant) {}
    /// Perform processing.  This optionally takes a datagram and produces either
    /// another data, a time that the simulator needs to wait, or nothing.
    fn process(&mut self, d: Option<Datagram>, now: Instant) -> Output;
    /// This is called after setup is complete and before the main processing starts.
    fn prepare(&mut self, _now: Instant) {}
    /// An node can report when it considers itself "done".
    /// Prior to calling `prepare`, this should return `true` if it is ready.
    fn done(&self) -> bool {
        true
    }
    /// Print out a summary of the state of the node.
    fn print_summary(&self, _test_name: &str) {}
}

/// The state of a single node.  Nodes will be activated if they are `Active`
/// or if the previous node in the loop generated a datagram.  Nodes that return
/// `true` from `Node::done` will be activated as normal.
#[derive(Clone, Copy, Debug, PartialEq)]
enum NodeState {
    /// The node just produced a datagram.  It should be activated again as soon as possible.
    Active,
    /// The node is waiting.
    Waiting(Instant),
    /// The node became idle.
    Idle,
}

#[derive(Debug)]
struct NodeHolder {
    node: Box<dyn Node>,
    state: NodeState,
}

impl NodeHolder {
    fn ready(&self, now: Instant) -> bool {
        match self.state {
            Active => true,
            Waiting(t) => t >= now,
            Idle => false,
        }
    }
}

impl Deref for NodeHolder {
    type Target = dyn Node;
    fn deref(&self) -> &Self::Target {
        self.node.as_ref()
    }
}

impl DerefMut for NodeHolder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.node.as_mut()
    }
}

pub struct Simulator {
    name: String,
    nodes: Vec<NodeHolder>,
    rng: Rng,
}

impl Simulator {
    pub fn new(name: impl AsRef<str>, nodes: impl IntoIterator<Item = Box<dyn Node>>) -> Self {
        let name = String::from(name.as_ref());
        // The first node is marked as Active, the rest are idle.
        let mut it = nodes.into_iter();
        let nodes = it
            .next()
            .map(|node| NodeHolder {
                node,
                state: Active,
            })
            .into_iter()
            .chain(it.map(|node| NodeHolder { node, state: Idle }))
            .collect::<Vec<_>>();
        Self {
            name,
            nodes,
            rng: Rc::default(),
        }
    }

    pub fn seed(&mut self, seed: [u8; 32]) {
        self.rng = Rc::new(RefCell::new(Random::new(&seed)));
    }

    /// Seed from a hex string.
    /// # Panics
    /// When the provided string is not 32 bytes of hex (64 characters).
    pub fn seed_str(&mut self, seed: impl AsRef<str>) {
        let seed = Encoder::from_hex(seed);
        self.seed(<[u8; 32]>::try_from(seed.as_ref()).unwrap());
    }

    fn next_time(&self, now: Instant) -> Instant {
        let mut next = None;
        for n in &self.nodes {
            match n.state {
                Idle => continue,
                Active => return now,
                Waiting(a) => next = Some(next.map_or(a, |b| min(a, b))),
            }
        }
        next.expect("a node cannot be idle and not done")
    }

    fn process_loop(&mut self, start: Instant, mut now: Instant) -> Instant {
        let mut dgram = None;
        loop {
            for n in &mut self.nodes {
                if dgram.is_none() && !n.ready(now) {
                    qdebug!([self.name], "skipping {:?}", n.node);
                    continue;
                }

                qdebug!([self.name], "processing {:?}", n.node);
                let res = n.process(dgram.take(), now);
                n.state = match res {
                    Output::Datagram(d) => {
                        qtrace!([self.name], " => datagram {}", d.len());
                        dgram = Some(d);
                        Active
                    }
                    Output::Callback(delay) => {
                        qtrace!([self.name], " => callback {:?}", delay);
                        assert_ne!(delay, Duration::new(0, 0));
                        Waiting(now + delay)
                    }
                    Output::None => {
                        qtrace!([self.name], " => nothing");
                        assert!(n.done(), "nodes should be done when they go idle");
                        Idle
                    }
                };
            }

            if self.nodes.iter().all(|n| n.done()) {
                return now;
            }

            if dgram.is_none() {
                let next = self.next_time(now);
                if next > now {
                    qinfo!(
                        [self.name],
                        "advancing time by {:?} to {:?}",
                        next - now,
                        next - start
                    );
                    now = next;
                }
            }
        }
    }

    #[must_use]
    pub fn setup(mut self) -> ReadySimulator {
        let start = now();

        qinfo!("{}: seed {}", self.name, self.rng.borrow().seed_str());
        for n in &mut self.nodes {
            n.init(self.rng.clone(), start);
        }

        let setup_start = Instant::now();
        let now = self.process_loop(start, start);
        let setup_time = now - start;
        qinfo!(
            "{t}: Setup took {wall:?} (wall) {setup_time:?} (simulated)",
            t = self.name,
            wall = setup_start.elapsed(),
        );

        for n in &mut self.nodes {
            n.prepare(now);
        }

        ReadySimulator {
            sim: self,
            start,
            now,
        }
    }

    /// Runs the simulation.
    /// # Panics
    /// When sanity checks fail in unexpected ways; this is a testing function after all.
    pub fn run(self) {
        self.setup().run();
    }

    fn print_summary(&self) {
        for n in &self.nodes {
            n.print_summary(&self.name);
        }
    }
}

pub struct ReadySimulator {
    sim: Simulator,
    start: Instant,
    now: Instant,
}

impl ReadySimulator {
    pub fn run(mut self) {
        let real_start = Instant::now();
        let end = self.sim.process_loop(self.start, self.now);
        let sim_time = end - self.now;
        qinfo!(
            "{t}: Simulation took {wall:?} (wall) {sim_time:?} (simulated)",
            t = self.sim.name,
            wall = real_start.elapsed(),
        );
        self.sim.print_summary();
    }
}
