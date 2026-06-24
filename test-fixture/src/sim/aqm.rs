// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is test code.")]

use std::{
    cmp::max,
    time::{Duration, Instant},
};

use neqo_common::{Datagram, Dscp, Ecn, Tos, qtrace};

use super::Rng;

const CODEL_TARGET: Duration = Duration::from_millis(5);
const CODEL_INTERVAL: Duration = Duration::from_millis(100);

/// `CoDel` (RFC 8289) algorithm state.
#[derive(Clone, Default)]
pub struct CodelState {
    /// When sojourn time first exceeded TARGET in the current busy period,
    /// offset by INTERVAL. None when sojourn is below target or queue is empty.
    first_above_time: Option<Instant>,
    /// Whether we are currently in the "dropping" (signalling) state.
    dropping: bool,
    /// How many marks/drops have occurred in the current dropping interval.
    /// `u32` because [`Duration`] only implements [`Div<u32>`](std::ops::Div).
    count: u32,
    /// `count` at entry to the last dropping period; used for fast restart.
    lastcount: u32,
    /// The time at which the next mark/drop is due (only valid when dropping).
    next_mark_time: Option<Instant>,
}

impl CodelState {
    /// Update the `CoDel` state machine for the packet just dequeued.
    /// Returns true if congestion should be signalled for this packet.
    fn update(&mut self, sojourn: Duration, queue_empty: bool, now: Instant) -> bool {
        // Track when sojourn first exceeded TARGET.
        if sojourn < CODEL_TARGET || queue_empty {
            self.first_above_time = None;
        } else if self.first_above_time.is_none() {
            self.first_above_time = Some(now + CODEL_INTERVAL);
        }

        let over_interval = self.first_above_time.is_some_and(|fat| now >= fat);

        if self.dropping {
            if !over_interval {
                // ok_to_drop became false (RFC 8289): leave dropping state.
                self.dropping = false;
            } else if let Some(dn) = self.next_mark_time.filter(|&dn| now >= dn) {
                // Time for another mark/drop in the current dropping interval.
                // RFC 8289: next drop is relative to the previous next_mark_time, not now.
                self.count += 1;
                self.next_mark_time = Some(self.control_law(dn));
                return true;
            }
        } else if over_interval {
            // Enter dropping state.
            self.dropping = true;
            // Fast restart (RFC 8289 §4): if we re-enter dropping within 16×INTERVAL
            // of the previous interval, start count at `count − lastcount` (the increment
            // from the last dropping period) rather than 1.  This means the marking rate
            // picks up where it left off rather than restarting from scratch each time.
            let recently_dropping = self
                .next_mark_time
                .is_some_and(|dn| now.saturating_duration_since(dn) < CODEL_INTERVAL * 16);
            self.count = if recently_dropping {
                max(1, self.count.saturating_sub(self.lastcount))
            } else {
                1
            };
            self.lastcount = self.count;
            self.next_mark_time = Some(self.control_law(now));
            return true;
        }

        false
    }

    fn control_law(&self, base: Instant) -> Instant {
        base + CODEL_INTERVAL / self.count.max(1).isqrt()
    }
}

/// RED (Random Early Detection) state.
#[derive(Clone, Default)]
pub struct RedState {
    rng: Option<Rng>,
}

impl RedState {
    pub(super) fn should_mark(&self, used: usize, capacity: usize) -> bool {
        // Apply RED which starts at 0 mark chance at 40% of the capacity.
        // From there, follow a quadratic that reaches 1 at 90% capacity.
        // Cap at around 95% mark probability.
        //
        // let p = (2 * ((used / capacity) - 0.4));
        // if rand(0, 1) < p.pow(2).clamp(0, 0.95) { mark(d) } else { d }
        //
        // This code scales that up by a factor of 1024 so we can use integers.
        // This is mostly because our RNG can't sample from 0..1_f64.
        // We multiply capacity by 4096 below and need to avoid overflow.
        assert!(capacity < usize::MAX / 4096, "too much capacity");
        // We need to square a value close to 1000x this and have it fit within a u128.
        #[cfg(target_pointer_width = "64")]
        assert!(capacity < (1 << 54), "too much capacity");
        let Some(n) = (2048 * used).checked_sub(capacity * 4096 / 5) else {
            return false; // (used / capacity) < 0.4
        };
        // Cap pre-squaring: 998 =~ 1024 * Math.pow(0.95, 1/2)
        let p = u128::try_from(n.min(capacity * 998)).unwrap();
        let c = u128::try_from(capacity).unwrap();
        let p = u64::try_from(p * p / c / c).unwrap();
        let r = self
            .rng
            .as_ref()
            .unwrap()
            .borrow_mut()
            .random_from(0..(1 << 20));
        r < p
    }
}

/// CE-mark an ECT(0) datagram; drop (return `None`) if not ECT-capable.
fn mark_ce(dgram: &Datagram) -> Option<Datagram> {
    let tos = dgram.tos();
    let ecn = Ecn::from(tos);
    if ecn.is_ect() {
        assert_ne!(ecn, Ecn::Ect1, "ECT(1)/L4S is not implemented");
        qtrace!("taildrop marking {} bytes CE", dgram.len());
        Some(Datagram::new(
            dgram.source(),
            dgram.destination(),
            Tos::from((Dscp::from(tos), Ecn::Ce)),
            dgram.to_vec(),
        ))
    } else {
        qtrace!("taildrop dropping {} bytes (not ECT-capable)", dgram.len());
        None
    }
}

/// Congestion-signalling mode for a [`TailDrop`](super::taildrop::TailDrop) queue.
///
/// The inner state types are opaque; use [`Aqm::codel()`] and [`Aqm::red()`] to create instances.
#[derive(Clone, Default)]
pub enum Aqm {
    /// No AQM; packets are dropped only on buffer overflow (pure tail-drop).
    #[default]
    None,
    /// `CoDel` (RFC 8289) sojourn-time marking with TARGET=5ms / INTERVAL=100ms.
    CoDel(CodelState),
    /// RED (Random Early Detection) ECN marking; requires RNG initialisation via `Node::init`.
    Red(RedState),
}

impl Aqm {
    /// Create a [`CoDel`](Aqm::CoDel) instance with default parameters.
    #[must_use]
    pub fn codel() -> Self {
        Self::CoDel(CodelState::default())
    }

    /// Create a [`Red`](Aqm::Red) instance.
    /// The node must be passed to a [`Simulator`](crate::sim::Simulator) (or have
    /// `Node::init` called) before use so the RNG is wired up.
    #[must_use]
    pub fn red() -> Self {
        Self::Red(RedState::default())
    }

    /// Wire up the RNG for [`Aqm::Red`]; no-op for other variants.
    pub(super) fn init_rng(&mut self, rng: Rng) {
        if let Self::Red(state) = self {
            state.rng = Some(rng);
        }
    }

    /// Apply AQM policy to the dequeued packet.
    ///
    /// Returns `Some(datagram)` to forward (possibly CE-marked), or `None` if dropped.
    pub(super) fn mark(
        &mut self,
        pkt: Datagram,
        sojourn: Duration,
        queue_empty: bool,
        used: usize,
        capacity: usize,
        now: Instant,
    ) -> Option<Datagram> {
        let should_signal = match self {
            Self::CoDel(state) => state.update(sojourn, queue_empty, now),
            Self::Red(state) => Ecn::from(pkt.tos()).is_ect() && state.should_mark(used, capacity),
            Self::None => false,
        };
        if should_signal {
            mark_ce(&pkt)
        } else {
            Some(pkt)
        }
    }
}
