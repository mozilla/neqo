// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracking of some useful statistics.
#![deny(clippy::pedantic)]

use neqo_common::qinfo;
use std::cell::RefCell;
use std::fmt::{self, Debug};
use std::ops::Deref;
use std::rc::Rc;

pub(crate) const MAX_PTO_COUNTS: usize = 10;

/// Connection statistics
#[derive(Default, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct Stats {
    info: String,

    /// Total packets received, including all the bad ones.
    pub packets_rx: usize,
    /// Duplicate packets received.
    pub dups_rx: usize,
    /// Dropped packets or dropped garbage.
    pub dropped_rx: usize,
    /// The number of packet that were saved for later processing.
    pub saved_datagrams: usize,

    /// Total packets sent.
    pub packets_tx: usize,
    /// Total number of packets that are declared lost.
    pub lost: usize,
    /// Late acknowledgments, for packets that were declared lost already.
    pub late_ack: usize,
    /// Acknowledgments for packets that contained data that was marked
    /// for retransmission when the PTO timer popped.
    pub pto_ack: usize,

    /// Whether the connection was resumed successfully.
    pub resumed: bool,

    /// Count PTOs. Single PTOs, 2 PTOs in a row, 3 PTOs in row, etc. are counted
    /// separately.
    pub pto_counts: [usize; MAX_PTO_COUNTS],
}

impl Stats {
    pub fn init(&mut self, info: String) {
        self.info = info;
    }

    pub fn pkt_dropped(&mut self, reason: impl AsRef<str>) {
        self.dropped_rx += 1;
        qinfo!(
            [self.info],
            "Dropped received packet: {}; Total: {}",
            reason.as_ref(),
            self.dropped_rx
        )
    }

    pub fn add_pto_count(&mut self, count: usize) {
        if count > 0 {
            let inx = if count < MAX_PTO_COUNTS {
                count - 1
            } else {
                MAX_PTO_COUNTS - 1
            };
            if inx > 0 {
                // if this is a second, third, etc. PTO in a row remove the count for the previous
                // one. 
                debug_assert!(self.pto_counts[inx - 1] > 0);
                self.pto_counts[inx - 1] -= 1;
            }
            self.pto_counts[inx] += 1;
        }
    }
}

impl Debug for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "stats for {}", self.info)?;
        writeln!(
            f,
            "  rx: {} drop {} dup {} saved {}",
            self.packets_rx, self.dropped_rx, self.dups_rx, self.saved_datagrams
        )?;
        writeln!(
            f,
            "  tx: {} lost {} lateack {} ptoack {}",
            self.packets_tx, self.lost, self.late_ack, self.pto_ack
        )?;
        write!(f, "  resumed: {} ", self.resumed)
    }
}

#[derive(Default, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct StatsCell {
    stats: Rc<RefCell<Stats>>,
}

impl Deref for StatsCell {
    type Target = RefCell<Stats>;
    fn deref(&self) -> &Self::Target {
        &*self.stats
    }
}

impl Debug for StatsCell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.stats.borrow().fmt(f)
    }
}
