// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Tracking of some useful statistics.

use neqo_common::qinfo;
use std::fmt::{self, Debug};

#[derive(Default)]
/// Connection statistics
pub struct Stats {
    info: String,

    /// Total packets received
    pub packets_rx: usize,
    /// Total packets sent
    pub packets_tx: usize,
    /// Duplicate packets received
    pub dups_rx: usize,
    /// Dropped datagrams, or parts thereof
    pub dropped_rx: usize,
    /// resumption used
    pub resumed: bool,
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
}

impl Debug for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "stats for {}", self.info)?;
        writeln!(f, "  packets: tx {} ", self.packets_tx)?;
        writeln!(f, "           rx {}", self.packets_rx)?;
        writeln!(f, "           dropped {}", self.dropped_rx)?;
        writeln!(f, "           dups {}", self.dups_rx)?;
        write!(f, "  resumed: {} ", self.resumed)
    }
}
