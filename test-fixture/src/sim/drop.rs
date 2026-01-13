// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is test code.")]

use std::time::Instant;

use neqo_common::{qtrace, Datagram};
use neqo_transport::Output;

use super::{Node, Rng};

/// A random dropper.
#[derive(derive_more::Debug)]
#[debug("drop")]
pub struct Drop {
    threshold: u64,
    max: u64,
    rng: Option<Rng>,
}

impl Drop {
    /// Make a new random drop generator.  Each `drop` is called, this generates a
    /// random value between 0 and `max` (exclusive).  If this value is less than
    /// `threshold` a value of `true` is returned.
    #[must_use]
    pub const fn new(threshold: u64, max: u64) -> Self {
        Self {
            threshold,
            max,
            rng: None,
        }
    }

    /// Generate random drops with the given percentage.
    #[must_use]
    pub fn percentage(pct: u8) -> Self {
        // Multiply by 10 so that the random number generator works more efficiently.
        Self::new(u64::from(pct) * 10, 1000)
    }

    /// Determine whether or not to drop a packet.
    /// # Panics
    /// When this is invoked after test configuration has been torn down,
    /// such that the RNG is no longer available.
    #[must_use]
    pub fn drop(&self) -> bool {
        let mut rng = self.rng.as_ref().unwrap().borrow_mut();
        let r = rng.random_from(0..self.max);
        r < self.threshold
    }
}

impl Node for Drop {
    fn init(&mut self, rng: Rng, _now: Instant) {
        self.rng = Some(rng);
    }

    // Pass any datagram provided directly out, but drop some of them.
    fn process(&mut self, d: Option<Datagram>, _now: Instant) -> Output {
        d.map_or(Output::None, |dgram| {
            if self.drop() {
                qtrace!("drop {}", dgram.len());
                Output::None
            } else {
                Output::Datagram(dgram)
            }
        })
    }
}
