// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "This is test code.")]

use std::ops::Range;

use neqo_common::Decoder;

/// An implementation of a xoshiro256** pseudorandom generator.
pub struct Random {
    state: [u64; 4],
}

impl Random {
    #[must_use]
    #[expect(clippy::missing_panics_doc, reason = "These are impossible.")]
    pub fn new(seed: &[u8; 32]) -> Self {
        assert!(seed.iter().any(|&x| x != 0));
        let mut dec = Decoder::from(&seed);
        Self {
            state: [
                dec.decode_uint().unwrap(),
                dec.decode_uint().unwrap(),
                dec.decode_uint().unwrap(),
                dec.decode_uint().unwrap(),
            ],
        }
    }

    pub const fn random(&mut self) -> u64 {
        let result = (self.state[1].overflowing_mul(5).0)
            .rotate_right(7)
            .overflowing_mul(9)
            .0;
        let t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];

        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_right(45);

        result
    }

    /// Generate a random value from the range.
    /// If the range is empty or inverted (`range.start > range.end`), then
    /// this returns the value of `range.start` without generating any random values.
    #[must_use]
    pub const fn random_from(&mut self, range: Range<u64>) -> u64 {
        let max = range.end.saturating_sub(range.start);
        if max == 0 {
            return range.start;
        }

        let shift = (max - 1).leading_zeros();
        loop {
            let r = self.random() >> shift;
            if r < max {
                return range.start + r;
            }
        }
    }

    /// Get the seed necessary to continue from the current state of the RNG.
    #[must_use]
    pub fn seed_str(&self) -> String {
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            self.state[0], self.state[1], self.state[2], self.state[3],
        )
    }
}

impl Default for Random {
    #[cfg(not(feature = "disable-random"))]
    fn default() -> Self {
        Self::new(&nss_rs::random::<32>())
    }

    #[cfg(feature = "disable-random")]
    // Use a fixed seed for a deterministic sequence of numbers.
    fn default() -> Self {
        Self::new(&[1; 32])
    }
}
