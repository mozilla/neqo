// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// A send-group identifier, unique within the connection that minted it.
///
/// `Id(0)` is never valid; 0 is reserved as a sentinel by the transport scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(u64);

impl Id {
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Mints connection-unique send-group [`Id`]s. Owned by the connection rather than a
/// global, so uniqueness holds within a connection no matter which thread it runs on.
#[derive(Debug, Default)]
pub struct Generator(u64);

impl Generator {
    /// Mint the next send-group [`Id`]. IDs start at 1; 0 is reserved as a sentinel.
    ///
    /// # Panics
    ///
    /// Panics if the counter overflows `u64::MAX`.
    pub const fn next_id(&mut self) -> Id {
        let id = self.0.checked_add(1).expect("SendGroup ID overflow");
        self.0 = id;
        Id(id)
    }
}
