// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::MIN_INITIAL_PACKET_SIZE;

// From https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2
// const MAX_PROBES: usize = 3;
// const MIN_PLPMTU: usize = MIN_INITIAL_PACKET_SIZE;
// const MAX_PLPMTU: usize = 9202; // TODO: Get from interface.
// const BASE_PLPMTU: usize = MIN_PLPMTU;

// enum PmtudPhase {
//     Base,
//     Search,
//     SearchComplete,
//     Error,
// }

#[derive(Debug, Default)]
pub enum PmtudState {
    #[default]
    Disabled,
    // Base,
    // Searching,
    // SearchComplete,
    // Error,
}

impl PmtudState {
    #[allow(clippy::unused_self)]
    pub fn max_datagram_size(&self) -> usize {
        MIN_INITIAL_PACKET_SIZE
    }
}
