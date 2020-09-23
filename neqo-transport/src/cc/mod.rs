// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Congestion control
#![deny(clippy::pedantic)]

pub mod cc;
mod new_reno_cc;

pub use cc::CongestionControl;
use new_reno_cc::NewReno;
pub use new_reno_cc::{CWND_INITIAL_PKTS, CWND_MIN, MAX_DATAGRAM_SIZE, PACING_BURST_SIZE};

pub enum CongestionControlAlgorithm {
    NewReno,
}

impl CongestionControlAlgorithm {
    pub fn create(&self) -> Box<dyn CongestionControl> {
        match self {
            Self::NewReno => Box::new(NewReno::default()),
        }
    }
}

impl Default for CongestionControlAlgorithm {
    fn default() -> Self {
        Self::NewReno
    }
}
