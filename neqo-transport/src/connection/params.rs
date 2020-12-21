// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::stream_id::{StreamIndex, StreamType};
use crate::{CongestionControlAlgorithm, QuicVersion};

const LOCAL_STREAM_LIMIT_BIDI: StreamIndex = StreamIndex::new(16);
const LOCAL_STREAM_LIMIT_UNI: StreamIndex = StreamIndex::new(16);

/// ConnectionParameters use for setting intitial value for QUIC parameters.
/// This collect like initial limits, protocol version and congestion control.
#[derive(Clone)]
pub struct ConnectionParameters {
    quic_version: QuicVersion,
    cc_algorithm: CongestionControlAlgorithm,
    max_streams_bidi: StreamIndex,
    max_streams_uni: StreamIndex,
}

impl Default for ConnectionParameters {
    fn default() -> Self {
        Self {
            quic_version: QuicVersion::default(),
            cc_algorithm: CongestionControlAlgorithm::NewReno,
            max_streams_bidi: LOCAL_STREAM_LIMIT_BIDI,
            max_streams_uni: LOCAL_STREAM_LIMIT_UNI,
        }
    }
}

impl ConnectionParameters {
    pub fn get_quic_version(&self) -> QuicVersion {
        self.quic_version
    }

    pub fn quic_version(mut self, v: QuicVersion) -> Self {
        self.quic_version = v;
        self
    }

    pub fn get_cc_algorithm(&self) -> CongestionControlAlgorithm {
        self.cc_algorithm
    }

    pub fn cc_algorithm(mut self, v: CongestionControlAlgorithm) -> Self {
        self.cc_algorithm = v;
        self
    }

    pub fn get_max_streams(&self, stream_type: StreamType) -> StreamIndex {
        match stream_type {
            StreamType::BiDi => self.max_streams_bidi,
            StreamType::UniDi => self.max_streams_uni,
        }
    }

    pub fn max_streams(mut self, stream_type: StreamType, v: StreamIndex) -> Self {
        assert!(v.as_u64() <= (1 << 60), "max_streams is too large");
        match stream_type {
            StreamType::BiDi => {
                self.max_streams_bidi = v;
            }
            StreamType::UniDi => {
                self.max_streams_uni = v;
            }
        }
        self
    }
}
