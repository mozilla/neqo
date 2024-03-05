// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Instant;

use enum_map::EnumMap;
use neqo_common::{qdebug, qinfo, qwarn, IpTos, IpTosEcn};

use crate::{
    rtt::RttEstimate,
    tracking::{EcnCount, PacketNumberSpace, SentPacket},
};

/// The number of packets to use for testing a path for ECN capability.
pub const ECN_TEST_COUNT: usize = 10;

/// The state information related to testing a path for ECN capability.
/// See RFC9000, Appendix A.4.
#[derive(Debug, PartialEq)]
enum EcnValidationState {
    /// The path is currently being tested for ECN capability.
    Testing {
        /// The time when the ECN validation of the path started.
        start: Instant,
        /// The number of packets sent so far on the path during the ECN validation.
        count: usize,
        /// The number of packets declared lost so far during the ECN validation.
        lost: usize,
    },
    /// The validation test has concluded but the path's ECN capability is not yet known.
    Unknown,
    /// The path is known to **not** be ECN capable.
    Failed,
    /// The path is known to be ECN capable.
    Capable,
}

#[derive(Debug)]
pub struct EcnInfo {
    /// The current state of ECN validation on this path.
    state: EcnValidationState,

    /// The ECN counts received in the last ACK on this path, for each packet number space.
    /// Won't be updated after ECN has been disabled on a path.
    count: EnumMap<PacketNumberSpace, EcnCount>,
}

impl EcnInfo {
    pub fn new(now: Instant) -> Self {
        Self {
            state: EcnValidationState::Testing {
                start: now,
                count: 0,
                lost: 0,
            },
            count: EnumMap::default(),
        }
    }

    pub fn count_packets_out(&mut self) {
        self.state = match self.state {
            EcnValidationState::Testing { start, count, lost } => {
                // if count < ECN_TEST_COUNT {
                EcnValidationState::Testing {
                    start,
                    count: count + 1,
                    lost,
                }
                // } else {
                //     EcnValidationState::Unknown
                // }
            }
            EcnValidationState::Unknown => EcnValidationState::Unknown,
            EcnValidationState::Failed => EcnValidationState::Failed,
            EcnValidationState::Capable => EcnValidationState::Capable,
        };
        qdebug!("ECN {:?}", self.state);
    }

    pub fn count_packets_lost(&mut self, lost_packets: &[SentPacket]) {
        self.state = match self.state {
            EcnValidationState::Failed => EcnValidationState::Failed,
            EcnValidationState::Capable => EcnValidationState::Capable,
            EcnValidationState::Unknown => EcnValidationState::Unknown,
            EcnValidationState::Testing { start, count, lost } => {
                qdebug!("ECN {:?}", self);
                if start.elapsed()
                    > 3 * RttEstimate::default().pto(PacketNumberSpace::ApplicationData)
                    || count > ECN_TEST_COUNT
                {
                    qinfo!("ECN test concluded {}", lost_packets.len());
                    EcnValidationState::Unknown
                } else {
                    EcnValidationState::Testing {
                        start,
                        count,
                        lost: lost + lost_packets.len(),
                    }
                }
            }
        };
        qdebug!("ECN {:?}", self);
    }

    pub fn validate_ack_ecn(
        &mut self,
        space: PacketNumberSpace,
        acked_packets: &[SentPacket],
        ecn_count: &EcnCount,
    ) {
        // RFC 9000, Appendix A.4:
        // From the "unknown" state, successful validation of the ECN counts in an ACK frame
        // (see Section 13.4.2.1) causes the ECN state for the path to become "capable", unless
        // no marked packet has been acknowledged.
        if self.state != EcnValidationState::Unknown {
            return;
        }

        // RFC 9000, Section 13.4.2.1:
        //
        // > An endpoint that receives an ACK frame with ECN counts therefore validates
        // > the counts before using them. It performs this validation by comparing newly
        // > received counts against those from the last successfully processed ACK frame.
        //
        // RFC 9000 fails to state that this is done *per packet number space*.
        //
        // > If an ACK frame newly acknowledges a packet that the endpoint sent with
        // > either the ECT(0) or ECT(1) codepoint set, ECN validation fails if the
        // > corresponding ECN counts are not present in the ACK frame.
        //
        // We always mark with ECT(0) - if at all - so we only need to check for that.
        // Also, if we sent a packet with ECT(0) and get only an ACK frame (and not an
        // ACK-ECN frame), `ecn_counts` will be all zero and the check below will fail,
        // so no need to explicitly check for the above.
        //
        // > ECN validation also fails if the sum of the increase in ECT(0) and ECN-CE counts is
        // > less than the number of newly acknowledged packets that were originally sent with an
        // > ECT(0) marking.
        let newly_acked = acked_packets.len().try_into().unwrap();
        let ecn_diff = ecn_count - &self.count[space];
        let sum_inc = ecn_diff[IpTosEcn::Ect0] + ecn_diff[IpTosEcn::Ce];
        if sum_inc < newly_acked {
            qwarn!(
                "ACK had {} new marks, but acked {} packets, disabling ECN",
                sum_inc,
                newly_acked
            );
            self.state = EcnValidationState::Failed;
        } else {
            qinfo!("ECN validation succeeded");
            self.state = EcnValidationState::Capable;
        }
        qdebug!("ECN {:?}", self);
        self.count[space] = ecn_count.clone();
    }

    pub fn tos(&self) -> IpTos {
        // XXX simplify
        match self.state {
            EcnValidationState::Testing {
                start: _,
                count: _,
                lost: _,
            }
            | EcnValidationState::Capable
            | EcnValidationState::Unknown => IpTosEcn::Ect0.into(),
            EcnValidationState::Failed => IpTosEcn::NotEct.into(),
        }
    }
}
