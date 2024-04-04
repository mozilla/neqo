// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::{AddAssign, Deref, DerefMut, Sub};

use enum_map::EnumMap;
use neqo_common::{qdebug, qinfo, qwarn, IpTosEcn};

use crate::tracking::SentPacket;

/// The number of packets to use for testing a path for ECN capability.
pub const ECN_TEST_COUNT: usize = 10;

/// The state information related to testing a path for ECN capability.
/// See RFC9000, Appendix A.4.
#[derive(Debug, PartialEq, Default, Clone)]
enum EcnValidationState {
    /// The path is currently being tested for ECN capability.
    #[default]
    Testing,
    /// The validation test has concluded but the path's ECN capability is not yet known.
    Unknown,
    /// The path is known to **not** be ECN capable.
    Failed,
    /// The path is known to be ECN capable.
    Capable,
}

/// The counts for different ECN marks.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub struct EcnCount(EnumMap<IpTosEcn, u64>);

impl Deref for EcnCount {
    type Target = EnumMap<IpTosEcn, u64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EcnCount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl EcnCount {
    pub fn new(not_ect: u64, ect0: u64, ect1: u64, ce: u64) -> Self {
        // Yes, the enum array order is different from the argument order.
        Self(EnumMap::from_array([not_ect, ect1, ect0, ce]))
    }

    /// Whether any of the ECN counts are non-zero.
    pub fn is_some(&self) -> bool {
        self[IpTosEcn::Ect0] > 0 || self[IpTosEcn::Ect1] > 0 || self[IpTosEcn::Ce] > 0
    }
}

impl<'a, 'b> Sub<&'a EcnCount> for &'b EcnCount {
    type Output = EcnCount;

    /// Subtract the ECN counts in `other` from `self`.
    fn sub(self, other: &'a EcnCount) -> EcnCount {
        let mut diff = EcnCount::default();
        for (ecn, count) in &mut *diff {
            *count = self[ecn].saturating_sub(other[ecn]);
        }
        diff
    }
}

impl AddAssign<IpTosEcn> for EcnCount {
    fn add_assign(&mut self, ecn: IpTosEcn) {
        self[ecn] += 1;
    }
}

#[derive(Debug, Default)]
pub struct EcnInfo {
    /// The current state of ECN validation on this path.
    state: EcnValidationState,
    /// The number of probes sent so far on the path during the ECN validation.
    probes_sent: usize,
    /// The ECN counts from the last ACK frame.
    baseline: EcnCount,
}

impl EcnInfo {
    /// Set the baseline (= the ECN counts from the last ACK Frame).
    pub fn set_baseline(&mut self, baseline: EcnCount) {
        self.baseline = baseline;
    }

    /// Expose the current baseline.
    pub fn baseline(&self) -> EcnCount {
        self.baseline
    }

    /// Count the number of packets sent out on this path during ECN validation.
    /// Exit ECN validation if the number of packets sent exceeds `ECN_TEST_COUNT`.
    /// We do not implement the part of the RFC that says to exit ECN validation if the time since
    /// the start of ECN validation exceeds 3 * PTO, since this seems to happen much too quickly.
    pub fn on_packet_sent(&mut self) {
        if self.state != EcnValidationState::Testing {
            return;
        }

        self.probes_sent += 1;
        if self.probes_sent == ECN_TEST_COUNT {
            qdebug!(
                "ECN probing concluded with {} packet sent",
                self.probes_sent
            );
            self.state = EcnValidationState::Unknown;
        }
    }

    /// After the ECN validation test has ended, check if the path is ECN capable.
    pub fn validate_ack_ecn(&mut self, acked_packets: &[SentPacket], ack_ecn: &EcnCount) {
        if self.state != EcnValidationState::Unknown {
            return;
        }

        // RFC 9000, Appendix A.4:
        // From the "unknown" state, successful validation of the ECN counts in an ACK frame
        // (see Section 13.4.2.1) causes the ECN state for the path to become "capable", unless
        // no marked packet has been acknowledged.

        // RFC 9000, Section 13.4.2.1:
        //
        // > An endpoint that receives an ACK frame with ECN counts therefore validates
        // > the counts before using them. It performs this validation by comparing newly
        // > received counts against those from the last successfully processed ACK frame.
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
        let newly_acked_sent_with_ect0 = acked_packets
            .iter()
            .filter(|p| p.ecn_mark == IpTosEcn::Ect0)
            .count();
        let ecn_diff = ack_ecn - &self.baseline;
        let sum_inc = ecn_diff[IpTosEcn::Ect0] + ecn_diff[IpTosEcn::Ce];
        if sum_inc < newly_acked_sent_with_ect0.try_into().unwrap() {
            qwarn!(
                "ACK had {} new marks, but {} of newly acked packets were sent with ECN, ECN validation failed",
                sum_inc,
                newly_acked_sent_with_ect0
            );
            self.state = EcnValidationState::Failed;
        } else {
            qinfo!(
                "ECN validation succeeded {} {}, path is capable",
                sum_inc,
                newly_acked_sent_with_ect0
            );
            self.state = EcnValidationState::Capable;
        }
        self.baseline = *ack_ecn;
    }

    /// The ECN mark to use for packets sent on this path.
    pub fn ecn_mark(&self) -> IpTosEcn {
        match self.state {
            EcnValidationState::Testing | EcnValidationState::Capable => IpTosEcn::Ect0,
            EcnValidationState::Failed | EcnValidationState::Unknown => IpTosEcn::NotEct,
        }
    }
}
