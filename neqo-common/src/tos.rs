// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::{self, Debug, Formatter};

use enum_map::Enum;
use strum::{EnumIter, FromRepr};

/// ECN (Explicit Congestion Notification) codepoints mapped to the
/// lower 2 bits of the TOS field.
/// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
#[derive(Copy, Clone, PartialEq, Eq, Enum, Default, Debug, FromRepr, EnumIter)]
#[repr(u8)]
pub enum Ecn {
    #[default]
    /// Not-ECT, Not ECN-Capable Transport, RFC3168
    NotEct = 0b00,
    /// ECT(1), ECN-Capable Transport(1), RFC8311 and RFC9331
    Ect1 = 0b01,
    /// ECT(0), ECN-Capable Transport(0), RFC3168
    Ect0 = 0b10,
    /// CE, Congestion Experienced, RFC3168
    Ce = 0b11,
}

impl From<Ecn> for u8 {
    fn from(v: Ecn) -> Self {
        v as Self
    }
}

impl From<u8> for Ecn {
    fn from(v: u8) -> Self {
        Self::from_repr(v & 0b0000_0011).expect("all ECN values are covered")
    }
}

impl From<Tos> for Ecn {
    fn from(v: Tos) -> Self {
        Self::from(u8::from(v))
    }
}

impl Ecn {
    /// Return `true` for any marking: ECT(0), ECT(1), or CE.
    #[must_use]
    pub const fn is_marked(self) -> bool {
        matches!(self, Self::Ect0 | Self::Ect1 | Self::Ce)
    }

    /// Return `true` if the value is ECT(0) or ECT(1).
    #[must_use]
    pub const fn is_ect(self) -> bool {
        matches!(self, Self::Ect0 | Self::Ect1)
    }
}

/// Diffserv codepoints, mapped to the upper six bits of the TOS field.
/// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
#[derive(Copy, Clone, PartialEq, Eq, Enum, Default, Debug, FromRepr)]
#[repr(u8)]
pub enum Dscp {
    #[default]
    /// Class Selector 0, RFC2474
    Cs0 = 0b0000_0000,
    /// Lower-Effort, RFC8622
    Le = 0b0000_0100,
    Reserved2 = 0b0000_1000,
    Reserved3 = 0b0000_1100,
    Reserved4 = 0b0001_0000,
    Reserved5 = 0b0001_0100,
    Reserved6 = 0b0001_1000,
    Reserved7 = 0b0001_1100,
    /// Class Selector 1, RFC2474
    Cs1 = 0b0010_0000,
    Reserved9 = 0b0010_0100,
    Af11 = 0b0010_1000,
    /// Assured Forwarding 12, RFC2597
    Reserved11 = 0b0010_1100,
    /// Assured Forwarding 11, RFC2597
    Af12 = 0b0011_0000,
    Reserved13 = 0b0011_0100,
    /// Assured Forwarding 13, RFC2597
    Af13 = 0b0011_1000,
    Reserved15 = 0b0011_1100,
    /// Class Selector 2, RFC2474
    Cs2 = 0b0100_0000,
    Reserved17 = 0b0100_0100,
    /// Assured Forwarding 21, RFC2597
    Af21 = 0b0100_1000,
    Reserved19 = 0b0100_1100,
    /// Assured Forwarding 22, RFC2597
    Af22 = 0b0101_0000,
    Reserved21 = 0b0101_0100,
    /// Assured Forwarding 23, RFC2597
    Af23 = 0b0101_1000,
    Reserved23 = 0b0101_1100,
    /// Class Selector 3, RFC2474
    Cs3 = 0b0110_0000,
    Reserved25 = 0b0110_0100,
    /// Assured Forwarding 31, RFC2597
    Af31 = 0b0110_1000,
    Reserved27 = 0b0110_1100,
    /// Assured Forwarding 32, RFC2597
    Af32 = 0b0111_0000,
    Reserved29 = 0b0111_0100,
    /// Assured Forwarding 33, RFC2597
    Af33 = 0b0111_1000,
    Reserved31 = 0b0111_1100,
    /// Class Selector 4, RFC2474
    Cs4 = 0b1000_0000,
    Reserved33 = 0b1000_0100,
    /// Assured Forwarding 41, RFC2597
    Af41 = 0b1000_1000,
    Reserved35 = 0b1000_1100,
    /// Assured Forwarding 42, RFC2597
    Af42 = 0b1001_0000,
    Reserved37 = 0b1001_0100,
    /// Assured Forwarding 43, RFC2597
    Af43 = 0b1001_1000,
    Reserved39 = 0b1001_1100,
    /// Class Selector 5, RFC2474
    Cs5 = 0b1010_0000,
    Reserved41 = 0b1010_0100,
    Reserved42 = 0b1010_1000,
    Reserved43 = 0b1010_1100,
    /// Capacity-Admitted Traffic, RFC5865
    VoiceAdmit = 0b1011_0000,
    Reserved45 = 0b1011_0100,
    /// Expedited Forwarding, RFC3246
    Ef = 0b1011_1000,
    Reserved47 = 0b1011_1100,
    /// Class Selector 6, RFC2474
    Cs6 = 0b1100_0000,
    Reserved49 = 0b1100_0100,
    Reserved50 = 0b1100_1000,
    Reserved51 = 0b1100_1100,
    Reserved52 = 0b1101_0000,
    Reserved53 = 0b1101_0100,
    Reserved54 = 0b1101_1000,
    Reserved55 = 0b1101_1100,
    /// Class Selector 7, RFC2474
    Cs7 = 0b1110_0000,
    Reserved57 = 0b1110_0100,
    Reserved58 = 0b1110_1000,
    Reserved59 = 0b1110_1100,
    Reserved60 = 0b1111_0000,
    Reserved61 = 0b1111_0100,
    Reserved62 = 0b1111_1000,
    Reserved63 = 0b1111_1100,
}

impl From<Dscp> for u8 {
    fn from(v: Dscp) -> Self {
        v as Self
    }
}

impl From<u8> for Dscp {
    fn from(v: u8) -> Self {
        Self::from_repr(v & 0b1111_1100).expect("all DCSP values are covered")
    }
}

impl From<Tos> for Dscp {
    fn from(v: Tos) -> Self {
        Self::from(u8::from(v))
    }
}

/// The type-of-service field in an IP packet.
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct Tos(u8);

impl From<Ecn> for Tos {
    fn from(v: Ecn) -> Self {
        Self(u8::from(v))
    }
}

impl From<Dscp> for Tos {
    fn from(v: Dscp) -> Self {
        Self(u8::from(v))
    }
}

impl From<(Dscp, Ecn)> for Tos {
    fn from(v: (Dscp, Ecn)) -> Self {
        Self(u8::from(v.0) | u8::from(v.1))
    }
}

impl From<(Ecn, Dscp)> for Tos {
    fn from(v: (Ecn, Dscp)) -> Self {
        Self(u8::from(v.0) | u8::from(v.1))
    }
}

impl From<Tos> for u8 {
    fn from(v: Tos) -> Self {
        v.0
    }
}

impl From<u8> for Tos {
    fn from(v: u8) -> Self {
        Self(v)
    }
}

impl Debug for Tos {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Tos")
            .field(&Dscp::from(*self))
            .field(&Ecn::from(*self))
            .finish()
    }
}

impl Tos {
    pub fn set_ecn(&mut self, ecn: Ecn) {
        self.0 = u8::from(Dscp::from(*self)) | u8::from(ecn);
    }

    pub fn set_dscp(&mut self, dscp: Dscp) {
        self.0 = u8::from(Ecn::from(*self)) | u8::from(dscp);
    }

    #[must_use]
    pub fn is_ecn_marked(self) -> bool {
        Ecn::from(self).is_marked()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Dscp, Ecn, Tos};

    #[test]
    fn ecn_into_u8() {
        assert_eq!(u8::from(Ecn::NotEct), 0b00);
        assert_eq!(u8::from(Ecn::Ect1), 0b01);
        assert_eq!(u8::from(Ecn::Ect0), 0b10);
        assert_eq!(u8::from(Ecn::Ce), 0b11);
    }

    #[test]
    fn u8_into_ecn() {
        assert_eq!(Ecn::from(0b00), Ecn::NotEct);
        assert_eq!(Ecn::from(0b01), Ecn::Ect1);
        assert_eq!(Ecn::from(0b10), Ecn::Ect0);
        assert_eq!(Ecn::from(0b11), Ecn::Ce);
    }

    #[test]
    fn u8_into_ecn_all() {
        for i in 0..=u8::MAX {
            _ = Ecn::from(i);
        }
    }

    #[test]
    fn dscp_into_u8() {
        assert_eq!(u8::from(Dscp::Cs0), 0b0000_0000);
        assert_eq!(u8::from(Dscp::Cs1), 0b0010_0000);
        assert_eq!(u8::from(Dscp::Cs2), 0b0100_0000);
        assert_eq!(u8::from(Dscp::Cs3), 0b0110_0000);
        assert_eq!(u8::from(Dscp::Cs4), 0b1000_0000);
        assert_eq!(u8::from(Dscp::Cs5), 0b1010_0000);
        assert_eq!(u8::from(Dscp::Cs6), 0b1100_0000);
        assert_eq!(u8::from(Dscp::Cs7), 0b1110_0000);
        assert_eq!(u8::from(Dscp::Af11), 0b0010_1000);
        assert_eq!(u8::from(Dscp::Af12), 0b0011_0000);
        assert_eq!(u8::from(Dscp::Af13), 0b0011_1000);
        assert_eq!(u8::from(Dscp::Af21), 0b0100_1000);
        assert_eq!(u8::from(Dscp::Af22), 0b0101_0000);
        assert_eq!(u8::from(Dscp::Af23), 0b0101_1000);
        assert_eq!(u8::from(Dscp::Af31), 0b0110_1000);
        assert_eq!(u8::from(Dscp::Af32), 0b0111_0000);
        assert_eq!(u8::from(Dscp::Af33), 0b0111_1000);
        assert_eq!(u8::from(Dscp::Af41), 0b1000_1000);
        assert_eq!(u8::from(Dscp::Af42), 0b1001_0000);
        assert_eq!(u8::from(Dscp::Af43), 0b1001_1000);
        assert_eq!(u8::from(Dscp::Ef), 0b1011_1000);
        assert_eq!(u8::from(Dscp::VoiceAdmit), 0b1011_0000);
        assert_eq!(u8::from(Dscp::Le), 0b0000_0100);
    }

    #[test]
    fn u8_into_dscp_all() {
        for i in 0..=u8::MAX {
            _ = Dscp::from(i);
        }
    }

    #[test]
    fn u8_into_dscp() {
        assert_eq!(Dscp::from(0b0000_0000), Dscp::Cs0);
        assert_eq!(Dscp::from(0b0010_0000), Dscp::Cs1);
        assert_eq!(Dscp::from(0b0100_0000), Dscp::Cs2);
        assert_eq!(Dscp::from(0b0110_0000), Dscp::Cs3);
        assert_eq!(Dscp::from(0b1000_0000), Dscp::Cs4);
        assert_eq!(Dscp::from(0b1010_0000), Dscp::Cs5);
        assert_eq!(Dscp::from(0b1100_0000), Dscp::Cs6);
        assert_eq!(Dscp::from(0b1110_0000), Dscp::Cs7);
        assert_eq!(Dscp::from(0b0010_1000), Dscp::Af11);
        assert_eq!(Dscp::from(0b0011_0000), Dscp::Af12);
        assert_eq!(Dscp::from(0b0011_1000), Dscp::Af13);
        assert_eq!(Dscp::from(0b0100_1000), Dscp::Af21);
        assert_eq!(Dscp::from(0b0101_0000), Dscp::Af22);
        assert_eq!(Dscp::from(0b0101_1000), Dscp::Af23);
        assert_eq!(Dscp::from(0b0110_1000), Dscp::Af31);
        assert_eq!(Dscp::from(0b0111_0000), Dscp::Af32);
        assert_eq!(Dscp::from(0b0111_1000), Dscp::Af33);
        assert_eq!(Dscp::from(0b1000_1000), Dscp::Af41);
        assert_eq!(Dscp::from(0b1001_0000), Dscp::Af42);
        assert_eq!(Dscp::from(0b1001_1000), Dscp::Af43);
        assert_eq!(Dscp::from(0b1011_1000), Dscp::Ef);
        assert_eq!(Dscp::from(0b1011_0000), Dscp::VoiceAdmit);
        assert_eq!(Dscp::from(0b0000_0100), Dscp::Le);
    }

    #[test]
    fn ecn_into_tos() {
        let ecn = Ecn::default();
        let tos: Tos = ecn.into();
        assert_eq!(u8::from(tos), ecn as u8);
    }

    #[test]
    fn dscp_into_tos() {
        let dscp = Dscp::default();
        let tos_dscp: Tos = dscp.into();
        assert_eq!(u8::from(tos_dscp), dscp as u8);
    }

    #[test]
    fn u8_to_tos() {
        let tos_u8 = 0x8b;
        let tos = Tos::from((Ecn::Ce, Dscp::Af41));
        assert_eq!(tos_u8, u8::from(tos));
        assert_eq!(Tos::from(tos_u8), tos);
    }

    #[test]
    fn tos_to_dscp() {
        let tos = Tos::from((Dscp::Af41, Ecn::NotEct));
        let dscp = Dscp::from(tos);
        assert_eq!(dscp, Dscp::Af41);
    }

    #[test]
    fn tos_modify_ecn() {
        let mut tos: Tos = (Dscp::Af41, Ecn::NotEct).into();
        tos.set_ecn(Ecn::Ce);
        assert_eq!(u8::from(tos), 0b1000_1011);
    }

    #[test]
    fn tos_modify_dscp() {
        let mut tos: Tos = (Dscp::Af41, Ecn::Ect1).into();
        tos.set_dscp(Dscp::Le);
        assert_eq!(u8::from(tos), 0b0000_0101);
    }

    #[test]
    fn tos_is_ecn_marked() {
        let tos: Tos = (Dscp::Af41, Ecn::Ce).into();
        assert!(tos.is_ecn_marked());
    }

    #[test]
    fn ecn_is_ecn_marked() {
        assert!(Ecn::Ce.is_marked());
        assert!(!Ecn::NotEct.is_marked());
    }
}
