// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::ops::Deref;

use enum_map::Enum;

use crate::hex_with_len;

// ECN (Explicit Congestion Notification) codepoints mapped to the
// lower 2 bits of the TOS field.
// https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
#[derive(Copy, Clone, PartialEq, Eq, Enum, Default)]
#[repr(u8)]
pub enum IpTosEcn {
    #[default]
    NotEct = 0b00, // Not-ECT, Not ECN-Capable Transport, [RFC3168]
    Ect1 = 0b01, // ECT(1), ECN-Capable Transport(1), [RFC8311][RFC9331]
    Ect0 = 0b10, // ECT(0), ECN-Capable Transport(0), [RFC3168]
    Ce = 0b11,   // CE, Congestion Experienced, [RFC3168]
}

impl std::fmt::Debug for IpTosEcn {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IpTosEcn::NotEct => f.write_str("Not-ECT"),
            IpTosEcn::Ect1 => f.write_str("ECT(1)"),
            IpTosEcn::Ect0 => f.write_str("ECT(0)"),
            IpTosEcn::Ce => f.write_str("CE"),
        }
    }
}

// DiffServ Codepoints, mapped to the upper six bits of the TOS field.
// https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
#[derive(Copy, Clone, PartialEq, Eq, Enum, Default)]
#[repr(u8)]
pub enum IpTosDscp {
    #[default]
    Cs0 = 0b0000_0000, // Class Selector 0, [RFC2474]
    Cs1 = 0b0010_0000,        // Class Selector 1, [RFC2474]
    Cs2 = 0b0100_0000,        // Class Selector 2, [RFC2474]
    Cs3 = 0b0110_0000,        // Class Selector 3, [RFC2474]
    Cs4 = 0b1000_0000,        // Class Selector 4, [RFC2474]
    Cs5 = 0b1010_0000,        // Class Selector 5, [RFC2474]
    Cs6 = 0b1100_0000,        // Class Selector 6, [RFC2474]
    Cs7 = 0b1110_0000,        // Class Selector 7, [RFC2474]
    Af11 = 0b0010_1000,       // Assured Forwarding 11, [RFC2597]
    Af12 = 0b0011_0000,       // Assured Forwarding 12, [RFC2597]
    Af13 = 0b0011_1000,       // Assured Forwarding 13, [RFC2597]
    Af21 = 0b0100_1000,       // Assured Forwarding 21, [RFC2597]
    Af22 = 0b0101_0000,       // Assured Forwarding 22, [RFC2597]
    Af23 = 0b0101_1000,       // Assured Forwarding 23, [RFC2597]
    Af31 = 0b0110_1000,       // Assured Forwarding 31, [RFC2597]
    Af32 = 0b0111_0000,       // Assured Forwarding 32, [RFC2597]
    Af33 = 0b0111_1000,       // Assured Forwarding 33, [RFC2597]
    Af41 = 0b1000_1000,       // Assured Forwarding 41, [RFC2597]
    Af42 = 0b1001_0000,       // Assured Forwarding 42, [RFC2597]
    Af43 = 0b1001_1000,       // Assured Forwarding 43, [RFC2597]
    Ef = 0b1011_1000,         // Expedited Forwarding, [RFC3246]
    VoiceAdmit = 0b1011_0000, // Capacity-Admitted Traffic, [RFC5865]
    Le = 0b0000_0100,         // Lower-Effort, [RFC8622]
}

impl std::fmt::Debug for IpTosDscp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IpTosDscp::Cs0 => f.write_str("CS0"),
            IpTosDscp::Cs1 => f.write_str("CS1"),
            IpTosDscp::Cs2 => f.write_str("CS2"),
            IpTosDscp::Cs3 => f.write_str("CS3"),
            IpTosDscp::Cs4 => f.write_str("CS4"),
            IpTosDscp::Cs5 => f.write_str("CS5"),
            IpTosDscp::Cs6 => f.write_str("CS6"),
            IpTosDscp::Cs7 => f.write_str("CS7"),
            IpTosDscp::Af11 => f.write_str("AF11"),
            IpTosDscp::Af12 => f.write_str("AF12"),
            IpTosDscp::Af13 => f.write_str("AF13"),
            IpTosDscp::Af21 => f.write_str("AF21"),
            IpTosDscp::Af22 => f.write_str("AF22"),
            IpTosDscp::Af23 => f.write_str("AF23"),
            IpTosDscp::Af31 => f.write_str("AF31"),
            IpTosDscp::Af32 => f.write_str("AF32"),
            IpTosDscp::Af33 => f.write_str("AF33"),
            IpTosDscp::Af41 => f.write_str("AF41"),
            IpTosDscp::Af42 => f.write_str("AF42"),
            IpTosDscp::Af43 => f.write_str("AF43"),
            IpTosDscp::Ef => f.write_str("EF"),
            IpTosDscp::VoiceAdmit => f.write_str("VOICE-ADMIT"),
            IpTosDscp::Le => f.write_str("LE"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct IpTos((IpTosDscp, IpTosEcn));

impl std::fmt::Debug for IpTos {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_tuple("IpTos")
            .field(&self.0 .0)
            .field(&self.0 .1)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    tos: IpTos,
    ttl: Option<u8>,
    d: Vec<u8>,
}

impl Datagram {
    pub fn new<V: Into<Vec<u8>>>(
        src: SocketAddr,
        dst: SocketAddr,
        tos: IpTos,
        ttl: Option<u8>,
        d: V,
    ) -> Self {
        Self {
            src,
            dst,
            tos,
            ttl,
            d: d.into(),
        }
    }

    #[must_use]
    pub fn source(&self) -> SocketAddr {
        self.src
    }

    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        self.dst
    }

    #[must_use]
    pub fn tos(&self) -> IpTos {
        self.tos
    }

    #[must_use]
    pub fn ttl(&self) -> Option<u8> {
        self.ttl
    }
}

impl Deref for Datagram {
    type Target = Vec<u8>;
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

impl std::fmt::Debug for Datagram {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Datagram {:?} TTL {:?} {:?}->{:?}: {}",
            self.tos,
            self.ttl,
            self.src,
            self.dst,
            hex_with_len(&self.d)
        )
    }
}

#[cfg(test)]
use test_fixture::datagram;

#[test]
fn ip_tos_ecn_fmt() {
    assert_eq!(format!("{:?}", IpTosEcn::NotEct), "Not-ECT");
    assert_eq!(format!("{:?}", IpTosEcn::Ect1), "ECT(1)");
    assert_eq!(format!("{:?}", IpTosEcn::Ect0), "ECT(0)");
    assert_eq!(format!("{:?}", IpTosEcn::Ce), "CE");
}

#[test]
fn ip_tos_dscp_fmt() {
    assert_eq!(format!("{:?}", IpTosDscp::Cs0), "CS0");
    assert_eq!(format!("{:?}", IpTosDscp::Cs1), "CS1");
    assert_eq!(format!("{:?}", IpTosDscp::Cs2), "CS2");
    assert_eq!(format!("{:?}", IpTosDscp::Cs3), "CS3");
    assert_eq!(format!("{:?}", IpTosDscp::Cs4), "CS4");
    assert_eq!(format!("{:?}", IpTosDscp::Cs5), "CS5");
    assert_eq!(format!("{:?}", IpTosDscp::Cs6), "CS6");
    assert_eq!(format!("{:?}", IpTosDscp::Cs7), "CS7");
    assert_eq!(format!("{:?}", IpTosDscp::Af11), "AF11");
    assert_eq!(format!("{:?}", IpTosDscp::Af12), "AF12");
    assert_eq!(format!("{:?}", IpTosDscp::Af13), "AF13");
    assert_eq!(format!("{:?}", IpTosDscp::Af21), "AF21");
    assert_eq!(format!("{:?}", IpTosDscp::Af22), "AF22");
    assert_eq!(format!("{:?}", IpTosDscp::Af23), "AF23");
    assert_eq!(format!("{:?}", IpTosDscp::Af31), "AF31");
    assert_eq!(format!("{:?}", IpTosDscp::Af32), "AF32");
    assert_eq!(format!("{:?}", IpTosDscp::Af33), "AF33");
    assert_eq!(format!("{:?}", IpTosDscp::Af41), "AF41");
    assert_eq!(format!("{:?}", IpTosDscp::Af42), "AF42");
    assert_eq!(format!("{:?}", IpTosDscp::Af43), "AF43");
    assert_eq!(format!("{:?}", IpTosDscp::Ef), "EF");
    assert_eq!(format!("{:?}", IpTosDscp::VoiceAdmit), "VOICE-ADMIT");
    assert_eq!(format!("{:?}", IpTosDscp::Le), "LE");
}

#[test]
fn ip_tos_debug_fmt() {
    let ip_tos = IpTos((IpTosDscp::Cs0, IpTosEcn::NotEct));
    assert_eq!(format!("{ip_tos:?}"), "IpTos(CS0, Not-ECT)");

    let ip_tos = IpTos((IpTosDscp::Af11, IpTosEcn::Ce));
    assert_eq!(format!("{ip_tos:?}"), "IpTos(AF11, CE)");
}

#[test]
fn fmt_datagram() {
    let d = datagram([0; 1].to_vec());
    assert_eq!(
        format!("{d:?}"),
        "Datagram IpTos(CS0, Not-ECT) TTL Some(128) [fe80::1]:443->[fe80::1]:443: [1]: 00"
            .to_string()
    );
}
