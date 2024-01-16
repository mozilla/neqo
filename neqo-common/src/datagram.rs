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
#[derive(Copy, Clone, PartialEq, Eq, Enum)]
#[repr(u8)]
pub enum IpTosEcn {
    NotEct = 0b00, // Not-ECT (Not ECN-Capable Transport) [RFC3168]
    Ect1 = 0b01,   // ECT(1) (ECN-Capable Transport(1))[1] [RFC8311][RFC Errata 5399][RFC9331]
    Ect0 = 0b10,   // ECT(0) (ECN-Capable Transport(0)) [RFC3168]
    Ce = 0b11,     // CE (Congestion Experienced) [RFC3168]
}

impl From<u8> for IpTosEcn {
    fn from(v: u8) -> Self {
        match v & 0b11 {
            0b00 => IpTosEcn::NotEct,
            0b01 => IpTosEcn::Ect1,
            0b10 => IpTosEcn::Ect0,
            0b11 => IpTosEcn::Ce,
            _ => unreachable!(),
        }
    }
}

impl From<IpTosEcn> for u8 {
    fn from(val: IpTosEcn) -> Self {
        val as u8
    }
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
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum IpTosDscp {
    Cs0 = 0b0000_0000,        // [RFC2474]
    Cs1 = 0b0010_0000,        // [RFC2474]
    Cs2 = 0b0100_0000,        // [RFC2474]
    Cs3 = 0b0110_0000,        // [RFC2474]
    Cs4 = 0b1000_0000,        // [RFC2474]
    Cs5 = 0b1010_0000,        // [RFC2474]
    Cs6 = 0b1100_0000,        // [RFC2474]
    Cs7 = 0b1110_0000,        // [RFC2474]
    Af11 = 0b0010_1000,       // [RFC2597]
    Af12 = 0b0011_0000,       // [RFC2597]
    Af13 = 0b0011_1000,       // [RFC2597]
    Af21 = 0b0100_1000,       // [RFC2597]
    Af22 = 0b0101_0000,       // [RFC2597]
    Af23 = 0b0101_1000,       // [RFC2597]
    Af31 = 0b0110_1000,       // [RFC2597]
    Af32 = 0b0111_0000,       // [RFC2597]
    Af33 = 0b0111_1000,       // [RFC2597]
    Af41 = 0b1000_1000,       // [RFC2597]
    Af42 = 0b1001_0000,       // [RFC2597]
    Af43 = 0b1001_1000,       // [RFC2597]
    Ef = 0b1011_1000,         // [RFC3246]
    VoiceAdmit = 0b1011_0000, // [RFC5865]
    Le = 0b0000_0100,         // [RFC8622]
}

#[derive(PartialEq, Eq, Clone)]
pub struct Datagram {
    src: SocketAddr,
    dst: SocketAddr,
    tos: u8,
    ttl: u8,
    d: Vec<u8>,
}

impl Datagram {
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, tos: u8, ttl: u8, d: V) -> Self {
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
    pub fn tos(&self) -> u8 {
        self.tos
    }

    #[must_use]
    pub fn ttl(&self) -> u8 {
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
            "Datagram {:?}->{:?}: {}",
            self.src,
            self.dst,
            hex_with_len(&self.d)
        )
    }
}
