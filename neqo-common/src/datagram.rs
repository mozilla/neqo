// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::ops::Deref;

use crate::hex_with_len;

// ECN (Explicit Congestion Notification) codepoints mapped to the
// lower 2 bits of the TOS field.
// https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum IpTosEcn {
    EcnNotEct = 0b00, // Not-ECT (Not ECN-Capable Transport) [RFC3168]
    EcnEct1 = 0b01,   // ECT(1) (ECN-Capable Transport(1))[1] [RFC8311][RFC Errata 5399][RFC9331]
    EcnEct0 = 0b10,   // ECT(0) (ECN-Capable Transport(0)) [RFC3168]
    EcnCe = 0b11,     // CE (Congestion Experienced) [RFC3168]
}

// DiffServ Codepoints, mapped to the upper six bits of the TOS field.
// https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum IpTosDscp {
    DscpCs0 = 0b0000_0000,        // [RFC2474]
    DscpCs1 = 0b0010_0000,        // [RFC2474]
    DscpCs2 = 0b0100_0000,        // [RFC2474]
    DscpCs3 = 0b0110_0000,        // [RFC2474]
    DscpCs4 = 0b1000_0000,        // [RFC2474]
    DscpCs5 = 0b1010_0000,        // [RFC2474]
    DscpCs6 = 0b1100_0000,        // [RFC2474]
    DscpCs7 = 0b1110_0000,        // [RFC2474]
    DscpAf11 = 0b0010_1000,       // [RFC2597]
    DscpAf12 = 0b0011_0000,       // [RFC2597]
    DscpAf13 = 0b0011_1000,       // [RFC2597]
    DscpAf21 = 0b0100_1000,       // [RFC2597]
    DscpAf22 = 0b0101_0000,       // [RFC2597]
    DscpAf23 = 0b0101_1000,       // [RFC2597]
    DscpAf31 = 0b0110_1000,       // [RFC2597]
    DscpAf32 = 0b0111_0000,       // [RFC2597]
    DscpAf33 = 0b0111_1000,       // [RFC2597]
    DscpAf41 = 0b1000_1000,       // [RFC2597]
    DscpAf42 = 0b1001_0000,       // [RFC2597]
    DscpAf43 = 0b1001_1000,       // [RFC2597]
    DscpEf = 0b1011_1000,         // [RFC3246]
    DscpVoiceAdmit = 0b1011_0000, // [RFC5865]
    DscpLe = 0b0000_0100,         // [RFC8622]
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
    pub fn new<V: Into<Vec<u8>>>(src: SocketAddr, dst: SocketAddr, d: V) -> Self {
        Self {
            src,
            dst,
            tos: IpTosEcn::EcnEct0 as u8,
            ttl: 128,
            d: d.into(),
        }
    }

    pub fn new_with_tos_and_ttl<V: Into<Vec<u8>>>(
        src: SocketAddr,
        dst: SocketAddr,
        tos: u8,
        ttl: u8,
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
