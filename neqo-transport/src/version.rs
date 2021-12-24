// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, Res};
use std::convert::TryFrom;

pub type WireVersion = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    Version2,
    Version1,
    Draft29,
    Draft30,
    Draft31,
    Draft32,
}

impl Version {
    pub const fn as_u32(self) -> WireVersion {
        match self {
            Self::Version2 => 0xff020000,
            Self::Version1 => 1,
            Self::Draft29 => 0xff00_0000 + 29,
            Self::Draft30 => 0xff00_0000 + 30,
            Self::Draft31 => 0xff00_0000 + 31,
            Self::Draft32 => 0xff00_0000 + 32,
        }
    }

    pub fn initial_salt(self) -> &'static [u8] {
        const INITIAL_SALT_V2: &[u8] = &[
            0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d, 0x62, 0xca, 0x57, 0x04,
            0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3,
        ];
        const INITIAL_SALT_V1: &[u8] = &[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        const INITIAL_SALT_29_32: &[u8] = &[
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
            0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
        ];
        match self {
            Version::Version2 => INITIAL_SALT_V2,
            Version::Version1 => INITIAL_SALT_V1,
            Version::Draft29 | Version::Draft30 | Version::Draft31 | Version::Draft32 => {
                INITIAL_SALT_29_32
            }
        }
    }

    pub fn label_prefix(self) -> &'static str {
        match self {
            Self::Version2 => "quicv2 ",
            Version::Version1
            | Version::Draft29
            | Version::Draft30
            | Version::Draft31
            | Version::Draft32 => "quic ",
        }
    }

    pub fn retry_secret(self) -> &'static [u8] {
        const RETRY_SECRET_29: &[u8] = &[
            0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2, 0x07, 0xd8,
            0x0d, 0xf2, 0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42, 0xc3, 0x0a, 0x8b, 0xaa,
            0x2b, 0xaa, 0xff, 0x4c,
        ];
        const RETRY_SECRET_V1: &[u8] = &[
            0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20, 0x00, 0x21, 0x50, 0x6b, 0xcc, 0x02,
            0x81, 0x4c, 0x73, 0x03, 0x0f, 0x25, 0xc7, 0x9d, 0x71, 0xce, 0x87, 0x6e, 0xca, 0x87,
            0x6e, 0x6f, 0xca, 0x8e,
        ];
        const RETRY_SECRET_V2: &[u8] = &[
            0x34, 0x25, 0xc2, 0x0c, 0xf8, 0x87, 0x79, 0xdf, 0x2f, 0xf7, 0x1e, 0x8a, 0xbf, 0xa7,
            0x82, 0x49, 0x89, 0x1e, 0x76, 0x3b, 0xbe, 0xd2, 0xf1, 0x3c, 0x04, 0x83, 0x43, 0xd3,
            0x48, 0xc0, 0x60, 0xe2,
        ];
        match self {
            Version::Version2 => RETRY_SECRET_V2,
            Version::Version1 => RETRY_SECRET_V1,
            Version::Draft29 | Version::Draft30 | Version::Draft31 | Version::Draft32 => {
                RETRY_SECRET_29
            }
        }
    }

    pub(crate) fn is_draft(self) -> bool {
        matches!(
            self,
            Self::Draft29 | Self::Draft30 | Self::Draft31 | Self::Draft32,
        )
    }

    /// Determine if `self` can be upgraded to `other` compatibly.
    pub fn compatible(self, other: Self) -> bool {
        self == other
            || matches!(
                (self, other),
                (Self::Version1, Self::Version2) | (Self::Version2, Self::Version1)
            )
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::Version2,
            Self::Version1,
            Self::Draft32,
            Self::Draft31,
            Self::Draft30,
            Self::Draft29,
        ]
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::Version1
    }
}

impl TryFrom<WireVersion> for Version {
    type Error = Error;

    fn try_from(wire: WireVersion) -> Res<Self> {
        if wire == 1 {
            Ok(Self::Version1)
        } else if wire == 0xff020000 {
            Ok(Self::Version2)
        } else if wire == 0xff00_0000 + 29 {
            Ok(Self::Draft29)
        } else if wire == 0xff00_0000 + 30 {
            Ok(Self::Draft30)
        } else if wire == 0xff00_0000 + 31 {
            Ok(Self::Draft31)
        } else if wire == 0xff00_0000 + 32 {
            Ok(Self::Draft32)
        } else {
            Err(Error::VersionNegotiation)
        }
    }
}
