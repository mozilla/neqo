// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, Header, MessageType, Res};
use std::ops::Deref;
use std::ops::DerefMut;

const PSEUDO_HEADER_STATUS: u8 = 0x1;
const PSEUDO_HEADER_METHOD: u8 = 0x2;
const PSEUDO_HEADER_SCHEME: u8 = 0x4;
const PSEUDO_HEADER_AUTHORITY: u8 = 0x8;
const PSEUDO_HEADER_PATH: u8 = 0x10;
const REGULAR_HEADER: u8 = 0x80;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Headers {
    headers: Vec<Header>,
}

impl Default for Headers {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
        }
    }
}

impl Headers {
    pub fn new(headers: &[Header]) -> Self {
        Self {
            headers: headers.to_vec(),
        }
    }

    pub fn is_interim(&self) -> Res<bool> {
        let status = self.headers.iter().find(|h| h.name() == ":status");
        if let Some(h) = status {
            #[allow(clippy::map_err_ignore)]
            let status_code = h.value().parse::<i32>().map_err(|_| Error::InvalidHeader)?;
            Ok((100..200).contains(&status_code))
        } else {
            Err(Error::InvalidHeader)
        }
    }

    fn track_pseudo(name: &str, state: &mut u8, message_type: MessageType) -> Res<bool> {
        let (pseudo, bit) = if name.starts_with(':') {
            if *state & REGULAR_HEADER != 0 {
                return Err(Error::InvalidHeader);
            }
            let bit = match message_type {
                MessageType::Response => match name {
                    ":status" => PSEUDO_HEADER_STATUS,
                    _ => return Err(Error::InvalidHeader),
                },
                MessageType::Request => match name {
                    ":method" => PSEUDO_HEADER_METHOD,
                    ":scheme" => PSEUDO_HEADER_SCHEME,
                    ":authority" => PSEUDO_HEADER_AUTHORITY,
                    ":path" => PSEUDO_HEADER_PATH,
                    _ => return Err(Error::InvalidHeader),
                },
            };
            (true, bit)
        } else {
            (false, REGULAR_HEADER)
        };

        if *state & bit == 0 || !pseudo {
            *state |= bit;
            Ok(pseudo)
        } else {
            Err(Error::InvalidHeader)
        }
    }

    pub fn headers_valid(&self, message_type: MessageType) -> Res<()> {
        let mut method_value: Option<&str> = None;
        let mut pseudo_state = 0;
        for header in &self.headers {
            let is_pseudo = Self::track_pseudo(header.name(), &mut pseudo_state, message_type)?;

            let mut bytes = header.name().bytes();
            if is_pseudo {
                if header.name() == ":method" {
                    method_value = Some(header.value());
                }
                let _ = bytes.next();
            }

            if bytes.any(|b| matches!(b, 0 | 0x10 | 0x13 | 0x3a | 0x41..=0x5a)) {
                return Err(Error::InvalidHeader); // illegal characters.
            }
        }
        // Clear the regular header bit, since we only check pseudo headers below.
        pseudo_state &= !REGULAR_HEADER;
        let pseudo_header_mask = match message_type {
            MessageType::Response => PSEUDO_HEADER_STATUS,
            MessageType::Request => {
                if method_value == Some(&"CONNECT".to_string()) {
                    PSEUDO_HEADER_METHOD | PSEUDO_HEADER_AUTHORITY
                } else {
                    PSEUDO_HEADER_METHOD | PSEUDO_HEADER_SCHEME | PSEUDO_HEADER_PATH
                }
            }
        };
        if pseudo_state & pseudo_header_mask != pseudo_header_mask {
            return Err(Error::InvalidHeader);
        }

        Ok(())
    }

    pub fn retain_valid_for_response(&mut self) {
        self.headers.retain(Header::is_allowed_for_response);
    }
}

impl From<&[Header]> for Headers {
    fn from(h: &[Header]) -> Self {
        Headers::new(h)
    }
}

impl From<Vec<Header>> for Headers {
    fn from(headers: Vec<Header>) -> Self {
        Self { headers }
    }
}

impl DerefMut for Headers {
    #[must_use]
    fn deref_mut(&mut self) -> &mut Vec<Header> {
        &mut self.headers
    }
}

impl Deref for Headers {
    type Target = Vec<Header>;
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.headers
    }
}

impl AsRef<[Header]> for Headers {
    fn as_ref(&self) -> &[Header] {
        &self.headers
    }
}
