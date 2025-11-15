// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub struct Header {
    name: String,
    value: Vec<u8>,
}

impl Header {
    pub fn new<N, V>(name: N, value: V) -> Self
    where
        N: Into<String>,
        V: AsRef<[u8]>,
    {
        Self {
            name: name.into(),
            value: value.as_ref().to_vec(),
        }
    }

    #[must_use]
    pub fn is_allowed_for_response(&self) -> bool {
        !matches!(
            self.name.as_str(),
            "connection"
                | "host"
                | "keep-alive"
                | "proxy-connection"
                | "te"
                | "transfer-encoding"
                | "upgrade"
        )
    }

    #[allow(
        clippy::allow_attributes,
        clippy::missing_const_for_fn,
        reason = "False positive on 1.86, remove when MSRV is higher."
    )]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[allow(
        clippy::allow_attributes,
        clippy::missing_const_for_fn,
        reason = "False positive on 1.86, remove when MSRV is higher."
    )]
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl<T: AsRef<str>, U: AsRef<[u8]>> PartialEq<(T, U)> for Header {
    fn eq(&self, other: &(T, U)) -> bool {
        self.name == other.0.as_ref() && self.value == other.1.as_ref()
    }
}

pub trait HeadersExt<'h> {
    fn contains_header<T: AsRef<str>, U: AsRef<[u8]>>(self, name: T, value: U) -> bool;
    fn find_header<T: AsRef<str> + 'h>(self, name: T) -> Option<&'h Header>;
}

impl<'h, H> HeadersExt<'h> for H
where
    H: IntoIterator<Item = &'h Header> + 'h,
{
    fn contains_header<T: AsRef<str>, U: AsRef<[u8]>>(self, name: T, value: U) -> bool {
        let (name, value) = (name.as_ref(), value.as_ref());
        self.into_iter().any(|h| h == &(name, value))
    }

    fn find_header<T: AsRef<str> + 'h>(self, name: T) -> Option<&'h Header> {
        let name = name.as_ref();
        self.into_iter().find(|h| h.name == name)
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum FromStrError {
    #[error("Header string missing colon")]
    MissingColon,
    #[error("Header string missing name")]
    MissingName,
}

impl FromStr for Header {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (seperator, _) = s
            .match_indices(':')
            // Pseudo-header starts with a ':'. Skip it.
            .find(|(i, _)| *i != 0)
            .ok_or(FromStrError::MissingColon)?;

        let name = s[..seperator].trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(FromStrError::MissingName);
        }

        let value = s[seperator + 1..].trim().as_bytes().to_vec();

        Ok(Self::new(name, value))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn from_str_valid() {
        let header = Header::from_str("Content-Type: text/html").unwrap();
        assert_eq!(header.name(), "content-type");
        assert_eq!(header.value(), b"text/html");

        let header = Header::from_str("Content-Type:").unwrap();
        assert_eq!(header.name(), "content-type");
        assert_eq!(header.value(), b"");
    }

    #[test]
    fn from_str_pseudo_header() {
        let header = Header::from_str(":scheme: https").unwrap();
        assert_eq!(header.name(), ":scheme");
        assert_eq!(header.value(), b"https");
    }

    #[test]
    fn from_str_pseudo_header_with_value_with_colon() {
        let header = Header::from_str(":some: he:ader").unwrap();
        assert_eq!(header.name(), ":some");
        assert_eq!(header.value(), b"he:ader");
    }

    #[test]
    fn from_str_errors() {
        assert_eq!(Header::from_str("").err(), Some(FromStrError::MissingColon));
        assert_eq!(
            Header::from_str(" : text/html").err(),
            Some(FromStrError::MissingName)
        );
    }

    #[test]
    fn non_utf8_header_value() {
        // Create a header with non-UTF-8 bytes in the value
        let non_utf8_bytes: Vec<u8> = vec![0xFF, 0xFE, 0xFD, 0x80, 0x81];
        let header = Header::new("custom-header", &non_utf8_bytes);

        assert_eq!(header.name(), "custom-header");
        assert_eq!(header.value(), non_utf8_bytes.as_slice());

        // Verify that the value is indeed not valid UTF-8
        assert!(std::str::from_utf8(header.value()).is_err());
    }

    #[test]
    fn non_ascii_header_value() {
        // Create a header with non-ASCII but valid UTF-8 bytes
        let emoji_value = "🚀🌟";
        let header = Header::new("emoji-header", emoji_value);

        assert_eq!(header.name(), "emoji-header");
        assert_eq!(header.value(), emoji_value.as_bytes());

        // Verify we can convert back to UTF-8
        assert_eq!(std::str::from_utf8(header.value()).unwrap(), emoji_value);
    }

    #[test]
    fn header_comparison_with_bytes() {
        let header = Header::new("test", b"value");

        // Test PartialEq with byte slice
        assert_eq!(header, ("test", b"value".as_ref()));

        // Test with string (converted to bytes)
        let header2 = Header::new("test2", "string_value");
        assert_eq!(header2, ("test2", b"string_value".as_ref()));
    }
}
