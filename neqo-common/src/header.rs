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
    value: String,
}

impl Header {
    pub fn new<N, V>(name: N, value: V) -> Self
    where
        N: Into<String>,
        V: Into<String>,
    {
        Self {
            name: name.into(),
            value: value.into(),
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
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl<T: AsRef<str>, U: AsRef<str>> PartialEq<(T, U)> for Header {
    fn eq(&self, other: &(T, U)) -> bool {
        self.name == other.0.as_ref() && self.value == other.1.as_ref()
    }
}

pub trait HeadersExt<'h> {
    fn contains_header<T: AsRef<str>, U: AsRef<str>>(self, name: T, value: U) -> bool;
    fn find_header<T: AsRef<str> + 'h>(self, name: T) -> Option<&'h Header>;
}

impl<'h, H> HeadersExt<'h> for H
where
    H: IntoIterator<Item = &'h Header> + 'h,
{
    fn contains_header<T: AsRef<str>, U: AsRef<str>>(self, name: T, value: U) -> bool {
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

        let value = s[seperator + 1..].trim();

        Ok(Self::new(name, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_valid() {
        let header = Header::from_str("Content-Type: text/html").unwrap();
        assert_eq!(header.name(), "content-type");
        assert_eq!(header.value(), "text/html");

        let header = Header::from_str("Content-Type:").unwrap();
        assert_eq!(header.name(), "content-type");
        assert_eq!(header.value(), "");
    }

    #[test]
    fn from_str_pseudo_header() {
        let header = Header::from_str(":scheme: https").unwrap();
        assert_eq!(header.name(), ":scheme");
        assert_eq!(header.value(), "https");
    }

    #[test]
    fn from_str_pseudo_header_with_value_with_colon() {
        let header = Header::from_str(":some: he:ader").unwrap();
        assert_eq!(header.name(), ":some");
        assert_eq!(header.value(), "he:ader");
    }

    #[test]
    fn from_str_errors() {
        assert_eq!(Header::from_str("").err(), Some(FromStrError::MissingColon));
        assert_eq!(
            Header::from_str(" : text/html").err(),
            Some(FromStrError::MissingName)
        );
    }
}
