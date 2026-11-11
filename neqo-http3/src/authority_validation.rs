// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Validation of the `:authority` pseudo-header host against the
//! [WHATWG URL Standard][whatwg] host rules.
//!
//! The rules implemented here are the ones that matter for a received
//! `:authority` value: a host is either a registered name (hostname), an IPv4
//! address, or a bracketed IPv6 address, and a value that ends in a number is
//! an IPv4 address or nothing. See [§ 3.5 Host processing][host].
//!
//! [whatwg]: https://url.spec.whatwg.org/
//! [host]: https://url.spec.whatwg.org/#host-processing

/// Validate a single host (no port) against the WHATWG URL host rules.
///
/// Returns the canonical (lowercased, trailing dot removed) host when it is
/// valid, or [`None`] when it is not.
#[must_use]
pub fn validate_host(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }

    // An IPv6 address is enclosed in square brackets.
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        // `Ipv6Addr` accepts the compressed forms, including an embedded IPv4
        // tail, and rejects everything else.
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        return Some(host.to_ascii_lowercase());
    }

    // > If url's host ends in a number, then it is an IPv4 address.
    //
    // A host whose last label is all digits is therefore parsed as IPv4 and,
    // when that fails, is rejected rather than falling back to a hostname.
    let last = host.rsplit('.').next().unwrap_or_default();
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return validate_ipv4(host).then(|| host.to_ascii_lowercase());
    }

    validate_hostname(host).then(|| host.to_ascii_lowercase())
}

/// Whether `host` is four dot-separated decimal octets, each `0..=255`.
///
/// A leading zero on a multi-digit octet is rejected, as the WHATWG algorithm
/// would read it as an octal (or, for `0x`, hexadecimal) number.
fn validate_ipv4(host: &str) -> bool {
    let mut octets = 0;
    for part in host.split('.') {
        octets += 1;
        if part.is_empty()
            || part.len() > 3
            || (part.len() > 1 && part.starts_with('0'))
            || part.parse::<u8>().is_err()
        {
            return false;
        }
    }
    octets == 4
}

/// Whether `host` is a valid registered name (hostname).
///
/// Each dot-separated label is 1 to 63 characters of ASCII letters, digits, and
/// hyphens, and does not start or end with a hyphen.
fn validate_hostname(host: &str) -> bool {
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Whether an `:authority` value, a host with an optional port, is valid.
///
/// An empty value carries no host and is accepted: HTTP/3 allows a request to
/// omit `:authority`.
#[must_use]
pub fn authority_is_valid(authority: &str) -> bool {
    if authority.is_empty() {
        return true;
    }

    // A bracketed IPv6 literal may be followed by `:port`, so the port is only
    // sought after the closing bracket. Otherwise the final colon, if any,
    // separates the port.
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((inner, tail)) = rest.split_once(']') else {
            return false;
        };
        let host = &authority[..inner.len() + 2];
        match tail.strip_prefix(':') {
            Some(port) => (host, Some(port)),
            None if tail.is_empty() => (host, None),
            None => return false,
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };

    if port.is_some_and(|port| port.parse::<u16>().is_err()) {
        return false;
    }

    validate_host(host).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames() {
        for host in ["example.com", "EXAMPLE.COM", "a", "my-host.example.com"] {
            assert!(validate_host(host).is_some(), "{host} should be valid");
        }
        // A trailing dot (root label) is allowed and dropped.
        assert_eq!(
            validate_host("example.com.").as_deref(),
            Some("example.com")
        );
        // Hostnames are lowercased.
        assert_eq!(validate_host("EXAMPLE.com").as_deref(), Some("example.com"));
    }

    #[test]
    fn invalid_hostnames() {
        for host in ["", "-example.com", "example-.com", "exa_mple.com"] {
            assert!(validate_host(host).is_none(), "{host} should be invalid");
        }
        // A label may not exceed 63 characters.
        let long = "a".repeat(64);
        assert!(validate_host(&long).is_none());
    }

    #[test]
    fn ipv4() {
        for host in ["192.168.1.1", "0.0.0.0", "255.255.255.255"] {
            assert!(validate_host(host).is_some(), "{host} should be valid");
        }
        // An out-of-range octet, a leading zero, and the wrong arity are all
        // rejected rather than treated as hostnames.
        for host in ["256.0.0.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "999"] {
            assert!(validate_host(host).is_none(), "{host} should be invalid");
        }
    }

    #[test]
    fn ipv6() {
        for host in ["[::1]", "[fe80::1]", "[2001:db8::1]"] {
            assert!(validate_host(host).is_some(), "{host} should be valid");
        }
        // Missing brackets, or a bracketed non-address, are rejected.
        for host in ["::1", "[not-an-address]", "[]"] {
            assert!(validate_host(host).is_none(), "{host} should be invalid");
        }
    }

    #[test]
    fn authority_with_port() {
        assert!(authority_is_valid("example.com:443"));
        assert!(authority_is_valid("[::1]:443"));
        assert!(authority_is_valid("example.com"));
        assert!(authority_is_valid("[::1]"));
        // An empty :authority carries no host and is accepted.
        assert!(authority_is_valid(""));

        assert!(!authority_is_valid("example.com:not-a-port"));
        assert!(!authority_is_valid("-example.com:443"));
        assert!(!authority_is_valid("[::1]junk"));
        assert!(!authority_is_valid("[::1"));
    }
}
