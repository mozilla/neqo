// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{borrow::Cow, fmt::Debug};

use http::Uri as Url;

pub trait RequestTarget: Debug {
    fn scheme(&self) -> &str;
    fn authority(&self) -> &str;
    /// The value of the `:path` pseudo-header field, i.e., the path and query
    /// of the target, without any fragment.
    fn path(&self) -> Cow<'_, str>;
}

impl RequestTarget for &Url {
    fn scheme(&self) -> &str {
        self.scheme_str().unwrap_or("")
    }

    fn authority(&self) -> &str {
        Url::authority(self).map_or("", |a| a.as_str())
    }

    fn path(&self) -> Cow<'_, str> {
        // Not `Url::path_and_query`, which yields `?q` without a leading `/`
        // for targets like `https://example.com?q`.
        let path = Url::path(self);
        self.query().map_or(Cow::Borrowed(path), |query| {
            Cow::Owned(format!("{path}?{query}"))
        })
    }
}

impl<'s, 'a, 'p> RequestTarget for (&'s str, &'a str, &'p str) {
    fn scheme(&self) -> &'s str {
        self.0
    }

    fn authority(&self) -> &'a str {
        self.1
    }

    fn path(&self) -> Cow<'p, str> {
        Cow::Borrowed(self.2)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use http::Uri;

    use super::RequestTarget;

    #[test]
    fn uri_path_includes_query() {
        for (uri, path) in [
            ("https://example.com/search?q=term", "/search?q=term"),
            ("https://example.com/a?b=1&c=2", "/a?b=1&c=2"),
            ("https://example.com", "/"),
            ("https://example.com/", "/"),
            ("https://example.com?q=1", "/?q=1"),
            ("https://example.com/a?", "/a?"),
            ("https://example.com/a#frag", "/a"),
            ("https://example.com/a?q=1#frag", "/a?q=1"),
        ] {
            let uri = uri.parse::<Uri>().unwrap();
            // Call the trait method explicitly; `Uri::path` would shadow it.
            assert_eq!(RequestTarget::path(&&uri), path, "{uri}");
        }
    }

    #[test]
    fn tuple_path_is_verbatim() {
        assert_eq!(
            RequestTarget::path(&("https", "example.com", "/search?q=term")),
            "/search?q=term"
        );
    }
}
