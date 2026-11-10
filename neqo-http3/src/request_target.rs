// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::Debug;

use http::Uri as Url;

pub trait RequestTarget: Debug {
    fn scheme(&self) -> &str;
    fn authority(&self) -> &str;
    /// The value of the `:path` pseudo-header field.
    ///
    /// Not named `path`, so that [`Url::path`], which excludes the query,
    /// cannot shadow it when called on a concrete `&Url`.
    fn request_path(&self) -> String;
}

impl RequestTarget for &Url {
    fn scheme(&self) -> &str {
        self.scheme_str().unwrap_or("")
    }

    fn authority(&self) -> &str {
        Url::authority(self).map_or("", |a| a.as_str())
    }

    /// The path and query of the target, without any fragment.
    fn request_path(&self) -> String {
        // Unlike `PathAndQuery::as_str`, the `Display` implementation adds the
        // leading `/` for targets like `https://example.com?q`.
        self.path_and_query()
            .map_or_else(String::new, ToString::to_string)
    }
}

impl<'s, 'a> RequestTarget for (&'s str, &'a str, &str) {
    fn scheme(&self) -> &'s str {
        self.0
    }

    fn authority(&self) -> &'a str {
        self.1
    }

    /// The path verbatim; the caller is responsible for its form.
    fn request_path(&self) -> String {
        self.2.to_owned()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use http::Uri;

    use super::RequestTarget as _;

    #[test]
    fn uri_request_path_includes_query() {
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
            assert_eq!((&uri).request_path(), path, "{uri}");
        }
    }

    #[test]
    fn tuple_request_path_is_verbatim() {
        assert_eq!(
            ("https", "example.com", "/search?q=term").request_path(),
            "/search?q=term"
        );
    }
}
