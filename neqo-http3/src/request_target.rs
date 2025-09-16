// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::Debug;

use url::Url;

pub trait RequestTarget: Debug {
    fn scheme(&self) -> &str;
    fn authority(&self) -> &str;
    fn path(&self) -> &str;
}

impl RequestTarget for &Url {
    fn scheme(&self) -> &str {
        Url::scheme(self)
    }

    fn authority(&self) -> &str {
        self.host_str().unwrap_or("")
    }

    fn path(&self) -> &str {
        Url::path(self)
    }
}

impl<'s, 'a, 'p> RequestTarget for (&'s str, &'a str, &'p str) {
    fn scheme(&self) -> &'s str {
        self.0
    }

    fn authority(&self) -> &'a str {
        self.1
    }

    fn path(&self) -> &'p str {
        self.2
    }
}
