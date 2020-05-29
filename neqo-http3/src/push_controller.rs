// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, Res};
use neqo_common::qtrace;
use std::fmt::Debug;
use std::fmt::Display;

#[derive(Debug)]
pub(crate) struct PushController {
    max_concurent_push_streams: u64,
}

impl PushController {
    pub fn new(max_concurent_push_streams: u64) -> Self {
        PushController {
            max_concurent_push_streams,
        }
    }
}

impl Display for PushController {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Push controler")
    }
}

impl PushController {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new_push_promise(&self, push_id: u64, header_block: Vec<u8>) -> Res<()> {
        qtrace!(
            [self],
            "New push promise push_id={} header_block={:?} max_push={}",
            push_id,
            header_block,
            self.max_concurent_push_streams
        );
        qtrace!("A new push promise {} {:?}", push_id, header_block);
        Err(Error::HttpId)
    }
}
