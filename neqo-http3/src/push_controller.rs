// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, Res};
use neqo_common::qtrace;
use std::fmt::Debug;

#[derive(Debug)]
pub(crate) struct PushController {}

impl PushController {
    pub fn new() -> Self {
        PushController {}
    }
}

impl PushController {
    pub fn new_push_promise(&self, push_id: u64, header_block: Vec<u8>) -> Res<()> {
        qtrace!("A new push promise {} {:?}", push_id, header_block);
        Err(Error::HttpId)
    }

    pub fn new_duplicate_push(&self, push_id: u64) -> Res<()> {
        qtrace!("A new duplicate push {}", push_id);
        Err(Error::HttpId)
    }
}
