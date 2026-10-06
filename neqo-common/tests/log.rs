// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use tracing::{debug, error, info, trace, warn};

#[test]
fn basic() {
    neqo_common::log::init(None);
    error!("error");
    warn!("warn");
    info!("info");
    debug!("debug");
    trace!("trace");
}

#[test]
fn args() {
    neqo_common::log::init(None);
    let num = 1;
    let obj = test_fixture::now();
    error!("error {num} {obj:?}");
    warn!("warn {num} {obj:?}");
    info!("info {num} {obj:?}");
    debug!("debug {num} {obj:?}");
    trace!("trace {num} {obj:?}");
}
