// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use clap::Parser as _;
use neqo_bin::server::Res;

#[tokio::main(flavor = "current_thread")]
#[allow(
    clippy::allow_attributes,
    clippy::unwrap_in_result,
    reason = "FIXME: False positive?"
)]
async fn main() -> Res<()> {
    let args = neqo_bin::server::Args::parse();

    neqo_bin::server::run(args)?.0.await
}
