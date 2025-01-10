// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use clap::Parser as _;

#[tokio::main]
async fn main() -> Result<(), neqo_bin::client::Error> {
    let args = neqo_bin::client::Args::parse();

    neqo_bin::client::client(args).await
}
