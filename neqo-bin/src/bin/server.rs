// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use clap::Parser as _;
use neqo_bin::server::{http09, http3, Res};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Res<()> {
    let mut args = neqo_bin::server::Args::parse();

    args.update_for_tests();

    if args.get_shared().get_alpn() == "h3" {
        neqo_bin::server::server::<http3::HttpServer>(args)?
            .run()
            .await
    } else {
        neqo_bin::server::server::<http09::HttpServer>(args)?
            .run()
            .await
    }
}
