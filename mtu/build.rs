// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

fn main() {
    cfg_aliases::cfg_aliases! {
        bsd: {
            any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "solaris"
            )
        },
        // Platforms that have no `interface_and_mtu_impl` and fall back to the
        // stub in `lib.rs`. They need none of the supporting machinery.
        unsupported: {
            any(
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "redox"
            )
        }
    }
}
