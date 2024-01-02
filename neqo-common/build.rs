use cfg_aliases::cfg_aliases;
use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    if target.contains("windows") {
        println!("cargo:rustc-link-lib=winmm");
    }

    cfg_aliases! {
        posix_socket: { any(target_os = "macos", target_os = "linux", target_os = "android") },
    }
}
