// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{collections::HashMap, env, fs, path::PathBuf, process::Command};

use bindgen::Builder;
use serde_derive::Deserialize;

const BINDINGS_DIR: &str = "bindings";
const BINDINGS_CONFIG: &str = "bindings.toml";

// This is the format of a single section of the configuration file.
#[derive(Deserialize)]
struct Bindings {
    /// types that are explicitly included
    #[serde(default)]
    types: Vec<String>,
    /// functions that are explicitly included
    #[serde(default)]
    functions: Vec<String>,
    /// variables (and `#define`s) that are explicitly included
    #[serde(default)]
    variables: Vec<String>,
    /// types that should be explicitly marked as opaque
    #[serde(default)]
    opaque: Vec<String>,
    /// enumerations that are turned into a module (without this, the enum is
    /// mapped using the default, which means that the individual values are
    /// formed with an underscore as <`enum_type`>_<`enum_value_name`>).
    #[serde(default)]
    enums: Vec<String>,

    /// Any item that is specifically excluded; if none of the types, functions,
    /// or variables fields are specified, everything defined will be mapped,
    /// so this can be used to limit that.
    #[serde(default)]
    exclude: Vec<String>,

    /// Whether the file is to be interpreted as C++
    #[serde(default)]
    cplusplus: bool,
}

// bindgen needs access to libclang.
// On windows, this doesn't just work, you have to set LIBCLANG_PATH.
// Rather than download the 400Mb+ files, like gecko does, let's just reuse their work.
fn setup_clang() {
    // If this isn't Windows, or we're in CI, then we don't need to do anything.
    if env::consts::OS != "windows" || env::var("GITHUB_WORKFLOW").unwrap() == "CI" {
        return;
    }
    println!("rerun-if-env-changed=LIBCLANG_PATH");
    println!("rerun-if-env-changed=MOZBUILD_STATE_PATH");
    if env::var("LIBCLANG_PATH").is_ok() {
        return;
    }
    let mozbuild_root = if let Ok(dir) = env::var("MOZBUILD_STATE_PATH") {
        PathBuf::from(dir.trim())
    } else {
        eprintln!("warning: Building without a gecko setup is not likely to work.");
        eprintln!("         A working libclang is needed to build neqo.");
        eprintln!("         Either LIBCLANG_PATH or MOZBUILD_STATE_PATH needs to be set.");
        eprintln!();
        eprintln!("    We recommend checking out https://github.com/mozilla/gecko-dev");
        eprintln!("    Then run `./mach bootstrap` which will retrieve clang.");
        eprintln!("    Make sure to export MOZBUILD_STATE_PATH when building.");
        return;
    };
    let libclang_dir = mozbuild_root.join("clang").join("lib");
    if libclang_dir.is_dir() {
        env::set_var("LIBCLANG_PATH", libclang_dir.to_str().unwrap());
        println!("rustc-env:LIBCLANG_PATH={}", libclang_dir.to_str().unwrap());
    } else {
        println!("warning: LIBCLANG_PATH isn't set; maybe run ./mach bootstrap with gecko");
    }
}

fn pkg_config() -> Vec<String> {
    let modversion = Command::new("pkg-config")
        .args(["--modversion", "nss"])
        .output()
        .expect("pkg-config reports NSS as absent")
        .stdout;
    let modversion_str = String::from_utf8(modversion).expect("non-UTF8 from pkg-config");
    let mut v = modversion_str.split('.');
    assert_eq!(
        v.next(),
        Some("3"),
        "NSS version 3.62 or higher is needed (or set $NSS_DIR)"
    );
    if let Some(minor) = v.next() {
        let minor = minor
            .trim_end()
            .parse::<u32>()
            .expect("NSS minor version is not a number");
        assert!(
            minor >= 62,
            "NSS version 3.62 or higher is needed (or set $NSS_DIR)",
        );
    }

    let cfg = Command::new("pkg-config")
        .args(["--cflags", "--libs", "nss"])
        .output()
        .expect("NSS flags not returned by pkg-config")
        .stdout;
    let cfg_str = String::from_utf8(cfg).expect("non-UTF8 from pkg-config");

    let mut flags: Vec<String> = Vec::new();
    for f in cfg_str.split(' ') {
        if let Some(include) = f.strip_prefix("-I") {
            flags.push(String::from(f));
            println!("cargo:include={include}");
        } else if let Some(path) = f.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        } else if let Some(lib) = f.strip_prefix("-l") {
            println!("cargo:rustc-link-lib=dylib={lib}");
        } else {
            println!("Warning: Unknown flag from pkg-config: {f}");
        }
    }

    flags
}

fn build_bindings(base: &str, bindings: &Bindings, flags: &[String], gecko: bool) {
    let suffix = if bindings.cplusplus { ".hpp" } else { ".h" };
    let header_path = PathBuf::from(BINDINGS_DIR).join(String::from(base) + suffix);
    let header = header_path.to_str().unwrap();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(String::from(base) + ".rs");

    println!("cargo:rerun-if-changed={header}");

    let mut builder = Builder::default().header(header);
    builder = builder.generate_comments(false);
    builder = builder.size_t_is_usize(true);

    builder = builder.clang_arg("-v");

    if !gecko {
        builder = builder.clang_arg("-DNO_NSPR_10_SUPPORT");
        if env::consts::OS == "windows" {
            builder = builder.clang_arg("-DWIN");
        } else if env::consts::OS == "macos" {
            builder = builder.clang_arg("-DDARWIN");
        } else if env::consts::OS == "linux" {
            builder = builder.clang_arg("-DLINUX");
        } else if env::consts::OS == "android" {
            builder = builder.clang_arg("-DLINUX");
            builder = builder.clang_arg("-DANDROID");
        }
        if bindings.cplusplus {
            builder = builder.clang_args(&["-x", "c++", "-std=c++14"]);
        }
    }

    builder = builder.clang_args(flags);

    // Apply the configuration.
    for v in &bindings.types {
        builder = builder.allowlist_type(v);
    }
    for v in &bindings.functions {
        builder = builder.allowlist_function(v);
    }
    for v in &bindings.variables {
        builder = builder.allowlist_var(v);
    }
    for v in &bindings.exclude {
        builder = builder.blocklist_item(v);
    }
    for v in &bindings.opaque {
        builder = builder.opaque_type(v);
    }
    for v in &bindings.enums {
        builder = builder.constified_enum_module(v);
    }

    let bindings = builder.generate().expect("unable to generate bindings");
    bindings
        .write_to_file(out)
        .expect("couldn't write bindings");
}

fn setup_standalone() -> Vec<String> {
    setup_clang();
    pkg_config()
}

#[cfg(feature = "gecko")]
fn setup_for_gecko() -> Vec<String> {
    use mozbuild::TOPOBJDIR;

    let fold_libs = mozbuild::config::MOZ_FOLD_LIBS;
    let libs = if fold_libs {
        vec!["nss3"]
    } else {
        vec!["nssutil3", "nss3", "ssl3", "plds4", "plc4", "nspr4"]
    };

    for lib in &libs {
        println!("cargo:rustc-link-lib=dylib={}", lib);
    }

    if fold_libs {
        println!(
            "cargo:rustc-link-search=native={}",
            TOPOBJDIR.join("security").to_str().unwrap()
        );
    } else {
        println!(
            "cargo:rustc-link-search=native={}",
            TOPOBJDIR.join("dist").join("bin").to_str().unwrap()
        );
        let nsslib_path = TOPOBJDIR.join("security").join("nss").join("lib");
        println!(
            "cargo:rustc-link-search=native={}",
            nsslib_path.join("nss").join("nss_nss3").to_str().unwrap()
        );
        println!(
            "cargo:rustc-link-search=native={}",
            nsslib_path.join("ssl").join("ssl_ssl3").to_str().unwrap()
        );
        println!(
            "cargo:rustc-link-search=native={}",
            TOPOBJDIR
                .join("config")
                .join("external")
                .join("nspr")
                .join("pr")
                .to_str()
                .unwrap()
        );
    }

    let flags_path = TOPOBJDIR.join("netwerk/socket/neqo/extra-bindgen-flags");

    println!("cargo:rerun-if-changed={}", flags_path.to_str().unwrap());
    let mut flags = fs::read_to_string(flags_path)
        .expect("Failed to read extra-bindgen-flags file")
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<_>>();

    flags.push(String::from("-include"));
    flags.push(
        TOPOBJDIR
            .join("dist")
            .join("include")
            .join("mozilla-config.h")
            .to_str()
            .unwrap()
            .to_string(),
    );
    flags
}

#[cfg(not(feature = "gecko"))]
fn setup_for_gecko() -> Vec<String> {
    unreachable!()
}

fn main() {
    let flags = if cfg!(feature = "gecko") {
        setup_for_gecko()
    } else {
        setup_standalone()
    };

    let config_file = PathBuf::from(BINDINGS_DIR).join(BINDINGS_CONFIG);
    println!("cargo:rerun-if-changed={}", config_file.to_str().unwrap());
    let config = fs::read_to_string(config_file).expect("unable to read binding configuration");
    let config: HashMap<String, Bindings> = ::toml::from_str(&config).unwrap();

    for (k, v) in &config {
        build_bindings(k, v, &flags[..], cfg!(feature = "gecko"));
    }
}
