use bindgen::Builder;
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use toml;

const BINDINGS_DIR: &'static str = "bindings";
const BINDINGS_CONFIG: &'static str = "bindings.toml";

// This is the format of a single section of the configuration file.
#[derive(Deserialize)]
struct Bindings {
    // types that are explicitly included
    types: Option<Vec<String>>,
    // functions that are explicitly included
    functions: Option<Vec<String>>,
    // variables (and `#define`s) that are explicitly included
    variables: Option<Vec<String>>,
    // types that should be explicitly marked as opaque
    opaque: Option<Vec<String>>,
    // enumerations that are turned into a module (without this, the enum is
    // mapped using the default, which means that the individual values are
    // formed with an underscore as <enum_type>_<enum_value_name>).
    enums: Option<Vec<String>>,

    // Any item that is specifically excluded; if none of the types, functions,
    // or variables fields are specified, everything defined will be mapped,
    // so this can be used to limit that.
    exclude: Option<Vec<String>>,
}

fn is_debug() -> bool {
    match env::var("DEBUG") {
        Ok(d) => d.parse::<bool>().unwrap(),
        Err(_) => false,
    }
}

fn nss_dir() -> PathBuf {
    let dir = match env::var("NSS_DIR") {
        Ok(dir) => PathBuf::from(dir.trim()),
        Err(_) => {
            let out_dir = env::var("OUT_DIR").unwrap();
            let dir = Path::new(&out_dir).join("nss");
            if !dir.exists() {
                Command::new("hg")
                    .args(&[
                        "clone",
                        "https://hg.mozilla.org/projects/nss",
                        dir.to_str().unwrap(),
                    ])
                    .status()
                    .expect("can't clone nss");
            }
            let nspr_dir = Path::new(&out_dir).join("nspr");
            if !nspr_dir.exists() {
                Command::new("hg")
                    .args(&[
                        "clone",
                        "https://hg.mozilla.org/projects/nspr",
                        nspr_dir.to_str().unwrap(),
                    ])
                    .status()
                    .expect("can't clone nspr");
            }
            dir.to_path_buf()
        }
    };
    assert!(dir.is_dir());
    // Note that this returns a relative path because UNC
    // paths on windows cause certain tools to explode.
    dir
}

fn static_link() {
    // This is kludgy.
    let debug_dir = nss_dir().join("out").join("Debug");
    println!("cargo:rustc-link-search={}", debug_dir.to_str().unwrap());
    for lib in &[
        "certdb",
        "certhi",
        "cryptohi",
        "dbm",
        "freebl",
        "nss_static",
        "nssb",
        "nssdev",
        "nsspki",
        "nssutil",
        "pk11wrap",
        "pkcs12",
        "pkcs7",
        "smime",
        "softokn_static",
        "ssl",
    ] {
        println!("cargo:rustc-link-lib=static={}", lib);
    }

    for lib in &[
        "sqlite3", "pthread", "dl", "c", "z", "plds4", "plc4", "nspr4",
    ] {
        println!("cargo:rustc-link-lib={}", lib);
    }
}

fn build_bindings(base: &str, bindings: &Bindings, includes: &[&Path]) {
    let header = String::from(BINDINGS_DIR) + "/" + base + ".h";
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(String::from(base) + ".rs");

    println!("cargo:rerun-if-changed={}", header);

    let mut builder = Builder::default().header(header).generate_comments(false);

    for i in includes {
        builder = builder.clang_arg(String::from("-I") + i.to_str().unwrap());
    }

    // Apply the configuration.
    let empty: Vec<String> = vec![];
    for v in bindings.types.as_ref().unwrap_or_else(|| &empty).iter() {
        builder = builder.whitelist_type(v);
    }
    for v in bindings.functions.as_ref().unwrap_or_else(|| &empty).iter() {
        builder = builder.whitelist_function(v);
    }
    for v in bindings.variables.as_ref().unwrap_or_else(|| &empty).iter() {
        builder = builder.whitelist_var(v);
    }
    for v in bindings.exclude.as_ref().unwrap_or_else(|| &empty).iter() {
        builder = builder.blacklist_item(v);
    }
    for v in bindings.opaque.as_ref().unwrap_or_else(|| &empty).iter() {
        builder = builder.opaque_type(v);
        // .raw_line(String::from("pub enum ") + v + "{}");
    }
    for v in bindings.enums.as_ref().unwrap_or_else(|| &empty).iter() {
        builder = builder.constified_enum_module(v);
    }

    let bindings = builder.generate().expect("unable to generate bindings");
    bindings
        .write_to_file(out)
        .expect("couldn't write bindings");
}

fn main() {
    println!("cargo:rerun-if-env-changed=NSS_DIR");
    let nss = nss_dir();
    let mut build_nss = vec!["-c", "./build.sh"];
    if is_debug() {
        build_nss.push("--test");
    }
    Command::new("bash")
        .args(build_nss)
        .current_dir(nss.clone())
        .status()
        .expect("NSS build failed");

    // $NSS_DIR/../dist/
    let nssdist = nss.parent().unwrap().join("dist").canonicalize().unwrap();
    println!("cargo:rerun-if-env-changed=NSS_TARGET");
    let nsstarget = env::var("NSS_TARGET")
        .unwrap_or_else(|_| fs::read_to_string(nssdist.join("latest")).unwrap());
    let nsstarget = nssdist.join(nsstarget.trim());

    let nsprinclude = nsstarget.join("include").join("nspr");
    let nssinclude = nssdist.join("public").join("nss");
    let includes = vec![nsprinclude.as_path(), nssinclude.as_path()];
    for i in &includes {
        println!("cargo:include={}", i.to_str().unwrap());
    }

    let nsslibdir = nsstarget.join("lib");
    println!(
        "cargo:rustc-link-search=native={}",
        nsslibdir.to_str().unwrap()
    );

    if is_debug() {
        static_link();
    } else {
        println!("cargo:rustc-link-lib=nspr4");
        println!("cargo:rustc-link-lib=nss3");
        println!("cargo:rustc-link-lib=ssl3");
    }

    let config_file = PathBuf::from(BINDINGS_DIR).join(BINDINGS_CONFIG);
    println!("cargo:rerun-if-changed={}", config_file.to_str().unwrap());
    let config = fs::read_to_string(config_file).expect("unable to read binding configuration");
    let config: HashMap<String, Bindings> = toml::from_str(&config).unwrap();

    for (k, v) in &config {
        build_bindings(k, v, &includes[..]);
    }
}
