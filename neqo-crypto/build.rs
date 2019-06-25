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
        _ => false,
    }
}

// bindgen needs access to libclang.
// On windows, this doesn't just work, you have to set LIBCLANG_PATH.
// Rather than download the 400Mb+ files, like gecko does, let's just reuse their work.
fn setup_clang() {
    match env::var("LIBCLANG_PATH") {
        Ok(_) => return,
        _ => {}
    };
    let mozbuild_root = match env::var("MOZBUILD_STATE_PATH") {
        Ok(dir) => PathBuf::from(dir.trim()),
        _ => {
            if env::consts::OS == "windows" {
                eprintln!("warning: Building without a gecko setup is not likely to work.");
                eprintln!("         A working libclang is needed to build neqo.");
                eprintln!("         Either LIBCLANG_PATH or MOZBUILD_STATE_PATH needs to be set.");
                eprintln!("");
                eprintln!("    We recommend checking out https://github.com/mozilla/gecko-dev");
                eprintln!("    Then run `./mach bootstrap` which will retrieve clang.");
                eprintln!("    Make sure to export MOZBUILD_STATE_PATH when building.");
            }
            return;
        }
    };
    let libclang_dir = mozbuild_root.join("clang").join("lib");
    if libclang_dir.is_dir() {
        env::set_var("LIBCLANG_PATH", libclang_dir.to_str().unwrap());
        println!("env:LIBCLANG_PATH={}", libclang_dir.to_str().unwrap());
    } else {
        println!("warning: LIBCLANG_PATH isn't set; maybe run ./mach bootstrap with gecko");
    }
}

fn nss_dir() -> PathBuf {
    let dir = match env::var("NSS_DIR") {
        Ok(dir) => PathBuf::from(dir.trim()),
        _ => {
            let out_dir = env::var("OUT_DIR").unwrap();
            let dir = Path::new(&out_dir).join("nss");
            if !dir.exists() {
                Command::new("hg")
                    .args(&[
                        "clone",
                        "-r", // TODO(mt) use the real repo when these patches land
                        "c92be7ed922a0781973ccc69356d797cb1507b6f",
                        "https://hg.mozilla.org/projects/nss-try",
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

fn get_bash() -> PathBuf {
    // When running under MOZILLABUILD, we need to make sure not to invoke
    // another instance of bash that might be sitting around (like WSL).
    match env::var("MOZILLABUILD") {
        Ok(d) => PathBuf::from(d).join("msys").join("bin").join("bash.exe"),
        _ => PathBuf::from("bash"),
    }
}

fn build_nss(dir: PathBuf) {
    let mut build_nss = vec![String::from("./build.sh")];
    if is_debug() {
        build_nss.push(String::from("--static"));
    } else {
        build_nss.push(String::from("-o"));
    }
    match env::var("NSS_JOBS") {
        Ok(d) => {
            build_nss.push(String::from("-j"));
            build_nss.push(d);
        }
        _ => (),
    }
    Command::new(get_bash())
        .args(build_nss)
        .current_dir(dir)
        .status()
        .expect("NSS build failed");
}

fn static_link(nsstarget: &PathBuf) {
    let lib_dir = nsstarget.join("lib");
    println!("cargo:rustc-link-search={}", lib_dir.to_str().unwrap());
    let mut static_libs = vec![
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
    ];
    if env::consts::OS != "macos" {
        static_libs.push("sqlite");
    }
    for lib in static_libs {
        println!("cargo:rustc-link-lib=static={}", lib);
    }

    let mut other_libs = if env::consts::OS == "windows" {
        vec!["libplds4", "libplc4", "libnspr4"]
    } else {
        vec!["pthread", "dl", "c", "z", "plds4", "plc4", "nspr4"]
    };
    if env::consts::OS == "macos" {
        other_libs.push("sqlite3");
    }
    for lib in other_libs {
        println!("cargo:rustc-link-lib={}", lib);
    }
}

fn get_includes(nsstarget: &Path, nssdist: &Path) -> Vec<PathBuf> {
    let nsprinclude = nsstarget.join("include").join("nspr");
    let nssinclude = nssdist.join("public").join("nss");
    let includes = vec![nsprinclude, nssinclude];
    for i in &includes {
        println!("cargo:include={}", i.to_str().unwrap());
    }
    includes
}

fn build_bindings(base: &str, bindings: &Bindings, includes: &[PathBuf]) {
    let header_path = PathBuf::from(BINDINGS_DIR).join(String::from(base) + ".h");
    let header = header_path.to_str().unwrap();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(String::from(base) + ".rs");

    println!("cargo:rerun-if-changed={}", header);

    let mut builder = Builder::default().header(header).generate_comments(false);

    builder = builder.clang_arg(String::from("-v"));
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
    setup_clang();

    println!("cargo:rerun-if-env-changed=NSS_DIR");
    let nss = nss_dir();
    build_nss(nss.clone());

    // $NSS_DIR/../dist/
    let nssdist = nss.parent().unwrap().join("dist");
    println!("cargo:rerun-if-env-changed=NSS_TARGET");
    let nsstarget = env::var("NSS_TARGET")
        .unwrap_or_else(|_| fs::read_to_string(nssdist.join("latest")).unwrap());
    let nsstarget = nssdist.join(nsstarget.trim());

    let includes = get_includes(&nsstarget, &nssdist);

    let nsslibdir = nsstarget.join("lib");
    println!(
        "cargo:rustc-link-search=native={}",
        nsslibdir.to_str().unwrap()
    );

    if is_debug() {
        static_link(&nsstarget);
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
