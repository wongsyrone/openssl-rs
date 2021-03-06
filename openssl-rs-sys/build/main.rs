#![allow(clippy::inconsistent_digit_grouping, clippy::unusual_byte_groupings)]

extern crate autocfg;
extern crate cc;
#[cfg(feature = "vendored")]
extern crate openssl_src;
extern crate pkg_config;
#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

mod cfgs;

mod find_normal;
#[cfg(feature = "vendored")]
mod find_vendored;

enum Version {
    Openssl11x,
    Openssl30x,
}

fn env_inner(name: &str) -> Option<OsString> {
    let var = env::var_os(name);
    println!("cargo:rerun-if-env-changed={}", name);

    match var {
        Some(ref v) => println!("{} = {}", name, v.to_string_lossy()),
        None => println!("{} unset", name),
    }

    var
}

fn env(name: &str) -> Option<OsString> {
    let prefix = env::var("TARGET").unwrap().to_uppercase().replace("-", "_");
    let prefixed = format!("{}_{}", prefix, name);
    env_inner(&prefixed).or_else(|| env_inner(name))
}

fn find_openssl(target: &str) -> (PathBuf, PathBuf) {
    #[cfg(feature = "vendored")]
    {
        // vendor if the feature is present, unless
        // OPENSSL_NO_VENDOR exists and isn't `0`
        if env("OPENSSL_NO_VENDOR").map_or(true, |s| s == "0") {
            return find_vendored::get_openssl(target);
        }
    }
    find_normal::get_openssl(target)
}

fn main() {
    check_rustc_versions();

    let target = env::var("TARGET").unwrap();

    let (lib_dir, include_dir) = find_openssl(&target);

    if !Path::new(&lib_dir).exists() {
        panic!(
            "OpenSSL library directory does not exist: {}",
            lib_dir.to_string_lossy()
        );
    }
    if !Path::new(&include_dir).exists() {
        panic!(
            "OpenSSL include directory does not exist: {}",
            include_dir.to_string_lossy()
        );
    }

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir.to_string_lossy()
    );
    println!("cargo:include={}", include_dir.to_string_lossy());

    let version = validate_headers(&[include_dir]);

    let libs_env = env("OPENSSL_LIBS");
    let libs = match libs_env.as_ref().and_then(|s| s.to_str()) {
        Some(v) => {
            if v.is_empty() {
                vec![]
            } else {
                v.split(':').collect()
            }
        }
        None => match version {
            Version::Openssl11x if target.contains("windows-msvc") => vec!["libssl", "libcrypto"],
            _ => vec!["ssl", "crypto"],
        },
    };

    let kind = determine_mode(Path::new(&lib_dir), &libs);
    for lib in libs.into_iter() {
        println!("cargo:rustc-link-lib={}={}", kind, lib);
    }

    if kind == "static" && target.contains("windows") {
        println!("cargo:rustc-link-lib=dylib=gdi32");
        println!("cargo:rustc-link-lib=dylib=user32");
        println!("cargo:rustc-link-lib=dylib=crypt32");
        println!("cargo:rustc-link-lib=dylib=ws2_32");
        println!("cargo:rustc-link-lib=dylib=advapi32");
    }
}

fn check_rustc_versions() {
    let cfg = autocfg::new();

    if cfg.probe_rustc_version(1, 31) {
        println!("cargo:rustc-cfg=const_fn");
    }
}

/// Validates the header files found in `include_dir` and then returns the
/// version string of OpenSSL.
#[allow(clippy::manual_strip)] // we need to support pre-1.45.0
fn validate_headers(include_dirs: &[PathBuf]) -> Version {
    // This `*-sys` crate only works with OpenSSL 1.0.1, 1.0.2, and 1.1.0. To
    // correctly expose the right API from this crate, take a look at
    // `opensslv.h` to see what version OpenSSL claims to be.
    //
    // OpenSSL has a number of build-time configuration options which affect
    // various structs and such. Since OpenSSL 1.1.0 this isn't really a problem
    // as the library is much more FFI-friendly, but 1.0.{1,2} suffer this problem.
    //
    // To handle all this conditional compilation we slurp up the configuration
    // file of OpenSSL, `opensslconf.h`, and then dump out everything it defines
    // as our own #[cfg] directives. That way the `ossl10x.rs` bindings can
    // account for compile differences and such.
    let mut gcc = cc::Build::new();
    for include_dir in include_dirs {
        gcc.include(include_dir);
    }
    let expanded = match gcc.file("build/expando.c").try_expand() {
        Ok(expanded) => expanded,
        Err(e) => {
            panic!(
                "
Header expansion error:
{:?}

Failed to find OpenSSL development headers.

You can try fixing this setting the `OPENSSL_DIR` environment variable
pointing to your OpenSSL installation or installing OpenSSL headers package
specific to your distribution:

    # On Ubuntu
    sudo apt-get install libssl-dev
    # On Arch Linux
    sudo pacman -S openssl
    # On Fedora
    sudo dnf install openssl-devel
",
                e
            );
        }
    };
    let expanded = String::from_utf8(expanded).unwrap();

    let mut enabled = vec![];
    let mut openssl_version = None;
    for line in expanded.lines() {
        let line = line.trim();

        let openssl_prefix = "RUST_VERSION_OPENSSL_";
        let new_openssl_prefix = "RUST_VERSION_NEW_OPENSSL_";
        let conf_prefix = "RUST_CONF_";
        if line.starts_with(openssl_prefix) {
            let version = &line[openssl_prefix.len()..];
            openssl_version = Some(parse_version(version));
        } else if line.starts_with(new_openssl_prefix) {
            let version = &line[new_openssl_prefix.len()..];
            openssl_version = Some(parse_new_version(version));
        } else if line.starts_with(conf_prefix) {
            enabled.push(&line[conf_prefix.len()..]);
        }
    }

    for enabled in &enabled {
        println!("cargo:rustc-cfg=osslconf=\"{}\"", enabled);
    }
    println!("cargo:conf={}", enabled.join(","));

    for cfg in cfgs::get(openssl_version) {
        println!("cargo:rustc-cfg={}", cfg);
    }

    let openssl_version = openssl_version.unwrap();
    println!("cargo:version_number={:x}", openssl_version);

    if openssl_version >= 0x4_00_00_00_0 {
        version_error()
    } else if openssl_version >= 0x3_00_00_00_0 {
        println!("cargo:version=300");
        Version::Openssl30x
    } else if openssl_version >= 0x1_01_01_00_0 {
        println!("cargo:version=111");
        Version::Openssl11x
    } else {
        version_error()
    }
}

fn version_error() -> ! {
    panic!(
        "

This crate is only compatible with OpenSSL 1.1.1 or OpenSSL 3.x,
but a different version of OpenSSL was found. The build is now aborting
due to this version mismatch.

"
    );
}

// parses a string that looks like "0x100020cfL"
#[allow(deprecated)] // trim_right_matches is now trim_end_matches
#[allow(clippy::match_like_matches_macro)] // matches macro requires rust 1.42.0
fn parse_version(version: &str) -> u64 {
    // cut off the 0x prefix
    assert!(version.starts_with("0x"));
    let version = &version[2..];

    // and the type specifier suffix
    let version = version.trim_right_matches(|c: char| match c {
        '0'..='9' | 'a'..='f' | 'A'..='F' => false,
        _ => true,
    });

    u64::from_str_radix(version, 16).unwrap()
}

// parses a string that looks like 3_0_0
fn parse_new_version(version: &str) -> u64 {
    println!("version: {}", version);
    let mut it = version.split('_');
    let major = it.next().unwrap().parse::<u64>().unwrap();
    let minor = it.next().unwrap().parse::<u64>().unwrap();
    let patch = it.next().unwrap().parse::<u64>().unwrap();

    (major << 28) | (minor << 20) | (patch << 4)
}

/// Given a libdir for OpenSSL (where artifacts are located) as well as the name
/// of the libraries we're linking to, figure out whether we should link them
/// statically or dynamically.
fn determine_mode(libdir: &Path, libs: &[&str]) -> &'static str {
    // First see if a mode was explicitly requested
    let kind = env("OPENSSL_STATIC");
    match kind.as_ref().and_then(|s| s.to_str()) {
        Some("0") => return "dylib",
        Some(_) => return "static",
        None => {}
    }

    // Next, see what files we actually have to link against, and see what our
    // possibilities even are.
    let files = libdir
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| e.file_name())
        .filter_map(|e| e.into_string().ok())
        .collect::<HashSet<_>>();
    let can_static = libs.iter().all(|l| {
        files.contains(&format!("lib{}.a", l))
            || files.contains(&format!("{}.lib", l))
            || files.contains(&format!("lib{}.lib", l))
    });
    let can_dylib = libs.iter().all(|l| {
        files.contains(&format!("lib{}.so", l))
            || files.contains(&format!("{}.dll", l))
            || files.contains(&format!("lib{}.dll", l))
            || files.contains(&format!("lib{}.dylib", l))
    });
    match (can_static, can_dylib) {
        (true, false) => return "static",
        (false, true) => return "dylib",
        (false, false) => {
            panic!(
                "OpenSSL libdir at `{}` does not contain the required files \
                 to either statically or dynamically link OpenSSL",
                libdir.display()
            );
        }
        (true, true) => {}
    }

    // Ok, we've got not explicit preference and can *either* link statically or
    // link dynamically. In the interest of "security upgrades" and/or "best
    // practices with security libs", let's link dynamically.
    "dylib"
}
