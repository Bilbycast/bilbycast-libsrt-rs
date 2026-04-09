// Copyright (c) 2026 Reza Rahimi / Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Build script for libsrt-sys.
//!
//! Default: compile vendored libsrt v1.5.5-rc.2 from `vendor/srt/` via CMake.
//! Override: set `LIBSRT_DIR` env var to point to a pre-built libsrt install.
//! Override: enable `system-libsrt` feature to use pkg-config.

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Determine include path and link instructions
    let include_path = if let Ok(libsrt_dir) = env::var("LIBSRT_DIR") {
        // User-specified libsrt install
        let libsrt_path = PathBuf::from(&libsrt_dir);
        println!(
            "cargo:rustc-link-search=native={}",
            libsrt_path.join("lib").display()
        );
        println!("cargo:rustc-link-lib=static=srt");
        link_crypto_deps();
        libsrt_path.join("include")
    } else if cfg!(feature = "system-libsrt") {
        // System libsrt via pkg-config
        let lib = pkg_config::Config::new()
            .atleast_version("1.5.2")
            .probe("srt")
            .expect("pkg-config: libsrt >= 1.5.2 not found. Install libsrt-openssl-dev or set LIBSRT_DIR");
        PathBuf::from(lib.include_paths.first().expect("no include path from pkg-config"))
    } else {
        // Vendored build via CMake (default)
        build_vendored(&out_dir)
    };

    // Generate Rust bindings via bindgen
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", include_path.display()))
        .clang_arg("-DENABLE_AEAD_API_PREVIEW")
        .clang_arg("-DENABLE_BONDING")
        .allowlist_function("srt_.*")
        .allowlist_type("SRT_.*")
        .allowlist_type("SRTS_.*")
        .allowlist_type("CBytePerfMon")
        .allowlist_type("SRT_TRACEBSTATS")
        .allowlist_type("SRT_SOCKGROUPCONFIG")
        .allowlist_type("SRT_SOCKGROUPDATA")
        .allowlist_type("SRT_MSGCTRL")
        .allowlist_var("SRTO_.*")
        .allowlist_var("SRT_.*")
        .allowlist_var("SRTS_.*")
        .allowlist_var("SRTT_.*")
        .derive_debug(true)
        .derive_copy(true)
        .derive_default(true)
        .generate()
        .expect("bindgen failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}

/// Build libsrt from vendored source using CMake.
fn build_vendored(out_dir: &PathBuf) -> PathBuf {
    let srt_source = PathBuf::from("vendor/srt");
    if !srt_source.exists() {
        panic!(
            "Vendored libsrt source not found at {}. \
             Clone it with: git submodule update --init, \
             or set LIBSRT_DIR to a pre-built install, \
             or enable the system-libsrt feature.",
            srt_source.display()
        );
    }

    let dst = cmake::Config::new(&srt_source)
        .define("ENABLE_SHARED", "OFF")
        .define("ENABLE_APPS", "OFF")
        .define("ENABLE_TESTING", "OFF")
        .define("ENABLE_BONDING", "ON")
        .define("ENABLE_ENCRYPTION", "ON")
        .define("ENABLE_AEAD_API_PREVIEW", "ON")
        .define("USE_ENCLIB", "openssl-evp")
        .define("CMAKE_INSTALL_PREFIX", out_dir.to_str().unwrap())
        .build();

    let lib_dir = dst.join("lib");
    // Some systems use lib64
    let lib_dir = if lib_dir.exists() {
        lib_dir
    } else {
        dst.join("lib64")
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=srt");
    link_crypto_deps();

    dst.join("include")
}

/// Link OpenSSL and system dependencies required by libsrt.
fn link_crypto_deps() {
    // OpenSSL
    if let Ok(lib) = pkg_config::probe_library("openssl") {
        for path in &lib.link_paths {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
    } else {
        // Fallback: try common locations
        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
    }

    // Platform-specific deps
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=stdc++");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=c++");
        }
        _ => {}
    }
}
