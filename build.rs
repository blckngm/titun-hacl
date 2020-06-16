#![allow(non_upper_case_globals)]

use std::path::{Path, PathBuf};
use std::io::Write;

static vec256_sources: &[&str] = &[
    "Hacl_Chacha20_Vec256.c",
    "Hacl_Curve25519_64_Slow.c",
    "Hacl_Chacha20Poly1305_256.c",
    "Hacl_Poly1305_256.c",
    "Hacl_Curve25519_64.c",
];

static vec128_sources: &[&str] = &[
    "Hacl_Poly1305_128.c",
    "Hacl_Chacha20Poly1305_128.c",
    "Hacl_Chacha20_Vec128.c",
];

static x86_64_linux_asm_sources: &[&str] = &[
    "sha256-x86_64-linux.S",
    "poly1305-x86_64-linux.S",
    "aesgcm-x86_64-linux.S",
    "aes-x86_64-linux.S",
    "curve25519-x86_64-linux.S",
    "cpuid-x86_64-linux.S",
    "oldaesgcm-x86_64-linux.S",
];

static x86_64_mingw_asm_sources: &[&str] = &[
    "sha256-x86_64-mingw.S",
    "poly1305-x86_64-mingw.S",
    "aesgcm-x86_64-mingw.S",
    "aes-x86_64-mingw.S",
    "curve25519-x86_64-mingw.S",
    "cpuid-x86_64-mingw.S",
    "oldaesgcm-x86_64-mingw.S",
];

static x86_64_darwin_asm_sources: &[&str] = &[
    "sha256-x86_64-darwin.S",
    "poly1305-x86_64-darwin.S",
    "aesgcm-x86_64-darwin.S",
    "aes-x86_64-darwin.S",
    "curve25519-x86_64-darwin.S",
    "cpuid-x86_64-darwin.S",
    "oldaesgcm-x86_64-darwin.S",
];

static x86_64_msvc_asm_sources: &[&str] = &[
    "aesgcm-x86_64-msvc.asm",
    "aes-x86_64-msvc.asm",
    "cpuid-x86_64-msvc.asm",
    "curve25519-x86_64-msvc.asm",
    "oldaesgcm-x86_64-msvc.asm",
    "poly1305-x86_64-msvc.asm",
    "sha256-x86_64-msvc.asm",
];

static i686_msvc_asm_sources: &[&str] = &["aes-i686.asm"];

static evercrypt_sources: &[&str] = &[
    "EverCrypt_Error.c",
    "EverCrypt_Ed25519.c",
    "EverCrypt_Vale.c",
    "EverCrypt_DRBG.c",
    "EverCrypt_AEAD.c",
    "EverCrypt_Chacha20Poly1305.c",
    "EverCrypt_Curve25519.c",
    "EverCrypt_AutoConfig2.c",
    "EverCrypt_HMAC.c",
    "EverCrypt_Hash.c",
    "EverCrypt_Poly1305.c",
    "EverCrypt_StaticConfig.c",
    // "evercrypt_vale_stubs.c",
    "EverCrypt_HKDF.c",
];

static hacl_sources: &[&str] = &[
    "Hacl_Salsa20.c",
    "Hacl_Hash.c",
    "Lib_PrintBuffer.c",
    "Lib_Memzero0.c",
    "Hacl_Poly1305_32.c",
    "Hacl_SHA3.c",
    "MerkleTree.c",
    "Hacl_Ed25519.c",
    "Lib_Memzero.c",
    "Hacl_NaCl.c",
    "Lib_RandomBuffer_System.c",
    "Vale.c",
    "Hacl_HMAC.c",
    "Hacl_Spec.c",
    "Hacl_HMAC_DRBG.c",
    "Hacl_Curve25519_51.c",
    "Hacl_Frodo_KEM.c",
    "Hacl_HKDF.c",
    "Hacl_AES.c",
    "Hacl_Chacha20Poly1305_32.c",
    "Hacl_Kremlib.c",
    "Hacl_Chacha20_Vec32.c",
    "Hacl_Chacha20.c",
];

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_pointer_width = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
    let out_dir = std::env::var_os("OUT_DIR").unwrap();

    let distro = if env == "msvc" {
        "hacl-star-dist/msvc-compatible"
    } else {
        "hacl-star-dist/gcc-compatible"
    };

    fn map_sources(
        distro: &'static str,
        sources: &'static [&'static str],
    ) -> impl Iterator<Item = PathBuf> {
        sources.into_iter().map(move |s| Path::new(distro).join(s))
    }

    let asm = match &*os {
        "windows" if env == "msvc" => "msvc",
        "windows" => "mingw",
        "linux" | "android" => "linux",
        "macos" | "ios" | "freebsd" | "dragonfly" | "openbsd" | "netbsd" => "darwin",
        os => panic!("Unsupported target OS: {}", os),
    };

    let asm_sources = match (asm, &*arch) {
        ("linux", "x86_64") => x86_64_linux_asm_sources,
        ("mingw", "x86_64") => x86_64_mingw_asm_sources,
        ("darwin", "x86_64") => x86_64_darwin_asm_sources,
        ("msvc", "x86_64") => x86_64_msvc_asm_sources,
        ("msvc", "x86") => i686_msvc_asm_sources,
        _ => &[],
    };

    let build_vec256 = arch == "x86_64";
    let build_vec128 = build_vec256 || arch == "aarch64";

    // Generate config.h
    let mut config_h = std::fs::File::create(Path::new(&out_dir).join("config.h")).unwrap();
    if arch == "aarch64" {
        config_h.write_all(b"#define IS_ARM_8 1\n").unwrap();
    } else if arch == "arm" {
        config_h.write_all(b"#define IS_ARM_7 1\n").unwrap();
    }
    if arch != "x86_64" {
        // XXX: What's this for?
        config_h.write_all(b"#define BROKEN_INTRINSICS 1\n").unwrap();
        config_h.write_all(b"#define IS_NOT_X64 1\n").unwrap();
    }
    config_h.write_all(b"#define LINUX_NO_EXPLICIT_BZERO 1").unwrap();
    config_h.flush().unwrap();
    drop(config_h);

    let build_common = {
        let mut build = cc::Build::new();
        build.flag_if_supported("-std=gnu11");
        build.warnings(false);
        build.extra_warnings(false);
        build.include(out_dir);
        // Some older compiler does not support __has_include. Hard code as 1.
        // TODO: don't redefine it.
        build.define("__has_include(x)", "1");
        if target_pointer_width != "64" {
            build.define("KRML_VERIFIED_UINT128", None);
        }
        if arch == "aarch64" || arch == "arm" {
            build.define("Lib_IntVector_Intrinsics_vec256", "void *");
        }
        if arch == "x86" {
            build.define("Lib_IntVector_Intrinsics_vec256", "void *");
            build.define("Lib_IntVector_Intrinsics_vec128", "void *");
        }
        if arch == "arm" {
            // libintvector.h is including arm_nean.h unconditionally. Need this
            // for it to compile at all.
            build.flag_if_supported("-mfpu=neon");
        }
        build.include(distro);
        build.include("hacl-star-dist/kremlin/include");
        build.include("hacl-star-dist/kremlin/kremlib/dist/minimal/");
        build
    };

    if build_vec256 {
        build_common
            .clone()
            .flag_if_supported("/arch:AVX")
            .flag_if_supported("/arch:AVX2")
            .flag_if_supported("-mavx")
            .flag_if_supported("-mavx2")
            .files(map_sources(distro, vec256_sources))
            .compile("evercrypt_vec256");
    }

    if build_vec128 {
        build_common
            .clone()
            .flag_if_supported("/arch:AVX")
            .flag_if_supported("-mavx")
            .flag_if_supported("-march=armv8-a+simd")
            .files(map_sources(distro, vec128_sources))
            .compile("evercrypt_vec128");
    }

    if !asm_sources.is_empty() {
        build_common
            .clone()
            .files(map_sources(distro, asm_sources))
            .compile("evercrypt_asm");
    }

    build_common
        .clone()
        .files(map_sources(distro, evercrypt_sources))
        .files(map_sources(distro, hacl_sources))
        .compile("evercrypt");
}
