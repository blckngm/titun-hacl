#![allow(non_upper_case_globals)]

use std::io::Write;
use std::path::{Path, PathBuf};

static vec256_sources: &[&str] = &[
    "Hacl_Chacha20_Vec256.c",
    "Hacl_Chacha20Poly1305_256.c",
    "Hacl_Poly1305_256.c",
    // "Hacl_Blake2b_256.c",
];

static vec128_sources: &[&str] = &[
    // "Hacl_Blake2s_128.c",
    "Hacl_Poly1305_128.c",
    "Hacl_Chacha20Poly1305_128.c",
    "Hacl_Chacha20_Vec128.c",
];

static x86_64_linux_asm_sources: &[&str] = &[
    // "sha256-x86_64-linux.S",
    // "poly1305-x86_64-linux.S",
    // "aesgcm-x86_64-linux.S",
    // "aes-x86_64-linux.S",
    "curve25519-x86_64-linux.S",
    // "oldaesgcm-x86_64-linux.S",
];

static x86_64_mingw_asm_sources: &[&str] = &[
    // "sha256-x86_64-mingw.S",
    // "poly1305-x86_64-mingw.S",
    // "aesgcm-x86_64-mingw.S",
    // "aes-x86_64-mingw.S",
    "curve25519-x86_64-mingw.S",
    // "oldaesgcm-x86_64-mingw.S",
];

static x86_64_darwin_asm_sources: &[&str] = &[
    // "sha256-x86_64-darwin.S",
    // "poly1305-x86_64-darwin.S",
    // "aesgcm-x86_64-darwin.S",
    // "aes-x86_64-darwin.S",
    "curve25519-x86_64-darwin.S",
    // "oldaesgcm-x86_64-darwin.S",
];

static x86_64_msvc_asm_sources: &[&str] = &[
    // "aesgcm-x86_64-msvc.asm",
    // "aes-x86_64-msvc.asm",
    "curve25519-x86_64-msvc.asm",
    // "oldaesgcm-x86_64-msvc.asm",
    // "poly1305-x86_64-msvc.asm",
    // "sha256-x86_64-msvc.asm",
];

static i686_msvc_asm_sources: &[&str] = &[
    // "aes-i686.asm"
];

static adx_bmi2_c_sources: &[&str] = &["Hacl_Curve25519_64.c"];

static c_sources: &[&str] = &[
    // "EverCrypt_AEAD.c",
    // "EverCrypt_AutoConfig2.c",
    // "EverCrypt_Chacha20Poly1305.c",
    // "EverCrypt_CTR.c",
    // "EverCrypt_Curve25519.c",
    // "EverCrypt_DRBG.c",
    // "EverCrypt_Ed25519.c",
    // "EverCrypt_Error.c",
    // "EverCrypt_Hash.c",
    // "EverCrypt_HKDF.c",
    // "EverCrypt_HMAC.c",
    // "EverCrypt_Poly1305.c",
    // "EverCrypt_StaticConfig.c",
    // "evercrypt_vale_stubs.c",
    // "Hacl_AES.c",
    // "Hacl_Blake2b_32.c",
    // "Hacl_Blake2s_32.c",
    "Hacl_Chacha20_Vec32.c",
    "Hacl_Chacha20.c",
    "Hacl_Chacha20Poly1305_32.c",
    "Hacl_Curve25519_51.c",
    // "Hacl_Curve25519_64_Slow.c",
    // "Hacl_Ed25519.c",
    // "Hacl_Frodo_KEM.c",
    // "Hacl_Hash.c",
    // "Hacl_HKDF.c",
    // "Hacl_HMAC_DRBG.c",
    // "Hacl_HMAC.c",
    // "Hacl_HPKE_Curve51_CP128_SHA256.c",
    // "Hacl_HPKE_Curve51_CP128_SHA512.c",
    // "Hacl_HPKE_Curve51_CP256_SHA256.c",
    // "Hacl_HPKE_Curve51_CP256_SHA512.c",
    // "Hacl_HPKE_Curve51_CP32_SHA256.c",
    // "Hacl_HPKE_Curve51_CP32_SHA512.c",
    // "Hacl_HPKE_Curve64_CP128_SHA256.c",
    // "Hacl_HPKE_Curve64_CP128_SHA512.c",
    // "Hacl_HPKE_Curve64_CP256_SHA256.c",
    // "Hacl_HPKE_Curve64_CP256_SHA512.c",
    // "Hacl_HPKE_Curve64_CP32_SHA256.c",
    // "Hacl_HPKE_Curve64_CP32_SHA512.c",
    // "Hacl_HPKE_P256_CP128_SHA256.c",
    // "Hacl_HPKE_P256_CP256_SHA256.c",
    // "Hacl_HPKE_P256_CP32_SHA256.c",
    // "Hacl_Kremlib.c",
    // "Hacl_NaCl.c",
    // "Hacl_P256.c",
    "Hacl_Poly1305_32.c",
    // "Hacl_Salsa20.c",
    // "Hacl_SHA3.c",
    // "Hacl_Spec.c",
    // "Hacl_Streaming_Poly1305_32.c",
    // "Hacl_Streaming_SHA2_256.c",
    // "Lib_Memzero.c",
    // "Lib_PrintBuffer.c",
    // "Lib_RandomBuffer_System.c",
    // "MerkleTree.c",
    // "Vale.c",
];

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
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
        sources.iter().map(move |s| Path::new(distro).join(s))
    }

    let asm_os = match &*os {
        "windows" if env == "msvc" => "msvc",
        "windows" => "mingw",
        // The difference between linux and darwin is whether the symbols are
        // prefixed with an underscore. BSDs don't use the underscore either, so
        // they use linux ASM sources.
        "linux" | "android" | "freebsd" | "dragonfly" | "netbsd" | "openbsd" => "linux",
        "macos" | "ios" => "darwin",
        _ => {
            println!(
                "cargo:warning=evercrypt-sys: using linux asm sources, hopefully that'll work."
            );
            "linux"
        }
    };

    let asm_sources = match (asm_os, &*arch) {
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
    let mut config_h_define = |k: &str, v: &str| writeln!(config_h, "#define {} {}", k, v).unwrap();
    if arch == "aarch64" {
        config_h_define("TARGET_ARCHITECTURE", "TARGET_ARCHITECTURE_ID_ARM8");
    } else if arch == "arm" {
        config_h_define("TARGET_ARCHITECTURE", "TARGET_ARCHITECTURE_ID_ARM7");
    } else if arch == "x86_64" {
        config_h_define("TARGET_ARCHITECTURE", "TARGET_ARCHITECTURE_ID_X64");
    } else if arch == "i686" {
        config_h_define("TARGET_ARCHITECTURE", "TARGET_ARCHITECTURE_ID_X86");
    }
    if arch == "x86_64" || arch == "i686" {
        config_h_define("HACL_CAN_COMPILE_INTRINSICS", "1");
    }
    if arch == "x86_64" {
        config_h_define("HACL_CAN_COMPILE_VALE", "1");
        if env != "msvc" {
            config_h_define("HACL_CAN_COMPILE_UINT128", "1");
            config_h_define("HACL_CAN_COMPILE_INLINE_ASM", "1");
        }
    }
    if build_vec256 {
        config_h_define("HACL_CAN_COMPILE_VEC256", "1");
    }
    if build_vec128 {
        config_h_define("HACL_CAN_COMPILE_VEC128", "1");
    }
    config_h.flush().unwrap();
    drop(config_h);

    let build_common = {
        let mut build = cc::Build::new();
        build.flag_if_supported("-std=gnu11");
        build.flag_if_supported("-fwrapv");
        build.define("_BSD_SOURCE", None);
        build.define("_DEFAULT_SOURCE", None);
        build.flag_if_supported("-mtune=skylake");
        build.warnings(false);
        build.extra_warnings(false);
        build.include(out_dir);
        build.include(distro);
        build.include("hacl-star-dist/kremlin/include");
        build.include("hacl-star-dist/kremlin/kremlib/dist/minimal/");
        build
    };

    if build_vec256 {
        build_common
            .clone()
            .flag_if_supported("/arch:AVX2")
            .flag_if_supported("-mavx2")
            .files(map_sources(distro, vec256_sources))
            .compile("evercrypt_vec256");
    }

    if build_vec128 {
        let mut build = build_common.clone();
        build
            .flag_if_supported("-mtune=silvermont")
            .flag_if_supported("-msse4.2")
            .flag_if_supported("-march=armv8-a+simd");

        build
            .files(map_sources(distro, vec128_sources))
            .compile("evercrypt_vec128");
    }

    if !asm_sources.is_empty() {
        let mut build = build_common.clone();
        if env == "msvc" {
            build.flag("/nologo");
        }
        build.files(map_sources(distro, asm_sources));
        build.compile("evercrypt_asm");
    }

    if arch == "x86_64" {
        let mut build = build_common.clone();
        // Need these or clang won't be happy with the inline assembly.
        build.flag_if_supported("-madx");
        build.flag_if_supported("-mbmi2");
        build.files(map_sources(distro, adx_bmi2_c_sources));
        build.compile("evercrypt_adx_bmi2");
    }

    #[allow(clippy::redundant_clone)]
    let mut build = build_common.clone();
    build.files(map_sources(distro, c_sources));
    build.compile("evercrypt");
}
