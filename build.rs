fn main() {
    if std::env::var("CARGO_CFG_TARGET_ENV").map_or(false, |env| env == "msvc") {
        msvc();
    } else {
        gcc();
    }
}

fn gcc() {
    let is_64 = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() == "64";
    let variant = match &*std::env::var("CARGO_CFG_TARGET_OS").unwrap() {
        "windows" => "mingw",
        "linux" | "android" => "linux",
        "macos" | "ios" | "freebsd" | "dragonfly" | "openbsd" | "netbsd" => "darwin",
        os => panic!("Unsupported target OS: {}", os),
    };

    let base = if is_64 {
        "hacl-star-v0.2.1/gcc64-only"
    } else {
        "hacl-star-v0.2.1/gcc-compatible"
    };

    let all_sources: Vec<_> = std::fs::read_dir(base)
        .unwrap()
        .map(|x| x.unwrap().path())
        .collect();

    let mut vec256_sources = Vec::new();
    let mut vec128_sources = Vec::new();
    let mut asm_sources = Vec::new();
    let mut c_sources = Vec::new();

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let asm_suffix = format!("-{}-{}.S", arch, variant);
    for source in all_sources {
        let file_name = source.file_name().unwrap().to_str().unwrap();
        if file_name.ends_with("256.c") {
            vec256_sources.push(source);
        } else if file_name.ends_with("128.c") {
            vec128_sources.push(source);
        } else if file_name.ends_with(&asm_suffix) {
            asm_sources.push(source);
        } else if file_name.ends_with(".c")
            && file_name != "evercrypt_bcrypt.c"
            && file_name != "evercrypt_openssl.c"
            && file_name != "EverCrypt.c"
            && file_name != "EverCrypt_CTR.c"
            && file_name != "EverCrypt_Cipher.c"
            && !(file_name == "Hacl_Curve25519_64.c" && arch != "x86_64")
        {
            c_sources.push(source);
        }
    }
    dbg!(&vec256_sources);
    dbg!(&vec128_sources);
    dbg!(&asm_sources);
    dbg!(&c_sources);

    fn new_build(base: &str) -> cc::Build {
        let mut build = cc::Build::new();
        build.flag("-std=gnu11");
        build.warnings(false);
        build.extra_warnings(false);
        build.include(base);
        build.include("hacl-star-v0.2.1/kremlin/include");
        build.include("hacl-star-v0.2.1/kremlin/kremlib/dist/minimal/");
        build
    }

    if arch == "x86_64" {
        new_build(base)
            .flag("-march=haswell")
            .flag("-mavx")
            .flag("-mavx2")
            .files(vec256_sources)
            .compile("evercrypt_vec256");

        new_build(base)
            .flag("-mavx")
            .files(vec128_sources)
            .compile("evercrypt_vec128");
    }

    new_build(base)
        .files(c_sources)
        .files(asm_sources)
        .compile("evercrypt");
}

fn msvc() {
    let all_sources: Vec<_> = std::fs::read_dir("hacl-star-v0.2.1/msvc-compatible")
        .unwrap()
        .map(|x| x.unwrap().path())
        .collect();

    let mut vec256_sources = Vec::new();
    let mut vec128_sources = Vec::new();
    let mut x64_msvc_asm_sources = Vec::new();
    let mut i686_asm_sources = Vec::new();
    let mut general_sources = Vec::new();

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    for source in all_sources {
        let file_name = source.file_name().unwrap().to_str().unwrap();
        if file_name.ends_with("256.c") {
            vec256_sources.push(source);
        } else if file_name.ends_with("128.c") {
            vec128_sources.push(source);
        } else if file_name.ends_with("-x86_64-msvc.asm") {
            x64_msvc_asm_sources.push(source);
        } else if file_name.ends_with("i686.asm") {
            i686_asm_sources.push(source);
        } else if file_name.ends_with(".c")
            && file_name != "evercrypt_bcrypt.c"
            && file_name != "evercrypt_openssl.c"
            && file_name != "EverCrypt.c"
            && file_name != "EverCrypt_CTR.c"
            && file_name != "EverCrypt_Cipher.c"
            && !(file_name == "Hacl_Curve25519_64.c" && target_arch != "x86_64")
        {
            general_sources.push(source);
        }
    }

    fn new_build() -> cc::Build {
        let mut build = cc::Build::new();
        build.warnings(false);
        build.extra_warnings(false);
        build.include("hacl-star-v0.2.1/msvc-compatible");
        build.include("hacl-star-v0.2.1/kremlin/include");
        build.include("hacl-star-v0.2.1/kremlin/kremlib/dist/minimal/");
        build
    }

    if target_arch == "x86_64" {
        new_build()
            .flag("/arch:AVX")
            .flag("/arch:AVX2")
            .files(vec256_sources)
            .compile("evercrypt_vec256");

        new_build()
            .flag("/arch:AVX")
            .files(vec128_sources)
            .compile("evercrypt_vec128");
    }

    let mut build = new_build();
    build.files(general_sources);
    match &*target_arch {
        "x86_64" => {
            build.files(x64_msvc_asm_sources);
        }
        "i686" => {
            build.files(i686_asm_sources);
        }
        _ => {}
    }
    build.compile("evercrypt");
}
