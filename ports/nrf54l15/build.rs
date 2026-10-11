use std::{env, fs, path::PathBuf};

fn main() {
    #[cfg(feature = "cracen-p256-experimental")]
    {
        cc::Build::new()
            .file("src/cracen_microcode.c")
            .include("vendor/nordic-cracen")
            .compile("manekey_cracen_microcode");
        println!("cargo::rerun-if-changed=src/cracen_microcode.c");
        println!("cargo::rerun-if-changed=vendor/nordic-cracen/microcode_binary.h");
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let secure = env::var_os("CARGO_FEATURE_TRUSTZONE_SECURE_LAYOUT").is_some();
    let nonsecure = env::var_os("CARGO_FEATURE_TRUSTZONE_NONSECURE_IMAGE").is_some();
    let nonsecure_shared = env::var_os("CARGO_FEATURE_TRUSTZONE_NONSECURE_SHARED_IMAGE").is_some();

    let nonsecure_radio = false;
    if secure && (nonsecure || nonsecure_shared || nonsecure_radio)
        || nonsecure && (nonsecure_shared || nonsecure_radio)
        || nonsecure_shared && nonsecure_radio
    {
        panic!("select one nRF54L15 TrustZone image layout");
    }
    let kmu = env::var_os("CARGO_FEATURE_KMU_KEY_STORE").is_some();
    let flash_keys = env::var_os("CARGO_FEATURE_FLASH_MANAGED_KEYS").is_some();
    let large = env::var_os("CARGO_FEATURE_TRUSTZONE_LARGE_LAYOUT").is_some();

    if large && !(secure || nonsecure_shared) {
        panic!("large TZ profile requires a Secure or shared Non-Secure image");
    }

    let pqc = [
        "CARGO_FEATURE_EXPERIMENTAL_ML_DSA_FIPS204",
        "CARGO_FEATURE_EXPERIMENTAL_ML_DSA_FIPS204_SCRATCH",
        "CARGO_FEATURE_EXPERIMENTAL_ML_DSA_MLDSA_NATIVE",
    ]
    .iter()
    .any(|feature| env::var_os(feature).is_some());
    if secure && pqc && !large {
        panic!("TZ ML-DSA requires a paired large-response RAM/shared layout");
    }
    if kmu && flash_keys {
        panic!("select one managed key persistence backend");
    }
    if flash_keys && (nonsecure || nonsecure_shared || nonsecure_radio) {
        panic!("managed key journal must be Secure-owned");
    }
    if kmu && (nonsecure || nonsecure_shared || nonsecure_radio) {
        panic!("KMU product key store must be Secure-owned");
    }
    let memory = memory_image(secure, nonsecure, nonsecure_shared, kmu, large);
    fs::write(out.join("memory.x"), memory).expect("write memory.x");
    fs::write(
        out.join("kmu-product.x"),
        include_bytes!("linker/kmu-product.x"),
    )
    .expect("write KMU linker section");
    println!("cargo::rustc-link-search={}", out.display());
    println!("cargo::rerun-if-changed=linker/default.x");

    println!("cargo::rerun-if-changed=linker/default-kmu.x");
    println!("cargo::rerun-if-changed=linker/trustzone/secure-kmu.x");
    println!("cargo::rerun-if-changed=linker/kmu-product.x");
    println!("cargo::rerun-if-changed=linker/trustzone/secure.x");

    println!("cargo::rerun-if-changed=linker/trustzone/nonsecure.x");
    println!("cargo::rerun-if-changed=linker/trustzone/nonsecure-shared.x");

    println!("cargo::rerun-if-changed=linker/trustzone/secure-large.x");
    println!("cargo::rerun-if-changed=linker/trustzone/secure-large-kmu.x");
    println!("cargo::rerun-if-changed=linker/trustzone/nonsecure-large.x");
}

fn memory_image(
    secure: bool,
    nonsecure: bool,
    nonsecure_shared: bool,
    kmu: bool,
    large: bool,
) -> &'static [u8] {
    if large && secure && kmu {
        include_bytes!("linker/trustzone/secure-large-kmu.x")
    } else if large && secure {
        include_bytes!("linker/trustzone/secure-large.x")
    } else if large && nonsecure_shared {
        include_bytes!("linker/trustzone/nonsecure-large.x")
    } else if secure && kmu {
        include_bytes!("linker/trustzone/secure-kmu.x")
    } else if kmu {
        include_bytes!("linker/default-kmu.x")
    } else if secure {
        include_bytes!("linker/trustzone/secure.x")
    } else if nonsecure {
        include_bytes!("linker/trustzone/nonsecure.x")
    } else if nonsecure_shared {
        include_bytes!("linker/trustzone/nonsecure-shared.x")
    } else {
        include_bytes!("linker/default.x")
    }
}
