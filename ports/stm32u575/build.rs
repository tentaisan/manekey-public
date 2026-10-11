fn main() {
    let secure = std::env::var_os("CARGO_FEATURE_TRUSTZONE_SECURE_LAYOUT").is_some();
    let nonsecure = std::env::var_os("CARGO_FEATURE_TRUSTZONE_NONSECURE_IMAGE").is_some();
    assert!(!(secure && nonsecure), "Select one TrustZone image layout");
    let managed = std::env::var_os("CARGO_FEATURE_FLASH_MANAGED_KEYS").is_some();
    assert!(!(managed && nonsecure), "managed storage belongs to Secure");
    let memory = if managed && secure {
        include_bytes!("linker/trustzone/secure-managed.x").as_slice()
    } else if managed {
        include_bytes!("linker/default-managed.x").as_slice()
    } else if secure {
        include_bytes!("linker/trustzone/secure.x").as_slice()
    } else if nonsecure {
        include_bytes!("linker/trustzone/nonsecure.x").as_slice()
    } else {
        include_bytes!("linker/default.x").as_slice()
    };
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("memory.x"), memory).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=linker/default.x");
    println!("cargo:rerun-if-changed=linker/trustzone/secure.x");
    println!("cargo:rerun-if-changed=linker/trustzone/nonsecure.x");
    println!("cargo:rerun-if-changed=linker/trustzone/secure-managed.x");
    println!("cargo:rerun-if-changed=linker/default-managed.x");
}
