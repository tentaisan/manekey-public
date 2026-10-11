fn main() {
    println!("cargo:rerun-if-changed=linker/experimental-low-flash.x");
    if std::env::var_os("CARGO_FEATURE_EXPERIMENTAL_LOW_FLASH").is_some() {
        let script = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("linker/experimental-low-flash.x");
        println!(
            "cargo:rustc-link-arg-bin=ch32v203_multi_fido=-T{}",
            script.display()
        );
    }
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
}
