fn main() {
    if std::env::var_os("CARGO_FEATURE_ML_DSA_INTEGRATED_LAYOUT").is_some()
        || std::env::var_os("CARGO_FEATURE_ML_DSA_NATIVE_INTEGRATED_LAYOUT").is_some()
    {
        println!("cargo:rustc-link-search=linker");
        println!("cargo:rustc-link-arg-bin=esp32c6_ble_secure_fido=-Tlinkall-ml-dsa-integrated.x");
        println!(
            "cargo:rustc-link-arg-bin=esp32c6_ble_internal_uart_fido=-Tlinkall-ml-dsa-integrated.x"
        );
        println!("cargo:rerun-if-changed=linker/linkall-ml-dsa-integrated.x");
    } else {
        println!("cargo:rustc-link-arg-bins=-Tlinker/linkall-no-memory.x");
    }
    println!("cargo:rerun-if-changed=linker/linkall-no-memory.x");
}
