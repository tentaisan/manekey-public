fn main() {
    if std::env::var_os("CARGO_FEATURE_ML_DSA_INTEGRATED_LAYOUT").is_some() {
        println!("cargo:rustc-link-search=linker");
        println!("cargo:rustc-link-arg-bin=esp32c3_ble_secure_fido=-Tlinkall-ml-dsa-integrated.x");
        println!("cargo:rerun-if-changed=linker/linkall-ml-dsa-integrated.x");
    } else {
        println!("cargo:rustc-link-arg-bins=-Tlinkall.x");
    }
}
