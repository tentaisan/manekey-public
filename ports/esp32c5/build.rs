fn main() {
    if std::env::var_os("CARGO_FEATURE_PMP_INTERNAL_UART_FIDO").is_some() {
        if std::env::var_os("CARGO_FEATURE_FLASH_MANAGED_KEYS").is_some() {
            println!(
                "cargo:rustc-link-arg-bin=esp32c5_pmp_internal_uart_fido=--defsym=__c5_managed_pmp_ram=1"
            );
        }
        for name in ["memset", "memcpy", "memmove"] {
            println!(
                "cargo:rustc-link-arg-bin=esp32c5_pmp_internal_uart_fido=--defsym={name}=c5_pmp_user_{name}"
            );
        }
    }

    if std::env::var_os("CARGO_FEATURE_PMP_INTERNAL_UART_FIDO").is_some() {
        println!(
            "cargo:rustc-link-arg-bin=esp32c5_pmp_internal_uart_fido=-Tlinker/linkall-pmp-product.x"
        );
        println!("cargo:rerun-if-changed=linker/linkall-pmp-product.x");
    } else if std::env::var_os("CARGO_FEATURE_ML_DSA_INTEGRATED_LAYOUT").is_some()
        || std::env::var_os("CARGO_FEATURE_BLE_ML_DSA_NATIVE").is_some()
    {
        println!("cargo:rustc-link-search=linker");
        println!("cargo:rustc-link-arg-bin=esp32c5_ble_secure_fido=-Tlinkall-ml-dsa-integrated.x");
        println!(
            "cargo:rustc-link-arg-bin=esp32c5_ble_internal_uart_fido=-Tlinkall-ml-dsa-integrated.x"
        );
        println!("cargo:rerun-if-changed=linker/linkall-ml-dsa-integrated.x");
    } else {
        println!("cargo:rustc-link-arg-bins=-Tlinker/linkall-no-memory.x");
    }
    println!("cargo:rerun-if-changed=linker/linkall-no-memory.x");
}
