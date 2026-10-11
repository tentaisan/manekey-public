fn main() {
    println!("cargo:rustc-link-search=linker");
    for binary in [
        "esp32_ble_internal_uart_fido",
        "esp32_ble_fido",
        "esp32_ble_secure_fido",
    ] {
        let linker = "linkall.x";

        println!("cargo:rustc-link-arg-bin={binary}=-T{linker}");
    }
}
