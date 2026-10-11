#[cfg(feature = "mpu-layout")]
fn memory_layout() -> &'static [u8] {
    include_bytes!("linker/mpu.x")
}

#[cfg(all(feature = "product-layout", not(feature = "mpu-layout")))]
fn memory_layout() -> &'static [u8] {
    include_bytes!("linker/product.x")
}

#[cfg(all(not(any()), not(feature = "product-layout")))]
fn memory_layout() -> &'static [u8] {
    panic!("select a firmware memory layout")
}

fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("memory.x"), memory_layout()).unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rerun-if-changed=linker/product.x");
    println!("cargo:rerun-if-changed=linker/mpu.x");
}
