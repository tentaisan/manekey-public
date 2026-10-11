fn main() {
    #[cfg(all(not(any()), feature = "ml-dsa-memory-layout"))]
    {
        println!("cargo:rustc-link-search=linker");
        println!("cargo:rustc-link-arg-bin=esp32s2_usb_fido=-Tlinkall-ml-dsa-integrated.x");
        println!("cargo:rerun-if-changed=linker/linkall-ml-dsa-integrated.x");
    }
    #[cfg(all(not(any()), not(feature = "ml-dsa-memory-layout")))]
    {
        println!("cargo:rustc-link-arg-bins=-Tlinkall.x");
    }
}
