use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Stdio},
};

fn main() {
    install_memory_layout();
    println!("cargo:rerun-if-changed=boards/xiao/linker/softdevice-s140.x");
    println!("cargo:rerun-if-changed=boards/xiao/linker/usb-full-ram.x");
    println!("cargo:rerun-if-env-changed=NRF5_SDK_ROOT");

    if env::var_os("CARGO_FEATURE_NRF_CRYPTOCELL_P256").is_some() {
        build_cc310_p256_shim();
    }
}

fn install_memory_layout() {
    let source = if env::var_os("CARGO_FEATURE_NRF_USB_FULL_RAM").is_some() {
        "boards/xiao/linker/usb-full-ram.x"
    } else {
        "boards/xiao/linker/softdevice-s140.x"
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::copy(source, out.join("memory.x")).expect("copy selected nRF52840 memory layout");
    println!("cargo:rustc-link-search={}", out.display());
}

fn build_cc310_p256_shim() {
    let sdk = PathBuf::from(
        env::var_os("NRF5_SDK_ROOT")
            .expect("nrf-cryptocell-p256 requires NRF5_SDK_ROOT pointing to nRF5 SDK 17.1.0"),
    );
    let include = sdk.join("external/nrf_cc310/include");
    let library = sdk.join("external/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts");
    let archive = library.join("libnrf_cc310_0.9.13.a");
    assert!(
        include.join("crys_ecpki_kg.h").is_file() && archive.is_file(),
        "NRF5_SDK_ROOT does not contain the expected CC310 0.9.13 files"
    );

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let object = out.join("cc310_p256_shim.o");
    let shim_archive = out.join("libmanekey_cc310_p256_shim.a");
    run(Command::new("arm-none-eabi-gcc").args([
        "-c",
        "src/cc310_p256_shim.c",
        "-o",
        object.to_str().unwrap(),
        "-mcpu=cortex-m4",
        "-mthumb",
        "-mabi=aapcs",
        "-mfloat-abi=hard",
        "-mfpu=fpv4-sp-d16",
        "-O2",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-ffunction-sections",
        "-fdata-sections",
        "-fshort-enums",
        "-DDX_CC_TEE",
        "-DFLOAT_ABI_HARD",
        "-I",
        include.to_str().unwrap(),
    ]));
    run(Command::new("arm-none-eabi-ar").args([
        "crs",
        shim_archive.to_str().unwrap(),
        object.to_str().unwrap(),
    ]));

    println!("cargo:rerun-if-changed=src/cc310_p256_shim.c");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=manekey_cc310_p256_shim");
    println!("cargo:rustc-link-search=native={}", library.display());
    println!("cargo:rustc-link-lib=static=nrf_cc310_0.9.13");
}

fn run(command: &mut Command) {
    let status = command
        .stdin(Stdio::null())
        .status()
        .expect("run CC310 shim build tool");
    assert!(status.success(), "CC310 shim build tool failed");
}
